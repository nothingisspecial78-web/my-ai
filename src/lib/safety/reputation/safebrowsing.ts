/**
 * Google Safe Browsing Live Reputation Provider (Phase 4.8C)
 * 
 * Implements lookup-only reputation intelligence against the official
 * Google Safe Browsing Lookup API v4 (https://safebrowsing.googleapis.com/v4/threatMatches:find).
 * 
 * Enforces strict security boundaries:
 * - LOOKUP ONLY: Queries official hash/URL threat lists; never crawls, downloads, or navigates.
 * - Server-only API authentication via SAFE_BROWSING_API_KEY.
 * - Missing API key gracefully degrades to 'unavailable' status without crashing.
 * - Empty threat match ({}) normalizes to 'clean' (authoritative web threat list check).
 * - Sanitized evidence generation without leaking API keys or raw payload.
 */

import { ConfidenceLevel } from '../types';
import { BaseReputationProvider } from './provider';
import {
  ProviderStatus,
  ReputationCache,
  ReputationDetectionStatus,
  ReputationLookupOptions,
  ReputationThreatCategory,
} from './types';

// Google Safe Browsing v4 Threat Match payload structure
export interface SafeBrowsingThreatMatch {
  threatType: string;
  platformType: string;
  threatEntryType: string;
  threat?: { url?: string };
  threatEntryMetadata?: {
    entries?: Array<{ key: string; value: string }>;
  };
  cacheDuration?: string;
}

// Google Safe Browsing v4 Threat Matches Find response
export interface SafeBrowsingApiResponse {
  matches?: SafeBrowsingThreatMatch[];
}

export interface SafeBrowsingProviderConfig {
  apiKey?: string;
  apiUrl?: string;
  defaultTimeoutMs?: number;
  cache?: ReputationCache;
  fetchFn?: typeof fetch;
}

const DEFAULT_SAFE_BROWSING_API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
const DEFAULT_TIMEOUT_MS = 3000;

export class SafeBrowsingReputationProvider extends BaseReputationProvider {
  private apiKey?: string;
  private apiUrl: string;
  private fetchFn: typeof fetch;

  constructor(config?: SafeBrowsingProviderConfig) {
    super('safebrowsing', 'Google Safe Browsing', {
      defaultTimeoutMs: config?.defaultTimeoutMs ?? DEFAULT_TIMEOUT_MS,
      cache: config?.cache,
    });

    // Server-only key retrieval
    this.apiKey = config?.apiKey ?? process.env.SAFE_BROWSING_API_KEY?.trim();
    this.apiUrl = config?.apiUrl ?? DEFAULT_SAFE_BROWSING_API_URL;
    this.fetchFn = config?.fetchFn ?? globalThis.fetch;

    // Set initial operational status based on key availability
    if (!this.apiKey) {
      this.status = 'unavailable';
    } else {
      this.status = 'ready';
    }
  }

  /**
   * Returns operational status. Automatically reflects unconfigured status
   * when the server-side API key is missing.
   */
  override getStatus(): ProviderStatus {
    const currentKey = this.apiKey ?? process.env.SAFE_BROWSING_API_KEY?.trim();
    if (!currentKey) {
      this.status = 'unavailable';
      return 'unavailable';
    }

    // Refresh key reference if injected into environment at runtime
    if (!this.apiKey && currentKey) {
      this.apiKey = currentKey;
      this.status = 'ready';
    }

    return super.getStatus();
  }

  /**
   * Executes isolated HTTP POST lookup to Google Safe Browsing API v4.
   */
  protected async executeLookup(
    normalizedUrl: string,
    options?: ReputationLookupOptions
  ): Promise<{
    detectionStatus: ReputationDetectionStatus;
    confidence: ConfidenceLevel;
    threatCategories?: ReputationThreatCategory[];
    rawDetails?: Record<string, unknown>;
    description?: string;
    snippet?: string;
  }> {
    const key = this.apiKey ?? process.env.SAFE_BROWSING_API_KEY?.trim();

    // 1. Guard: Missing API key
    if (!key) {
      const err = new Error('Google Safe Browsing provider is unavailable (missing configuration).');
      (err as unknown as { code: string }).code = 'provider_unavailable';
      throw err;
    }

    // 2. Prepare threat request body conforming to Safe Browsing v4 threatMatches:find
    const requestBody = {
      client: {
        clientId: 'myai-safety-service',
        clientVersion: '1.0.0',
      },
      threatInfo: {
        threatTypes: [
          'MALWARE',
          'SOCIAL_ENGINEERING',
          'UNWANTED_SOFTWARE',
          'POTENTIALLY_HARMFUL_APPLICATION',
        ],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url: normalizedUrl }],
      },
    };

    // 3. Prepare URL with API key query parameter (URL constructed safely)
    const urlWithKey = new URL(this.apiUrl);
    urlWithKey.searchParams.set('key', key);

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'MyAI-SafetyCheck/1.0',
    };

    let response: Response;
    try {
      response = await this.fetchFn(urlWithKey.toString(), {
        method: 'POST',
        headers,
        body: JSON.stringify(requestBody),
        signal: options?.signal,
      });
    } catch (fetchErr: unknown) {
      const err = fetchErr as { name?: string; message?: string };
      if (err.name === 'AbortError' || err.message?.toLowerCase().includes('abort')) {
        const timeoutErr = new Error('Google Safe Browsing lookup timed out.');
        (timeoutErr as unknown as { code: string }).code = 'timeout';
        throw timeoutErr;
      }
      const netErr = new Error('Google Safe Browsing network connection failure.');
      (netErr as unknown as { code: string }).code = 'network_error';
      throw netErr;
    }

    // 4. Handle HTTP error status codes safely without exposing secrets
    if (response.status === 429) {
      const err = new Error('Google Safe Browsing API rate limit exceeded (HTTP 429).');
      (err as unknown as { statusCode: number; code: string; retryAfterMs: number }).statusCode = 429;
      (err as unknown as { code: string }).code = 'rate_limited';
      (err as unknown as { retryAfterMs: number }).retryAfterMs = 60000;
      throw err;
    }

    if (response.status === 400) {
      const err = new Error('Google Safe Browsing returned HTTP 400 (Bad Request).');
      (err as unknown as { statusCode: number; code: string }).statusCode = 400;
      (err as unknown as { code: string }).code = 'invalid_response';
      throw err;
    }

    if (response.status === 401 || response.status === 403) {
      const err = new Error('Google Safe Browsing authentication failed (HTTP 401/403).');
      (err as unknown as { statusCode: number; code: string }).statusCode = response.status;
      (err as unknown as { code: string }).code = 'network_error';
      throw err;
    }

    if (response.status >= 500) {
      const err = new Error(`Google Safe Browsing upstream server error (HTTP ${response.status}).`);
      (err as unknown as { statusCode: number; code: string }).statusCode = response.status;
      (err as unknown as { code: string }).code = 'network_error';
      throw err;
    }

    if (!response.ok) {
      const err = new Error(`Google Safe Browsing request failed with status ${response.status}.`);
      (err as unknown as { statusCode: number; code: string }).statusCode = response.status;
      (err as unknown as { code: string }).code = 'network_error';
      throw err;
    }

    // 5. Parse JSON response
    let data: SafeBrowsingApiResponse;
    try {
      data = (await response.json()) as SafeBrowsingApiResponse;
    } catch {
      const err = new Error('Google Safe Browsing returned a malformed or non-JSON response.');
      (err as unknown as { code: string }).code = 'invalid_response';
      throw err;
    }

    // 6. Threat Matches Evaluation
    const matches = Array.isArray(data.matches) ? data.matches : [];

    if (matches.length > 0) {
      // One or more threat types identified
      const categoriesSet = new Set<ReputationThreatCategory>();
      const threatTypes: string[] = [];

      for (const m of matches) {
        threatTypes.push(m.threatType);
        const upper = m.threatType.toUpperCase();
        if (upper.includes('MALWARE')) {
          categoriesSet.add('malware');
        } else if (upper.includes('SOCIAL_ENGINEERING')) {
          categoriesSet.add('phishing');
        } else if (upper.includes('UNWANTED')) {
          categoriesSet.add('unwanted');
        } else if (upper.includes('HARMFUL') || upper.includes('POTENTIALLY')) {
          categoriesSet.add('suspicious');
        } else {
          categoriesSet.add('malware');
        }
      }

      const threatCategories = Array.from(categoriesSet);
      const threatTypesList = threatTypes.join(', ');

      return {
        detectionStatus: 'malicious',
        confidence: 'high',
        threatCategories,
        rawDetails: {
          matchCount: matches.length,
          threatTypes,
          platforms: matches.map(m => m.platformType),
          cacheDuration: matches[0]?.cacheDuration,
        },
        description: `Google Safe Browsing: Known threat detected (${threatTypesList}).`,
        snippet: `Threats: ${threatTypesList} | Matches: ${matches.length}`,
      };
    }

    // 7. No matches in database -> No threat match found on lists
    // Google Safe Browsing is an authoritative blocklist.
    // Empty result indicates no matching malware/phishing list entries.
    return {
      detectionStatus: 'clean',
      confidence: 'medium', // Medium confidence: external clean status != guarantee of safety
      rawDetails: {
        matchCount: 0,
      },
      description: "Google Safe Browsing: No matching threat was found on Google's Safe Browsing lists.",
      snippet: 'Status: not_flagged | No threat match found on Google Safe Browsing lists',
    };
  }
}

// Global default singleton instance
export const safeBrowsingProvider = new SafeBrowsingReputationProvider();
