/**
 * URLhaus Live Reputation Provider
 * 
 * Implements lookup-only reputation intelligence against the official
 * abuse.ch URLhaus Community API (https://urlhaus-api.abuse.ch/v1/url/).
 * 
 * Enforces strict security boundaries:
 * - LOOKUP ONLY: Never submits URLs, crawls websites, follows redirects, or resolves DNS.
 * - Server-only API authentication via URLHAUS_AUTH_KEY.
 * - Missing API key gracefully degrades to 'unavailable' status without crashing.
 * - "Not found in URLhaus" normalizes to 'unknown' (absence of record ≠ safe).
 * - Sanitized evidence generation without leaking raw payload or auth keys.
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

// Expected JSON response structure from abuse.ch URLhaus API
export interface UrlhausApiResponse {
  query_status: 'ok' | 'no_results' | 'invalid_url' | string;
  id?: string | number;
  urlhaus_reference?: string;
  url?: string;
  url_status?: 'online' | 'offline' | string;
  host?: string;
  date_added?: string;
  threat?: string;
  blacklists?: Record<string, string>;
  reporter?: string;
  tags?: string[];
  payloads?: unknown[];
}

export interface UrlhausProviderConfig {
  apiKey?: string;
  apiUrl?: string;
  defaultTimeoutMs?: number;
  cache?: ReputationCache;
  fetchFn?: typeof fetch;
}

const DEFAULT_URLHAUS_API_URL = 'https://urlhaus-api.abuse.ch/v1/url/';
const DEFAULT_TIMEOUT_MS = 3000;

export class UrlhausReputationProvider extends BaseReputationProvider {
  private apiKey?: string;
  private apiUrl: string;
  private fetchFn: typeof fetch;

  constructor(config?: UrlhausProviderConfig) {
    super('urlhaus', 'URLhaus', {
      defaultTimeoutMs: config?.defaultTimeoutMs ?? DEFAULT_TIMEOUT_MS,
      cache: config?.cache,
    });

    // Server-only key retrieval
    this.apiKey = config?.apiKey ?? process.env.URLHAUS_AUTH_KEY?.trim();
    this.apiUrl = config?.apiUrl ?? DEFAULT_URLHAUS_API_URL;
    this.fetchFn = config?.fetchFn ?? globalThis.fetch;

    // Set initial operational status based on configuration
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
    // If no key is configured, provider is always unavailable
    const currentKey = this.apiKey ?? process.env.URLHAUS_AUTH_KEY?.trim();
    if (!currentKey) {
      this.status = 'unavailable';
      return 'unavailable';
    }

    // Refresh key reference if it was injected into process.env at runtime
    if (!this.apiKey && currentKey) {
      this.apiKey = currentKey;
      this.status = 'ready';
    }

    return super.getStatus();
  }

  /**
   * Executes the isolated HTTP POST lookup to the URLhaus API.
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
    const key = this.apiKey ?? process.env.URLHAUS_AUTH_KEY?.trim();

    // 1. Guard: Missing API key
    if (!key) {
      const err = new Error('URLhaus provider is unavailable (missing configuration).');
      (err as unknown as { code: string }).code = 'provider_unavailable';
      throw err;
    }

    // 2. Prepare URL-encoded form payload (abuse.ch API specification)
    const bodyParams = new URLSearchParams();
    bodyParams.append('url', normalizedUrl);

    // 3. Prepare headers strictly protecting secrets from logs
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Auth-Key': key,
      'User-Agent': 'MyAI-SafetyCheck/1.0',
    };

    let response: Response;
    try {
      response = await this.fetchFn(this.apiUrl, {
        method: 'POST',
        headers,
        body: bodyParams.toString(),
        signal: options?.signal,
      });
    } catch (fetchErr: unknown) {
      const err = fetchErr as { name?: string; message?: string };
      if (err.name === 'AbortError' || err.message?.toLowerCase().includes('abort')) {
        const timeoutErr = new Error('URLhaus lookup timed out.');
        (timeoutErr as unknown as { code: string }).code = 'timeout';
        throw timeoutErr;
      }
      const netErr = new Error('URLhaus network connection failure.');
      (netErr as unknown as { code: string }).code = 'network_error';
      throw netErr;
    }

    // 4. Handle HTTP status codes
    if (response.status === 429) {
      const err = new Error('URLhaus API rate limit exceeded (HTTP 429).');
      (err as unknown as { statusCode: number; code: string; retryAfterMs: number }).statusCode = 429;
      (err as unknown as { code: string }).code = 'rate_limited';
      (err as unknown as { retryAfterMs: number }).retryAfterMs = 60000;
      throw err;
    }

    if (response.status === 401 || response.status === 403) {
      const err = new Error('URLhaus API authentication failed (HTTP 401/403).');
      (err as unknown as { statusCode: number; code: string }).statusCode = response.status;
      (err as unknown as { code: string }).code = 'network_error';
      throw err;
    }

    if (response.status >= 500) {
      const err = new Error(`URLhaus upstream server error (HTTP ${response.status}).`);
      (err as unknown as { statusCode: number; code: string }).statusCode = response.status;
      (err as unknown as { code: string }).code = 'network_error';
      throw err;
    }

    if (!response.ok) {
      const err = new Error(`URLhaus request failed with status ${response.status}.`);
      (err as unknown as { statusCode: number; code: string }).statusCode = response.status;
      (err as unknown as { code: string }).code = 'network_error';
      throw err;
    }

    // 5. Parse JSON safely
    let data: UrlhausApiResponse;
    try {
      data = (await response.json()) as UrlhausApiResponse;
    } catch {
      const err = new Error('URLhaus returned a malformed or non-JSON response.');
      (err as unknown as { code: string }).code = 'invalid_response';
      throw err;
    }

    // 6. Normalize query_status
    if (data.query_status === 'ok') {
      // Threat identified in database
      const threatType = data.threat || 'malware_download';
      const threatCategories: ReputationThreatCategory[] = ['malware'];

      if (threatType.toLowerCase().includes('phish')) {
        threatCategories.push('phishing');
      }

      const tags = Array.isArray(data.tags) ? data.tags.slice(0, 8) : [];
      const urlStatus = data.url_status || 'unknown';

      return {
        detectionStatus: 'malicious',
        confidence: 'high',
        threatCategories,
        rawDetails: {
          urlhausId: data.id,
          urlStatus,
          threat: threatType,
          tags,
          dateAdded: data.date_added,
          reporter: data.reporter,
        },
        description: `URLhaus reputation: Known malicious URL associated with malware distribution (${threatType}).`,
        snippet: `Threat: ${threatType} | Status: ${urlStatus}${tags.length > 0 ? ` | Tags: ${tags.join(', ')}` : ''}`,
      };
    }

    if (data.query_status === 'no_results') {
      // Not found in URLhaus. Absence of record != Safe!
      return {
        detectionStatus: 'unknown',
        confidence: 'low',
        rawDetails: {
          queryStatus: 'no_results',
        },
        description: 'URLhaus: No matching malicious record found. Absence of a record is not proof of safety.',
        snippet: 'Status: no_results | No malware records found in URLhaus feed',
      };
    }

    // Other non-matching or invalid responses normalize to unknown
    return {
      detectionStatus: 'unknown',
      confidence: 'low',
      rawDetails: {
        queryStatus: data.query_status,
      },
      description: `URLhaus returned unindexed status: ${data.query_status}.`,
      snippet: `Status: ${data.query_status}`,
    };
  }
}

// Global default instance
export const urlhausProvider = new UrlhausReputationProvider();
