/**
 * Reputation Provider Base Architecture & Mock Provider
 * 
 * Defines the abstract BaseReputationProvider handling timeouts, rate limits,
 * caching checks, error normalization, and evidence synthesis.
 * Provides MockReputationProvider for rigorous offline verification.
 */

import crypto from 'crypto';
import { ConfidenceLevel, Evidence } from '../types';
import {
  ProviderReputationResult,
  ProviderStatus,
  ReputationCache,
  ReputationDetectionStatus,
  ReputationError,
  ReputationLookupOptions,
  ReputationProvider,
  ReputationThreatCategory,
} from './types';
import {
  generateUrlCacheKey,
  normalizeUrlForReputation,
  reputationCache,
} from './cache';

/**
 * Abstract Base Class for URL Reputation Providers.
 * Provides timeout protection, caching, rate-limit backoff, and error normalization.
 */
export abstract class BaseReputationProvider implements ReputationProvider {
  readonly id: string;
  readonly name: string;
  readonly defaultTimeoutMs: number;
  protected cache: ReputationCache;
  protected status: ProviderStatus = 'ready';
  protected rateLimitResetAt?: number;

  constructor(
    id: string,
    name: string,
    options?: {
      defaultTimeoutMs?: number;
      cache?: ReputationCache;
    }
  ) {
    this.id = id;
    this.name = name;
    this.defaultTimeoutMs = options?.defaultTimeoutMs ?? 3000;
    this.cache = options?.cache ?? reputationCache;
  }

  /**
   * Retrieves operational status, resetting rate limits if window has elapsed.
   */
  getStatus(): ProviderStatus {
    if (this.status === 'rate_limited' && this.rateLimitResetAt) {
      if (Date.now() >= this.rateLimitResetAt) {
        this.status = 'ready';
        this.rateLimitResetAt = undefined;
      }
    }
    return this.status;
  }

  /**
   * Sets manual rate-limited state with cooldown duration in ms.
   */
  setRateLimited(durationMs = 60000): void {
    this.status = 'rate_limited';
    this.rateLimitResetAt = Date.now() + durationMs;
  }

  /**
   * Main entry point for URL reputation lookup.
   * Performs normalization, cache lookup, timeout racing, and error isolation.
   */
  async lookupUrl(
    rawUrl: string,
    options?: ReputationLookupOptions
  ): Promise<ProviderReputationResult> {
    const startTime = Date.now();
    const normalizedUrl = normalizeUrlForReputation(rawUrl);
    const cacheKey = generateUrlCacheKey(normalizedUrl, this.id);

    // 1. Check Cache unless bypassed
    if (!options?.bypassCache) {
      try {
        const cachedEntry = await this.cache.get(cacheKey);
        if (cachedEntry && !cachedEntry.stale) {
          return {
            ...cachedEntry.result,
            cached: true,
            latencyMs: Date.now() - startTime,
          };
        }
      } catch {
        // Cache read failure is non-fatal
      }
    }

    // 2. Check if currently rate limited
    if (this.getStatus() === 'rate_limited') {
      const result: ProviderReputationResult = {
        providerId: this.id,
        providerName: this.name,
        url: normalizedUrl,
        status: 'rate_limited',
        detectionStatus: 'unavailable',
        confidence: 'low',
        timestamp: new Date().toISOString(),
        latencyMs: Date.now() - startTime,
        cached: false,
        error: {
          code: 'rate_limited',
          message: `${this.name} is temporarily rate-limited. Cooldown active.`,
          retryAfterMs: this.rateLimitResetAt ? Math.max(0, this.rateLimitResetAt - Date.now()) : undefined,
        },
        evidence: this.buildEvidence(
          normalizedUrl,
          'unavailable',
          'low',
          undefined,
          'Provider rate limit encountered. Query not executed.'
        ),
      };
      return result;
    }

    // 3. Execute lookup with timeout guard
    const timeoutMs = options?.timeoutMs ?? this.defaultTimeoutMs;

    try {
      const lookupPromise = this.executeLookup(normalizedUrl, options);

      const timeoutPromise = new Promise<never>((_, reject) => {
        const timer = setTimeout(() => {
          const timeoutErr = new Error(`Provider lookup timed out after ${timeoutMs}ms`);
          (timeoutErr as unknown as { code: string }).code = 'timeout';
          reject(timeoutErr);
        }, timeoutMs);

        if (options?.signal) {
          options.signal.addEventListener('abort', () => {
            clearTimeout(timer);
            const abortErr = new Error('Lookup aborted');
            (abortErr as unknown as { code: string }).code = 'aborted';
            reject(abortErr);
          });
        }
      });

      const response = await Promise.race([lookupPromise, timeoutPromise]);
      const latencyMs = Date.now() - startTime;
      const timestamp = new Date().toISOString();

      const evidence = this.buildEvidence(
        normalizedUrl,
        response.detectionStatus,
        response.confidence,
        response.threatCategories,
        response.description || `Reputation verdict from ${this.name}: ${response.detectionStatus}`
      );

      const result: ProviderReputationResult = {
        providerId: this.id,
        providerName: this.name,
        url: normalizedUrl,
        status: this.getStatus(),
        detectionStatus: response.detectionStatus,
        confidence: response.confidence,
        threatCategories: response.threatCategories,
        rawDetails: response.rawDetails,
        evidence,
        timestamp,
        latencyMs,
        cached: false,
      };

      // Store in cache
      await this.cache.set(cacheKey, {
        result,
        cachedAt: Date.now(),
        expiresAt: Date.now() + 3600 * 1000,
        stale: false,
      });

      return result;
    } catch (err: unknown) {
      const latencyMs = Date.now() - startTime;
      const timestamp = new Date().toISOString();
      const errObj = err as { code?: string; message?: string; statusCode?: number; retryAfterMs?: number };

      let errorCode: ReputationError['code'] = 'unknown';
      const errorMessage = errObj.message || 'Unknown provider error';

      if (errObj.code === 'timeout') {
        errorCode = 'timeout';
      } else if (errObj.statusCode === 429 || errObj.code === 'rate_limited') {
        errorCode = 'rate_limited';
        this.setRateLimited(errObj.retryAfterMs || 60000);
      } else if (errObj.code === 'network_error' || errObj.code === 'ECONNREFUSED' || errObj.code === 'ENOTFOUND') {
        errorCode = 'network_error';
      } else if (errObj.code === 'invalid_response') {
        errorCode = 'invalid_response';
      }

      const errorResult: ProviderReputationResult = {
        providerId: this.id,
        providerName: this.name,
        url: normalizedUrl,
        status: this.getStatus(),
        detectionStatus: 'unavailable',
        confidence: 'low',
        timestamp,
        latencyMs,
        cached: false,
        error: {
          code: errorCode,
          message: errorMessage,
          statusCode: errObj.statusCode,
          retryAfterMs: errObj.retryAfterMs,
        },
        evidence: this.buildEvidence(
          normalizedUrl,
          'unavailable',
          'low',
          undefined,
          `Provider lookup failed: ${errorMessage}`
        ),
      };

      return errorResult;
    }
  }

  /**
   * Helper to construct a standard Evidence record for a reputation result.
   */
  protected buildEvidence(
    url: string,
    detectionStatus: ReputationDetectionStatus,
    confidence: ConfidenceLevel,
    threatCategories?: ReputationThreatCategory[],
    customDescription?: string
  ): Evidence {
    return {
      id: crypto.randomUUID(),
      sourceType: 'reputation_provider',
      sourceName: this.name,
      label: `${this.name} Reputation Result`,
      description: customDescription || `${this.name} rated URL as ${detectionStatus} (confidence: ${confidence})`,
      snippet: `URL: ${url} | Detection: ${detectionStatus}`,
      data: {
        providerId: this.id,
        providerName: this.name,
        detectionStatus,
        confidence,
        threatCategories: threatCategories || [],
      },
      isAiGenerated: false,
      createdAt: new Date().toISOString(),
    };
  }

  /**
   * Subclasses must implement the actual provider-specific lookup logic.
   */
  protected abstract executeLookup(
    normalizedUrl: string,
    options?: ReputationLookupOptions
  ): Promise<{
    detectionStatus: ReputationDetectionStatus;
    confidence: ConfidenceLevel;
    threatCategories?: ReputationThreatCategory[];
    rawDetails?: Record<string, unknown>;
    description?: string;
  }>;
}

/**
 * Mock Provider for Offline Architectural Verification & Unit Testing.
 * Allows deterministic simulation of malicious, suspicious, clean, unknown,
 * timeout, error, and rate-limiting behaviors without network requests.
 */
export interface MockProviderConfig {
  id?: string;
  name?: string;
  defaultTimeoutMs?: number;
  status?: ProviderStatus;
  resultsMap?: Map<
    string,
    {
      detectionStatus: ReputationDetectionStatus;
      confidence: ConfidenceLevel;
      threatCategories?: ReputationThreatCategory[];
      rawDetails?: Record<string, unknown>;
    }
  >;
  defaultResult?: {
    detectionStatus: ReputationDetectionStatus;
    confidence: ConfidenceLevel;
    threatCategories?: ReputationThreatCategory[];
  };
  delayMs?: number;
  forceTimeout?: boolean;
  forceRateLimit?: boolean;
  forceError?: boolean;
  errorMessage?: string;
  cache?: ReputationCache;
}

export class MockReputationProvider extends BaseReputationProvider {
  private config: MockProviderConfig;

  constructor(config?: MockProviderConfig) {
    const id = config?.id || 'mock_provider';
    const name = config?.name || 'Mock Security Provider';
    super(id, name, {
      defaultTimeoutMs: config?.defaultTimeoutMs ?? 2000,
      cache: config?.cache,
    });
    this.config = config || {};
    if (config?.status) {
      this.status = config.status;
    }
  }

  updateConfig(config: Partial<MockProviderConfig>): void {
    this.config = { ...this.config, ...config };
    if (config.status) {
      this.status = config.status;
    }
  }

  protected async executeLookup(
    normalizedUrl: string
  ): Promise<{
    detectionStatus: ReputationDetectionStatus;
    confidence: ConfidenceLevel;
    threatCategories?: ReputationThreatCategory[];
    rawDetails?: Record<string, unknown>;
    description?: string;
  }> {
    // 1. Simulated delay
    if (this.config.delayMs && this.config.delayMs > 0) {
      await new Promise(resolve => setTimeout(resolve, this.config.delayMs));
    }

    // 2. Simulated timeout
    if (this.config.forceTimeout) {
      // Sleep longer than defaultTimeoutMs to guarantee timeout trigger
      await new Promise(resolve => setTimeout(resolve, this.defaultTimeoutMs + 500));
    }

    // 3. Simulated rate-limit
    if (this.config.forceRateLimit) {
      const err = new Error('HTTP 429: Rate limit exceeded');
      (err as unknown as { statusCode: number; code: string; retryAfterMs: number }).statusCode = 429;
      (err as unknown as { code: string }).code = 'rate_limited';
      (err as unknown as { retryAfterMs: number }).retryAfterMs = 60000;
      throw err;
    }

    // 4. Simulated general error
    if (this.config.forceError) {
      const err = new Error(this.config.errorMessage || 'Simulated provider internal error');
      (err as unknown as { code: string }).code = 'network_error';
      throw err;
    }

    // 5. Look up matching URL in mapped results
    if (this.config.resultsMap?.has(normalizedUrl)) {
      const res = this.config.resultsMap.get(normalizedUrl)!;
      return {
        detectionStatus: res.detectionStatus,
        confidence: res.confidence,
        threatCategories: res.threatCategories,
        rawDetails: res.rawDetails,
      };
    }

    // 6. Check pattern matching in normalizedUrl if no exact match in resultsMap
    if (normalizedUrl.includes('malicious') || normalizedUrl.includes('evil.com')) {
      return {
        detectionStatus: 'malicious',
        confidence: 'high',
        threatCategories: ['malware', 'phishing'],
      };
    }

    if (normalizedUrl.includes('suspicious') || normalizedUrl.includes('sketchy.net')) {
      return {
        detectionStatus: 'suspicious',
        confidence: 'medium',
        threatCategories: ['suspicious'],
      };
    }

    if (normalizedUrl.includes('unknown') || normalizedUrl.includes('obscure.org')) {
      return {
        detectionStatus: 'unknown',
        confidence: 'low',
      };
    }

    // Default result
    const def = this.config.defaultResult || {
      detectionStatus: 'clean',
      confidence: 'medium',
    };

    return {
      detectionStatus: def.detectionStatus,
      confidence: def.confidence,
      threatCategories: def.threatCategories,
    };
  }
}
