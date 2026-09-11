/**
 * Comprehensive Unit Tests for Google Safe Browsing Live Reputation Provider (Phase 4.8C)
 * 
 * Verifies all required provider behaviors using strictly mocked HTTP responses:
 * 1. Valid malicious match (MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE)
 * 2. Clean result (no threat matches found)
 * 3. Malformed non-JSON response
 * 4. HTTP 429 rate limiting & cooldown fast-fail
 * 5. HTTP 400 bad request / invalid response
 * 6. HTTP 401/403 authentication failure
 * 7. HTTP 500 upstream server error
 * 8. Timeout handling
 * 9. Network connection failure
 * 10. Missing API key handling (degrades gracefully to unavailable)
 * 11. API key never appears in evidence, snippets, details, or error messages
 * 12. Provider result normalization conforms to ProviderReputationResult
 * 13. Cache hit
 * 14. Cache miss
 * 15. Stale cache handling
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SafeBrowsingReputationProvider } from './safebrowsing';
import { RedisReputationCache, generateUrlCacheKey } from './cache';

const TEST_SECRET_KEY = 'super_secret_safebrowsing_api_key_abc123';

function createMockFetch(response: {
  status?: number;
  body?: unknown;
  rawText?: string;
  delayMs?: number;
  shouldThrow?: Error;
}): typeof fetch {
  return vi.fn().mockImplementation(async () => {
    if (response.delayMs) {
      await new Promise(resolve => setTimeout(resolve, response.delayMs));
    }

    if (response.shouldThrow) {
      throw response.shouldThrow;
    }

    const statusCode = response.status ?? 200;
    const isOk = statusCode >= 200 && statusCode < 300;

    return {
      status: statusCode,
      ok: isOk,
      json: async () => {
        if (response.rawText !== undefined) {
          throw new SyntaxError('Unexpected token in JSON');
        }
        return response.body;
      },
      text: async () => response.rawText ?? JSON.stringify(response.body),
    } as unknown as Response;
  });
}

describe('Phase 4.8C — Google Safe Browsing Reputation Provider', () => {
  let cache: RedisReputationCache;

  beforeEach(async () => {
    cache = new RedisReputationCache(3600);
    await cache.clear();
  });

  // 1. Valid Malicious Match
  it('1. correctly maps confirmed malicious match from Safe Browsing API', async () => {
    const mockFetch = createMockFetch({
      status: 200,
      body: {
        matches: [
          {
            threatType: 'MALWARE',
            platformType: 'ANY_PLATFORM',
            threatEntryType: 'URL',
            threat: { url: 'https://evil-trojan.com/install.exe' },
            cacheDuration: '300s',
          },
          {
            threatType: 'SOCIAL_ENGINEERING',
            platformType: 'ANY_PLATFORM',
            threatEntryType: 'URL',
            threat: { url: 'https://evil-trojan.com/install.exe' },
          },
        ],
      },
    });

    const provider = new SafeBrowsingReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const result = await provider.lookupUrl('https://evil-trojan.com/install.exe');

    expect(result.detectionStatus).toBe('malicious');
    expect(result.confidence).toBe('high');
    expect(result.threatCategories).toContain('malware');
    expect(result.threatCategories).toContain('phishing');
    expect(result.rawDetails?.matchCount).toBe(2);
    expect(result.evidence.description).toContain('MALWARE');
    expect(result.evidence.snippet).toContain('Threats:');
    expect(result.cached).toBe(false);
  });

  // 2. Clean Result (No Matches)
  it('2. maps empty response to clean detectionStatus with medium confidence', async () => {
    const mockFetch = createMockFetch({
      status: 200,
      body: {}, // Standard Safe Browsing response when URL is clean
    });

    const provider = new SafeBrowsingReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const result = await provider.lookupUrl('https://example.com/legitimate-page');

    expect(result.detectionStatus).toBe('clean');
    expect(result.confidence).toBe('medium'); // Medium confidence, external lists are not 100% proof
    expect(result.rawDetails?.matchCount).toBe(0);
    expect(result.evidence.description).toContain("No matching threat was found on Google's Safe Browsing lists");
    expect(result.evidence.snippet).toContain('No threat match found');
    expect(result.error).toBeUndefined();
  });

  // 3. Malformed Non-JSON Response
  it('3. handles malformed non-JSON response gracefully without crashing', async () => {
    const mockFetch = createMockFetch({
      status: 200,
      rawText: '<html><body>502 Bad Gateway</body></html>',
    });

    const provider = new SafeBrowsingReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const result = await provider.lookupUrl('https://target-domain.com');

    expect(result.detectionStatus).toBe('unavailable');
    expect(result.confidence).toBe('low');
    expect(result.error?.code).toBe('invalid_response');
    expect(result.error?.message).toContain('malformed or non-JSON');
  });

  // 4. HTTP 429 Rate Limiting & Cooldown
  it('4. handles HTTP 429 rate limiting with cooldown backoff', async () => {
    const mockFetch = createMockFetch({
      status: 429,
      body: { error: { message: 'Quota exceeded' } },
    });

    const provider = new SafeBrowsingReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const result1 = await provider.lookupUrl('https://domain1.com');
    expect(result1.detectionStatus).toBe('unavailable');
    expect(result1.error?.code).toBe('rate_limited');
    expect(provider.getStatus()).toBe('rate_limited');

    // Second call fast-fails without making an HTTP request
    const result2 = await provider.lookupUrl('https://domain2.com');
    expect(result2.detectionStatus).toBe('unavailable');
    expect(result2.error?.code).toBe('rate_limited');
    expect(result2.latencyMs).toBeLessThan(50);
  });

  // 5. HTTP 400 Bad Request
  it('5. handles HTTP 400 invalid request response', async () => {
    const mockFetch = createMockFetch({
      status: 400,
      body: { error: { message: 'Invalid URL threat entry format' } },
    });

    const provider = new SafeBrowsingReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const result = await provider.lookupUrl('https://target-domain.com');

    expect(result.detectionStatus).toBe('unavailable');
    expect(result.error?.code).toBe('invalid_response');
  });

  // 6. HTTP 401/403 Authentication Failure
  it('6. handles HTTP 401/403 authentication error', async () => {
    const mockFetch = createMockFetch({
      status: 403,
      body: { error: { message: 'API key not valid' } },
    });

    const provider = new SafeBrowsingReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const result = await provider.lookupUrl('https://target-domain.com');

    expect(result.detectionStatus).toBe('unavailable');
    expect(result.error?.code).toBe('network_error');
    expect(result.error?.statusCode).toBe(403);
  });

  // 7. HTTP 500 Upstream Server Error
  it('7. handles HTTP 500 upstream server error', async () => {
    const mockFetch = createMockFetch({
      status: 500,
      body: { error: { message: 'Internal Server Error' } },
    });

    const provider = new SafeBrowsingReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const result = await provider.lookupUrl('https://target-domain.com');

    expect(result.detectionStatus).toBe('unavailable');
    expect(result.error?.code).toBe('network_error');
    expect(result.error?.statusCode).toBe(500);
  });

  // 8. Timeout Handling
  it('8. handles provider timeout gracefully without throwing', async () => {
    const mockFetch = createMockFetch({
      delayMs: 300,
      body: {},
    });

    const provider = new SafeBrowsingReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      defaultTimeoutMs: 30, // 30ms timeout for fast test execution
      cache,
    });

    const result = await provider.lookupUrl('https://slow-site.com');

    expect(result.detectionStatus).toBe('unavailable');
    expect(result.error?.code).toBe('timeout');
    expect(result.evidence.description).toContain('timed out');
  });

  // 9. Network Connection Failure
  it('9. handles connection errors gracefully without crashing', async () => {
    const mockFetch = createMockFetch({
      shouldThrow: new Error('getaddrinfo ENOTFOUND safebrowsing.googleapis.com'),
    });

    const provider = new SafeBrowsingReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const result = await provider.lookupUrl('https://target-domain.com');

    expect(result.detectionStatus).toBe('unavailable');
    expect(result.error?.code).toBe('network_error');
    expect(result.error?.message).toContain('network connection failure');
  });

  // 10. Missing API Key Handling
  it('10. gracefully degrades to unavailable status when API key is unconfigured', async () => {
    const oldKey = process.env.SAFE_BROWSING_API_KEY;
    delete process.env.SAFE_BROWSING_API_KEY;

    try {
      const provider = new SafeBrowsingReputationProvider({
        apiKey: undefined,
        cache,
      });

      expect(provider.getStatus()).toBe('unavailable');

      const result = await provider.lookupUrl('https://example.com/test');

      expect(result.detectionStatus).toBe('unavailable');
      expect(result.error?.code).toBe('provider_unavailable');
    } finally {
      if (oldKey) process.env.SAFE_BROWSING_API_KEY = oldKey;
    }
  });

  // 11. Zero API Key Leakage
  it('11. never leaks the API key in evidence, details, snippets, or errors', async () => {
    const mockFetch = createMockFetch({
      status: 200,
      body: {
        matches: [
          {
            threatType: 'MALWARE',
            platformType: 'ANY_PLATFORM',
            threatEntryType: 'URL',
            threat: { url: 'https://test-leak.com' },
          },
        ],
      },
    });

    const provider = new SafeBrowsingReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const result = await provider.lookupUrl('https://test-leak.com');

    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(TEST_SECRET_KEY);
    expect(result.evidence.snippet).not.toContain(TEST_SECRET_KEY);
    expect(result.evidence.description).not.toContain(TEST_SECRET_KEY);
  });

  // 12. Provider Result Normalization
  it('12. normalizes output conforming to ProviderReputationResult specification', async () => {
    const mockFetch = createMockFetch({
      status: 200,
      body: {},
    });

    const provider = new SafeBrowsingReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const result = await provider.lookupUrl('https://domain.com/path?utm_source=ad');

    expect(result.providerId).toBe('safebrowsing');
    expect(result.providerName).toBe('Google Safe Browsing');
    expect(result.url).toBe('https://domain.com/path'); // tracking parameter stripped
    expect(result.status).toBe('ready');
    expect(result.detectionStatus).toBe('clean');
    expect(typeof result.latencyMs).toBe('number');
    expect(typeof result.timestamp).toBe('string');
    expect(result.evidence).toBeDefined();
    expect(result.evidence.sourceType).toBe('reputation_provider');
  });

  // 13 & 14. Cache Hit and Miss
  it('13 & 14. accurately caches results and serves hits from cache', async () => {
    let fetchCount = 0;
    const mockFetch = vi.fn().mockImplementation(async () => {
      fetchCount++;
      return {
        status: 200,
        ok: true,
        json: async () => ({}),
      } as unknown as Response;
    });

    const provider = new SafeBrowsingReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    // 1st lookup: Cache Miss
    const res1 = await provider.lookupUrl('https://cached-test.com/page');
    expect(fetchCount).toBe(1);
    expect(res1.cached).toBe(false);

    // 2nd lookup: Cache Hit
    const res2 = await provider.lookupUrl('https://cached-test.com/page');
    expect(fetchCount).toBe(1); // Not called again!
    expect(res2.cached).toBe(true);
    expect(res2.detectionStatus).toBe('clean');
  });

  // 15. Stale Cache Handling
  it('15. detects stale cache entry when expired', async () => {
    const shortTtlCache = new RedisReputationCache(1);
    const key = generateUrlCacheKey('https://stale-site.com/path', 'safebrowsing');

    const provider = new SafeBrowsingReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: createMockFetch({ status: 200, body: {} }),
      cache: shortTtlCache,
    });

    const entry = await provider.lookupUrl('https://stale-site.com/path');

    await shortTtlCache.set(
      key,
      {
        result: entry,
        cachedAt: Date.now() - 5000,
        expiresAt: Date.now() - 1000, // already expired
        stale: false,
      },
      1
    );

    const retrieved = await shortTtlCache.get(key);
    expect(retrieved?.stale).toBe(true);
  });
});
