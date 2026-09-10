/**
 * Comprehensive Unit Tests for URLhaus Live Reputation Provider (Phase 4.8B)
 * 
 * Verifies all 18 required scenarios using strictly mocked HTTP responses:
 * 1. Valid malicious match
 * 2. No match (unknown, not clean)
 * 3. Malformed non-JSON response
 * 4. HTTP 429 rate limiting & fast-fail
 * 5. HTTP 401/403 authentication failure
 * 6. HTTP 500 upstream server error
 * 7. Timeout handling
 * 8. Network failure
 * 9. Missing API key handling
 * 10. API key never appears in output or logs
 * 11. Provider result normalization
 * 12. Cache hit
 * 13. Cache miss
 * 14. Stale cache handling
 * 15. Aggregator integration
 * 16. Lexical high risk + URLhaus unknown (lexical risk preserved)
 * 17. Lexical low risk + URLhaus malicious (elevated to high)
 * 18. Provider unavailable while local analysis continues working
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { UrlhausReputationProvider } from './urlhaus';
import { RedisReputationCache, generateUrlCacheKey } from './cache';
import { ReputationAggregator } from './aggregator';
import { RiskEngine } from '../risk-engine';
import { SafetyService } from '../service';
import { AnalyzerResult, Finding } from '../types';
import { reputationRegistry } from './registry';

const TEST_SECRET_KEY = 'super_secret_urlhaus_api_key_12345';

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

describe('Phase 4.8B — URLhaus Live Reputation Provider', () => {
  let cache: RedisReputationCache;

  beforeEach(async () => {
    cache = new RedisReputationCache(3600);
    await cache.clear();
  });

  // 1. Valid Malicious Match
  it('1. correctly maps confirmed malicious match from URLhaus API', async () => {
    const mockFetch = createMockFetch({
      status: 200,
      body: {
        query_status: 'ok',
        id: '1234567',
        url: 'https://evil-malware-feed.com/download.exe',
        url_status: 'online',
        host: 'evil-malware-feed.com',
        threat: 'malware_download',
        reporter: 'threat_researcher',
        tags: ['Mozi', 'elf', 'arm'],
        date_added: '2026-09-10 00:00:00 UTC',
      },
    });

    const provider = new UrlhausReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const result = await provider.lookupUrl('https://evil-malware-feed.com/download.exe');

    expect(result.detectionStatus).toBe('malicious');
    expect(result.confidence).toBe('high');
    expect(result.threatCategories).toContain('malware');
    expect(result.rawDetails?.threat).toBe('malware_download');
    expect(result.rawDetails?.urlStatus).toBe('online');
    expect(result.evidence.description).toContain('malware_download');
    expect(result.evidence.snippet).toContain('Threat: malware_download');
    expect(result.evidence.snippet).toContain('Mozi');
    expect(result.cached).toBe(false);
  });

  // 2. No Match (Unknown, NOT Clean)
  it('2. maps no_results to unknown rather than falsely declaring clean', async () => {
    const mockFetch = createMockFetch({
      status: 200,
      body: {
        query_status: 'no_results',
      },
    });

    const provider = new UrlhausReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const result = await provider.lookupUrl('https://unlisted-domain.com/page');

    // CRITICAL REQUIREMENT: "Not found in URLhaus" != "safe"
    expect(result.detectionStatus).toBe('unknown');
    expect(result.detectionStatus).not.toBe('clean');
    expect(result.confidence).toBe('low');
    expect(result.evidence.description).toContain('Absence of a record is not proof of safety');
    expect(result.evidence.snippet).toContain('no_results');
  });

  // 3. Malformed Response
  it('3. handles malformed non-JSON response gracefully without crashing', async () => {
    const mockFetch = createMockFetch({
      status: 200,
      rawText: '<html><body>502 Bad Gateway</body></html>',
    });

    const provider = new UrlhausReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const result = await provider.lookupUrl('https://example.com/test');

    expect(result.detectionStatus).toBe('unavailable');
    expect(result.error?.code).toBe('invalid_response');
    expect(result.error?.message).toContain('malformed');
  });

  // 4. HTTP 429 Rate Limiting
  it('4. detects HTTP 429, marks provider rate_limited, and fast-fails cooldown', async () => {
    const mockFetch = createMockFetch({
      status: 429,
    });

    const provider = new UrlhausReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const res1 = await provider.lookupUrl('https://example.com/item1');
    expect(res1.detectionStatus).toBe('unavailable');
    expect(res1.status).toBe('rate_limited');
    expect(res1.error?.code).toBe('rate_limited');
    expect(provider.getStatus()).toBe('rate_limited');

    // Second call should fast-fail without invoking fetch
    const fetchSpy = vi.fn();
    (provider as unknown as { fetchFn: typeof fetch }).fetchFn = fetchSpy;

    const res2 = await provider.lookupUrl('https://example.com/item2');
    expect(res2.detectionStatus).toBe('unavailable');
    expect(res2.error?.code).toBe('rate_limited');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // 5. HTTP 401/403 Authentication Failure
  it('5. handles authentication failure without exposing API key', async () => {
    const mockFetch = createMockFetch({
      status: 401,
      body: { error: 'Unauthorized' },
    });

    const provider = new UrlhausReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const result = await provider.lookupUrl('https://example.com/check');

    expect(result.detectionStatus).toBe('unavailable');
    expect(result.error?.code).toBe('network_error');
    expect(result.error?.message).toContain('authentication failed');
    expect(JSON.stringify(result)).not.toContain(TEST_SECRET_KEY);
  });

  // 6. HTTP 500 Upstream Server Error
  it('6. handles upstream 500 error gracefully', async () => {
    const mockFetch = createMockFetch({
      status: 500,
    });

    const provider = new UrlhausReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const result = await provider.lookupUrl('https://example.com/check');

    expect(result.detectionStatus).toBe('unavailable');
    expect(result.error?.code).toBe('network_error');
    expect(result.error?.message).toContain('HTTP 500');
  });

  // 7. Timeout
  it('7. enforces strict timeout when provider exceeds deadline', async () => {
    const mockFetch = createMockFetch({
      delayMs: 300,
      body: { query_status: 'ok' },
    });

    const provider = new UrlhausReputationProvider({
      apiKey: TEST_SECRET_KEY,
      defaultTimeoutMs: 50, // Short timeout for unit test speed
      fetchFn: mockFetch,
      cache,
    });

    const result = await provider.lookupUrl('https://example.com/timeout');

    expect(result.detectionStatus).toBe('unavailable');
    expect(result.error?.code).toBe('timeout');
  });

  // 8. Network Failure
  it('8. handles socket or network disconnection gracefully', async () => {
    const mockFetch = createMockFetch({
      shouldThrow: new Error('connect ECONNREFUSED 127.0.0.1:443'),
    });

    const provider = new UrlhausReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const result = await provider.lookupUrl('https://example.com/fail');

    expect(result.detectionStatus).toBe('unavailable');
    expect(result.error?.code).toBe('network_error');
  });

  // 9. Missing API Key
  it('9. provider gracefully reports unavailable when API key is omitted', async () => {
    // Preserve current env
    const originalKey = process.env.URLHAUS_AUTH_KEY;
    delete process.env.URLHAUS_AUTH_KEY;

    try {
      const provider = new UrlhausReputationProvider({
        apiKey: undefined,
        cache,
      });

      expect(provider.getStatus()).toBe('unavailable');

      const result = await provider.lookupUrl('https://example.com/unconfigured');
      expect(result.detectionStatus).toBe('unavailable');
      expect(result.error?.code).toBe('provider_unavailable');
    } finally {
      if (originalKey) {
        process.env.URLHAUS_AUTH_KEY = originalKey;
      }
    }
  });

  // 10. API Key Never Appears in Output
  it('10. guarantees API key is never serialized into result, evidence, or error strings', async () => {
    const scenarios = [
      { status: 200, body: { query_status: 'ok', threat: 'malware' } },
      { status: 200, body: { query_status: 'no_results' } },
      { status: 401, body: { error: 'Unauthorized' } },
      { status: 429 },
      { status: 500 },
      { rawText: 'invalid' },
    ];

    for (const sc of scenarios) {
      const provider = new UrlhausReputationProvider({
        apiKey: TEST_SECRET_KEY,
        fetchFn: createMockFetch(sc),
        cache: new RedisReputationCache(3600),
      });

      const res = await provider.lookupUrl('https://example.com/test');
      const serialized = JSON.stringify(res);

      expect(serialized).not.toContain(TEST_SECRET_KEY);
      if (res.error?.message) {
        expect(res.error.message).not.toContain(TEST_SECRET_KEY);
      }
      expect(res.evidence.description).not.toContain(TEST_SECRET_KEY);
    }
  });

  // 11. Provider Normalization
  it('11. normalizes output adhering to ProviderReputationResult contract', async () => {
    const mockFetch = createMockFetch({
      status: 200,
      body: { query_status: 'ok', threat: 'malware_download', id: '999' },
    });

    const provider = new UrlhausReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    const res = await provider.lookupUrl('https://sample.org/file.bin');

    expect(res.providerId).toBe('urlhaus');
    expect(res.providerName).toBe('URLhaus');
    expect(res.status).toBe('ready');
    expect(res.detectionStatus).toBe('malicious');
    expect(res.confidence).toBe('high');
    expect(typeof res.latencyMs).toBe('number');
    expect(typeof res.timestamp).toBe('string');
    expect(res.evidence).toBeDefined();
    expect(res.evidence.sourceType).toBe('reputation_provider');
    expect(res.evidence.sourceName).toBe('URLhaus');
    expect(res.evidence.isAiGenerated).toBe(false);
  });

  // 12. Cache Hit & 13. Cache Miss
  it('12 & 13. correctly distinguishes cache miss on first lookup and cache hit on subsequent query', async () => {
    const mockFetch = createMockFetch({
      status: 200,
      body: { query_status: 'no_results' },
    });

    const provider = new UrlhausReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache,
    });

    // 1st query: Cache Miss
    const res1 = await provider.lookupUrl('https://cache-test-url.com/index');
    expect(res1.cached).toBe(false);
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // 2nd query: Cache Hit
    const res2 = await provider.lookupUrl('https://cache-test-url.com/index');
    expect(res2.cached).toBe(true);
    expect(res2.detectionStatus).toBe('unknown');
    expect(mockFetch).toHaveBeenCalledTimes(1); // Not called again!
  });

  // 14. Stale Cache Handling
  it('14. bypasses expired cache entry and refreshes live from provider', async () => {
    const shortCache = new RedisReputationCache(1); // 1s TTL
    const mockFetch = createMockFetch({
      status: 200,
      body: { query_status: 'no_results' },
    });

    const provider = new UrlhausReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: mockFetch,
      cache: shortCache,
    });

    const targetUrl = 'https://stale-check.com/page';

    // 1st query
    await provider.lookupUrl(targetUrl);
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // Manually expire entry in cache
    const normKey = generateUrlCacheKey(targetUrl, 'urlhaus');
    const entry = await shortCache.get(normKey);
    if (entry) {
      await shortCache.set(normKey, { ...entry, expiresAt: Date.now() - 5000, stale: true }, 1);
    }

    // Next lookup must bypass stale cache and fetch fresh
    const res2 = await provider.lookupUrl(targetUrl);
    expect(res2.cached).toBe(false);
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  // 15. Aggregator Integration
  it('15. aggregates URLhaus result with other providers in ReputationAggregator', async () => {
    const urlhausFetch = createMockFetch({
      status: 200,
      body: { query_status: 'ok', threat: 'malware_download' },
    });

    const provider = new UrlhausReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: urlhausFetch,
      cache,
    });

    const aggregate = await ReputationAggregator.lookupAndAggregate(
      'https://malicious-distribution.xyz/trojan',
      [provider]
    );

    expect(aggregate.aggregateStatus).toBe('malicious');
    expect(aggregate.confidence).toBe('high');
    expect(aggregate.findings.length).toBe(1);
    expect(aggregate.findings[0].type).toBe('reputation_malicious');
    expect(aggregate.evidence.length).toBe(1);
    expect(aggregate.evidence[0].sourceName).toBe('URLhaus');
  });

  // 16. Lexical High Risk + URLhaus Unknown (Lexical Risk Preserved)
  it('16. preserves high risk from lexical analysis when URLhaus returns unknown', () => {
    const lexicalFinding: Finding = {
      id: 'lex-1',
      type: 'lookalike_domain',
      severity: 'high',
      title: 'Lookalike Bank Domain',
      description: 'Misleads user to fake banking portal',
      confidence: 'high',
    };

    // URLhaus returned no match -> unknown (no finding, only evidence)
    const urlhausEvidence = {
      id: 'ev-urlhaus',
      sourceType: 'reputation_provider' as const,
      sourceName: 'URLhaus',
      label: 'URLhaus Threat Intelligence',
      description: 'URLhaus: No matching malicious record found. Absence of a record is not proof of safety.',
      data: { queryStatus: 'no_results' },
      isAiGenerated: false,
      createdAt: new Date().toISOString(),
    };

    const analyzerResult: AnalyzerResult = {
      analyzerId: 'url',
      analyzerType: 'url',
      status: 'success',
      confidence: 'high',
      findings: [lexicalFinding],
      evidence: [urlhausEvidence],
      limitations: ['Absence of a record in URLhaus does not imply the URL is safe.'],
    };

    const evalResult = RiskEngine.evaluate([lexicalFinding], [analyzerResult]);

    // High lexical risk MUST NOT be downgraded
    expect(evalResult.riskLevel).toBe('high');
    expect(evalResult.recommendations.some(r => r.action === 'verify_domain')).toBe(true);
  });

  // 17. Lexical Low Risk + URLhaus Malicious (Elevated to High Risk)
  it('17. elevates overall risk to high when lexical is low risk but URLhaus confirms malicious', () => {
    const lexicalFinding: Finding = {
      id: 'lex-1',
      type: 'shortened_url',
      severity: 'low',
      title: 'Shortened URL',
      description: 'Link shortener hides final destination',
      confidence: 'medium',
    };

    const urlhausFinding: Finding = {
      id: 'rep-1',
      type: 'reputation_malicious',
      severity: 'high',
      title: 'Known Malicious URL Reported',
      description: 'URLhaus confirms URL is associated with malware distribution',
      confidence: 'high',
    };

    const combinedFindings = [lexicalFinding, urlhausFinding];
    const analyzerResult: AnalyzerResult = {
      analyzerId: 'url',
      analyzerType: 'url',
      status: 'success',
      confidence: 'high',
      findings: combinedFindings,
      evidence: [],
    };

    const evalResult = RiskEngine.evaluate(combinedFindings, [analyzerResult]);

    expect(evalResult.riskLevel).toBe('high');
    expect(evalResult.recommendations.some(r => r.action === 'avoid_known_malicious_url')).toBe(true);
    expect(evalResult.recommendations.some(r => r.action === 'do_not_click')).toBe(true);
  });

  // 18. Provider Unavailable while Local Analysis Continues Working
  it('18. SafetyService continues successfully when URLhaus provider fails or is unconfigured', async () => {
    // Register a failing provider into registry
    const failingProvider = new UrlhausReputationProvider({
      apiKey: TEST_SECRET_KEY,
      fetchFn: createMockFetch({ shouldThrow: new Error('Simulated upstream failure') }),
      cache,
    });

    reputationRegistry.clear();
    reputationRegistry.register(failingProvider);

    try {
      const report = await SafetyService.analyze({
        type: 'url',
        rawContent: 'https://paypal.com.account-verification.xyz/login',
      });

      // Local lexical analysis MUST succeed and detect the lookalike domain
      expect(report.status).toBe('completed');
      expect(report.riskLevel).toBe('high');
      expect(report.findings.some(f => f.type === 'lookalike_domain' || f.type === 'suspicious_domain')).toBe(true);
      // Provider failure is noted in limitations, not a crash
      expect(report.limitations.some(l => l.includes('URLhaus') || l.includes('Reputation provider'))).toBe(true);
    } finally {
      reputationRegistry.resetDefaults();
    }
  });
});
