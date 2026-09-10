/**
 * Comprehensive Unit Tests for Live URL Reputation Intelligence Architecture
 * 
 * Verifies all 16 architectural scenarios:
 * 1. Provider normalization
 * 2. Malicious result
 * 3. Suspicious result
 * 4. Clean result
 * 5. Unknown result
 * 6. Provider timeout
 * 7. Provider error
 * 8. Provider rate limit
 * 9. Multiple providers
 * 10. Conflicting providers (dispute handling)
 * 11. All providers unavailable
 * 12. Cache key normalization
 * 13. Cache expiry and staleness
 * 14. Sensitive query parameter redaction
 * 15. Risk Engine integration
 * 16. Confidence calculation (decoupled from risk severity)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { RiskEngine } from '../risk-engine';
import { AnalyzerResult } from '../types';
import {
  normalizeUrlForReputation,
  generateUrlCacheKey,
  RedisReputationCache,
} from './cache';
import {
  MockReputationProvider,
} from './provider';
import {
  ReputationAggregator,
} from './aggregator';
import {
  ReputationProviderRegistry,
} from './registry';

describe('Phase 4.8A — URL Reputation Intelligence Architecture', () => {
  let cache: RedisReputationCache;

  beforeEach(async () => {
    cache = new RedisReputationCache(3600);
    await cache.clear();
  });

  // 1. Provider Normalization
  it('1. normalizes provider result structure conforming to ProviderReputationResult schema', async () => {
    const provider = new MockReputationProvider({
      id: 'test_provider',
      name: 'Test Threat Intel',
      defaultResult: {
        detectionStatus: 'clean',
        confidence: 'high',
      },
      cache,
    });

    const result = await provider.lookupUrl('https://example.com/login?utm_source=newsletter');

    expect(result.providerId).toBe('test_provider');
    expect(result.providerName).toBe('Test Threat Intel');
    expect(result.url).toBe('https://example.com/login'); // tracking stripped
    expect(result.status).toBe('ready');
    expect(result.detectionStatus).toBe('clean');
    expect(result.confidence).toBe('high');
    expect(typeof result.latencyMs).toBe('number');
    expect(typeof result.timestamp).toBe('string');
    expect(result.cached).toBe(false);
    expect(result.evidence).toBeDefined();
    expect(result.evidence.sourceType).toBe('reputation_provider');
    expect(result.evidence.sourceName).toBe('Test Threat Intel');
    expect(result.evidence.isAiGenerated).toBe(false);
  });

  // 2. Malicious Result
  it('2. correctly identifies and structures malicious reputation verdict', async () => {
    const provider = new MockReputationProvider({
      id: 'test_malicious',
      name: 'Malware Feeds',
      cache,
    });

    const result = await provider.lookupUrl('https://malicious-domain.xyz/download.exe');

    expect(result.detectionStatus).toBe('malicious');
    expect(result.confidence).toBe('high');
    expect(result.threatCategories).toContain('malware');
    expect(result.threatCategories).toContain('phishing');
    expect(result.evidence.data.detectionStatus).toBe('malicious');
    expect(result.error).toBeUndefined();
  });

  // 3. Suspicious Result
  it('3. correctly identifies and structures suspicious reputation verdict', async () => {
    const provider = new MockReputationProvider({
      id: 'test_suspicious',
      name: 'Anomaly Hunter',
      cache,
    });

    const result = await provider.lookupUrl('https://suspicious-gateway.net/checkout');

    expect(result.detectionStatus).toBe('suspicious');
    expect(result.confidence).toBe('medium');
    expect(result.threatCategories).toContain('suspicious');
    expect(result.evidence.data.detectionStatus).toBe('suspicious');
  });

  // 4. Clean Result
  it('4. correctly identifies and structures clean reputation verdict', async () => {
    const provider = new MockReputationProvider({
      id: 'test_clean',
      name: 'Clean Domain Verifier',
      cache,
    });

    const result = await provider.lookupUrl('https://trusted-site.org/about');

    expect(result.detectionStatus).toBe('clean');
    expect(result.confidence).toBe('medium');
    expect(result.error).toBeUndefined();
  });

  // 5. Unknown Result
  it('5. handles URLs with unknown reputation without error', async () => {
    const provider = new MockReputationProvider({
      id: 'test_unknown',
      name: 'Domain Registry Intel',
      cache,
    });

    const result = await provider.lookupUrl('https://obscure.org/unindexed-page');

    expect(result.detectionStatus).toBe('unknown');
    expect(result.confidence).toBe('low');
    expect(result.error).toBeUndefined();
  });

  // 6. Provider Timeout
  it('6. gracefully handles provider lookup timeout without throwing', async () => {
    const provider = new MockReputationProvider({
      id: 'slow_provider',
      name: 'Slow Provider',
      defaultTimeoutMs: 50, // Short timeout for test speed
      forceTimeout: true,
      cache,
    });

    const result = await provider.lookupUrl('https://example.com/test');

    expect(result.detectionStatus).toBe('unavailable');
    expect(result.confidence).toBe('low');
    expect(result.error).toBeDefined();
    expect(result.error?.code).toBe('timeout');
    expect(result.error?.message).toContain('timed out');
  });

  // 7. Provider Error
  it('7. captures provider internal/network failure and isolates error safely', async () => {
    const provider = new MockReputationProvider({
      id: 'failing_provider',
      name: 'Failing Provider',
      forceError: true,
      errorMessage: 'Socket connection reset by peer',
      cache,
    });

    const result = await provider.lookupUrl('https://example.com/test');

    expect(result.detectionStatus).toBe('unavailable');
    expect(result.error?.code).toBe('network_error');
    expect(result.error?.message).toBe('Socket connection reset by peer');
  });

  // 8. Provider Rate Limit
  it('8. detects rate limiting (429), enters cooldown, and fast-fails subsequent calls', async () => {
    const provider = new MockReputationProvider({
      id: 'rate_limited_provider',
      name: 'Rate Limited Service',
      forceRateLimit: true,
      cache,
    });

    // First call triggers rate limit
    const res1 = await provider.lookupUrl('https://example.com/item1');
    expect(res1.detectionStatus).toBe('unavailable');
    expect(res1.status).toBe('rate_limited');
    expect(res1.error?.code).toBe('rate_limited');

    // Verify provider status is now rate_limited
    expect(provider.getStatus()).toBe('rate_limited');

    // Second call should fast-fail immediately without executing lookup
    provider.updateConfig({ forceRateLimit: false }); // even if underlying endpoint is relieved
    const res2 = await provider.lookupUrl('https://example.com/item2');
    expect(res2.detectionStatus).toBe('unavailable');
    expect(res2.error?.code).toBe('rate_limited');
    expect(res2.latencyMs).toBeLessThan(50); // fast rejection
  });

  // 9. Multiple Providers
  it('9. aggregates multiple agreeing providers with high confidence', async () => {
    const providerA = new MockReputationProvider({
      id: 'provider_a',
      name: 'Provider Alpha',
      defaultResult: { detectionStatus: 'clean', confidence: 'high' },
      cache,
    });

    const providerB = new MockReputationProvider({
      id: 'provider_b',
      name: 'Provider Beta',
      defaultResult: { detectionStatus: 'clean', confidence: 'medium' },
      cache,
    });

    const aggregate = await ReputationAggregator.lookupAndAggregate(
      'https://verified-site.com',
      [providerA, providerB]
    );

    expect(aggregate.aggregateStatus).toBe('clean');
    expect(aggregate.confidence).toBe('high');
    expect(aggregate.disputed).toBe(false);
    expect(aggregate.findings.length).toBe(1);
    expect(aggregate.findings[0].type).toBe('reputation_clean');
    expect(aggregate.evidence.length).toBe(2);
  });

  // 10. Conflicting Providers (Dispute Resolution)
  it('10. resolves provider conflict safely without blindly declaring malicious or critical', async () => {
    const providerA = new MockReputationProvider({
      id: 'provider_malicious',
      name: 'Malware Hunter',
      defaultResult: { detectionStatus: 'malicious', confidence: 'high', threatCategories: ['phishing'] },
      cache,
    });

    const providerB = new MockReputationProvider({
      id: 'provider_clean',
      name: 'Clean Domain Registry',
      defaultResult: { detectionStatus: 'clean', confidence: 'high' },
      cache,
    });

    const providerC = new MockReputationProvider({
      id: 'provider_unknown',
      name: 'Neutral Telemetry',
      defaultResult: { detectionStatus: 'unknown', confidence: 'low' },
      cache,
    });

    const aggregate = await ReputationAggregator.lookupAndAggregate(
      'https://disputed-domain.com',
      [providerA, providerB, providerC]
    );

    // CRITICAL REQUIREMENT: Must NOT simply say 'malicious' when 1 provider says malicious and another says clean
    expect(aggregate.disputed).toBe(true);
    expect(aggregate.aggregateStatus).toBe('suspicious');
    expect(aggregate.confidence).toBe('medium'); // Downgraded due to conflict
    expect(aggregate.findings.length).toBe(1);
    expect(aggregate.findings[0].type).toBe('reputation_disputed');
    expect(aggregate.findings[0].severity).toBe('medium'); // Non-alarmist
    expect(aggregate.limitations.some(l => l.includes('disagree'))).toBe(true);
  });

  // 11. All Providers Unavailable
  it('11. continues gracefully when all reputation providers are unavailable or timeout', async () => {
    const providerA = new MockReputationProvider({
      id: 'dead_a',
      name: 'Offline A',
      forceError: true,
      cache,
    });

    const providerB = new MockReputationProvider({
      id: 'dead_b',
      name: 'Timeout B',
      defaultTimeoutMs: 30,
      forceTimeout: true,
      cache,
    });

    const aggregate = await ReputationAggregator.lookupAndAggregate(
      'https://example.com/test',
      [providerA, providerB]
    );

    expect(aggregate.aggregateStatus).toBe('unavailable');
    expect(aggregate.confidence).toBe('low');
    expect(aggregate.findings.length).toBe(0); // No phantom findings
    expect(aggregate.limitations.length).toBeGreaterThanOrEqual(2);
    expect(aggregate.summary).toContain('unavailable');
  });

  // 12. Cache Key Normalization
  it('12. normalizes URLs consistently and produces identical cache keys for semantic duplicates', () => {
    const url1 = 'HTTPS://Example.COM:443/login/?utm_source=facebook&b=2&a=1#section';
    const url2 = 'https://example.com/login?a=1&b=2&utm_medium=cpc';

    const norm1 = normalizeUrlForReputation(url1);
    const norm2 = normalizeUrlForReputation(url2);

    expect(norm1).toBe('https://example.com/login?a=1&b=2');
    expect(norm2).toBe('https://example.com/login?a=1&b=2');

    const key1 = generateUrlCacheKey(norm1, 'virustotal');
    const key2 = generateUrlCacheKey(norm2, 'virustotal');

    expect(key1).toBe(key2);
    expect(key1).toMatch(/^rep:virustotal:[a-f0-9]{64}$/);
  });

  // 13. Cache Expiry & Staleness
  it('13. detects expired cache entries and marks them stale', async () => {
    const testCache = new RedisReputationCache(1); // 1 second TTL
    const key = 'rep:test:12345';

    const provider = new MockReputationProvider({
      id: 'cache_test',
      name: 'Cache Test',
      defaultResult: { detectionStatus: 'clean', confidence: 'medium' },
      cache: testCache,
    });

    const entry = await provider.lookupUrl('https://example.com/cached-page');

    await testCache.set(
      key,
      {
        result: entry,
        cachedAt: Date.now() - 5000,
        expiresAt: Date.now() - 1000, // already expired
        stale: false,
      },
      1
    );

    const retrieved = await testCache.get(key);
    expect(retrieved).not.toBeNull();
    expect(retrieved?.stale).toBe(true);
  });

  // 14. Redaction
  it('14. redacts sensitive query parameters before caching and in evidence', async () => {
    const sensitiveUrl = 'https://secure-portal.com/auth?token=secret12345&password=myPassword99&user=alice';

    const normalized = normalizeUrlForReputation(sensitiveUrl);
    expect(normalized).not.toContain('secret12345');
    expect(normalized).not.toContain('myPassword99');
    expect(normalized).toContain('token=[REDACTED]');
    expect(normalized).toContain('user=alice');

    const provider = new MockReputationProvider({
      id: 'redaction_provider',
      name: 'Redaction Intel',
      cache,
    });

    const result = await provider.lookupUrl(sensitiveUrl);
    expect(result.url).not.toContain('secret12345');
    expect(result.evidence.snippet).not.toContain('secret12345');
  });

  // 15. Risk Engine Integration
  it('15. maps reputation findings to proportional risk levels and recommendations in RiskEngine', () => {
    // 15a: Confirmed malicious reputation maps to high risk with avoid recommendation
    const maliciousAgg = ReputationAggregator.aggregate('https://evil.com', [
      {
        providerId: 'p1',
        providerName: 'ThreatFeed',
        url: 'https://evil.com',
        status: 'ready',
        detectionStatus: 'malicious',
        confidence: 'high',
        threatCategories: ['malware'],
        timestamp: new Date().toISOString(),
        latencyMs: 10,
        cached: false,
        evidence: {
          id: 'ev-1',
          sourceType: 'reputation_provider',
          sourceName: 'ThreatFeed',
          description: 'Malicious domain',
          data: {},
          isAiGenerated: false,
          createdAt: new Date().toISOString(),
        },
      },
    ]);

    const fakeAnalyzerResult: AnalyzerResult = {
      analyzerId: 'url',
      analyzerType: 'url',
      status: 'success',
      confidence: 'high',
      findings: maliciousAgg.findings,
      evidence: maliciousAgg.evidence,
      limitations: maliciousAgg.limitations,
    };

    const evalMalicious = RiskEngine.evaluate(maliciousAgg.findings, [fakeAnalyzerResult]);
    expect(evalMalicious.riskLevel).toBe('high');
    expect(evalMalicious.recommendations.some(r => r.action === 'avoid_known_malicious_url')).toBe(true);
    expect(evalMalicious.recommendations.some(r => r.action === 'do_not_click')).toBe(true);

    // 15b: Disputed reputation maps to medium risk with verification recommendation
    const disputedAgg = ReputationAggregator.aggregate('https://disputed.com', [
      {
        providerId: 'p1',
        providerName: 'Feed 1',
        url: 'https://disputed.com',
        status: 'ready',
        detectionStatus: 'malicious',
        confidence: 'medium',
        timestamp: new Date().toISOString(),
        latencyMs: 10,
        cached: false,
        evidence: { id: 'e1', sourceType: 'reputation_provider', sourceName: 'Feed 1', description: 'flagged', data: {}, isAiGenerated: false, createdAt: '' },
      },
      {
        providerId: 'p2',
        providerName: 'Feed 2',
        url: 'https://disputed.com',
        status: 'ready',
        detectionStatus: 'clean',
        confidence: 'high',
        timestamp: new Date().toISOString(),
        latencyMs: 10,
        cached: false,
        evidence: { id: 'e2', sourceType: 'reputation_provider', sourceName: 'Feed 2', description: 'clean', data: {}, isAiGenerated: false, createdAt: '' },
      },
    ]);

    const evalDisputed = RiskEngine.evaluate(disputedAgg.findings, [
      {
        analyzerId: 'url',
        analyzerType: 'url',
        status: 'success',
        confidence: 'medium',
        findings: disputedAgg.findings,
        evidence: disputedAgg.evidence,
        limitations: disputedAgg.limitations,
      },
    ]);

    expect(evalDisputed.riskLevel).toBe('medium');
    expect(evalDisputed.recommendations.some(r => r.action === 'verify_reported_threat')).toBe(true);
  });

  // 16. Confidence Calculation (Decoupled from Risk Severity)
  it('16. decouples risk severity from confidence and includes universal uncertainty limitation', () => {
    // Single provider clean result gives medium confidence (not absolute certainty)
    const singleCleanAgg = ReputationAggregator.aggregate('https://unknown-clean.org', [
      {
        providerId: 'p1',
        providerName: 'Feed 1',
        url: 'https://unknown-clean.org',
        status: 'ready',
        detectionStatus: 'clean',
        confidence: 'medium',
        timestamp: new Date().toISOString(),
        latencyMs: 10,
        cached: false,
        evidence: { id: 'e1', sourceType: 'reputation_provider', sourceName: 'Feed 1', description: 'clean', data: {}, isAiGenerated: false, createdAt: '' },
      },
    ]);

    expect(singleCleanAgg.confidence).toBe('medium'); // Never claiming 100% confidence
    expect(singleCleanAgg.limitations.some(l => l.includes('do not guarantee safety'))).toBe(true);

    // Evaluate in RiskEngine to confirm universal safety limitation
    const evalResult = RiskEngine.evaluate(singleCleanAgg.findings, [
      {
        analyzerId: 'url',
        analyzerType: 'url',
        status: 'success',
        confidence: singleCleanAgg.confidence,
        findings: singleCleanAgg.findings,
        evidence: singleCleanAgg.evidence,
        limitations: singleCleanAgg.limitations,
      },
    ]);

    expect(evalResult.limitations.some(l => l.includes('Absence of flags is not an absolute guarantee'))).toBe(true);
  });

  // Provider Registry test
  it('manages provider lifecycle cleanly in ReputationProviderRegistry', () => {
    const registry = new ReputationProviderRegistry();
    const mockP = new MockReputationProvider({ id: 'reg_test', name: 'Registry Test Provider' });

    registry.register(mockP);
    expect(registry.get('reg_test')).toBe(mockP);
    expect(registry.getAll().length).toBe(1);
    expect(registry.getActive().length).toBe(1);

    registry.unregister('reg_test');
    expect(registry.get('reg_test')).toBeUndefined();
    expect(registry.getAll().length).toBe(0);
  });

  // Helper to generate a minimal ProviderReputationResult for testing aggregation
  function createMockResult(
    providerId: string,
    providerName: string,
    detectionStatus: 'malicious' | 'suspicious' | 'clean' | 'unknown' | 'unavailable',
    confidence: 'low' | 'medium' | 'high'
  ) {
    return {
      providerId,
      providerName,
      url: 'https://target.com',
      status: 'ready' as const,
      detectionStatus,
      confidence,
      timestamp: new Date().toISOString(),
      latencyMs: 15,
      cached: false,
      evidence: {
        id: `ev-${providerId}`,
        sourceType: 'reputation_provider' as const,
        sourceName: providerName,
        label: `${providerName} Result`,
        description: `${providerName} rated as ${detectionStatus}`,
        data: { detectionStatus },
        isAiGenerated: false,
        createdAt: new Date().toISOString(),
      },
    };
  }

  // AUDIT 3: Isolated provider failure test (A succeeds, B throws, C times out)
  it('handles isolated provider failure (1 succeeds, 1 throws, 1 times out) without failing aggregate', async () => {
    const providerA = new MockReputationProvider({
      id: 'p_good',
      name: 'Good Provider',
      defaultResult: { detectionStatus: 'clean', confidence: 'medium' },
      cache,
    });
    const providerB = new MockReputationProvider({
      id: 'p_throw',
      name: 'Throwing Provider',
      forceError: true,
      errorMessage: 'Connection terminated',
      cache,
    });
    const providerC = new MockReputationProvider({
      id: 'p_timeout',
      name: 'Timeout Provider',
      defaultTimeoutMs: 30,
      forceTimeout: true,
      cache,
    });

    const aggregate = await ReputationAggregator.lookupAndAggregate('https://example.com', [
      providerA,
      providerB,
      providerC,
    ]);

    expect(aggregate.aggregateStatus).toBe('clean');
    expect(aggregate.limitations.length).toBeGreaterThanOrEqual(2);
    expect(aggregate.limitations.some(l => l.includes('Throwing Provider'))).toBe(true);
    expect(aggregate.limitations.some(l => l.includes('Timeout Provider'))).toBe(true);
  });

  // AUDIT 4: Disagreement combinations
  describe('AUDIT 4 — Specific Provider Disagreement Combinations', () => {
    it('correctly aggregates 2 malicious + 1 clean as disputed', () => {
      const agg = ReputationAggregator.aggregate('https://target.com', [
        createMockResult('p1', 'Feed 1', 'malicious', 'high'),
        createMockResult('p2', 'Feed 2', 'malicious', 'high'),
        createMockResult('p3', 'Feed 3', 'clean', 'high'),
      ]);
      expect(agg.disputed).toBe(true);
      expect(agg.aggregateStatus).toBe('suspicious');
      expect(agg.findings[0].type).toBe('reputation_disputed');
      expect(agg.findings[0].metadata?.maliciousCount).toBe(2);
      expect(agg.findings[0].metadata?.cleanCount).toBe(1);
    });

    it('correctly aggregates 1 malicious + 2 clean as disputed', () => {
      const agg = ReputationAggregator.aggregate('https://target.com', [
        createMockResult('p1', 'Feed 1', 'malicious', 'high'),
        createMockResult('p2', 'Feed 2', 'clean', 'high'),
        createMockResult('p3', 'Feed 3', 'clean', 'high'),
      ]);
      expect(agg.disputed).toBe(true);
      expect(agg.aggregateStatus).toBe('suspicious');
      expect(agg.findings[0].type).toBe('reputation_disputed');
      expect(agg.findings[0].metadata?.maliciousCount).toBe(1);
      expect(agg.findings[0].metadata?.cleanCount).toBe(2);
    });

    it('correctly aggregates 1 suspicious + 2 clean as clean majority with downgraded confidence and limitation', () => {
      const agg = ReputationAggregator.aggregate('https://target.com', [
        createMockResult('p1', 'Feed 1', 'suspicious', 'medium'),
        createMockResult('p2', 'Feed 2', 'clean', 'high'),
        createMockResult('p3', 'Feed 3', 'clean', 'high'),
      ]);
      expect(agg.aggregateStatus).toBe('clean');
      expect(agg.confidence).toBe('medium');
      expect(agg.findings[0].type).toBe('reputation_clean');
      expect(agg.limitations.some(l => l.includes('reported suspicious indicators'))).toBe(true);
    });

    it('correctly aggregates 3 unknown as unknown with low confidence', () => {
      const agg = ReputationAggregator.aggregate('https://target.com', [
        createMockResult('p1', 'Feed 1', 'unknown', 'low'),
        createMockResult('p2', 'Feed 2', 'unknown', 'low'),
        createMockResult('p3', 'Feed 3', 'unknown', 'low'),
      ]);
      expect(agg.aggregateStatus).toBe('unknown');
      expect(agg.confidence).toBe('low');
      expect(agg.findings.length).toBe(0);
      expect(agg.limitations.some(l => l.includes('no recorded historical telemetry'))).toBe(true);
    });
  });

  // AUDIT 5: Risk Engine Additive Tests
  describe('AUDIT 5 — Additive Risk Engine Interaction', () => {
    it('preserves high risk from lexical analysis even when reputation is clean', () => {
      const lexicalFinding = {
        id: 'lex-1',
        type: 'lookalike_domain' as const,
        severity: 'high' as const,
        title: 'Lookalike Domain',
        description: 'Impersonates known bank',
        confidence: 'high' as const,
      };

      const cleanRepFinding = {
        id: 'rep-1',
        type: 'reputation_clean' as const,
        severity: 'info' as const,
        title: 'Clean Reputation',
        description: 'Not yet listed in threat feeds',
        confidence: 'medium' as const,
      };

      const combinedFindings = [lexicalFinding, cleanRepFinding];
      const evalResult = RiskEngine.evaluate(combinedFindings, [
        {
          analyzerId: 'url',
          analyzerType: 'url',
          status: 'success',
          confidence: 'high',
          findings: [lexicalFinding],
          evidence: [],
        },
      ]);

      // Risk MUST remain high; clean reputation must NOT downgrade lexical risk
      expect(evalResult.riskLevel).toBe('high');
      expect(evalResult.recommendations.some(r => r.action === 'verify_domain')).toBe(true);
    });

    it('elevates risk to high when lexical is low risk but reputation is confirmed malicious', () => {
      const lexicalFinding = {
        id: 'lex-1',
        type: 'shortened_url' as const,
        severity: 'low' as const,
        title: 'Shortened Link',
        description: 'Uses URL shortener',
        confidence: 'medium' as const,
      };

      const maliciousRepFinding = {
        id: 'rep-1',
        type: 'reputation_malicious' as const,
        severity: 'high' as const,
        title: 'Malicious URL Reported',
        description: 'Active phishing campaign',
        confidence: 'high' as const,
      };

      const combinedFindings = [lexicalFinding, maliciousRepFinding];
      const evalResult = RiskEngine.evaluate(combinedFindings, [
        {
          analyzerId: 'url',
          analyzerType: 'url',
          status: 'success',
          confidence: 'high',
          findings: combinedFindings,
          evidence: [],
        },
      ]);

      expect(evalResult.riskLevel).toBe('high');
      expect(evalResult.recommendations.some(r => r.action === 'avoid_known_malicious_url')).toBe(true);
    });
  });

  // AUDIT 7: Cache Edge Cases
  describe('AUDIT 7 — Cache Hit, Miss, Scope, and Malformed Inputs', () => {
    it('distinguishes cache hit from cache miss and ensures provider-specific isolation', async () => {
      const testCache = new RedisReputationCache(3600);
      const providerA = new MockReputationProvider({ id: 'p_alpha', name: 'Alpha', cache: testCache });
      const providerB = new MockReputationProvider({ id: 'p_beta', name: 'Beta', cache: testCache });

      // Initial lookup is a cache miss for providerA
      const resA1 = await providerA.lookupUrl('https://isolated-test.com');
      expect(resA1.cached).toBe(false);

      // Second lookup is a cache hit for providerA
      const resA2 = await providerA.lookupUrl('https://isolated-test.com');
      expect(resA2.cached).toBe(true);

      // Initial lookup for providerB on the same URL is still a cache miss (provider-scoped)
      const resB1 = await providerB.lookupUrl('https://isolated-test.com');
      expect(resB1.cached).toBe(false);
    });

    it('handles malformed and non-standard URLs gracefully in normalization', () => {
      expect(normalizeUrlForReputation('')).toBe('');
      expect(normalizeUrlForReputation('   ')).toBe('');
      const fallback = normalizeUrlForReputation('not a valid url but has ?utm_source=test');
      expect(fallback).not.toContain('utm_source');
    });
  });
});
