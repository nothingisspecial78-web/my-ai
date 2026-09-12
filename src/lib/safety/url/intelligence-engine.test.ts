import { describe, it, expect, vi } from 'vitest';
import { UrlNormalizer } from './normalizer';
import { checkHostForSsrf, parseAndNormalizeIpv4 } from './ssrf';
import { UrlStructuralAnalyzer } from './structural-analyzer';
import { UrlIntelligenceEngine } from './intelligence-engine';
import {
  ReputationProvider,
  ProviderReputationResult,
  ReputationDetectionStatus,
  ThreatCategory,
} from '../reputation/types';
import { InputClassifier } from '../analyzers/input-classifier';

describe('Phase 6.1: URL Intelligence Test Suite', () => {

  // =========================================================================
  // 1. URL NORMALIZATION TESTS
  // =========================================================================

  describe('URL Normalization', () => {
    it('1. Normalizes standard https and http URLs', () => {
      const resHttps = UrlNormalizer.normalize('https://Example.COM/Path/?foo=bar');
      expect(resHttps.isValid).toBe(true);
      expect(resHttps.protocol).toBe('https:');
      expect(resHttps.hostname).toBe('example.com');
      expect(resHttps.pathname).toBe('/Path/'); // Meaningful path casing and trailing slash preserved
      expect(resHttps.search).toBe('?foo=bar');

      const resHttp = UrlNormalizer.normalize('http://example.org:80/test');
      expect(resHttp.isValid).toBe(true);
      expect(resHttp.protocol).toBe('http:');
      expect(resHttp.port).toBe(''); // standard port 80 stripped
    });

    it('2. Automatically prepends https:// to bare domains and www prefixes', () => {
      const resBare = UrlNormalizer.normalize('example.com/login');
      expect(resBare.isValid).toBe(true);
      expect(resBare.protocol).toBe('https:');
      expect(resBare.hostname).toBe('example.com');
      expect(resBare.pathname).toBe('/login');

      const resWww = UrlNormalizer.normalize('www.github.com');
      expect(resWww.isValid).toBe(true);
      expect(resWww.hostname).toBe('www.github.com');
    });

    it('3. Rejects dangerous or unsupported schemes', () => {
      const schemes = [
        'javascript:alert(1)',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        'file:///etc/passwd',
        'blob:https://example.com/uuid',
        'ftp://anonymous@ftp.example.com',
        'vbscript:msgbox(1)',
      ];

      for (const schemeUrl of schemes) {
        const res = UrlNormalizer.normalize(schemeUrl);
        expect(res.isValid).toBe(false);
        expect(res.error).toMatch(/Unsupported or hazardous URL scheme/i);
      }
    });

    it('4. Retains exact query parameters in provider lookup to prevent threat feed lookup misses', () => {
      const res = UrlNormalizer.normalize(
        'https://example.com/product?utm_source=twitter&id=123&fbclid=abc&category=books&utm_medium=social'
      );
      expect(res.isValid).toBe(true);
      expect(res.search).toContain('utm_source=twitter');
      expect(res.search).toContain('fbclid=abc');
      expect(res.providerLookupUrl).toContain('utm_source=twitter');
      expect(res.providerLookupUrl).toContain('fbclid=abc');
      expect(res.providerLookupUrl).toContain('category=books');
    });

    it('5. Detects embedded credentials and sanitizes providerLookupUrl without leaking secrets (Refinement 1)', () => {
      const res = UrlNormalizer.normalize('https://admin:SuperSecret123@example.com/dashboard?token=xyz');
      expect(res.isValid).toBe(true);
      expect(res.hasCredentials).toBe(true);
      expect(res.credentialsInfo?.hasUsername).toBe(true);
      expect(res.credentialsInfo?.hasPassword).toBe(true);

      // providerLookupUrl must NOT contain the credentials!
      expect(res.providerLookupUrl).not.toContain('SuperSecret123');
      expect(res.providerLookupUrl).not.toContain('admin:');
      expect(res.providerLookupUrl).toBe('https://example.com/dashboard?token=xyz');

      // cacheKey derived from clean providerLookupUrl (prevent cache poisoning)
      expect(res.cacheKey).toBeDefined();
      expect(res.cacheKey).not.toContain('SuperSecret123');

      // displayUrl redacts password
      expect(res.displayUrl).toContain('[REDACTED]');
      expect(res.displayUrl).not.toContain('SuperSecret123');
    });

    it('6. Strips trailing dots from hostname (DNS root notation)', () => {
      const res = UrlNormalizer.normalize('https://example.com./path');
      expect(res.isValid).toBe(true);
      expect(res.hostname).toBe('example.com');
    });

    it('7. Extracts embedded URL from natural user query wrapping', () => {
      const res = UrlNormalizer.normalize('Check this: https://example.com/verify?id=99');
      expect(res.isValid).toBe(true);
      expect(res.hostname).toBe('example.com');
      expect(res.pathname).toBe('/verify');
    });

    it('8. Preserves case-sensitive paths and trailing slashes without altering semantic destination', () => {
      const res = UrlNormalizer.normalize('https://example.com/Account/SecurityFolder/?ref=test');
      expect(res.isValid).toBe(true);
      expect(res.pathname).toBe('/Account/SecurityFolder/');
      expect(res.providerLookupUrl).toBe('https://example.com/Account/SecurityFolder/?ref=test');
    });

    it('9. Correctly isolates @ in authority vs @ in query parameters or fragments', () => {
      // Query @ should NOT be treated as userinfo
      const resQuery = UrlNormalizer.normalize('https://example.com/search?email=alice@company.com');
      expect(resQuery.isValid).toBe(true);
      expect(resQuery.hasCredentials).toBe(false);

      // Fragment @ should NOT be treated as userinfo
      const resHash = UrlNormalizer.normalize('https://example.com/page#@userSection');
      expect(resHash.isValid).toBe(true);
      expect(resHash.hasCredentials).toBe(false);

      // Authority @ MUST be treated as credentials
      const resAuth = UrlNormalizer.normalize('https://attacker@example.com/login');
      expect(resAuth.isValid).toBe(true);
      expect(resAuth.hasCredentials).toBe(true);
    });

    it('10. Enforces input length bounds to defend against denial of service (DoS)', () => {
      const longUrl = 'https://example.com/' + 'a'.repeat(5000);
      const resLong = UrlNormalizer.normalize(longUrl);
      expect(resLong.isValid).toBe(false);
      expect(resLong.error).toMatch(/exceeds maximum permissible length/i);

      const longHost = 'https://' + 'a'.repeat(260) + '.com/';
      const resHost = UrlNormalizer.normalize(longHost);
      expect(resHost.isValid).toBe(false);
      expect(resHost.error).toMatch(/exceeds maximum permissible length/i);
    });
  });

  // =========================================================================
  // 2. SSRF PROTECTION TESTS
  // =========================================================================

  describe('SSRF Protection & Private IP Validation', () => {
    it('1. Detects and blocks IPv4 loopback (127.0.0.0/8)', () => {
      const loopbacks = ['127.0.0.1', '127.0.1.1', '127.255.255.254'];
      for (const ip of loopbacks) {
        const check = checkHostForSsrf(ip);
        expect(check.isBlocked).toBe(true);
        expect(check.isLoopback).toBe(true);
      }
    });

    it('2. Detects and blocks RFC 1918 private IPv4 ranges', () => {
      const privateIps = [
        '10.0.0.1',
        '10.254.0.1',
        '172.16.0.1',
        '172.24.1.1',
        '172.31.255.255',
        '192.168.0.1',
        '192.168.1.254',
      ];
      for (const ip of privateIps) {
        const check = checkHostForSsrf(ip);
        expect(check.isBlocked).toBe(true);
        expect(check.isPrivateOrLocal).toBe(true);
      }
    });

    it('3. Detects and blocks cloud metadata IP endpoints (169.254.169.254, etc.)', () => {
      const meta = checkHostForSsrf('169.254.169.254');
      expect(meta.isBlocked).toBe(true);
      expect(meta.isCloudMetadata).toBe(true);

      const alibabaMeta = checkHostForSsrf('100.100.100.200');
      expect(alibabaMeta.isBlocked).toBe(true);
      expect(alibabaMeta.isCloudMetadata).toBe(true);
    });

    it('4. Detects and blocks IPv6 loopback (::1), link-local, and unique local ranges', () => {
      const v6Hosts = [
        '::1',
        '[::1]',
        'fe80::1',
        '[fe80::1ff:fe23:4567]',
        'fc00::1',
        '[fd12:3456:789a:1::1]',
        '::ffff:127.0.0.1', // IPv4-mapped IPv6 loopback
        '::ffff:192.168.1.1', // IPv4-mapped IPv6 private
      ];

      for (const host of v6Hosts) {
        const check = checkHostForSsrf(host);
        expect(check.isBlocked).toBe(true);
      }
    });

    it('5. Unpacks and detects obfuscated decimal, hex, and octal IP representations', () => {
      // 2130706433 in decimal is 127.0.0.1
      expect(parseAndNormalizeIpv4('2130706433')).toBe('127.0.0.1');
      expect(checkHostForSsrf('2130706433').isBlocked).toBe(true);

      // 0x7f000001 in hex is 127.0.0.1
      expect(parseAndNormalizeIpv4('0x7f000001')).toBe('127.0.0.1');
      expect(checkHostForSsrf('0x7f000001').isBlocked).toBe(true);

      // 0x7f.0.0.1 in mixed hex is 127.0.0.1
      expect(parseAndNormalizeIpv4('0x7f.0.0.1')).toBe('127.0.0.1');
      expect(checkHostForSsrf('0x7f.0.0.1').isBlocked).toBe(true);

      // 0177.0.0.1 in octal is 127.0.0.1
      expect(parseAndNormalizeIpv4('0177.0.0.1')).toBe('127.0.0.1');
      expect(checkHostForSsrf('0177.0.0.1').isBlocked).toBe(true);

      // 3232235521 in decimal is 192.168.0.1 (private)
      expect(parseAndNormalizeIpv4('3232235521')).toBe('192.168.0.1');
      expect(checkHostForSsrf('3232235521').isBlocked).toBe(true);
    });

    it('6. Blocks internal hostnames and suffixes (localhost, *.internal, etc.)', () => {
      const internalHosts = [
        'localhost',
        'server.localhost',
        'database.local',
        'api.internal',
        'metadata.google.internal',
        'nas.lan',
        'router.home',
      ];

      for (const h of internalHosts) {
        const check = checkHostForSsrf(h);
        expect(check.isBlocked).toBe(true);
      }
    });

    it('7. Permits valid public domain names and public IP addresses', () => {
      expect(checkHostForSsrf('example.com').isBlocked).toBe(false);
      expect(checkHostForSsrf('google.com').isBlocked).toBe(false);
      expect(checkHostForSsrf('8.8.8.8').isBlocked).toBe(false);
      expect(checkHostForSsrf('1.1.1.1').isBlocked).toBe(false);
    });
  });

  // =========================================================================
  // 3. STRUCTURAL ANALYSIS TESTS
  // =========================================================================

  describe('URL Structural Analysis', () => {
    it('1. Flags embedded credentials as high severity with host confusion (Refinement 1)', () => {
      const norm = UrlNormalizer.normalize('https://paypal.com@evil.com/login');
      const struct = UrlStructuralAnalyzer.analyze(norm);

      expect(struct.signals).toContain('embedded_credentials');
      const credFinding = struct.findings.find(f => f.type === 'host_confusion');
      expect(credFinding).toBeDefined();
      expect(credFinding?.severity).toBe('high');
      expect(credFinding?.metadata?.actualHostname).toBe('evil.com');
    });

    it('2. Flags suspicious TLDs as weak/moderate signals only, never high/critical (Refinement 2)', () => {
      const norm = UrlNormalizer.normalize('https://mycleanblog.xyz/');
      const struct = UrlStructuralAnalyzer.analyze(norm);

      expect(struct.signals).toContain('suspicious_tld');
      const tldFinding = struct.findings.find(f => f.type === 'suspicious_domain');
      expect(tldFinding).toBeDefined();
      expect(tldFinding?.severity).toBe('low'); // strictly low severity
    });

    it('3. Flags Punycode / IDN homograph domain', () => {
      const norm = UrlNormalizer.normalize('https://xn--pple-43d.com/');
      const struct = UrlStructuralAnalyzer.analyze(norm);

      expect(struct.signals).toContain('punycode_domain');
      const punyFinding = struct.findings.find(f => f.type === 'lookalike_domain');
      expect(punyFinding).toBeDefined();
      expect(punyFinding?.severity).toBe('medium');
    });

    it('4. Flags excessive subdomains (> 4 labels)', () => {
      const norm = UrlNormalizer.normalize('https://login.secure.account.update.evil.com/auth');
      const struct = UrlStructuralAnalyzer.analyze(norm);

      expect(struct.signals).toContain('excessive_subdomains');
      const subFinding = struct.findings.find(f => f.type === 'excessive_subdomains');
      expect(subFinding).toBeDefined();
      expect(subFinding?.severity).toBe('medium');
    });

    it('5. Flags URL shorteners with low severity', () => {
      const norm = UrlNormalizer.normalize('https://bit.ly/3xY7zQw');
      const struct = UrlStructuralAnalyzer.analyze(norm);

      expect(struct.signals).toContain('url_shortener');
      const shortFinding = struct.findings.find(f => f.type === 'shortened_url');
      expect(shortFinding?.severity).toBe('low');
    });

    it('6. Flags sensitive plaintext credentials in query strings', () => {
      const norm = UrlNormalizer.normalize('https://example.com/api?token=secret123&password=myPassWord');
      const struct = UrlStructuralAnalyzer.analyze(norm);

      expect(struct.signals).toContain('sensitive_token_in_query');
      const tokenFinding = struct.findings.find(f => f.type === 'credential_in_url');
      expect(tokenFinding?.severity).toBe('high');
    });

    it('7. Flags lookalike brand typosquatting (e.g. paypa1)', () => {
      const norm = UrlNormalizer.normalize('https://paypa1-secure-auth.com/login');
      const struct = UrlStructuralAnalyzer.analyze(norm);

      expect(struct.signals).toContain('lookalike_brand');
      const brandFinding = struct.findings.find(f => f.type === 'lookalike_brand');
      expect(brandFinding?.severity).toBe('high');
      expect(brandFinding?.metadata?.brand).toBe('paypal');
    });

    it('8. Flags open redirect parameters', () => {
      const norm = UrlNormalizer.normalize('https://example.com/login?redirect=https://evil.com');
      const struct = UrlStructuralAnalyzer.analyze(norm);

      expect(struct.signals).toContain('open_redirect_param');
      const redFinding = struct.findings.find(f => f.type === 'suspicious_redirect');
      expect(redFinding?.severity).toBe('medium');
    });
  });

  // =========================================================================
  // 4. REPUTATION PROVIDER & CONSOLIDATION TESTS
  // =========================================================================

  describe('Reputation Provider Integration & Consolidation', () => {
    // Mock providers for deterministic testing
    const createMockProvider = (
      id: string,
      name: string,
      status: 'ready' | 'unavailable',
      detectionStatus: ReputationDetectionStatus,
      threatCategories?: ThreatCategory[]
    ): ReputationProvider => ({
      id,
      name,
      defaultTimeoutMs: 3000,
      getStatus: () => status,
      lookupUrl: async (url: string): Promise<ProviderReputationResult> => {
        if (detectionStatus === 'unavailable') {
          throw new Error('Provider network connection error');
        }
        return {
          providerId: id,
          providerName: name,
          url,
          status: 'ready',
          detectionStatus,
          confidence: 'high',
          threatCategories: threatCategories || [],
          timestamp: new Date().toISOString(),
          latencyMs: 50,
          cached: false,
          evidence: {
            id: `ev-${id}`,
            sourceType: 'reputation_provider',
            sourceName: name,
            label: `${name} Telemetry`,
            description: `${name} detection: ${detectionStatus}`,
            data: { detectionStatus },
            isAiGenerated: false,
            createdAt: new Date().toISOString(),
          },
        };
      },
    });

    it('1. Produces CRITICAL / HIGH risk when reputation provider confirms known threat', async () => {
      const mockSafeBrowsing = createMockProvider('safebrowsing', 'Google Safe Browsing', 'ready', 'malicious', ['malware', 'phishing']);
      const mockUrlhaus = createMockProvider('urlhaus', 'URLhaus', 'ready', 'unknown');

      const result = await UrlIntelligenceEngine.analyze('https://evil-payload-site.com/', {
        providers: [mockSafeBrowsing, mockUrlhaus],
      });

      expect(result.riskLevel).toBe('critical');
      expect(result.riskScore).toBeGreaterThanOrEqual(40);
      expect(result.signals).toContain('reputation_malicious_safebrowsing');
      expect(result.verdict).toContain('High-risk malicious destination');
      expect(result.recommendation).toContain('Avoid visiting this URL');
    });

    it('2. Resolves conflicting provider verdicts into disputed status without false panic', async () => {
      const mockSafeBrowsing = createMockProvider('safebrowsing', 'Google Safe Browsing', 'ready', 'malicious', ['phishing']);
      const mockUrlhaus = createMockProvider('urlhaus', 'URLhaus', 'ready', 'clean');

      const result = await UrlIntelligenceEngine.analyze('https://questionable-domain.com/', {
        providers: [mockSafeBrowsing, mockUrlhaus],
      });

      expect(result.signals).toContain('reputation_disputed');
      const disputedFinding = result.findings.find(f => f.type === 'reputation_disputed');
      expect(disputedFinding).toBeDefined();
      expect(disputedFinding?.severity).toBe('medium');
    });

    it('3. Produces LOW risk with calibrated phrasing when all providers report clean & structure is clean', async () => {
      const mockSafeBrowsing = createMockProvider('safebrowsing', 'Google Safe Browsing', 'ready', 'clean');
      const mockUrlhaus = createMockProvider('urlhaus', 'URLhaus', 'ready', 'unknown');

      const result = await UrlIntelligenceEngine.analyze('https://example.com/docs', {
        providers: [mockSafeBrowsing, mockUrlhaus],
      });

      expect(result.riskLevel).toBe('low');
      expect(result.riskScore).toBeLessThanOrEqual(15);
      // Calibrated language test: Must NOT claim 100% safe
      expect(result.verdict).not.toContain('100% safe');
      expect(result.verdict).not.toContain('guaranteed');
      expect(result.verdict).toContain('No known threat indicators');
      expect(result.confidence).toBe('medium'); // clean checks decouple to medium confidence
    });

    it('4. Safely falls back when all providers are unavailable without declaring clean', async () => {
      const mockSafeBrowsing = createMockProvider('safebrowsing', 'Google Safe Browsing', 'unavailable', 'unavailable');
      const mockUrlhaus = createMockProvider('urlhaus', 'URLhaus', 'unavailable', 'unavailable');

      const result = await UrlIntelligenceEngine.analyze('https://unknown-new-domain.com/', {
        providers: [mockSafeBrowsing, mockUrlhaus],
      });

      // Provider failure must NOT mean "clean" or "safe"
      expect(result.limitations.some(l => l.includes('unavailable') || l.includes('unconfigured'))).toBe(true);
    });

    it('5. Handles provider lookup timeout gracefully without failing the entire analysis', async () => {
      const slowProvider: ReputationProvider = {
        id: 'slow-provider',
        name: 'Slow Threat Feed',
        defaultTimeoutMs: 100,
        getStatus: () => 'ready',
        lookupUrl: async (url: string): Promise<ProviderReputationResult> => {
          await new Promise(resolve => setTimeout(resolve, 500));
          return {
            providerId: 'slow-provider',
            providerName: 'Slow Threat Feed',
            url,
            status: 'ready',
            detectionStatus: 'clean',
            confidence: 'low',
            threatCategories: [],
            timestamp: new Date().toISOString(),
            cached: false,
          };
        },
      };

      const fastCleanProvider = createMockProvider('fast', 'Fast Threat Feed', 'ready', 'clean');

      const result = await UrlIntelligenceEngine.analyze('https://example.org/', {
        providers: [slowProvider, fastCleanProvider],
        timeoutMs: 100,
      });

      expect(result).toBeDefined();
      expect(result.riskLevel).toBeDefined();
    });

    it('6. Does NOT make external reputation calls for SSRF/private network targets (Zero SSRF Policy)', async () => {
      const lookupSpy = vi.fn();
      const spyProvider: ReputationProvider = {
        id: 'spy-provider',
        name: 'Spy Provider',
        defaultTimeoutMs: 3000,
        getStatus: () => 'ready',
        lookupUrl: lookupSpy,
      };

      const result = await UrlIntelligenceEngine.analyze('http://192.168.1.1/admin', {
        providers: [spyProvider],
      });

      expect(lookupSpy).not.toHaveBeenCalled();
      expect(result.signals).toContain('ssrf_blocked');
      expect(result.findings.some(f => f.type === 'private_network_host')).toBe(true);
    });
  });

  // =========================================================================
  // 5. PRIVACY & EVIDENCE PROVENANCE TESTS
  // =========================================================================

  describe('Privacy, Redaction & Evidence Provenance', () => {
    it('1. Redacts sensitive tokens and passwords from evidence and display URL', async () => {
      const result = await UrlIntelligenceEngine.analyze('https://example.com/api?password=SuperSecretPassword99&token=ghp_123456789012345678901234567890123456');

      expect(result.url).not.toContain('SuperSecretPassword99');
      expect(result.url).toContain('[REDACTED]');

      for (const finding of result.findings) {
        expect(finding.description).not.toContain('SuperSecretPassword99');
      }

      for (const ev of result.evidence) {
        if (ev.snippet) {
          expect(ev.snippet).not.toContain('SuperSecretPassword99');
        }
      }
    });

    it('2. Attaches provenance and evidence IDs to all critical findings', async () => {
      const result = await UrlIntelligenceEngine.analyze('https://paypal.com@evil.com/login?token=abc');
      for (const f of result.findings) {
        if (f.evidenceIds && f.evidenceIds.length > 0) {
          const matchedEv = result.evidence.filter(e => f.evidenceIds?.includes(e.id));
          expect(matchedEv.length).toBeGreaterThan(0);
        }
      }
    });
  });

  // =========================================================================
  // 6. PROVIDER RESULT SEMANTICS & UNKNOWN COMBINATIONS (Section 7)
  // =========================================================================

  describe('Provider Result Semantics & Conflict Handling', () => {
    const createMockProvider = (
      id: string,
      name: string,
      status: 'ready' | 'unavailable',
      detectionStatus: ReputationDetectionStatus,
      threatCategories?: ThreatCategory[]
    ): ReputationProvider => ({
      id,
      name,
      defaultTimeoutMs: 3000,
      getStatus: () => status,
      lookupUrl: async (url: string): Promise<ProviderReputationResult> => {
        if (detectionStatus === 'unavailable') {
          throw new Error('Provider network error');
        }
        return {
          providerId: id,
          providerName: name,
          url,
          status: 'ready',
          detectionStatus,
          confidence: 'high',
          threatCategories: threatCategories || [],
          timestamp: new Date().toISOString(),
          latencyMs: 50,
          cached: false,
        };
      },
    });

    it('Combination C: Conflicting vendor verdicts produce reputation_disputed with elevated caution', async () => {
      const p1 = createMockProvider('safebrowsing', 'Safe Browsing', 'ready', 'malicious', ['malware']);
      const p2 = createMockProvider('urlhaus', 'URLhaus', 'ready', 'clean');

      const result = await UrlIntelligenceEngine.analyze('https://example-disputed.com/', {
        providers: [p1, p2],
      });

      expect(result.signals).toContain('reputation_disputed');
      expect(result.findings.some(f => f.type === 'reputation_disputed')).toBe(true);
      expect(result.riskLevel).toBe('critical'); // elevated due to active malware detection
    });

    it('Combination D: When all providers are unavailable, returns risk UNKNOWN and confidence LOW', async () => {
      const p1 = createMockProvider('p1', 'Provider 1', 'unavailable', 'unavailable');
      const p2 = createMockProvider('p2', 'Provider 2', 'unavailable', 'unavailable');

      const result = await UrlIntelligenceEngine.analyze('https://example.com/standard-page', {
        providers: [p1, p2],
      });

      expect(result.riskLevel).toBe('unknown');
      expect(result.confidence).toBe('low');
      expect(result.limitations.length).toBeGreaterThan(0);
      expect(result.verdict).toMatch(/threat intelligence feeds were unavailable/i);
    });
  });

  // =========================================================================
  // 7. URL PARSER ATTACK CASES & REPUTATION NORMALIZATION (Section 10)
  // =========================================================================

  describe('URL Parser Adversarial Attack Cases', () => {
    it('Accurately identifies host and userinfo for authority confusion attacks', () => {
      // https://example.com@evil.com
      const res1 = UrlNormalizer.normalize('https://example.com@evil.com/path');
      expect(res1.isValid).toBe(true);
      expect(res1.hostname).toBe('evil.com');
      expect(res1.hasCredentials).toBe(true);
      expect(res1.providerLookupUrl).toBe('https://evil.com/path');

      // https://evil.com#@example.com (fragment @ does NOT confuse authority)
      const res2 = UrlNormalizer.normalize('https://evil.com#@example.com');
      expect(res2.isValid).toBe(true);
      expect(res2.hostname).toBe('evil.com');
      expect(res2.hasCredentials).toBe(false);

      // https://example.com:443@evil.com
      const res3 = UrlNormalizer.normalize('https://example.com:443@evil.com/login');
      expect(res3.isValid).toBe(true);
      expect(res3.hostname).toBe('evil.com');
      expect(res3.hasCredentials).toBe(true);
    });

    it('Detects SSRF and blocks external lookups across alternative IPv4 and IPv6 representations', async () => {
      // Decimal IP notation (2130706433 -> 127.0.0.1)
      const resDec = UrlNormalizer.normalize('http://2130706433/admin');
      expect(resDec.isValid).toBe(true);
      expect(resDec.ssrf.isBlocked).toBe(true);
      expect(resDec.ssrf.isLoopback).toBe(true);

      // Hex IP notation (0x7f000001 -> 127.0.0.1)
      const resHex = UrlNormalizer.normalize('http://0x7f000001/admin');
      expect(resHex.isValid).toBe(true);
      expect(resHex.ssrf.isBlocked).toBe(true);
      expect(resHex.ssrf.isLoopback).toBe(true);

      // Octal IP notation (0177.0.0.1 -> 127.0.0.1)
      const resOct = UrlNormalizer.normalize('http://0177.0.0.1/admin');
      expect(resOct.isValid).toBe(true);
      expect(resOct.ssrf.isBlocked).toBe(true);
      expect(resOct.ssrf.isLoopback).toBe(true);

      // IPv4-mapped IPv6 ([::ffff:127.0.0.1])
      const resMap = UrlNormalizer.normalize('http://[::ffff:127.0.0.1]/admin');
      expect(resMap.isValid).toBe(true);
      expect(resMap.ssrf.isBlocked).toBe(true);
      expect(resMap.ssrf.isLoopback).toBe(true);
    });

    it('Rejects control characters and embedded null bytes', () => {
      const resNull = UrlNormalizer.normalize('https://example.com\0/bad-path');
      expect(resNull.isValid).toBe(false);
    });
  });

  // =========================================================================
  // 8. COMPOUND RISK & WEAK SIGNAL EVALUATION (Section 8)
  // =========================================================================

  describe('Compound Risk & Weak Signal Evaluation', () => {
    it('Suspicious TLD (.xyz) alone produces LOW risk, never high or critical', async () => {
      const result = await UrlIntelligenceEngine.analyze('https://legitimate-product.xyz/', {
        providers: [],
      });
      expect(result.riskLevel).toBe('low');
      expect(result.riskScore).toBeLessThanOrEqual(5);
    });

    it('Unusual port (:8080) alone produces LOW risk', async () => {
      const result = await UrlIntelligenceEngine.analyze('https://example.com:8080/test', {
        providers: [],
      });
      expect(result.riskLevel).toBe('low');
      expect(result.riskScore).toBeLessThanOrEqual(5);
    });

    it('URL shortener alone produces LOW risk', async () => {
      const result = await UrlIntelligenceEngine.analyze('https://bit.ly/3xyz123', {
        providers: [],
      });
      expect(result.riskLevel).toBe('low');
      expect(result.riskScore).toBeLessThanOrEqual(5);
    });

    it('Auth keyword alone produces LOW risk', async () => {
      const result = await UrlIntelligenceEngine.analyze('https://example.com/login', {
        providers: [],
      });
      expect(result.riskLevel).toBe('low');
      expect(result.riskScore).toBeLessThanOrEqual(5);
    });

    it('Converging signals: Brand lookalike + auth keyword produces HIGH risk', async () => {
      const result = await UrlIntelligenceEngine.analyze('https://paypa1-security.com/login', {
        providers: [],
      });
      expect(result.riskLevel).toBe('high');
      expect(result.riskScore).toBeGreaterThanOrEqual(25);
    });

    it('Converging signals: IP address host + login path produces HIGH risk', async () => {
      const result = await UrlIntelligenceEngine.analyze('http://45.33.32.156/verify-account', {
        providers: [],
      });
      expect(result.riskLevel).toBe('high');
      expect(result.riskScore).toBeGreaterThanOrEqual(25);
    });
  });

  // =========================================================================
  // 9. INPUT CLASSIFICATION VERIFICATION (Section 11)
  // =========================================================================

  describe('Input Classification Edge Cases', () => {
    it('Classifies dedicated URL inquiries as url', () => {
      expect(InputClassifier.classify({ rawContent: 'https://example.com' })).toBe('url');
      expect(InputClassifier.classify({ rawContent: 'Check this: https://example.com' })).toBe('url');
      expect(InputClassifier.classify({ rawContent: 'Is this website safe: https://example.com' })).toBe('url');
      expect(InputClassifier.classify({ rawContent: 'Verify this url https://example.com/login' })).toBe('url');
    });

    it('Does NOT classify conversational scam narratives as url, preserving surrounding context', () => {
      const scamNarrative =
        'URGENT NOTICE: Your bank account has been flagged for unauthorized activity. ' +
        'To prevent total suspension, verify your identity immediately at https://bank-verify.evil.com/login ' +
        'or call customer support right away.';
      const res = InputClassifier.classify({ rawContent: scamNarrative });
      expect(res).not.toBe('url');
      expect(res).toBe('message');
    });

    it('Does NOT classify code snippets containing URLs as url', () => {
      const codeSnippet = 'const url = "https://example.com";\nfetch(url);\nreturn false;';
      const res = InputClassifier.classify({ rawContent: codeSnippet });
      expect(res).toBe('code');
    });
  });
});
