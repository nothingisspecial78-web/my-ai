/**
 * Deterministic URL Structural & Lexical Analyzer (Phase 6.1)
 * 
 * Inspects normalized URL components for deception, homographs, obfuscation,
 * open redirects, credential embedding, and brand spoofing patterns.
 * 
 * Never makes network calls or crawls target destinations.
 */

import crypto from 'crypto';
import { Finding, Evidence } from '../types';
import { NormalizedUrlResult } from './normalizer';

export interface StructuralAnalysisResult {
  findings: Finding[];
  evidence: Evidence[];
  signals: string[];
  limitations: string[];
}

export class UrlStructuralAnalyzer {
  // Known high-risk or elevated-abuse TLDs (USER REFINEMENT 2: Contextual signal ONLY, never high/critical by itself)
  private static SUSPICIOUS_TLDS = new Set([
    'zip', 'mov', 'top', 'xyz', 'country', 'kim', 'work', 'gq', 'cf', 'tk', 'ml', 'ga', 'buzz',
    'fit', 'rest', 'surf', 'live', 'click', 'link',
  ]);

  // Common URL shortening domains
  private static SHORTENER_DOMAINS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rebrand.ly', 'ow.ly', 'buff.ly',
  ]);

  // Major brand keywords for lookalike / spoofing heuristics
  private static BRAND_KEYWORDS = [
    'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'facebook', 'instagram', 'whatsapp',
    'chase', 'bankofamerica', 'wellsfargo', 'binance', 'coinbase', 'stripe', 'telegram', 'meta',
  ];

  // Specific authentication / credential keywords that indicate auth actions
  private static HIGH_RISK_AUTH_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'verification', 'account',
    'password', 'credential', 'secure-login', 'account-update', 'recover',
    'unlock', 'wallet', 'auth', 'authorize',
  ];

  // Generic security, payment, or notification keywords requiring contextual reinforcement
  private static CONTEXTUAL_KEYWORDS = [
    'security', 'update', 'bank', 'payment', 'confirm', 'urgent', 'support', 'billing', 'invoice',
  ];

  /**
   * Analyzes the normalized URL and produces findings, evidence, and detected signals.
   */
  static analyze(normalized: NormalizedUrlResult): StructuralAnalysisResult {
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];
    const signals: string[] = [];
    const limitations: string[] = [
      'The destination website was not visited, fetched, or resolved.',
      'Analysis is based on deterministic structural characteristics and observable patterns.',
    ];

    if (!normalized.isValid) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'syntax_anomaly',
        severity: 'medium',
        title: 'Malformed or Unsupported URL',
        description: normalized.error || 'The URL could not be parsed into valid web components.',
        confidence: 'high',
      });
      return { findings, evidence, signals: ['malformed_url'], limitations };
    }

    const evidenceId = crypto.randomUUID();
    evidence.push({
      id: evidenceId,
      sourceType: 'url_analysis',
      sourceName: 'Deterministic URL Structural Analyzer',
      label: 'URL Components & Lexical Structure',
      description: 'Extracted URL structure, protocol, hostname, and path tokens.',
      data: {
        displayUrl: normalized.displayUrl,
        protocol: normalized.protocol,
        hostname: normalized.hostname,
        port: normalized.port || (normalized.protocol === 'https:' ? '443' : '80'),
        pathname: normalized.pathname,
        hasCredentials: normalized.hasCredentials,
        isIpAddress: normalized.isIpAddress,
        isPrivateOrLocal: normalized.ssrf.isPrivateOrLocal,
      },
      isAiGenerated: false,
      createdAt: new Date().toISOString(),
    });

    const hostname = normalized.hostname;
    const pathname = normalized.pathname.toLowerCase();
    const search = normalized.search.toLowerCase();

    // ----------------------------------------------------
    // 1. SSRF / Private Network Target
    // ----------------------------------------------------
    if (normalized.ssrf.isBlocked) {
      signals.push('ssrf_blocked');
      findings.push({
        id: crypto.randomUUID(),
        type: 'private_network_host',
        severity: normalized.ssrf.isCloudMetadata ? 'high' : 'medium',
        title: normalized.ssrf.isCloudMetadata
          ? 'Cloud Metadata Endpoint Target'
          : normalized.ssrf.isLoopback
          ? 'Localhost / Loopback Target'
          : 'Private Network Hostname Target',
        description: normalized.ssrf.reason || 'The URL points to an internal or non-routable address.',
        evidenceIds: [evidenceId],
        confidence: 'high',
        metadata: {
          parsedIp: normalized.ssrf.parsedIp,
          isPrivate: normalized.ssrf.isPrivateOrLocal,
          isCloudMetadata: normalized.ssrf.isCloudMetadata,
        },
      });
    }

    // ----------------------------------------------------
    // 2. Embedded Userinfo / Credentials (USER REFINEMENT 1)
    // ----------------------------------------------------
    if (normalized.hasCredentials) {
      signals.push('embedded_credentials');
      findings.push({
        id: crypto.randomUUID(),
        type: 'host_confusion',
        severity: 'high',
        title: 'Embedded Credentials / Host Confusion (@)',
        description:
          'The URL contains embedded authentication details (user:pass@host) or an @ symbol. Attackers frequently use this pattern to confuse users into believing the destination is the prefix before the @ rather than the actual host.',
        evidenceIds: [evidenceId],
        confidence: 'high',
        metadata: {
          actualHostname: hostname,
          apparentPrefix: normalized.credentialsInfo?.rawUsername || undefined,
        },
      });
    }

    // ----------------------------------------------------
    // 3. Protocol Security
    // ----------------------------------------------------
    if (normalized.protocol === 'http:') {
      signals.push('insecure_http');
      findings.push({
        id: crypto.randomUUID(),
        type: 'insecure_protocol',
        severity: 'low',
        title: 'Unencrypted HTTP Protocol',
        description: 'The URL uses unencrypted HTTP. Data transferred over this connection is vulnerable to interception or tampering on public networks.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // ----------------------------------------------------
    // 4. IP Address Hostname
    // ----------------------------------------------------
    if (normalized.isIpAddress && !normalized.ssrf.isBlocked) {
      const hasAuthPath = UrlStructuralAnalyzer.HIGH_RISK_AUTH_KEYWORDS.some(kw => this.matchesKeyword(pathname, kw));
      signals.push('public_ip_host');
      findings.push({
        id: crypto.randomUUID(),
        type: 'ip_as_host',
        severity: hasAuthPath ? 'high' : 'medium',
        title: hasAuthPath
          ? 'Direct Public IP Address Hosting Authentication Form'
          : 'Direct Public IP Address as Hostname',
        description: hasAuthPath
          ? `The URL points directly to an IP address (${hostname}) hosting an authentication or verification path (${pathname}), a high-risk phishing indicator.`
          : `The URL uses a raw IP address (${hostname}) instead of a registered domain name, obscuring organizational identity and ownership.`,
        evidenceIds: [evidenceId],
        confidence: 'high',
        metadata: { ip: hostname, hasAuthPath },
      });
    }

    // ----------------------------------------------------
    // 5. Punycode / IDN Domain (Homograph attack indicator)
    // ----------------------------------------------------
    if (normalized.punycodeHostname) {
      signals.push('punycode_domain');
      findings.push({
        id: crypto.randomUUID(),
        type: 'lookalike_domain',
        severity: 'medium',
        title: 'Punycode / IDN Homograph Domain',
        description: `The domain uses Punycode encoding (${hostname}). Punycode allows international characters that can visually spoof legitimate Latin characters.`,
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // ----------------------------------------------------
    // 6. Excessive Subdomains (e.g. login.secure.bank.update.evil.com)
    // ----------------------------------------------------
    const hostParts = hostname.split('.');
    if (!normalized.isIpAddress && hostParts.length > 4) {
      signals.push('excessive_subdomains');
      findings.push({
        id: crypto.randomUUID(),
        type: 'excessive_subdomains',
        severity: 'medium',
        title: 'Excessive Subdomain Levels',
        description: `The domain contains ${hostParts.length} subdomain labels, a technique frequently used to bury suspicious domains inside lengthy names.`,
        evidenceIds: [evidenceId],
        confidence: 'medium',
        metadata: { subdomainCount: hostParts.length },
      });
    }

    // ----------------------------------------------------
    // 7. Suspicious TLD (USER REFINEMENT 2: Weak/moderate signal ONLY)
    // ----------------------------------------------------
    const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1] : '';
    if (UrlStructuralAnalyzer.SUSPICIOUS_TLDS.has(tld)) {
      signals.push('suspicious_tld');
      findings.push({
        id: crypto.randomUUID(),
        type: 'suspicious_domain',
        severity: 'low', // Strictly LOW severity: never high/critical independently
        title: `Uncommon or High-Abuse TLD (.${tld})`,
        description: `The top-level domain .${tld} has elevated statistical abuse rates in automated registrations. Note: This is an informational context signal, not proof of maliciousness.`,
        evidenceIds: [evidenceId],
        confidence: 'medium',
        metadata: { tld },
      });
    }

    // ----------------------------------------------------
    // 8. URL Shortener Service
    // ----------------------------------------------------
    if (UrlStructuralAnalyzer.SHORTENER_DOMAINS.has(hostname)) {
      signals.push('url_shortener');
      findings.push({
        id: crypto.randomUUID(),
        type: 'shortened_url',
        severity: 'low',
        title: 'URL Shortening Service Detected',
        description: `The link uses a shortening service (${hostname}), which masks the final destination address until clicked.`,
        evidenceIds: [evidenceId],
        confidence: 'high',
        metadata: { shortener: hostname },
      });
    }

    // ----------------------------------------------------
    // 9. Non-Standard Web Port
    // ----------------------------------------------------
    if (normalized.port) {
      const portNum = parseInt(normalized.port, 10);
      const isStandard = portNum === 80 || portNum === 443;
      if (!isStandard) {
        signals.push('unusual_port');
        findings.push({
          id: crypto.randomUUID(),
          type: 'syntax_anomaly',
          severity: 'low',
          title: `Non-Standard Web Port (:${normalized.port})`,
          description: `The URL specifies port ${normalized.port}. Standard web services operate over port 80 or 443.`,
          evidenceIds: [evidenceId],
          confidence: 'high',
          metadata: { port: normalized.port },
        });
      }
    }

    // ----------------------------------------------------
    // 10. Brand Impersonation & Typosquatting Patterns
    // ----------------------------------------------------
    const lookalike = this.detectLookalikePattern(hostname, pathname);
    if (lookalike) {
      signals.push('lookalike_brand');
      findings.push({
        id: crypto.randomUUID(),
        type: 'lookalike_brand',
        severity: 'high',
        title: 'Likely Brand Impersonation / Typosquatting',
        description: `The URL contains character substitutions ("${lookalike.pattern}") mimicking known brand "${lookalike.brand}".`,
        evidenceIds: [evidenceId],
        confidence: 'high',
        metadata: { brand: lookalike.brand, pattern: lookalike.pattern },
      });
    } else {
      // Check for exact brand keyword on non-official domain
      const isTrustedContentHost =
        hostname === 'github.com' ||
        hostname.endsWith('.github.com') ||
        hostname === 'gitlab.com' ||
        hostname === 'wikipedia.org' ||
        hostname.endsWith('.wikipedia.org') ||
        hostname === 'npmjs.com' ||
        hostname === 'pypi.org';

      for (const brand of UrlStructuralAnalyzer.BRAND_KEYWORDS) {
        const brandInHost = hostname.includes(brand);
        const brandInPath = !isTrustedContentHost && pathname.includes(`/${brand}`);
        if (brandInHost || brandInPath) {
          const isOfficial = hostname === `${brand}.com` || hostname.endsWith(`.${brand}.com`);
          if (!isOfficial) {
            signals.push('brand_in_unofficial_domain');
            findings.push({
              id: crypto.randomUUID(),
              type: 'lookalike_domain',
              severity: 'high',
              title: `Brand Keyword "${brand}" on Unofficial Domain`,
              description: `The URL references known brand "${brand}" but is hosted on an unofficial domain (${hostname}).`,
              evidenceIds: [evidenceId],
              confidence: 'high',
              metadata: { brand, hostname },
            });
            break;
          }
        }
      }
    }

    // ----------------------------------------------------
    // 11. Contextual Suspicious Keywords in Path/Host
    // ----------------------------------------------------
    const isDocOrWiki =
      /^\/(?:wiki|documentation|docs|articles?|blog|news|about|help|faq|knowledge|learn|topics?|reference)\b/i.test(pathname);

    const matchedAuthKw: string[] = [];
    for (const kw of UrlStructuralAnalyzer.HIGH_RISK_AUTH_KEYWORDS) {
      if (this.matchesKeyword(hostname, kw) || (!isDocOrWiki && this.matchesKeyword(pathname, kw))) {
        matchedAuthKw.push(kw);
      }
    }

    if (matchedAuthKw.length > 0) {
      signals.push('auth_keywords');
      findings.push({
        id: crypto.randomUUID(),
        type: 'suspicious_keyword',
        severity: 'low',
        title: 'Authentication or Credential Keywords in URL',
        description: `The URL contains authentication keywords (${matchedAuthKw.slice(0, 3).join(', ')}). In conjunction with unofficial domains, this may indicate a credential harvesting form.`,
        evidenceIds: [evidenceId],
        confidence: 'medium',
        metadata: { keywords: matchedAuthKw },
      });
    }

    // ----------------------------------------------------
    // 12. Plaintext Credentials & Sensitive Tokens in Query
    // ----------------------------------------------------
    if (
      search.includes('token=') ||
      search.includes('password=') ||
      search.includes('passwd=') ||
      search.includes('pwd=') ||
      search.includes('apikey=') ||
      search.includes('api_key=') ||
      search.includes('secret=') ||
      search.includes('otp=') ||
      search.includes('pin=')
    ) {
      signals.push('sensitive_token_in_query');
      findings.push({
        id: crypto.randomUUID(),
        type: 'credential_in_url',
        severity: 'high',
        title: 'Sensitive Credential or Token in URL Query',
        description: 'The URL includes authentication credentials, passwords, or tokens in plain text query parameters.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // ----------------------------------------------------
    // 13. Open Redirect Parameters
    // ----------------------------------------------------
    if (/(?:url|redirect|dest|target|next|return)=(?:https?%3a%2f%2f|https?:\/\/)/i.test(search)) {
      signals.push('open_redirect_param');
      findings.push({
        id: crypto.randomUUID(),
        type: 'suspicious_redirect',
        severity: 'medium',
        title: 'Embedded Redirect Destination Parameter',
        description: 'The URL includes an external destination redirect parameter, which can be exploited for open-redirect phishing attacks.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // ----------------------------------------------------
    // 14. Excessive or Nested Percent-Encoding
    // ----------------------------------------------------
    if (/%25|%20%20/i.test(search) || /%25/i.test(pathname)) {
      signals.push('excessive_encoding');
      findings.push({
        id: crypto.randomUUID(),
        type: 'excessive_encoding',
        severity: 'medium',
        title: 'Repeated or Nested Percent-Encoding',
        description: 'The URL uses repeated percent-encoding (%25), a technique commonly used to bypass security filters.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // ----------------------------------------------------
    // 15. Unusually Long Hostname or URL
    // ----------------------------------------------------
    if (hostname.length > 50 || normalized.normalizedUrl.length > 255) {
      signals.push('excessive_length');
      findings.push({
        id: crypto.randomUUID(),
        type: 'suspicious_domain',
        severity: 'low',
        title: 'Unusually Long URL String',
        description: `The URL length (${normalized.normalizedUrl.length} characters) is unusually long, frequently seen in obfuscated link schemes.`,
        evidenceIds: [evidenceId],
        confidence: 'low',
      });
    }

    return {
      findings,
      evidence,
      signals,
      limitations,
    };
  }

  /**
   * Detects character substitutions in brand names (e.g. 0 -> o, 1 -> l, etc.)
   */
  private static detectLookalikePattern(
    hostname: string,
    pathname: string
  ): { brand: string; pattern: string } | null {
    const full = `${hostname}/${pathname}`.toLowerCase();

    const normalized = full
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/5/g, 's')
      .replace(/vv/g, 'w');

    for (const brand of UrlStructuralAnalyzer.BRAND_KEYWORDS) {
      if (normalized.includes(brand)) {
        const hasL = brand.includes('l');
        const hasO = brand.includes('o');
        const hasS = brand.includes('s');
        const hasW = brand.includes('w');

        const p1 = hasL ? brand.replace(/l/g, '1') : '';
        const p0 = hasO ? brand.replace(/o/g, '0') : '';
        const p5 = hasS ? brand.replace(/s/g, '5') : '';
        const pW = hasW ? brand.replace(/w/g, 'vv') : '';

        const matchedPattern =
          (p1 && full.includes(p1) && p1) ||
          (p0 && full.includes(p0) && p0) ||
          (p5 && full.includes(p5) && p5) ||
          (pW && full.includes(pW) && pW);

        if (matchedPattern) {
          const isOfficial = hostname === `${brand}.com` || hostname.endsWith(`.${brand}.com`);
          if (!isOfficial) {
            return { brand, pattern: matchedPattern };
          }
        }
      }
    }

    return null;
  }

  private static matchesKeyword(text: string, kw: string): boolean {
    const pattern = new RegExp(`(?:^|[._/\\-?&=])${kw}(?:[._/\\-?&=]|$)`, 'i');
    return pattern.test(text);
  }
}
