import crypto from 'crypto';
import { SafetyAnalyzer } from './base';
import {
  SafetyInput,
  AnalyzerResult,
  Finding,
  Evidence,
  ConfidenceLevel,
} from '../types';
import { redactUrl } from '../redaction';

/**
 * Deterministic Lexical URL & Link Analyzer.
 * Performs rigorous offline structural, protocol, hostname, homograph, and credential checks.
 * NEVER visits, navigates, executes, or fetches from the target URL.
 */
export class UrlAnalyzer implements SafetyAnalyzer {
  readonly id = 'url-analyzer';
  readonly type = 'url' as const;
  readonly supportedInputTypes = ['url', 'website', 'qr'] as const;

  // Known high-risk / abused TLDs (heuristic indicator)
  private static SUSPICIOUS_TLDS = new Set([
    'zip', 'mov', 'top', 'xyz', 'country', 'kim', 'work', 'gq', 'cf', 'tk', 'ml', 'ga', 'buzz',
    'fit', 'rest', 'surf', 'live',
  ]);

  // Common URL shortening domains
  private static SHORTENER_DOMAINS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rebrand.ly', 'ow.ly', 'buff.ly',
  ]);

  // Major brand keywords for lookalike / spoofing heuristics
  private static BRAND_KEYWORDS = [
    'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'facebook', 'instagram', 'whatsapp',
    'chase', 'bankofamerica', 'wellsfargo', 'binance', 'coinbase',
  ];

  // Suspicious security/login keywords in URL paths or subdomains
  private static SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'verification', 'account', 'security', 'update',
    'password', 'wallet', 'bank', 'payment', 'recover', 'unlock', 'confirm', 'urgent', 'support',
  ];

  // Common private or local network IPv4 ranges
  private static PRIVATE_IP_REGEX = /^(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})$/;

  canAnalyze(input: SafetyInput): boolean {
    if (input.type && (this.supportedInputTypes as readonly string[]).includes(input.type)) {
      return true;
    }
    const text = input.rawContent.trim();
    return /^https?:\/\//i.test(text) || /^www\./i.test(text);
  }

  async analyze(input: SafetyInput): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];
    const rawUrl = input.rawContent.trim();
    const urlStr = /^https?:\/\//i.test(rawUrl) ? rawUrl : `http://${rawUrl}`;

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(urlStr);
    } catch {
      findings.push({
        id: crypto.randomUUID(),
        type: 'syntax_anomaly',
        severity: 'medium',
        title: 'Malformed URL Syntax',
        description: 'The provided string does not conform to valid standard URL syntax specifications.',
        confidence: 'high',
      });

      return {
        analyzerId: this.id,
        analyzerType: this.type,
        status: 'partial',
        confidence: 'medium',
        findings,
        evidence: [],
        limitations: ['URL could not be parsed into valid components; full lexical checks skipped.'],
      };
    }

    const sanitizedUrl = redactUrl(urlStr);
    const evidenceId = crypto.randomUUID();

    evidence.push({
      id: evidenceId,
      sourceType: 'url_analysis',
      sourceName: 'Deterministic Lexical URL Parser',
      description: 'Extracted URL components and lexical metadata',
      data: {
        rawUrl: sanitizedUrl,
        protocol: parsedUrl.protocol,
        hostname: parsedUrl.hostname,
        pathname: parsedUrl.pathname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? '443' : '80'),
        hasUsername: Boolean(parsedUrl.username),
      },
      isAiGenerated: false,
      createdAt: new Date().toISOString(),
    });

    const hostname = parsedUrl.hostname.toLowerCase();
    const pathname = parsedUrl.pathname.toLowerCase();

    // ----------------------------------------------------
    // A. Protocol Analysis
    // ----------------------------------------------------
    if (parsedUrl.protocol === 'http:') {
      findings.push({
        id: crypto.randomUUID(),
        type: 'insecure_protocol',
        severity: 'low',
        title: 'Unencrypted HTTP Protocol',
        description: 'The URL uses unencrypted HTTP rather than HTTPS. Communication can be intercepted on local networks.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    } else if (parsedUrl.protocol !== 'https:') {
      findings.push({
        id: crypto.randomUUID(),
        type: 'syntax_anomaly',
        severity: 'medium',
        title: `Unusual Protocol (${parsedUrl.protocol})`,
        description: `The URL uses a non-standard web protocol "${parsedUrl.protocol}".`,
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // ----------------------------------------------------
    // B. Credential Tricks & Host Confusion (@ symbol)
    // ----------------------------------------------------
    if (parsedUrl.username || rawUrl.includes('@')) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'host_confusion',
        severity: 'high',
        title: 'Misleading Embedded Credentials / Host Confusion (@)',
        description: `The URL uses embedded authentication (@) confusing the apparent authority "${parsedUrl.username || 'user'}" with the actual destination host "${hostname}".`,
        evidenceIds: [evidenceId],
        confidence: 'high',
        metadata: {
          actualHostname: hostname,
          apparentHostname: parsedUrl.username || undefined,
        },
      });
    }

    // ----------------------------------------------------
    // C. Hostname & IP Address Analysis
    // ----------------------------------------------------
    const isIpv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    if (isIpv4 || hostname === 'localhost') {
      const isPrivate = UrlAnalyzer.PRIVATE_IP_REGEX.test(hostname) || hostname === 'localhost';

      findings.push({
        id: crypto.randomUUID(),
        type: 'ip_as_host',
        severity: isPrivate ? 'low' : 'medium',
        title: isPrivate ? 'Private IP Address as Host' : 'Direct Public IP Address Hostname',
        description: isPrivate
          ? `The URL uses a private IP address (${hostname}).`
          : 'The URL uses a raw IP address instead of a domain name, which obscures the organizational identity of the host.',
        evidenceIds: [evidenceId],
        confidence: 'high',
        metadata: { ip: hostname, isPrivate },
      });

      if (isPrivate) {
        findings.push({
          id: crypto.randomUUID(),
          type: 'private_network_host',
          severity: 'low',
          title: 'Private Network or Localhost Address',
          description: `The URL references a private or local network host (${hostname}). This is typical for internal device or router interfaces.`,
          evidenceIds: [evidenceId],
          confidence: 'high',
          metadata: { host: hostname },
        });
      }
    }

    // Excessive subdomains check (e.g. login.secure.bank.update.example.com)
    const hostParts = hostname.split('.');
    if (!isIpv4 && hostParts.length > 4) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'excessive_subdomains',
        severity: 'medium',
        title: 'Excessive Subdomain Levels',
        description: `The domain contains ${hostParts.length} labels, a structure often used to obfuscate destination domain hierarchy.`,
        evidenceIds: [evidenceId],
        confidence: 'medium',
      });
    }

    // Suspicious hostname length
    if (hostname.length > 50) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'suspicious_domain',
        severity: 'medium',
        title: 'Unusually Long Hostname',
        description: `The hostname is ${hostname.length} characters long, which is statistically uncommon for legitimate commercial domains.`,
        evidenceIds: [evidenceId],
        confidence: 'medium',
      });
    }

    // Excessive hyphens in hostname (>= 3 hyphens)
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'suspicious_domain',
        severity: 'medium',
        title: 'Multiple Hyphens in Hostname',
        description: 'The domain contains multiple consecutive hyphens, frequently seen in spoofed registration strings.',
        evidenceIds: [evidenceId],
        confidence: 'medium',
      });
    }

    // ----------------------------------------------------
    // D. URL Shortening Services
    // ----------------------------------------------------
    if (UrlAnalyzer.SHORTENER_DOMAINS.has(hostname)) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'shortened_url',
        severity: 'low',
        title: 'URL Shortening Service Detected',
        description: `The link uses a URL shortener (${hostname}) which obscures the final destination.`,
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // ----------------------------------------------------
    // E. High-Risk / Abused TLDs
    // ----------------------------------------------------
    const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1] : '';
    if (UrlAnalyzer.SUSPICIOUS_TLDS.has(tld)) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'suspicious_domain',
        severity: 'medium',
        title: `Uncommon or High-Risk TLD (.${tld})`,
        description: `The top-level domain .${tld} has elevated statistical abuse rates. Note: this is a risk signal, not definitive proof of maliciousness.`,
        evidenceIds: [evidenceId],
        confidence: 'medium',
        metadata: { tld },
      });
    }

    // ----------------------------------------------------
    // F. Lookalike-Brand & Character Substitution Patterns
    // ----------------------------------------------------
    const lookalikeMatch = this.detectLookalikePattern(hostname, pathname);
    if (lookalikeMatch) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'lookalike_brand',
        severity: 'high',
        title: 'Possible Lookalike-Brand Pattern',
        description: `The domain or path contains character patterns ("${lookalikeMatch.pattern}") resembling known brand "${lookalikeMatch.brand}".`,
        evidenceIds: [evidenceId],
        confidence: 'high',
        metadata: { brand: lookalikeMatch.brand, pattern: lookalikeMatch.pattern },
      });
    } else {
      // Standard exact brand check on unofficial domains
      for (const brand of UrlAnalyzer.BRAND_KEYWORDS) {
        const brandInHost = hostname.includes(brand);
        const brandInPath = pathname.includes(`/${brand}`);
        if (brandInHost || brandInPath) {
          const isOfficial = hostname === `${brand}.com` || hostname.endsWith(`.${brand}.com`);
          if (!isOfficial) {
            findings.push({
              id: crypto.randomUUID(),
              type: 'lookalike_domain',
              severity: 'high',
              title: 'Possible Lookalike-Brand Pattern',
              description: `The URL references brand keyword "${brand}" on an unofficial domain or path.`,
              evidenceIds: [evidenceId],
              confidence: 'high',
              metadata: { brand, hostname },
            });
            break;
          }
        }
      }
    }

    // Punycode / IDN homograph check
    if (hostname.startsWith('xn--') || hostname.includes('.xn--')) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'lookalike_domain',
        severity: 'medium',
        title: 'Punycode / IDN Domain Detected',
        description: 'The domain uses Punycode character encoding (xn--). Lookalike Unicode characters can visually spoof legitimate domains.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // ----------------------------------------------------
    // G. Suspicious Keywords (login, verify, account, etc.)
    // ----------------------------------------------------
    const matchedKeywords: string[] = [];
    for (const kw of UrlAnalyzer.SUSPICIOUS_KEYWORDS) {
      if (pathname.includes(kw) || hostname.includes(kw)) {
        matchedKeywords.push(kw);
      }
    }
    if (matchedKeywords.length > 0) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'suspicious_keyword',
        severity: 'low',
        title: 'Security- or Account-Related Keywords Detected',
        description: `The URL contains keywords often targeted in authentication flows (${matchedKeywords.slice(0, 3).join(', ')}).`,
        evidenceIds: [evidenceId],
        confidence: 'medium',
        metadata: { keywords: matchedKeywords },
      });
    }

    // ----------------------------------------------------
    // H. Sensitive Query Values & Tokens
    // ----------------------------------------------------
    const searchLower = parsedUrl.search.toLowerCase();
    if (
      searchLower.includes('token=') ||
      searchLower.includes('password=') ||
      searchLower.includes('passwd=') ||
      searchLower.includes('pwd=') ||
      searchLower.includes('apikey=') ||
      searchLower.includes('api_key=') ||
      searchLower.includes('secret=') ||
      searchLower.includes('otp=') ||
      searchLower.includes('pin=')
    ) {
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
    // I. Excessive Encoding & Nested Redirect URLs
    // ----------------------------------------------------
    if (/%25|%20%20/i.test(parsedUrl.search) || /%25/i.test(parsedUrl.pathname)) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'excessive_encoding',
        severity: 'medium',
        title: 'Double or Excessive Percent Encoding',
        description: 'The URL contains repeated percent-encoding patterns, which can be used to evade simple pattern filters.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // Detect nested redirect targets (e.g. ?redirect=https://... or ?url=http://...)
    if (/(?:url|redirect|dest|target|next|return)=(?:https?%3a%2f%2f|https?:\/\/)/i.test(parsedUrl.search)) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'suspicious_redirect',
        severity: 'medium',
        title: 'Embedded Redirect Destination Parameter',
        description: 'The URL contains an open redirect destination parameter pointing to an external web location.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    const confidence: ConfidenceLevel = findings.length > 0 ? 'high' : 'medium';

    return {
      analyzerId: this.id,
      analyzerType: this.type,
      status: 'success',
      confidence,
      findings,
      evidence,
      limitations: [
        'The website was not visited or fetched.',
        'No external reputation database (e.g. Google Safe Browsing or VirusTotal) was queried in this phase.',
        'HTTPS presence indicates transport encryption only, not site safety or legitimacy.',
      ],
    };
  }

  /**
   * Helper detecting common typosquatting / character substitutions (0 -> o, 1 -> l/i, etc.)
   */
  private detectLookalikePattern(hostname: string, pathname: string): { brand: string; pattern: string } | null {
    const full = `${hostname}/${pathname}`.toLowerCase();

    // Map of common substitution patterns (e.g. paypa1 -> paypal, micros0ft -> microsoft)
    const normalized = full
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/5/g, 's')
      .replace(/vv/g, 'w');

    for (const brand of UrlAnalyzer.BRAND_KEYWORDS) {
      if (normalized.includes(brand)) {
        // If the brand is detected in normalized form, check if the original had a character substitution
        const brandL1 = brand.replace(/l/g, '1').replace(/o/g, '0');
        if (full.includes(brandL1) || full.includes(brand.replace(/l/g, '1')) || full.includes(brand.replace(/o/g, '0'))) {
          // It's a genuine substitution pattern
          const isOfficial = hostname === `${brand}.com` || hostname.endsWith(`.${brand}.com`);
          if (!isOfficial) {
            return { brand, pattern: brandL1 };
          }
        }
      }
    }

    return null;
  }
}
