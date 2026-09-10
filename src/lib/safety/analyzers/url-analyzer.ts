import crypto from 'crypto';
import { SafetyAnalyzer } from './base';
import {
  SafetyInput,
  AnalyzerResult,
  Finding,
  Evidence,
  ConfidenceLevel,
} from '../types';

/**
 * Deterministic URL and Link Analyzer.
 * Analyzes structure, protocol, domain characteristics, punycode, shortening, and query anomalies.
 */
export class UrlAnalyzer implements SafetyAnalyzer {
  readonly id = 'url-analyzer';
  readonly type = 'url' as const;
  readonly supportedInputTypes = ['url', 'website', 'qr'] as const;

  // Known high-risk / abused TLDs (heuristic signal, not definitive proof)
  private static SUSPICIOUS_TLDS = new Set([
    'zip', 'mov', 'top', 'xyz', 'country', 'kim', 'work', 'gq', 'cf', 'tk', 'ml', 'ga', 'buzz',
  ]);

  // Common URL shortening domains
  private static SHORTENER_DOMAINS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly', 'rebrand.ly',
  ]);

  // Major brand targets for lookalike impersonation heuristics
  private static BRAND_KEYWORDS = [
    'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'facebook', 'instagram', 'whatsapp', 'chase', 'bankofamerica', 'wellsfargo',
  ];

  canAnalyze(input: SafetyInput): boolean {
    if (input.type && (this.supportedInputTypes as readonly string[]).includes(input.type)) {
      return true;
    }
    // Also accept if content starts with http or looks like a URL
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
        limitations: ['URL could not be parsed into valid components; full domain checks skipped.'],
      };
    }

    const evidenceId = crypto.randomUUID();
    evidence.push({
      id: evidenceId,
      sourceType: 'url_analysis',
      sourceName: 'Deterministic URL Parser',
      description: 'Extracted URL components and metadata',
      data: {
        protocol: parsedUrl.protocol,
        hostname: parsedUrl.hostname,
        pathname: parsedUrl.pathname,
        search: parsedUrl.search,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? '443' : '80'),
      },
      isAiGenerated: false,
      createdAt: new Date().toISOString(),
    });

    const hostname = parsedUrl.hostname.toLowerCase();

    // 1. Protocol check (Insecure HTTP)
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
    }

    // 2. IP Address used directly as hostname
    const isIpv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    if (isIpv4) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'ip_as_host',
        severity: 'high',
        title: 'Direct IP Address Hostname',
        description: 'The URL uses a raw IP address instead of a registered domain name. This is frequently used to bypass domain reputation filters.',
        evidenceIds: [evidenceId],
        confidence: 'high',
        metadata: { ip: hostname },
      });
    }

    // 3. Shortened URL Detection
    if (UrlAnalyzer.SHORTENER_DOMAINS.has(hostname)) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'shortened_url',
        severity: 'medium',
        title: 'URL Shortening Service Detected',
        description: `The link uses a URL shortener (${hostname}) which obscures the ultimate destination.`,
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // 4. Suspicious or abusive TLD
    const parts = hostname.split('.');
    const tld = parts.length > 1 ? parts[parts.length - 1] : '';
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

    // 5. Lookalike / Brand Impersonation in subdomain or path
    for (const brand of UrlAnalyzer.BRAND_KEYWORDS) {
      const brandInHost = hostname.includes(brand);
      const brandInPath = parsedUrl.pathname.toLowerCase().includes(brand);
      if (brandInHost || brandInPath) {
        const isOfficial = hostname === `${brand}.com` || hostname.endsWith(`.${brand}.com`);
        if (!isOfficial) {
          findings.push({
            id: crypto.randomUUID(),
            type: 'lookalike_domain',
            severity: 'high',
            title: `Potential Brand Impersonation (${brand})`,
            description: `The URL references brand keyword "${brand}" on an unofficial host or path.`,
            evidenceIds: [evidenceId],
            confidence: 'high',
            metadata: { brand, hostname },
          });
        }
      }
    }

    // 6. Punycode / Internationalized Domain Name (IDN) homograph hint
    if (hostname.startsWith('xn--') || hostname.includes('.xn--')) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'lookalike_domain',
        severity: 'medium',
        title: 'Punycode / IDN Domain Detected',
        description: 'The domain uses Punycode character encoding (xn--). Attackers often use lookalike Unicode characters to spoof legitimate brand domains.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // 7. Sensitive credentials/tokens in query string
    const search = parsedUrl.search.toLowerCase();
    if (
      search.includes('token=') ||
      search.includes('password=') ||
      search.includes('passwd=') ||
      search.includes('apikey=') ||
      search.includes('secret=')
    ) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'credential_in_url',
        severity: 'high',
        title: 'Sensitive Credential or Token in URL Query',
        description: 'The URL includes authentication tokens or passwords in plain text query parameters.',
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
        'Domain reputation, DNS resolution, and live destination redirects were not contacted to protect user privacy.',
        'HTTPS presence indicates transport encryption only, not site safety or legitimacy.',
      ],
    };
  }
}
