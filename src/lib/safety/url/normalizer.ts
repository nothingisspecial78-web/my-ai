/**
 * URL Normalizer & Canonicalization Layer (Phase 6.1)
 * 
 * Safely parses, validates, and normalizes user-submitted URLs.
 * Enforces scheme whitelisting, SSRF protection, embedded credential detection,
 * tracking artifact removal, and privacy redaction.
 */

import crypto from 'crypto';
import { checkHostForSsrf, SsrfCheckResult } from './ssrf';
import { redactUrl } from '../redaction';

export interface NormalizedUrlResult {
  isValid: boolean;
  rawInput: string;
  normalizedUrl: string;       // Canonical representation for local inspection
  providerLookupUrl: string;   // Cleaned URL strictly safe for external reputation APIs (NO credentials!)
  displayUrl: string;          // Safe URL for user interface display (redacted credentials)
  cacheKey: string;            // Deterministic SHA-256 cache key (derived from providerLookupUrl)
  protocol: 'http:' | 'https:';
  hostname: string;            // Lowercased, stripped trailing dot
  punycodeHostname?: string;   // Original punycode if IDN
  port: string;                // Non-standard port if present
  pathname: string;            // Normalized path
  search: string;              // Canonical query string (sorted, tracking stripped)
  hasCredentials: boolean;     // Explicit flag for userinfo presence
  credentialsInfo?: {
    hasUsername: boolean;
    hasPassword: boolean;
    rawUsername?: string;
  };
  isIpAddress: boolean;
  ssrf: SsrfCheckResult;
  error?: string;
}

// Supported URL schemes for inspection
const SUPPORTED_SCHEMES = new Set(['http:', 'https:']);

// Unsupported or dangerous schemes that must be strictly rejected
const REJECTED_SCHEMES = new Set([
  'javascript:',
  'data:',
  'file:',
  'blob:',
  'ftp:',
  'ftps:',
  'ws:',
  'wss:',
  'vbscript:',
  'about:',
  'chrome:',
  'edge:',
]);

// Maximum allowable input lengths for DoS defense
export const MAX_URL_LENGTH = 4096;
export const MAX_HOSTNAME_LENGTH = 253;

export class UrlNormalizer {
  /**
   * Normalizes and validates a candidate URL string.
   */
  static normalize(rawInput: string): NormalizedUrlResult {
    const trimmed = (rawInput || '').trim();

    if (!trimmed) {
      return this.createInvalidResult(trimmed, 'Empty or missing URL string.');
    }

    // Guard against excessive input length (DoS protection)
    if (trimmed.length > MAX_URL_LENGTH) {
      return this.createInvalidResult(
        trimmed.slice(0, 100) + '...',
        `URL exceeds maximum permissible length of ${MAX_URL_LENGTH} characters.`
      );
    }

    // 1. Pre-check for explicit dangerous/unsupported schemes
    const lowerInput = trimmed.toLowerCase();
    for (const scheme of REJECTED_SCHEMES) {
      if (lowerInput.startsWith(scheme)) {
        return this.createInvalidResult(
          trimmed,
          `Unsupported or hazardous URL scheme: "${scheme.replace(':', '')}". Only HTTP and HTTPS URLs are accepted.`
        );
      }
    }

    // 2. Add default https:// scheme if missing, or extract embedded URL if wrapped in natural query
    let parseableUrl = trimmed;
    const urlMatch = trimmed.match(/(https?:\/\/[^\s<>"]+|www\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}[^\s<>"]*)/i);
    if (urlMatch && !/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(trimmed)) {
      parseableUrl = urlMatch[0];
    }

    const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(parseableUrl);

    if (!hasScheme) {
      // Check for malformed scheme attempts (e.g. "http:/example.com" or "http:///example.com")
      if (/^[a-zA-Z]+:\/+/i.test(parseableUrl)) {
        return this.createInvalidResult(trimmed, 'Malformed scheme separator in URL.');
      }
      parseableUrl = `https://${parseableUrl}`;
    }

    // 3. Parse with standard URL parser
    let parsed: URL;
    try {
      parsed = new URL(parseableUrl);
    } catch {
      return this.createInvalidResult(trimmed, 'Malformed URL syntax. Could not parse standard URL components.');
    }

    // 4. Validate scheme whitelist
    const protocol = parsed.protocol.toLowerCase() as 'http:' | 'https:';
    if (!SUPPORTED_SCHEMES.has(protocol)) {
      return this.createInvalidResult(
        trimmed,
        `Unsupported scheme "${parsed.protocol}". Only HTTP and HTTPS are permitted.`
      );
    }

    // 5. Embedded credentials detection (USER REFINEMENT 1)
    // Inspect the authority component specifically to prevent false positives from '@' in query or fragment.
    const schemeIndex = parseableUrl.indexOf('://');
    const authority = schemeIndex !== -1
      ? parseableUrl.slice(schemeIndex + 3).split(/[/?#]/)[0] || ''
      : '';
    const hasAtInAuthority = authority.includes('@');
    const hasUsername = Boolean(parsed.username);
    const hasPassword = Boolean(parsed.password);
    const hasCredentials = hasUsername || hasPassword || hasAtInAuthority;

    const credentialsInfo = hasCredentials
      ? {
          hasUsername,
          hasPassword,
          rawUsername: hasUsername ? parsed.username : undefined,
        }
      : undefined;

    // 6. Hostname normalization
    let hostname = parsed.hostname.toLowerCase();
    // Strip trailing dot (DNS root notation, e.g. "example.com." -> "example.com")
    if (hostname.endsWith('.')) {
      hostname = hostname.slice(0, -1);
    }

    if (!hostname) {
      return this.createInvalidResult(trimmed, 'Missing or empty hostname in URL.');
    }

    if (hostname.length > MAX_HOSTNAME_LENGTH) {
      return this.createInvalidResult(
        trimmed,
        `Hostname exceeds maximum permissible length of ${MAX_HOSTNAME_LENGTH} characters.`
      );
    }

    // Punycode detection
    const isPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');

    // 7. SSRF and private IP inspection
    const ssrf = checkHostForSsrf(hostname);

    // 8. Port normalization (standard ports 80/443 omitted)
    let port = parsed.port;
    if ((protocol === 'http:' && port === '80') || (protocol === 'https:' && port === '443')) {
      port = '';
    }

    // 9. Semantic Path & Query Preservation:
    // Retain exact pathname (case-sensitive, trailing slash) and query string.
    // Do NOT strip tracking parameters because doing so can cause threat-feed lookup misses on feeds that index the full campaign URL.
    const pathname = parsed.pathname || '/';
    const search = parsed.search || '';
    const portStr = port ? `:${port}` : '';

    // A. Canonical Normalized URL (for structural analysis)
    const normalizedUrl = `${protocol}//${hostname}${portStr}${pathname}${search}`;

    // B. Provider Lookup URL (strictly stripped of embedded credentials to never leak secrets to external APIs)
    const providerLookupUrl = `${protocol}//${hostname}${portStr}${pathname}${search}`;

    // C. Display URL (safely redacted credentials for UI presentation)
    const displayUrl = redactUrl(
      hasCredentials
        ? `${protocol}//${parsed.username ? parsed.username : 'user'}:${parsed.password ? '[REDACTED]' : ''}@${hostname}${portStr}${pathname}${search}`
        : normalizedUrl
    );

    // D. Cache Key derived strictly from providerLookupUrl
    const hash = crypto.createHash('sha256').update(providerLookupUrl).digest('hex');
    const cacheKey = `rep:urlintel:${hash}`;

    const isIpAddress = Boolean(ssrf.parsedIp);

    return {
      isValid: true,
      rawInput: trimmed,
      normalizedUrl,
      providerLookupUrl,
      displayUrl,
      cacheKey,
      protocol,
      hostname,
      punycodeHostname: isPunycode ? hostname : undefined,
      port,
      pathname,
      search,
      hasCredentials,
      credentialsInfo,
      isIpAddress,
      ssrf,
    };
  }

  private static createInvalidResult(rawInput: string, error: string): NormalizedUrlResult {
    return {
      isValid: false,
      rawInput,
      normalizedUrl: '',
      providerLookupUrl: '',
      displayUrl: rawInput,
      cacheKey: '',
      protocol: 'https:',
      hostname: '',
      port: '',
      pathname: '',
      search: '',
      hasCredentials: false,
      isIpAddress: false,
      ssrf: {
        isBlocked: true,
        isPrivateOrLocal: false,
        isCloudMetadata: false,
        isLoopback: false,
        reason: error,
      },
      error,
    };
  }
}
