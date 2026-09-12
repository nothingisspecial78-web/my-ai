/**
 * Unified Evidence Model & Normalization Engine (Stage 8.1)
 *
 * Implements deterministic evidence normalization, cross-domain source attribution,
 * length-bounding, privacy redaction verification, and deterministic sorting.
 *
 * Invariants:
 * - Single scoring authority: RiskEngine is NOT modified or duplicated here.
 * - Untrusted data: OCR text, QR payloads, and user strings are strictly sanitized as inert data.
 * - Zero fetch: No network requests, DNS queries, or outbound connections.
 * - Zero execution: No eval, new Function, child_process, or dynamic script execution.
 */

import crypto from 'crypto';
import {
  Evidence,
  EvidenceSourceType,
  FindingSeverity,
  ConfidenceLevel,
} from '../types';
import {
  UnifiedEvidenceDomain,
  SourceOriginType,
  SourceAttribution,
  PrivacyTag,
  UnifiedEvidence,
  NormalizationOptions,
} from './types';
import {
  redactSensitiveText,
  redactDataRecord,
} from '../redaction';

// Default truncation limits
export const DEFAULT_MAX_SNIPPET_LENGTH = 200;
export const DEFAULT_MAX_DESCRIPTION_LENGTH = 500;
export const DEFAULT_MAX_VALUE_LENGTH = 300;
export const DEFAULT_MAX_DATA_KEYS = 30;

/**
 * Domain priority for deterministic cross-domain sorting.
 * Critical threat vector carriers (QR/URL/Secret/Code) take precedence, followed by
 * content analysis (Scam/OCR/Authenticity/Image), and finally system/privacy.
 */
export const DOMAIN_SORT_PRIORITY: Record<UnifiedEvidenceDomain, number> = {
  qr: 0,
  url: 1,
  secret: 2,
  code: 3,
  scam: 4,
  ocr: 5,
  authenticity: 6,
  image: 7,
  privacy: 8,
  system: 9,
};

/**
 * FindingSeverity priority for deterministic sorting.
 */
export const SEVERITY_SORT_PRIORITY: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * Source origin priority for deterministic sorting.
 */
export const ORIGIN_SORT_PRIORITY: Record<SourceOriginType, number> = {
  qr_code: 0,
  embedded_url: 1,
  code_block: 2,
  ocr_text: 3,
  image_attachment: 4,
  file_attachment: 5,
  user_text: 6,
  metadata: 7,
  system: 8,
};

/**
 * Redacts Wi-Fi payloads ensuring P: (password) is thoroughly stripped.
 */
export function sanitizeWifiPayload(payload: string): string {
  if (!payload || typeof payload !== 'string') return '';
  return payload.replace(/(P:)([^;]*)(;|$)/gi, '$1[REDACTED_PASSWORD]$3');
}

/**
 * Redacts OTPAuth URI secrets.
 */
export function sanitizeOtpauthPayload(payload: string): string {
  if (!payload || typeof payload !== 'string') return '';
  return payload.replace(/([?&]secret=)([^&]+)/gi, '$1[REDACTED_SECRET]');
}

/**
 * Sanitizes any freeform text string and detects privacy redaction tags.
 */
export function sanitizeAnySensitiveText(rawText: string): {
  sanitized: string;
  detectedTags: PrivacyTag[];
} {
  if (!rawText || typeof rawText !== 'string') {
    return { sanitized: '', detectedTags: [] };
  }

  const tags = new Set<PrivacyTag>();

  // Pre-redaction pattern detection
  if (/\b(?:\d{4}[-\s]?){3}\d{4}\b/.test(rawText)) {
    tags.add('redacted_credit_card');
  }
  if (/(?:WIFI:|\bP:)[^;]*;P:[^;]*/i.test(rawText) || (/WIFI:[^;\s]+/i.test(rawText) && /P:[^;\s]+/i.test(rawText))) {
    tags.add('redacted_wifi_credentials');
  }
  if (/otpauth:\/\/[^\s]+[?&]secret=/i.test(rawText) || /[?&]secret=[a-zA-Z0-9]{8,}/i.test(rawText)) {
    tags.add('redacted_otpauth_secret');
  }

  // 1. Standard safety redaction (URLs, tokens, passwords, OTPs, keys, DB URIs)
  let sanitized = redactSensitiveText(rawText);

  // 2. Wi-Fi redaction
  if (/WIFI:/i.test(sanitized) && /P:/i.test(sanitized)) {
    sanitized = sanitizeWifiPayload(sanitized);
    tags.add('redacted_wifi_credentials');
  }

  // 3. OTPAuth redaction
  if (/otpauth:\/\//i.test(sanitized) || /[?&]secret=/i.test(sanitized)) {
    sanitized = sanitizeOtpauthPayload(sanitized);
    tags.add('redacted_otpauth_secret');
  }

  // Detect remaining masks in post-sanitized text
  detectPrivacyTagsInString(sanitized, tags);

  return {
    sanitized,
    detectedTags: Array.from(tags),
  };
}

/**
 * Removes GPS coordinates and device identifiers from data dictionaries.
 */
export function scrubPrivacyDataRecord(data: Record<string, unknown>): {
  sanitizedData: Record<string, unknown>;
  detectedTags: PrivacyTag[];
} {
  const detectedTags = new Set<PrivacyTag>();
  const sanitized = redactDataRecord(data) as Record<string, unknown>;

  const cleanObject = (obj: Record<string, unknown>, depth = 0): Record<string, unknown> => {
    if (depth > 4 || !obj || typeof obj !== 'object') return obj;
    const result: Record<string, unknown> = {};
    let keyCount = 0;

    for (const [k, v] of Object.entries(obj)) {
      if (keyCount++ >= DEFAULT_MAX_DATA_KEYS) break;
      const lowerKey = k.toLowerCase();

      // Check GPS fields
      if (
        lowerKey === 'latitude' ||
        lowerKey === 'longitude' ||
        lowerKey === 'gpslatitude' ||
        lowerKey === 'gpslongitude' ||
        lowerKey === 'altitude' ||
        lowerKey === 'coordinates' ||
        lowerKey === 'gps'
      ) {
        detectedTags.add('redacted_gps_coordinates');
        result[k] = '[REDACTED_GPS]';
        continue;
      }

      // Check Device identifier fields
      if (
        lowerKey === 'deviceid' ||
        lowerKey === 'imei' ||
        lowerKey === 'macaddress' ||
        lowerKey === 'serialnumber' ||
        lowerKey === 'udid' ||
        lowerKey === 'advertisingid'
      ) {
        detectedTags.add('redacted_device_id');
        result[k] = '[REDACTED_DEVICE_ID]';
        continue;
      }

      if (v && typeof v === 'object' && !Array.isArray(v)) {
        result[k] = cleanObject(v as Record<string, unknown>, depth + 1);
      } else if (typeof v === 'string') {
        const { sanitized: cleanStr, detectedTags: strTags } = sanitizeAnySensitiveText(v);
        strTags.forEach(t => detectedTags.add(t));
        result[k] = cleanStr;
      } else {
        result[k] = v;
      }
    }
    return result;
  };

  const finalData = cleanObject(sanitized);
  return {
    sanitizedData: finalData,
    detectedTags: Array.from(detectedTags),
  };
}

/**
 * Scans a string for recognized redaction masks and tags them.
 */
function detectPrivacyTagsInString(str: string, tags: Set<PrivacyTag>): void {
  if (!str) return;
  if (str.includes('[REDACTED_AWS_KEY]') || str.includes('[REDACTED_GOOGLE_KEY]') ||
      str.includes('[REDACTED_OPENAI_KEY]') || str.includes('[REDACTED_ANTHROPIC_KEY]') ||
      str.includes('[REDACTED_STRIPE_KEY]') || str.includes('api_key=[REDACTED]')) {
    tags.add('redacted_api_key');
  }
  if (str.includes('[REDACTED_GITHUB_TOKEN]') || str.includes('[REDACTED_SLACK_TOKEN]') ||
      str.includes('[REDACTED_BEARER_TOKEN]') || str.includes('[REDACTED_JWT_TOKEN]') ||
      str.includes('[REDACTED_DISCORD_WEBHOOK]')) {
    tags.add('redacted_auth_token');
  }
  if (str.includes('[REDACTED_PASSWORD]') || str.includes('password=[REDACTED]') ||
      str.includes('pwd=[REDACTED]') || str.includes('password is [REDACTED]')) {
    tags.add('redacted_password');
  }
  if (str.includes('[REDACTED_OTP]') || /otps*[:=is-]*s*[REDACTED]/i.test(str)) {
    tags.add('redacted_otp');
  }
  if (str.includes('[REDACTED_PRIVATE_KEY]') || str.includes('[REDACTED_KEY]')) {
    tags.add('redacted_private_key');
  }
  if (str.includes('[REDACTED_SECRET]') || str.includes('secret=[REDACTED]')) {
    tags.add('redacted_otpauth_secret');
  }
  if (str.includes('[REDACTED_GPS]')) {
    tags.add('redacted_gps_coordinates');
  }
  if (str.includes('[REDACTED_DEVICE_ID]')) {
    tags.add('redacted_device_id');
  }
  if (str.includes('token=[REDACTED]') || str.includes('auth_token=[REDACTED]')) {
    tags.add('redacted_url_params');
  }
  if (str.includes('[REDACTED_PASSWORD]@')) {
    tags.add('redacted_db_uri');
  }
  if (/phrases*[:=is-]+s*[REDACTED]/i.test(str)) {
    tags.add('redacted_seed_phrase');
  }
}

/**
 * Generates a stable deterministic evidence ID.
 */
export function generateDeterministicEvidenceId(
  domain: UnifiedEvidenceDomain,
  origin: SourceOriginType,
  category: string,
  entropyKey: string
): string {
  const hash = crypto
    .createHash('sha256')
    .update(`${domain}:${origin}:${category}:${entropyKey}`)
    .digest('hex')
    .slice(0, 16);
  return `ev_${domain}_${hash}`;
}

/**
 * Maps a domain to standard existing EvidenceSourceType.
 */
export function mapDomainToEvidenceSourceType(
  domain: UnifiedEvidenceDomain,
  isAiGenerated = false
): EvidenceSourceType {
  switch (domain) {
    case 'url':
      return 'url_analysis';
    case 'scam':
      return 'content_analysis';
    case 'code':
    case 'secret':
      return 'deterministic_rule';
    case 'image':
    case 'authenticity':
    case 'qr':
      return 'image_analysis';
    case 'ocr':
      return isAiGenerated ? 'ai_assessment' : 'image_analysis';
    case 'privacy':
      return 'metadata';
    case 'system':
      return 'metadata';
    default:
      return 'deterministic_rule';
  }
}

/**
 * Infers domain from existing Evidence item if not explicitly supplied.
 */
export function inferDomainFromEvidence(evidence: Partial<Evidence>): UnifiedEvidenceDomain {
  const sourceName = typeof evidence?.sourceName === 'string' ? evidence.sourceName.toLowerCase() : '';
  const label = typeof evidence?.label === 'string' ? evidence.label.toLowerCase() : '';
  const desc = typeof evidence?.description === 'string' ? evidence.description.toLowerCase() : '';
  const combined = `${sourceName} ${label} ${desc}`;

  if (combined.includes('qr') || combined.includes('quishing')) return 'qr';
  if (combined.includes('ocr') || combined.includes('visual text')) return 'ocr';
  if (combined.includes('authenticity') || combined.includes('manipulation') || combined.includes('synthetic')) return 'authenticity';
  if (combined.includes('secret') || combined.includes('credential') || combined.includes('api key')) return 'secret';
  if (combined.includes('code') || combined.includes('ast') || combined.includes('script') || combined.includes('vulnerability')) return 'code';
  if (combined.includes('url') || combined.includes('reputation') || combined.includes('safebrowsing') || combined.includes('urlhaus')) return 'url';
  if (combined.includes('scam') || combined.includes('social engineering') || combined.includes('phishing')) return 'scam';
  if (combined.includes('image') || combined.includes('dimension') || combined.includes('metadata')) return 'image';
  if (combined.includes('privacy') || combined.includes('redaction')) return 'privacy';

  return 'system';
}

/**
 * Infers origin from existing Evidence item if not explicitly supplied.
 */
export function inferOriginFromEvidence(
  evidence: Partial<Evidence>,
  domain: UnifiedEvidenceDomain
): SourceOriginType {
  const sourceName = typeof evidence?.sourceName === 'string' ? evidence.sourceName.toLowerCase() : '';

  if (domain === 'qr' || sourceName.includes('qr')) return 'qr_code';
  if (domain === 'ocr' || sourceName.includes('ocr')) return 'ocr_text';
  if (domain === 'url') return 'embedded_url';
  if (domain === 'authenticity' || domain === 'image') return 'image_attachment';
  if (domain === 'scam') return 'user_text';

  return 'system';
}

/**
 * Normalizes an arbitrary Evidence item into a validated, bounded UnifiedEvidence.
 */
export function normalizeEvidence(
  raw: unknown,
  options: NormalizationOptions = {}
): UnifiedEvidence {
  const maxSnippetLen = options.maxSnippetLength ?? DEFAULT_MAX_SNIPPET_LENGTH;
  const maxDescLen = options.maxDescriptionLength ?? DEFAULT_MAX_DESCRIPTION_LENGTH;

  // Safe fallback if raw is null/undefined/primitive
  const base = (raw && typeof raw === 'object' ? raw : {}) as Partial<Evidence> & Record<string, unknown>;

  // 1. Resolve Domain
  const domain: UnifiedEvidenceDomain =
    options.domain ||
    (typeof base.domain === 'string' && base.domain in DOMAIN_SORT_PRIORITY ? (base.domain as UnifiedEvidenceDomain) : null) ||
    inferDomainFromEvidence(base);

  // 2. Resolve Origin
  const origin: SourceOriginType =
    options.origin ||
    (base.source && typeof (base.source as SourceAttribution).origin === 'string' ? (base.source as SourceAttribution).origin : null) ||
    inferOriginFromEvidence(base, domain);

  // 3. Resolve Category
  const category =
    options.category ||
    (typeof base.category === 'string' ? base.category : null) ||
    (typeof base.label === 'string' ? base.label.toLowerCase().replace(/\s+/g, '_') : 'general');

  // 4. Sanitize Description & Snippet
  const rawDescription = typeof base.description === 'string' ? base.description : (typeof base.label === 'string' ? base.label : 'Security evidence');
  const { sanitized: sanitizedDescStr, detectedTags: descTags } = sanitizeAnySensitiveText(rawDescription);
  let sanitizedDescription = sanitizedDescStr;
  if (sanitizedDescription.length > maxDescLen) {
    sanitizedDescription = sanitizedDescription.slice(0, maxDescLen - 3) + '...';
  }

  const rawSnippet = typeof base.snippet === 'string' ? base.snippet : undefined;
  let sanitizedSnippet: string | undefined;
  const snippetTags: PrivacyTag[] = [];
  if (rawSnippet) {
    const { sanitized: cleanSnip, detectedTags } = sanitizeAnySensitiveText(rawSnippet);
    sanitizedSnippet = cleanSnip;
    if (sanitizedSnippet.length > maxSnippetLen) {
      sanitizedSnippet = sanitizedSnippet.slice(0, maxSnippetLen - 3) + '...';
    }
    detectedTags.forEach(t => snippetTags.push(t));
  }

  // 5. Sanitize Value if present
  let sanitizedValue: string | undefined;
  if (typeof base.sanitizedValue === 'string') {
    sanitizedValue = sanitizeAnySensitiveText(base.sanitizedValue).sanitized.slice(0, DEFAULT_MAX_VALUE_LENGTH);
  } else if (rawSnippet) {
    sanitizedValue = sanitizedSnippet;
  }

  // 6. Deep sanitize data record and collect privacy tags
  const rawData = (base.data && typeof base.data === 'object' && !Array.isArray(base.data))
    ? (base.data as Record<string, unknown>)
    : {};
  const { sanitizedData, detectedTags: dataTags } = scrubPrivacyDataRecord(rawData);

  const tagsSet = new Set<PrivacyTag>([...descTags, ...snippetTags, ...dataTags]);

  // 7. Resolve ID (deterministic)
  const entropyKey = sanitizedValue || sanitizedSnippet || sanitizedDescription.slice(0, 100);
  const id =
    typeof base.id === 'string' && base.id.trim().length > 0
      ? base.id
      : generateDeterministicEvidenceId(domain, origin, category, entropyKey);

  // 8. Build Source Attribution
  const baseSource = (base.source && typeof base.source === 'object' ? base.source : null) as Partial<SourceAttribution> | null;
  const sourceAttribution: SourceAttribution = {
    origin,
    domain,
    analyzerId:
      options.analyzerId ||
      baseSource?.analyzerId ||
      (typeof base.sourceName === 'string' ? base.sourceName : undefined),
    attachmentName: options.attachmentName || baseSource?.attachmentName,
    attachmentId: options.attachmentId || baseSource?.attachmentId,
    lineRange: options.lineRange || baseSource?.lineRange,
    snippet: sanitizedSnippet,
  };

  const sourceType = base.sourceType || mapDomainToEvidenceSourceType(domain, !!base.isAiGenerated);
  const sourceName = typeof base.sourceName === 'string' ? base.sourceName : `Unified ${domain.toUpperCase()} Engine`;
  const createdAt = typeof base.createdAt === 'string' ? base.createdAt : new Date().toISOString();

  const relatedFindingIds = options.relatedFindingIds ||
    (Array.isArray(base.relatedFindingIds) ? (base.relatedFindingIds as string[]) : undefined);

  const relatedEntity = options.relatedEntity ||
    (typeof base.relatedEntity === 'string' ? base.relatedEntity : undefined);

  return {
    id,
    sourceType,
    sourceName,
    label: typeof base.label === 'string' ? base.label : category.replace(/_/g, ' ').toUpperCase(),
    snippet: sanitizedSnippet,
    description: sanitizedDescription,
    data: sanitizedData,
    isAiGenerated: !!base.isAiGenerated,
    createdAt,
    domain,
    source: sourceAttribution,
    category,
    severity: options.severity || (base.severity as FindingSeverity) || undefined,
    confidence: options.confidence || (base.confidence as ConfidenceLevel) || undefined,
    sanitizedValue,
    privacyTags: Array.from(tagsSet),
    relatedFindingIds,
    relatedEntity,
  };
}

/**
 * Normalizes an array of Evidence items.
 */
export function normalizeEvidenceList(
  rawList: unknown[],
  options: NormalizationOptions = {}
): UnifiedEvidence[] {
  if (!Array.isArray(rawList)) return [];
  return rawList.map(raw => normalizeEvidence(raw, options));
}

/**
 * Sorts unified evidence deterministically based on domain, severity, origin, and ID.
 */
export function sortUnifiedEvidence(evidenceList: UnifiedEvidence[]): UnifiedEvidence[] {
  return [...evidenceList].sort((a, b) => {
    // 1. Domain priority
    const domainA = DOMAIN_SORT_PRIORITY[a.domain] ?? 99;
    const domainB = DOMAIN_SORT_PRIORITY[b.domain] ?? 99;
    if (domainA !== domainB) return domainA - domainB;

    // 2. Severity priority
    const sevA = a.severity ? (SEVERITY_SORT_PRIORITY[a.severity] ?? 99) : 99;
    const sevB = b.severity ? (SEVERITY_SORT_PRIORITY[b.severity] ?? 99) : 99;
    if (sevA !== sevB) return sevA - sevB;

    // 3. Origin priority
    const originA = ORIGIN_SORT_PRIORITY[a.source.origin] ?? 99;
    const originB = ORIGIN_SORT_PRIORITY[b.source.origin] ?? 99;
    if (originA !== originB) return originA - originB;

    // 4. Deterministic ID
    return a.id.localeCompare(b.id);
  });
}

/**
 * Merges duplicate evidence items observing the exact same entity and domain.
 * Combines privacy tags, merges finding IDs, and retains the highest severity.
 */
export function deduplicateUnifiedEvidence(evidenceList: UnifiedEvidence[]): UnifiedEvidence[] {
  const map = new Map<string, UnifiedEvidence>();

  for (const item of evidenceList) {
    const dedupKey = `${item.domain}:${item.category}:${item.sanitizedValue || item.snippet || item.id}`;
    const existing = map.get(dedupKey);

    if (!existing) {
      map.set(dedupKey, { ...item });
      continue;
    }

    // Merge tags
    const combinedTags = new Set<PrivacyTag>([...existing.privacyTags, ...item.privacyTags]);
    existing.privacyTags = Array.from(combinedTags);

    // Merge related findings
    if (item.relatedFindingIds && item.relatedFindingIds.length > 0) {
      const combinedFindings = new Set<string>([
        ...(existing.relatedFindingIds || []),
        ...item.relatedFindingIds,
      ]);
      existing.relatedFindingIds = Array.from(combinedFindings);
    }

    // Promote higher severity if newer item is more severe
    if (item.severity) {
      const currentSevScore = existing.severity ? (SEVERITY_SORT_PRIORITY[existing.severity] ?? 99) : 99;
      const newSevScore = SEVERITY_SORT_PRIORITY[item.severity] ?? 99;
      if (newSevScore < currentSevScore) {
        existing.severity = item.severity;
      }
    }
  }

  return sortUnifiedEvidence(Array.from(map.values()));
}

/**
 * Converts UnifiedEvidence back to standard backwards-compatible Evidence.
 */
export function toStandardEvidence(unified: UnifiedEvidence): Evidence {
  return {
    id: unified.id,
    sourceType: unified.sourceType,
    sourceName: unified.sourceName,
    label: unified.label,
    snippet: unified.snippet,
    description: unified.description,
    data: unified.data,
    isAiGenerated: unified.isAiGenerated,
    createdAt: unified.createdAt,
  };
}
