/**
 * Finding Consolidator & Cross-Domain Correlator (Stage 8.2)
 *
 * Combines multiple observations of the same underlying entity/threat into a single
 * consolidated finding while preserving 100% of underlying evidence and source provenance.
 *
 * Invariants:
 * - Single scoring authority: RiskEngine is NOT modified or duplicated here.
 * - Deduplication removes duplicate presentation, NOT evidence.
 * - Zero fetch: No network requests, DNS queries, or outbound connections.
 * - Zero execution: No eval, new Function, child_process, or dynamic script execution.
 * - Untrusted data: Prompt injections inside findings remain strictly passive data.
 */

import crypto from 'crypto';
import {
  Finding,
  Evidence,
  FindingSeverity,
  ConfidenceLevel,
} from '../types';
import {
  UnifiedEvidenceDomain,
  SourceOriginType,
  SourceAttribution,
  ConsolidatedFinding,
  ConsolidationResult,
  ConsolidationOptions,
  UnifiedEvidence,
} from './types';
import {
  normalizeEvidence,
  deduplicateUnifiedEvidence,
  sanitizeAnySensitiveText,
  SEVERITY_SORT_PRIORITY,
  DOMAIN_SORT_PRIORITY,
} from './evidence-model';
import { UrlNormalizer } from '../url/normalizer';

// Conservative bounding caps
export const DEFAULT_MAX_FINDINGS = 50;
export const DEFAULT_MAX_EVIDENCE_PER_FINDING = 20;
export const DEFAULT_MAX_SOURCES_PER_FINDING = 10;
export const DEFAULT_MAX_CORRELATED_PER_FINDING = 10;

/**
 * Derives a canonical, normalized target entity key for a finding.
 * Uses existing UrlNormalizer for URLs to guarantee semantic identity.
 */
export function extractTargetEntity(finding: Finding): {
  targetEntity?: string;
  normalizedUrl?: string;
  hostname?: string;
} {
  const meta = finding.metadata || {};

  // 1. Direct URL in metadata
  const candidateUrl =
    (typeof meta.url === 'string' && meta.url) ||
    (typeof meta.displayUrl === 'string' && meta.displayUrl) ||
    (typeof meta.delegatedUrl === 'string' && meta.delegatedUrl) ||
    (typeof meta.rawPayload === 'string' && /^https?:\/\//i.test(meta.rawPayload) && meta.rawPayload) ||
    null;

  if (candidateUrl) {
    const norm = UrlNormalizer.normalize(candidateUrl);
    if (norm.isValid) {
      return {
        targetEntity: norm.normalizedUrl,
        normalizedUrl: norm.normalizedUrl,
        hostname: norm.hostname,
      };
    }
  }

  // 2. Direct hostname in metadata
  if (typeof meta.hostname === 'string' && meta.hostname) {
    const cleanHost = meta.hostname.toLowerCase().trim();
    return { targetEntity: cleanHost, hostname: cleanHost };
  }

  // 3. Secret class (CodeEngine)
  if (typeof meta.secretClass === 'string' && meta.secretClass) {
    return { targetEntity: meta.secretClass.toLowerCase() };
  }

  // 4. Vulnerability category (CodeEngine)
  if (typeof meta.vulnerabilityCategory === 'string' && meta.vulnerabilityCategory) {
    return { targetEntity: meta.vulnerabilityCategory.toLowerCase() };
  }

  // 5. Visual scam category (Stage 7.4)
  if (typeof meta.category === 'string' && meta.category) {
    return { targetEntity: meta.category.toLowerCase() };
  }

  // 6. Scam dedup group (Stage 6.2)
  if (typeof meta.dedupGroup === 'string' && meta.dedupGroup) {
    return { targetEntity: meta.dedupGroup.toLowerCase() };
  }

  // 7. Check if title contains an embedded URL
  const match = finding.title.match(/https?:\/\/[^\s<>"]+/i) || finding.description.match(/https?:\/\/[^\s<>"]+/i);
  if (match) {
    const norm = UrlNormalizer.normalize(match[0]);
    if (norm.isValid) {
      return {
        targetEntity: norm.normalizedUrl,
        normalizedUrl: norm.normalizedUrl,
        hostname: norm.hostname,
      };
    }
  }

  return {};
}

/**
 * Infers intelligence domain from a Finding's properties.
 */
export function inferFindingDomain(finding: Finding): UnifiedEvidenceDomain {
  const type = finding.type;
  const meta = finding.metadata || {};

  if (typeof meta.domain === 'string' && meta.domain in DOMAIN_SORT_PRIORITY) {
    return meta.domain as UnifiedEvidenceDomain;
  }
  if (type === 'suspicious_qr' || meta.isQr) return 'qr';
  if (type === 'exposed_secret' || meta.secretClass) return 'secret';
  if (type === 'suspicious_code' || type === 'sql_injection_pattern' || type === 'command_injection_pattern' || type === 'dangerous_function') return 'code';
  if (type === 'possible_ai_generated' || type === 'possible_manipulation' || type === 'metadata_anomaly') return 'authenticity';
  if (type === 'suspicious_attachment' || meta.isImage || meta.isScreenshot || meta.category === 'fake_banking' || meta.category === 'fake_courier') return 'image';
  if (
    type === 'suspicious_domain' ||
    type === 'lookalike_domain' ||
    type === 'lookalike_brand' ||
    type === 'host_confusion' ||
    type === 'private_network_host' ||
    type === 'excessive_subdomains' ||
    type === 'excessive_encoding' ||
    type === 'suspicious_redirect' ||
    type === 'insecure_protocol' ||
    type === 'ip_as_host' ||
    type === 'shortened_url' ||
    type === 'credential_in_url' ||
    type.startsWith('reputation_')
  ) {
    return 'url';
  }
  if (
    type === 'scam_indicator' ||
    type === 'urgency_language' ||
    type === 'threat_coercion' ||
    type === 'financial_request' ||
    type === 'prize_lure' ||
    type === 'otp_request' ||
    type === 'authority_impersonation' ||
    type === 'credential_request' ||
    type === 'job_scam' ||
    type === 'delivery_scam' ||
    type === 'social_engineering'
  ) {
    return 'scam';
  }

  return 'system';
}

/**
 * Infers source origin for a finding based on its metadata and evidence.
 */
export function inferFindingOrigin(finding: Finding, domain: UnifiedEvidenceDomain): SourceOriginType {
  const meta = finding.metadata || {};

  if (domain === 'qr' || meta.sourceContext === 'qr') return 'qr_code';
  if (meta.sourceContext === 'ocr' || meta.isOcr) return 'ocr_text';
  if (domain === 'code' || domain === 'secret' || meta.sourceContext === 'code') return 'code_block';
  if (domain === 'authenticity' || domain === 'image' || meta.sourceContext === 'attachment') return 'image_attachment';
  if (domain === 'url' && (meta.sourceContext === 'embedded_document_url' || meta.isEmbedded)) return 'embedded_url';
  if (domain === 'scam' || meta.sourceContext === 'conversation_turn' || meta.sourceContext === 'direct_prompt') return 'user_text';

  return 'system';
}

/**
 * Generates a stable deterministic finding ID.
 */
export function generateDeterministicFindingId(
  domain: UnifiedEvidenceDomain,
  type: string,
  targetKey: string
): string {
  const hash = crypto
    .createHash('sha256')
    .update(`${domain}:${type}:${targetKey}`)
    .digest('hex')
    .slice(0, 16);
  return `fnd_${domain}_${hash}`;
}

/**
 * Confidence ranking for deterministic comparison.
 */
const CONFIDENCE_RANK: Record<ConfidenceLevel, number> = {
  high: 0,
  medium: 1,
  low: 2,
};

/**
 * Finding Consolidator Engine.
 */
export class FindingConsolidator {
  /**
   * Consolidates an array of findings and evidence items into a deduplicated,
   * source-attributed representation with preserved cross-domain correlations.
   */
  static consolidate(
    findings: Finding[],
    evidence: (Evidence | UnifiedEvidence)[],
    options: ConsolidationOptions = {}
  ): ConsolidationResult {
    const maxFindings = options.maxFindings ?? DEFAULT_MAX_FINDINGS;
    const maxEvPerFinding = options.maxEvidencePerFinding ?? DEFAULT_MAX_EVIDENCE_PER_FINDING;
    const maxSourcesPerFinding = options.maxSourcesPerFinding ?? DEFAULT_MAX_SOURCES_PER_FINDING;
    const maxCorrelated = options.maxCorrelatedPerFinding ?? DEFAULT_MAX_CORRELATED_PER_FINDING;

    // 1. Normalize all input evidence into UnifiedEvidence
    const normalizedEvidenceList = deduplicateUnifiedEvidence(
      evidence.map(ev => normalizeEvidence(ev))
    );
    const evidenceById = new Map<string, UnifiedEvidence>();
    const domainsInvolvedSet = new Set<UnifiedEvidenceDomain>();
    for (const ev of normalizedEvidenceList) {
      evidenceById.set(ev.id, ev);
      domainsInvolvedSet.add(ev.domain);
    }

    // 2. Group findings by semantic identity key
    // Semantic key format: domain:type:canonicalEntity
    const groups = new Map<string, Finding[]>();

    for (const rawFinding of findings) {
      const domain = inferFindingDomain(rawFinding);
      const { targetEntity } = extractTargetEntity(rawFinding);
      const entityKey = targetEntity || rawFinding.title.toLowerCase().replace(/\s+/g, '_').slice(0, 80);
      const semanticKey = `${domain}:${rawFinding.type}:${entityKey}`;

      const list = groups.get(semanticKey) || [];
      list.push(rawFinding);
      groups.set(semanticKey, list);
    }

    // 3. Build ConsolidatedFinding for each group
    const consolidatedList: ConsolidatedFinding[] = [];

    for (const memberFindings of groups.values()) {
      const first = memberFindings[0];
      const domain = inferFindingDomain(first);
      domainsInvolvedSet.add(domain);
      const { targetEntity } = extractTargetEntity(first);

      // Resolve primary severity deterministically:
      // In accordance with conflict handling, select the highest severity among contributing findings.
      let primarySeverity: FindingSeverity = first.severity;
      let primaryConfidence: ConfidenceLevel = first.confidence;
      let primaryTitle = first.title;
      let primaryDescription = first.description;

      for (const m of memberFindings) {
        const currentRank = SEVERITY_SORT_PRIORITY[primarySeverity] ?? 99;
        const candidateRank = SEVERITY_SORT_PRIORITY[m.severity] ?? 99;
        if (candidateRank < currentRank) {
          primarySeverity = m.severity;
          primaryTitle = m.title;
          primaryDescription = m.description;
          primaryConfidence = m.confidence;
        } else if (candidateRank === currentRank) {
          // Break severity tie with confidence
          if ((CONFIDENCE_RANK[m.confidence] ?? 99) < (CONFIDENCE_RANK[primaryConfidence] ?? 99)) {
            primaryConfidence = m.confidence;
          }
        }
      }

      // Collect all evidence IDs across all members without loss
      const evidenceIdsSet = new Set<string>();
      for (const m of memberFindings) {
        if (Array.isArray(m.evidenceIds)) {
          for (const eid of m.evidenceIds) {
            evidenceIdsSet.add(eid);
          }
        }
      }

      // Link evidence items that match this targetEntity or domain
      if (targetEntity) {
        for (const ev of normalizedEvidenceList) {
          if (ev.sanitizedValue && ev.sanitizedValue.includes(targetEntity)) {
            evidenceIdsSet.add(ev.id);
          }
        }
      }

      // Collect all source attributions
      const sourceMap = new Map<string, SourceAttribution>();
      for (const m of memberFindings) {
        const origin = inferFindingOrigin(m, domain);
        const key = `${origin}:${domain}`;
        if (!sourceMap.has(key)) {
          sourceMap.set(key, {
            origin,
            domain,
            analyzerId: typeof m.metadata?.analyzerId === 'string' ? m.metadata.analyzerId : undefined,
            attachmentName: typeof m.metadata?.attachmentName === 'string' ? m.metadata.attachmentName : undefined,
          });
        }
      }

      // Also inherit source attributions from linked evidence
      for (const eid of evidenceIdsSet) {
        const ev = evidenceById.get(eid);
        if (ev && ev.source) {
          const key = `${ev.source.origin}:${ev.domain}`;
          if (!sourceMap.has(key)) {
            sourceMap.set(key, ev.source);
          }
        }
      }

      // Deterministic finding ID
      const targetKey = targetEntity || first.title.toLowerCase().replace(/\s+/g, '_').slice(0, 80);
      const deterministicId = generateDeterministicFindingId(domain, first.type, targetKey);

      // Sanitize title and description (untrusted text boundary)
      const sanitizedTitle = sanitizeAnySensitiveText(primaryTitle).sanitized.slice(0, 150);
      const sanitizedDesc = sanitizeAnySensitiveText(primaryDescription).sanitized.slice(0, 500);

      // Preserve full contributing findings data in metadata for zero-loss auditability
      const contributingFindingsData = memberFindings.map(mf => ({
        id: mf.id,
        severity: mf.severity,
        confidence: mf.confidence,
        title: sanitizeAnySensitiveText(mf.title).sanitized,
        evidenceCount: mf.evidenceIds?.length || 0,
      }));

      const consolidated: ConsolidatedFinding = {
        id: deterministicId,
        type: first.type,
        severity: primarySeverity,
        confidence: primaryConfidence,
        title: sanitizedTitle,
        description: sanitizedDesc,
        domain,
        targetEntity,
        sources: Array.from(sourceMap.values()).slice(0, maxSourcesPerFinding),
        evidenceIds: Array.from(evidenceIdsSet).slice(0, maxEvPerFinding),
        observationCount: memberFindings.length,
        metadata: {
          ...first.metadata,
          targetEntity,
          observationCount: memberFindings.length,
          contributingFindings: contributingFindingsData,
        },
      };

      consolidatedList.push(consolidated);
    }

    // 4. Cross-Domain Correlation (Cluster Detection)
    // Conservative, explainable linking between distinct findings
    for (let i = 0; i < consolidatedList.length; i++) {
      for (let j = i + 1; j < consolidatedList.length; j++) {
        const a = consolidatedList[i];
        const b = consolidatedList[j];

        let correlationTag: string | undefined;

        // A. Shared URL Target Correlation (e.g. QR finding and URL finding pointing to same destination)
        if (
          a.targetEntity &&
          b.targetEntity &&
          (a.targetEntity === b.targetEntity ||
           (a.metadata?.hostname && b.metadata?.hostname && a.metadata.hostname === b.metadata.hostname))
        ) {
          if (a.domain === 'qr' || b.domain === 'qr') {
            correlationTag = 'quishing_url_match';
          } else {
            correlationTag = 'shared_target_url';
          }
        }

        // B. Visual Scam + Phishing / Credential Solicitation
        if (!correlationTag) {
          const isVisualScam = a.domain === 'image' || a.type === 'scam_indicator';
          const isPhishOrCredential =
            b.domain === 'url' ||
            b.type === 'otp_request' ||
            b.type === 'credential_request' ||
            b.type === 'financial_request';

          const isVisualScamB = b.domain === 'image' || b.type === 'scam_indicator';
          const isPhishOrCredentialA =
            a.domain === 'url' ||
            a.type === 'otp_request' ||
            a.type === 'credential_request' ||
            a.type === 'financial_request';

          if ((isVisualScam && isPhishOrCredential) || (isVisualScamB && isPhishOrCredentialA)) {
            // Only link if at least one is high or critical
            const hasSevereA = a.severity === 'high' || a.severity === 'critical';
            const hasSevereB = b.severity === 'high' || b.severity === 'critical';
            if (hasSevereA || hasSevereB) {
              correlationTag = 'visual_social_engineering_campaign';
            }
          }
        }

        // C. Code Vulnerability + Secret Co-occurrence
        if (!correlationTag) {
          if (
            (a.domain === 'code' && b.domain === 'secret') ||
            (a.domain === 'secret' && b.domain === 'code')
          ) {
            correlationTag = 'vulnerability_secret_cooccurrence';
          }
        }

        // Apply correlation links symmetrically if detected
        if (correlationTag) {
          a.correlatedFindingIds = a.correlatedFindingIds || [];
          b.correlatedFindingIds = b.correlatedFindingIds || [];

          if (!a.correlatedFindingIds.includes(b.id) && a.correlatedFindingIds.length < maxCorrelated) {
            a.correlatedFindingIds.push(b.id);
            a.correlationTag = a.correlationTag || correlationTag;
          }
          if (!b.correlatedFindingIds.includes(a.id) && b.correlatedFindingIds.length < maxCorrelated) {
            b.correlatedFindingIds.push(a.id);
            b.correlationTag = b.correlationTag || correlationTag;
          }
        }
      }
    }

    // 5. Deterministic Output Sorting:
    // 1) Severity priority (critical > high > medium > low > info)
    // 2) Domain priority (qr > url > secret > code > scam > ocr > authenticity > image > system)
    // 3) Observation count descending
    // 4) Deterministic ID ascending
    const sortedFindings = [...consolidatedList].sort((a, b) => {
      const sevA = SEVERITY_SORT_PRIORITY[a.severity] ?? 99;
      const sevB = SEVERITY_SORT_PRIORITY[b.severity] ?? 99;
      if (sevA !== sevB) return sevA - sevB;

      const domA = DOMAIN_SORT_PRIORITY[a.domain] ?? 99;
      const domB = DOMAIN_SORT_PRIORITY[b.domain] ?? 99;
      if (domA !== domB) return domA - domB;

      if (b.observationCount !== a.observationCount) {
        return b.observationCount - a.observationCount;
      }

      return a.id.localeCompare(b.id);
    });

    const finalFindings = sortedFindings.slice(0, maxFindings);

    // 6. Update evidence items with reverse links to consolidated finding IDs
    for (const f of finalFindings) {
      for (const eid of f.evidenceIds) {
        const ev = evidenceById.get(eid);
        if (ev) {
          const links = ev.relatedFindingIds || [];
          if (!links.includes(f.id)) {
            ev.relatedFindingIds = [...links, f.id];
          }
        }
      }
    }

    return {
      consolidatedFindings: finalFindings,
      consolidatedEvidence: normalizedEvidenceList,
      domainsInvolved: Array.from(domainsInvolvedSet),
      totalRawObservations: findings.length,
      totalConsolidatedFindings: finalFindings.length,
    };
  }
}
