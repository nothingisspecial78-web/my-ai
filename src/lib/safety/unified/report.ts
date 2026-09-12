/**
 * Unified Security Report Layer (Stage 8.3)
 *
 * Constructs a comprehensive, source-attributed, and privacy-guaranteed security report
 * from consolidated findings and normalized evidence.
 *
 * Invariants:
 * - Single scoring authority: RiskEngine is the sole authority for risk score and level.
 *   This module performs ZERO score calculations, weighted averages, or score adjustments.
 * - Epistemic humility: Absences of indicators are never claimed as absolute safety or authenticity.
 * - Zero fetch: No network requests, DNS queries, or outbound connections.
 * - Zero execution: No eval, new Function, child_process, or dynamic script execution.
 * - Untrusted data: Prompt injections inside text, code, or images remain inert strings.
 */

import crypto from 'crypto';
import type {
  SafetyInputType,
  AnalysisStatus,
  Recommendation,
  AnalyzerResult,
  Finding,
  Evidence,
  SafetyReport,
} from '../types';
import type {
  UnifiedSecurityReport,
  ConsolidatedFinding,
  UnifiedEvidenceDomain,
  PrivacyTag,
  BuildReportOptions,
} from './types';
import { FindingConsolidator } from './consolidator';
import {
  toStandardEvidence,
  normalizeEvidence,
  sanitizeAnySensitiveText,
  scrubPrivacyDataRecord,
} from './evidence-model';
import { RiskEngine } from '../risk-engine';

// Strict caps for bounded presentation
export const MAX_REPORT_RECOMMENDATIONS = 10;
export const MAX_REPORT_SUMMARIES = 10;
export const MAX_REPORT_CORRELATIONS = 10;
export const MAX_AFFECTED_ENTITIES = 20;
export const MAX_REPORT_ANALYZER_RESULTS = 10;
export const MAX_REPORT_LIMITATIONS = 15;
export const MAX_REPORT_FINDINGS = 50;
export const MAX_REPORT_EVIDENCE = 50;

/**
 * Sanitizes an AnalyzerResult using existing Stage 8.1 redaction utilities.
 * Guarantees that raw secrets, Wi-Fi credentials, OTPAuth tokens, and sensitive metadata
 * cannot escape via report.analyzerResults or toSafetyReport().
 */
export function sanitizeAnalyzerResult(res: AnalyzerResult): AnalyzerResult {
  return {
    analyzerId: res.analyzerId,
    analyzerType: res.analyzerType,
    status: res.status,
    confidence: res.confidence,
    findings: (res.findings || []).slice(0, 20).map(f => ({
      id: f.id,
      type: f.type,
      severity: f.severity,
      confidence: f.confidence,
      title: sanitizeAnySensitiveText(f.title).sanitized.slice(0, 150),
      description: sanitizeAnySensitiveText(f.description).sanitized.slice(0, 500),
      evidenceIds: f.evidenceIds,
      metadata: f.metadata && typeof f.metadata === 'object'
        ? scrubPrivacyDataRecord(f.metadata as Record<string, unknown>).sanitizedData
        : f.metadata,
    })),
    evidence: (res.evidence || []).slice(0, 20).map(e => toStandardEvidence(normalizeEvidence(e))),
    metadata: res.metadata && typeof res.metadata === 'object'
      ? scrubPrivacyDataRecord(res.metadata as Record<string, unknown>).sanitizedData
      : res.metadata,
    limitations: res.limitations
      ? res.limitations.slice(0, 10).map(l => sanitizeAnySensitiveText(l).sanitized.slice(0, 200))
      : undefined,
    error: res.error ? sanitizeAnySensitiveText(res.error).sanitized.slice(0, 200) : undefined,
  };
}

/**
 * Human-readable intelligence domain names.
 */
export const DOMAIN_DISPLAY_NAMES: Record<UnifiedEvidenceDomain, string> = {
  qr: 'QR Code & Quishing Intelligence',
  url: 'URL Structure & Threat Reputation Intelligence',
  scam: 'Social Engineering & Scam Message Intelligence',
  code: 'Static Code Security & Vulnerability Analysis',
  secret: 'Credential & Secret Leak Detection',
  ocr: 'Visual Text & OCR Extraction',
  image: 'Visual Scam & Screenshot Layout Analysis',
  authenticity: 'Visual Media Authenticity & Manipulation Heuristics',
  privacy: 'Privacy & Sensitive Data Sanitization',
  system: 'System & Architecture Analysis',
};

/**
 * Generates a stable deterministic report ID based on inputs.
 * Avoids Math.random() and timestamps so identical inputs yield identical IDs.
 */
export function generateDeterministicReportId(
  inputType: SafetyInputType,
  findings: Finding[],
  evidence: Evidence[]
): string {
  const findingKeys = findings.map(f => `${f.type}:${f.title}`).sort().join('|');
  const evidenceKeys = evidence.map(e => `${e.sourceType}:${e.description.slice(0, 50)}`).sort().join('|');
  const hash = crypto
    .createHash('sha256')
    .update(`${inputType}:${findingKeys}:${evidenceKeys}`)
    .digest('hex')
    .slice(0, 16);
  return `rep_${hash}`;
}

/**
 * Deterministically derives the Primary Security Concern in plain language.
 * Never makes absolute claims ('definitely', '100%') and respects authenticity uncertainty.
 */
export function derivePrimarySecurityConcern(
  findings: ConsolidatedFinding[],
  score: number,
  domainsInvolved: UnifiedEvidenceDomain[]
): string {
  // Case 1: Clean report
  if (findings.length === 0 || score === 0) {
    if (domainsInvolved.includes('authenticity')) {
      return 'No suspicious security indicators identified; authenticity remains unverified from available evidence.';
    }
    return 'No significant security threats or malicious indicators detected.';
  }

  // Findings are sorted by severity descending; inspect the highest priority finding
  const top = findings[0];

  // Domain-specific primary concern mapping
  switch (top.domain) {
    case 'qr':
      if (top.correlationTag === 'quishing_url_match' || top.type === 'shortened_url') {
        return 'Potentially malicious QR code directing to a suspicious or obfuscated destination.';
      }
      if (top.type === 'private_network_host') {
        return 'QR code points to a restricted internal or private network host.';
      }
      return 'Suspicious QR code target identified requiring caution before accessing.';

    case 'url':
      if (top.type === 'reputation_malicious') {
        return 'Known malicious destination flagged by threat intelligence feeds.';
      }
      if (top.type === 'lookalike_domain' || top.type === 'lookalike_brand') {
        return 'Lookalike domain observed mimicking an established organization.';
      }
      if (top.type === 'private_network_host') {
        return 'Target URL addresses a private network or internal system.';
      }
      return 'Suspicious web destination exhibiting deceptive or high-risk characteristics.';

    case 'secret':
      return 'Exposed credential or sensitive API token detected in inspected content.';

    case 'code':
      if (top.type === 'sql_injection_pattern' || top.type === 'command_injection_pattern') {
        return 'Code contains potential injection vulnerability patterns.';
      }
      return 'Code contains suspicious execution patterns or potential security risks.';

    case 'scam':
      if (top.type === 'otp_request' || top.type === 'credential_request') {
        return 'Message uses high-pressure urgency cues to request sensitive verification credentials.';
      }
      if (top.type === 'financial_request' || top.type === 'prize_lure') {
        return 'Message exhibits patterns consistent with financial deception or advance-fee fraud.';
      }
      return 'Communication exhibits social engineering or deceptive manipulation patterns.';

    case 'image':
      if (top.metadata?.category === 'fake_banking') {
        return 'Screenshot visually resembles a banking interface requiring verification.';
      }
      if (top.metadata?.category === 'fake_courier') {
        return 'Screenshot visually resembles an urgent parcel delivery alert requiring caution.';
      }
      return 'Visual media exhibits deceptive layout patterns or suspicious interface cues.';

    case 'authenticity':
      if (top.type === 'possible_ai_generated') {
        return 'Visual characteristics are consistent with synthetic media generation heuristics.';
      }
      if (top.type === 'possible_manipulation') {
        return 'Visual markers indicate possible image manipulation or composite artifacts.';
      }
      return 'Image metadata or structural characteristics indicate potential anomalies.';

    default:
      if (top.severity === 'critical') {
        return 'High-risk security anomaly identified requiring immediate caution.';
      }
      if (top.severity === 'high') {
        return 'Potential security threat identified requiring verification.';
      }
      return 'Suspicious security indicator detected; exercise caution.';
  }
}

/**
 * Builds human-readable correlation summaries from consolidated findings.
 */
export function buildCorrelationSummaries(findings: ConsolidatedFinding[]): string[] {
  const summaries = new Set<string>();

  for (const f of findings) {
    if (f.correlationTag === 'quishing_url_match') {
      summaries.add('QR code payload and extracted URL point to the same destination, linking physical and web threat vectors.');
    } else if (f.correlationTag === 'visual_social_engineering_campaign') {
      summaries.add('Visual interface impersonation aligns with urgent credential solicitation, indicating a coordinated phishing scenario.');
    } else if (f.correlationTag === 'vulnerability_secret_cooccurrence') {
      summaries.add('Vulnerability patterns co-occur alongside exposed credentials in the same source context.');
    } else if (f.correlationTag === 'shared_target_url' || (f.observationCount > 1 && f.targetEntity)) {
      summaries.add(`Target entity (${f.targetEntity}) was independently confirmed across multiple extraction sources.`);
    }
  }

  return Array.from(summaries).slice(0, MAX_REPORT_CORRELATIONS);
}

/**
 * Consolidates and deduplicates recommendations across analyzers and RiskEngine.
 */
export function consolidateRecommendations(
  recommendations: Recommendation[],
  findings: ConsolidatedFinding[]
): Recommendation[] {
  const seenActions = new Set<string>();
  const seenTitles = new Set<string>();
  const result: Recommendation[] = [];

  // Determine top severity to guide priority
  const hasCritical = findings.some(f => f.severity === 'critical');
  const hasHigh = findings.some(f => f.severity === 'high');

  for (const rec of recommendations) {
    const normTitle = rec.title.toLowerCase().trim();
    if (seenActions.has(rec.action) || seenTitles.has(normTitle)) {
      continue;
    }

    seenActions.add(rec.action);
    seenTitles.add(normTitle);

    // Sanitize title and description to prevent leaks
    const cleanTitle = sanitizeAnySensitiveText(rec.title).sanitized.slice(0, 100);
    const cleanDesc = sanitizeAnySensitiveText(rec.description).sanitized.slice(0, 300);

    // Prioritize critical threat actions
    let priority = rec.priority;
    if (hasCritical && (rec.action === 'do_not_click' || rec.action === 'do_not_share_otp' || rec.action === 'rotate_exposed_secret')) {
      priority = 'high';
    } else if (hasHigh && priority === 'low') {
      priority = 'medium';
    }

    result.push({
      action: rec.action,
      title: cleanTitle,
      description: cleanDesc,
      priority,
    });

    if (result.length >= MAX_REPORT_RECOMMENDATIONS) break;
  }

  // Ensure an actionable recommendation always exists
  if (result.length === 0) {
    if (findings.length === 0) {
      result.push({
        action: 'no_action_needed',
        title: 'No Action Required',
        description: 'No threat indicators were detected in the analyzed submission.',
        priority: 'low',
      });
    } else {
      result.push({
        action: 'proceed_with_caution',
        title: 'Exercise General Caution',
        description: 'Verify unfamiliar destinations and do not submit confidential information.',
        priority: hasCritical || hasHigh ? 'high' : 'medium',
      });
    }
  }

  return result;
}

/**
 * Derives executive narrative summary.
 */
export function deriveReportSummary(
  findings: ConsolidatedFinding[],
  score: number,
  primaryConcern: string,
  domainsInvolved: UnifiedEvidenceDomain[]
): string {
  if (findings.length === 0 || score === 0) {
    return primaryConcern;
  }

  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const mediumCount = findings.filter(f => f.severity === 'medium').length;

  const severityDesc = criticalCount > 0
    ? 'CRITICAL'
    : highCount > 0
    ? 'HIGH'
    : mediumCount > 0
    ? 'MEDIUM'
    : 'LOW';

  const domainStr = domainsInvolved.map(d => DOMAIN_DISPLAY_NAMES[d] || d).slice(0, 3).join(', ');

  return `Identified ${findings.length} technical finding${findings.length === 1 ? '' : 's'} with ${severityDesc} severity across ${domainStr}. Primary concern: ${primaryConcern}`;
}

/**
 * Unified Report Builder.
 */
export class UnifiedReportBuilder {
  /**
   * Builds an authoritative, consolidated UnifiedSecurityReport.
   */
  static build(options: BuildReportOptions): UnifiedSecurityReport {
    const inputType = options.inputType || 'message';
    const rawFindings = options.findings || [];
    const rawEvidence = options.evidence || [];
    const inputAnalyzerResults = options.analyzerResults || [];
    const analyzerResults = inputAnalyzerResults
      .slice(0, MAX_REPORT_ANALYZER_RESULTS)
      .map(sanitizeAnalyzerResult);
    const status: AnalysisStatus = options.status || (rawFindings.length > 0 || analyzerResults.length > 0 ? 'completed' : 'completed');

    // 1. Consolidate findings and evidence via Stage 8.2 FindingConsolidator
    const consolidation = FindingConsolidator.consolidate(rawFindings, rawEvidence);
    const consolidatedFindings = consolidation.consolidatedFindings.slice(0, MAX_REPORT_FINDINGS);
    const consolidatedEvidence = consolidation.consolidatedEvidence.slice(0, MAX_REPORT_EVIDENCE);
    const domainsInvolved = consolidation.domainsInvolved;

    // 2. Authoritative Risk Evaluation: RiskEngine is the SINGLE authority
    // Pass consolidated findings and analyzer results to RiskEngine.evaluate()
    const riskEval = RiskEngine.evaluate(consolidatedFindings, analyzerResults);

    // Invariants: Score and RiskLevel MUST come directly from RiskEngine
    const score = riskEval.score;
    const riskLevel = riskEval.riskLevel;
    const confidenceLevel = riskEval.confidenceLevel;

    // 3. Collect and consolidate limitations
    const limitationsSet = new Set<string>(riskEval.limitations);
    if (options.limitations) {
      options.limitations.forEach(l => limitationsSet.add(l));
    }
    // Universal authenticity boundary disclaimer if visual authenticity domain participated
    if (domainsInvolved.includes('authenticity')) {
      limitationsSet.add(
        'Automated authenticity checks evaluate observable visual heuristics. Absence of manipulation signals is not proof of authenticity.'
      );
    }
    const limitations = Array.from(limitationsSet).slice(0, MAX_REPORT_LIMITATIONS);

    // 4. Primary Security Concern
    const primaryConcern = derivePrimarySecurityConcern(consolidatedFindings, score, domainsInvolved);

    // 5. Correlation Summaries
    const correlationSummaries = buildCorrelationSummaries(consolidatedFindings);

    // 6. Analyzer Summaries
    const analyzerSummaries = domainsInvolved
      .map(d => DOMAIN_DISPLAY_NAMES[d])
      .filter(Boolean)
      .slice(0, MAX_REPORT_SUMMARIES);

    // 7. Affected Entities (Deduplicated targets like URLs, hostnames, secret classes)
    const entitySet = new Set<string>();
    for (const f of consolidatedFindings) {
      if (f.targetEntity) entitySet.add(f.targetEntity);
    }
    const affectedEntities = Array.from(entitySet).slice(0, MAX_AFFECTED_ENTITIES);

    // 8. Privacy Guarantees (Union of all privacy tags applied to evidence and findings)
    const privacyTagsSet = new Set<PrivacyTag>();
    for (const ev of consolidatedEvidence) {
      ev.privacyTags.forEach(tag => privacyTagsSet.add(tag));
    }
    for (const f of rawFindings) {
      const { detectedTags: tTags } = sanitizeAnySensitiveText(f.title);
      const { detectedTags: dTags } = sanitizeAnySensitiveText(f.description);
      tTags.forEach(tag => privacyTagsSet.add(tag));
      dTags.forEach(tag => privacyTagsSet.add(tag));
      if (f.metadata && typeof f.metadata === 'object') {
        const { detectedTags: mTags } = scrubPrivacyDataRecord(f.metadata as Record<string, unknown>);
        mTags.forEach(tag => privacyTagsSet.add(tag));
        for (const val of Object.values(f.metadata)) {
          if (typeof val === 'string') {
            const { detectedTags: sTags } = sanitizeAnySensitiveText(val);
            sTags.forEach(tag => privacyTagsSet.add(tag));
          }
        }
      }
    }
    for (const f of consolidatedFindings) {
      const { detectedTags: tTags } = sanitizeAnySensitiveText(f.title);
      const { detectedTags: dTags } = sanitizeAnySensitiveText(f.description);
      tTags.forEach(tag => privacyTagsSet.add(tag));
      dTags.forEach(tag => privacyTagsSet.add(tag));
    }
    for (const ar of inputAnalyzerResults) {
      if (ar.findings) {
        for (const f of ar.findings) {
          const { detectedTags: tTags } = sanitizeAnySensitiveText(f.title);
          const { detectedTags: dTags } = sanitizeAnySensitiveText(f.description);
          tTags.forEach(tag => privacyTagsSet.add(tag));
          dTags.forEach(tag => privacyTagsSet.add(tag));
        }
      }
    }
    const privacyGuarantees = Array.from(privacyTagsSet);

    // 9. Recommendations Consolidation
    const allRecommendations = [...(riskEval.recommendations || [])];
    const recommendations = consolidateRecommendations(allRecommendations, consolidatedFindings);

    // 10. Summary
    const summary = deriveReportSummary(consolidatedFindings, score, primaryConcern, domainsInvolved);

    // 11. Deterministic Report ID
    const reportId = generateDeterministicReportId(
      inputType,
      consolidatedFindings,
      consolidatedEvidence
    );

    const createdAt = options.createdAt || new Date().toISOString();

    // 12. Construct the UnifiedSecurityReport instance
    const report: UnifiedSecurityReport = {
      id: reportId,
      inputType,
      status,
      riskLevel,
      score,
      confidenceLevel,
      primaryConcern,
      summary,
      findings: consolidatedFindings,
      evidence: consolidatedEvidence,
      recommendations,
      limitations,
      domainsInvolved,
      analyzerSummaries,
      correlationSummaries,
      affectedEntities,
      privacyGuarantees,
      analyzerResults,
      createdAt,

      /**
       * Backward-compatible export to standard SafetyReport.
       */
      toSafetyReport(): SafetyReport {
        return {
          analysisId: this.id,
          inputType: this.inputType,
          status: this.status,
          riskLevel: this.riskLevel,
          confidenceLevel: this.confidenceLevel,
          score: this.score,
          summary: this.summary,
          findings: this.findings.map(f => ({
            id: f.id,
            type: f.type,
            severity: f.severity,
            title: f.title,
            description: f.description,
            evidenceIds: f.evidenceIds,
            confidence: f.confidence,
            metadata: f.metadata,
          })),
          evidence: this.evidence.map(e => toStandardEvidence(e)),
          recommendations: this.recommendations,
          limitations: this.limitations,
          analyzerResults: this.analyzerResults,
          createdAt: this.createdAt,
        };
      },
    };

    return report;
  }
}
