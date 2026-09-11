/**
 * Reputation Aggregation Layer
 * 
 * Synthesizes reputation outputs from multiple providers into a coherent,
 * balanced assessment. Handles provider conflict resolution, consensus scoring,
 * limitation tracking, and evidence linkage for the deterministic Risk Engine.
 */

import crypto from 'crypto';
import { ConfidenceLevel, Evidence, Finding } from '../types';
import {
  AggregatedReputationResult,
  ProviderReputationResult,
  ReputationDetectionStatus,
  ReputationLookupOptions,
  ReputationProvider,
} from './types';

// Scoring weights for detection statuses
const DETECTION_WEIGHTS: Record<ReputationDetectionStatus, number> = {
  malicious: 1.0,
  suspicious: 0.5,
  unknown: 0.0,
  clean: -1.0,
  unavailable: 0.0,
};

// Confidence multipliers
const CONFIDENCE_MULTIPLIERS: Record<ConfidenceLevel, number> = {
  high: 1.0,
  medium: 0.7,
  low: 0.4,
};

export class ReputationAggregator {
  /**
   * Concurrently queries all supplied providers and aggregates their results.
   * Tolerates timeouts, network errors, and individual provider outages.
   */
  static async lookupAndAggregate(
    url: string,
    providers: ReputationProvider[],
    options?: ReputationLookupOptions
  ): Promise<AggregatedReputationResult> {
    if (!providers || providers.length === 0) {
      return this.aggregate(url, []);
    }

    const promises = providers.map(p =>
      p.lookupUrl(url, options).catch(err => {
        // Absolute fallback if a provider throws an unhandled rejection
        const fallbackResult: ProviderReputationResult = {
          providerId: p.id,
          providerName: p.name,
          url,
          status: 'unavailable',
          detectionStatus: 'unavailable',
          confidence: 'low',
          timestamp: new Date().toISOString(),
          latencyMs: 0,
          cached: false,
          error: {
            code: 'provider_unavailable',
            message: err instanceof Error ? err.message : 'Unhandled lookup exception',
          },
          evidence: {
            id: crypto.randomUUID(),
            sourceType: 'reputation_provider',
            sourceName: p.name,
            label: `${p.name} Fallback`,
            description: 'Provider threw an unhandled error.',
            data: {},
            isAiGenerated: false,
            createdAt: new Date().toISOString(),
          },
        };
        return fallbackResult;
      })
    );

    const settled = await Promise.all(promises);
    return this.aggregate(url, settled);
  }

  /**
   * Deterministically aggregates an array of provider reputation results.
   */
  static aggregate(
    url: string,
    providerResults: ProviderReputationResult[]
  ): AggregatedReputationResult {
    const limitations: string[] = [];
    const allEvidence: Evidence[] = [];
    const findings: Finding[] = [];

    // Collect all evidence items from results
    for (const res of providerResults) {
      if (res.evidence) {
        allEvidence.push(res.evidence);
      }
    }

    // Filter available operational results
    const availableResults = providerResults.filter(
      r => r.detectionStatus !== 'unavailable'
    );
    const unavailableResults = providerResults.filter(
      r => r.detectionStatus === 'unavailable'
    );

    // Track unavailable provider limitations
    for (const un of unavailableResults) {
      const reason = un.error?.message || un.error?.code || 'offline';
      limitations.push(
        `Reputation provider "${un.providerName}" was unavailable (${reason}).`
      );
    }

    // Case 1: No providers configured or all providers unavailable
    if (availableResults.length === 0) {
      limitations.push(
        'No external reputation intelligence was available. Analysis relies on deterministic pattern checks.'
      );
      return {
        url,
        aggregateStatus: 'unavailable',
        confidence: 'low',
        consensusScore: 0,
        disputed: false,
        providerResults,
        findings: [],
        evidence: allEvidence,
        limitations,
        summary:
          providerResults.length > 0
            ? 'All reputation providers were unavailable or timed out.'
            : 'No external reputation providers configured.',
      };
    }

    // Calculate consensus metrics
    let weightedScoreSum = 0;
    let weightSum = 0;
    let maliciousCount = 0;
    let suspiciousCount = 0;
    let cleanCount = 0;
    let unknownCount = 0;

    for (const r of availableResults) {
      const statusWeight = DETECTION_WEIGHTS[r.detectionStatus];
      const confMultiplier = CONFIDENCE_MULTIPLIERS[r.confidence];
      const effectiveWeight = confMultiplier;

      weightedScoreSum += statusWeight * effectiveWeight;
      weightSum += effectiveWeight;

      if (r.detectionStatus === 'malicious') maliciousCount++;
      if (r.detectionStatus === 'suspicious') suspiciousCount++;
      if (r.detectionStatus === 'clean') cleanCount++;
      if (r.detectionStatus === 'unknown') unknownCount++;
    }

    // Explicitly document partial provider coverage
    if (unknownCount > 0 && (maliciousCount > 0 || cleanCount > 0 || suspiciousCount > 0)) {
      limitations.push(
        `${unknownCount} provider(s) had no recorded telemetry for this URL (partial coverage).`
      );
    }
    if (unavailableResults.length > 0 && availableResults.length > 0) {
      limitations.push(
        'Reputation assessment is based on partial provider coverage due to unavailable vendor(s).'
      );
    }

    const consensusScore = weightSum > 0 ? weightedScoreSum / weightSum : 0;

    // Detect Conflict / Disagreement
    // Provider A says malicious, Provider B says clean
    const hasDispute = maliciousCount > 0 && cleanCount > 0;

    let aggregateStatus: ReputationDetectionStatus = 'unknown';
    let confidence: ConfidenceLevel = 'medium';

    if (hasDispute) {
      // Direct disagreement: Do NOT blindly declare malicious!
      // Treat as disputed / suspicious and downgrade confidence
      aggregateStatus = 'suspicious';
      confidence = 'medium';

      limitations.push(
        'Reputation providers disagree on the safety of this URL. Findings reflect a disputed status.'
      );

      const evidenceIds = availableResults.map(r => r.evidence.id);

      findings.push({
        id: crypto.randomUUID(),
        type: 'reputation_disputed',
        severity: 'medium',
        title: 'Disputed URL Reputation',
        description: `External reputation providers returned conflicting verdicts (${maliciousCount} malicious vs ${cleanCount} clean). Further verification is strongly recommended.`,
        confidence: 'medium',
        evidenceIds,
        metadata: {
          maliciousCount,
          cleanCount,
          suspiciousCount,
          consensusScore: Math.round(consensusScore * 100) / 100,
        },
      });
    } else if (maliciousCount > 0) {
      // Consensus malicious (no clean counter-reports)
      aggregateStatus = 'malicious';
      confidence = availableResults.some(r => r.detectionStatus === 'malicious' && r.confidence === 'high')
        ? 'high'
        : 'medium';

      const maliciousEvidenceIds = availableResults
        .filter(r => r.detectionStatus === 'malicious')
        .map(r => r.evidence.id);

      // Collect threat categories
      const threatCategories = new Set<string>();
      for (const r of availableResults) {
        if (r.threatCategories) {
          r.threatCategories.forEach(c => threatCategories.add(c));
        }
      }

      findings.push({
        id: crypto.randomUUID(),
        type: 'reputation_malicious',
        severity: 'high',
        title: 'Known Malicious URL Reported',
        description: `Flagged as malicious by threat intelligence (${Array.from(threatCategories).join(', ') || 'malware/phishing'}).`,
        confidence,
        evidenceIds: maliciousEvidenceIds,
        metadata: {
          maliciousCount,
          threatCategories: Array.from(threatCategories),
          consensusScore: Math.round(consensusScore * 100) / 100,
        },
      });
    } else if (suspiciousCount > 0 && cleanCount > 0) {
      // Disagreement between suspicious and clean providers
      if (cleanCount > suspiciousCount && consensusScore <= -0.2) {
        // Clean majority outweighs minority suspicious signal
        aggregateStatus = 'clean';
        confidence = 'medium'; // Capped due to presence of suspicious indicator

        const cleanEvidenceIds = availableResults
          .filter(r => r.detectionStatus === 'clean')
          .map(r => r.evidence.id);

        findings.push({
          id: crypto.randomUUID(),
          type: 'reputation_clean',
          severity: 'info',
          title: 'Clean Reputation Across Majority of Providers',
          description: `Rated clean by ${cleanCount} provider(s), with ${suspiciousCount} provider(s) reporting suspicious telemetry.`,
          confidence: 'medium',
          evidenceIds: cleanEvidenceIds,
          metadata: {
            cleanCount,
            suspiciousCount,
            consensusScore: Math.round(consensusScore * 100) / 100,
          },
        });

        limitations.push(
          `${suspiciousCount} provider(s) reported suspicious indicators while ${cleanCount} provider(s) rated the URL clean.`
        );
      } else {
        // Suspicious outweighs or balances clean
        aggregateStatus = 'suspicious';
        confidence = 'medium';

        const suspiciousEvidenceIds = availableResults
          .filter(r => r.detectionStatus === 'suspicious')
          .map(r => r.evidence.id);

        findings.push({
          id: crypto.randomUUID(),
          type: 'reputation_suspicious',
          severity: 'medium',
          title: 'Suspicious Reputation Indicators Detected',
          description: `Threat intelligence providers reported suspicious indicators (${suspiciousCount} suspicious vs ${cleanCount} clean).`,
          confidence: 'medium',
          evidenceIds: suspiciousEvidenceIds,
          metadata: {
            cleanCount,
            suspiciousCount,
            consensusScore: Math.round(consensusScore * 100) / 100,
          },
        });
      }
    } else if (suspiciousCount > 0) {
      // Suspicious consensus without clean counter-reports
      aggregateStatus = 'suspicious';
      confidence = 'medium';

      const suspiciousEvidenceIds = availableResults
        .filter(r => r.detectionStatus === 'suspicious')
        .map(r => r.evidence.id);

      findings.push({
        id: crypto.randomUUID(),
        type: 'reputation_suspicious',
        severity: 'medium',
        title: 'Suspicious Reputation Indicators',
        description: 'Threat intelligence providers reported suspicious signals or unclassified anomalies for this URL.',
        confidence: 'medium',
        evidenceIds: suspiciousEvidenceIds,
        metadata: {
          suspiciousCount,
          consensusScore: Math.round(consensusScore * 100) / 100,
        },
      });
    } else if (cleanCount > 0) {
      // Clean consensus
      aggregateStatus = 'clean';
      // Confidence: if multiple providers say clean -> high; if 1 provider -> medium
      confidence = cleanCount >= 2 ? 'high' : 'medium';

      const cleanEvidenceIds = availableResults
        .filter(r => r.detectionStatus === 'clean')
        .map(r => r.evidence.id);

      const title = unknownCount > 0
        ? 'No Threat Matches in Available Checks'
        : cleanCount >= 2
        ? 'No Threats Flagged Across Queried Providers'
        : 'No Threat Matches Found';

      const description = unknownCount > 0
        ? 'The available reputation checks found no matching threat listing, but some providers may return unknown when they have no record.'
        : cleanCount >= 2
        ? 'No matching threat records were found across queried security vendors.'
        : 'The queried reputation provider found no matching threat listing for this URL.';

      findings.push({
        id: crypto.randomUUID(),
        type: 'reputation_clean',
        severity: 'info',
        title,
        description,
        confidence,
        evidenceIds: cleanEvidenceIds,
        metadata: {
          cleanCount,
          consensusScore: Math.round(consensusScore * 100) / 100,
        },
      });

      limitations.push(
        'Clean reputation records reflect known threat feeds only and do not guarantee safety for newly registered domains or targeted zero-day attacks.'
      );
    } else {
      // All available providers reported unknown
      aggregateStatus = 'unknown';
      confidence = 'low';

      limitations.push(
        'URL has no recorded historical telemetry in external reputation feeds.'
      );
    }

    // Build concise natural summary
    let summary: string;
    if (hasDispute) {
      summary = `Reputation Disputed: ${maliciousCount} provider(s) reported threats, while ${cleanCount} reported clean.`;
    } else if (aggregateStatus === 'malicious') {
      summary = `Known Threat: ${maliciousCount} provider(s) confirmed malicious reputation.`;
    } else if (aggregateStatus === 'suspicious') {
      summary = `Suspicious: Telemetry providers flagged anomalous behavior.`;
    } else if (aggregateStatus === 'clean') {
      if (unknownCount > 0) {
        summary = `No threat matches found in available checks (${cleanCount} unflagged, ${unknownCount} with no record).`;
      } else if (cleanCount >= 2) {
        summary = `No threat listings found across ${cleanCount} queried providers.`;
      } else {
        summary = `No threat matches found by queried provider.`;
      }
    } else {
      summary = 'Unknown: Insufficient external telemetry available for this URL.';
    }

    return {
      url,
      aggregateStatus,
      confidence,
      consensusScore: Math.round(consensusScore * 100) / 100,
      disputed: hasDispute,
      providerResults,
      findings,
      evidence: allEvidence,
      limitations,
      summary,
    };
  }
}
