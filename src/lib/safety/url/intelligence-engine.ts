/**
 * URL Intelligence Engine (Phase 6.1)
 * 
 * Reusable server-side engine coordinating URL normalization, SSRF protection,
 * deterministic structural analysis, live threat reputation feeds (Safe Browsing & URLhaus),
 * and calibrated risk scoring.
 * 
 * ZERO USER-URL FETCHING POLICY: Never visits, crawls, or resolves user-submitted URLs.
 */

import crypto from 'crypto';
import {
  Finding,
  Evidence,
  Recommendation,
  RiskLevel,
  ConfidenceLevel,
  SafetyReport,
} from '../types';
import { UrlNormalizer, NormalizedUrlResult } from './normalizer';
import { UrlStructuralAnalyzer, StructuralAnalysisResult } from './structural-analyzer';
import { safeBrowsingProvider } from '../reputation/safebrowsing';
import { urlhausProvider } from '../reputation/urlhaus';
import {
  ProviderReputationResult,
  ReputationProvider,
} from '../reputation/types';
import { RedisReputationCache } from '../reputation/cache';
import { redactSensitiveText, redactDataRecord } from '../redaction';

export interface UrlIntelligenceOptions {
  enableReputation?: boolean;
  providers?: ReputationProvider[];
  timeoutMs?: number;
  sourceContext?: string;
  cache?: RedisReputationCache;
}

export interface UrlIntelligenceResult {
  url: string;                     // Display/normalized target URL
  riskLevel: RiskLevel;            // 'low' | 'medium' | 'high' | 'critical' | 'unknown'
  riskScore: number;               // Deterministic calibrated score (0-100)
  confidence: ConfidenceLevel;     // 'low' | 'medium' | 'high'
  verdict: string;                 // Calibrated assessment statement
  recommendation: string;          // Primary actionable recommendation
  signals: string[];               // Machine-readable signal list
  providers: {
    name: string;
    status: string;
    detectionStatus: string;
    threatTypes?: string[];
  }[];
  findings: Finding[];
  evidence: Evidence[];
  limitations: string[];
  report: SafetyReport;            // Full unified SafetyReport for UI & persistence
  createdAt: string;
}

export class UrlIntelligenceEngine {
  private static defaultCache = new RedisReputationCache(3600);

  /**
   * Analyzes a candidate URL through the complete URL Intelligence pipeline.
   */
  static async analyze(
    rawInput: string,
    options?: UrlIntelligenceOptions
  ): Promise<UrlIntelligenceResult> {
    const createdAt = new Date().toISOString();
    const analysisId = crypto.randomUUID();

    // 1. URL Normalization & SSRF Defense
    const normalized: NormalizedUrlResult = UrlNormalizer.normalize(rawInput);

    // If URL syntax is invalid or unsupported scheme:
    if (!normalized.isValid) {
      return this.buildInvalidResponse(rawInput, normalized, analysisId, createdAt);
    }

    // 2. Deterministic Structural Analysis
    const structural: StructuralAnalysisResult = UrlStructuralAnalyzer.analyze(normalized);
    const allFindings: Finding[] = [...structural.findings];
    const allEvidence: Evidence[] = [...structural.evidence];
    const allSignals: string[] = [...structural.signals];
    const allLimitations: string[] = [...structural.limitations];

    // 3. Live Threat Reputation Feeds (Google Safe Browsing & URLhaus)
    // If the host is a private/SSRF target, we do NOT query external reputation providers
    const enableRep = options?.enableReputation !== false;
    const providerResults: ProviderReputationResult[] = [];

    if (enableRep && !normalized.ssrf.isBlocked) {
      const activeProviders = options?.providers ?? [urlhausProvider, safeBrowsingProvider];
      const enabledProviders = activeProviders.filter(p => p.getStatus() !== 'disabled');

      if (enabledProviders.length > 0) {
        const timeoutMs = options?.timeoutMs ?? 3000;
        const lookupPromises = enabledProviders.map(async (provider): Promise<ProviderReputationResult> => {
          if (provider.getStatus() === 'unavailable') {
            return {
              providerId: provider.id,
              providerName: provider.name,
              url: normalized.providerLookupUrl,
              status: 'unavailable',
              detectionStatus: 'unavailable',
              confidence: 'low',
              timestamp: new Date().toISOString(),
              latencyMs: 0,
              cached: false,
              evidence: {
                id: crypto.randomUUID(),
                sourceType: 'reputation_provider',
                sourceName: provider.name,
                label: `${provider.name} Telemetry`,
                description: 'Threat list lookup was unavailable or timed out.',
                data: { status: 'unavailable' },
                isAiGenerated: false,
                createdAt: new Date().toISOString(),
              },
              error: {
                code: 'provider_unavailable',
                message: `${provider.name} is currently unavailable or unconfigured`,
              },
            };
          }

          try {
            // Strict timeout wrapper
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), timeoutMs);

            // Crucial: Use providerLookupUrl (which has credentials completely removed)
            const result = await provider.lookupUrl(normalized.providerLookupUrl, {
              signal: controller.signal,
            });
            clearTimeout(timer);
            return result;
          } catch (err: unknown) {
            const fallbackResult: ProviderReputationResult = {
              providerId: provider.id,
              providerName: provider.name,
              url: normalized.providerLookupUrl,
              status: 'unavailable',
              detectionStatus: 'unavailable',
              confidence: 'low',
              timestamp: new Date().toISOString(),
              latencyMs: 0,
              cached: false,
              error: {
                code: 'provider_unavailable',
                message: err instanceof Error ? err.message : 'Lookup failed',
              },
              evidence: {
                id: crypto.randomUUID(),
                sourceType: 'reputation_provider',
                sourceName: provider.name,
                label: `${provider.name} Telemetry`,
                description: 'Threat list lookup was unavailable or timed out.',
                data: { status: 'unavailable' },
                isAiGenerated: false,
                createdAt: new Date().toISOString(),
              },
            };
            return fallbackResult;
          }
        });

        const settledResults = await Promise.all(lookupPromises);
        providerResults.push(...settledResults);

        // Aggregate provider findings and evidence
        for (const res of settledResults) {
          if (res.evidence) {
            allEvidence.push(res.evidence);
          }

          if (res.detectionStatus === 'malicious') {
            allSignals.push(`reputation_malicious_${res.providerId}`);
            const threatList = (res.threatCategories || []).join(', ') || 'malware';
            allFindings.push({
              id: crypto.randomUUID(),
              type: 'reputation_malicious',
              severity: 'critical',
              title: `Known Threat Listed in ${res.providerName}`,
              description: `${res.providerName} rates this URL as known malicious (${threatList}).`,
              evidenceIds: [res.evidence?.id || ''],
              confidence: res.confidence || 'high',
              metadata: {
                providerId: res.providerId,
                threatCategories: res.threatCategories,
              },
            });
          } else if (res.detectionStatus === 'suspicious') {
            allSignals.push(`reputation_suspicious_${res.providerId}`);
            allFindings.push({
              id: crypto.randomUUID(),
              type: 'reputation_suspicious',
              severity: 'medium',
              title: `Suspicious Indicator in ${res.providerName}`,
              description: `${res.providerName} flagged elevated risk indicators for this destination.`,
              evidenceIds: [res.evidence?.id || ''],
              confidence: res.confidence || 'medium',
              metadata: { providerId: res.providerId },
            });
          } else if (res.detectionStatus === 'clean') {
            allSignals.push(`reputation_clean_${res.providerId}`);
          } else if (res.detectionStatus === 'unavailable') {
            allLimitations.push(`${res.providerName} reputation query was unavailable or timed out.`);
          }
        }
      } else {
        allLimitations.push('External reputation threat feeds were unconfigured or unavailable.');
      }
    } else if (normalized.ssrf.isBlocked) {
      allLimitations.push('External reputation lookup skipped for private network / localhost address.');
    }

    // 4. Provider Conflict Resolution & Multi-Provider Consensus
    const maliciousProviders = providerResults.filter(r => r.detectionStatus === 'malicious');
    const cleanProviders = providerResults.filter(r => r.detectionStatus === 'clean');
    const isDisputed = maliciousProviders.length > 0 && cleanProviders.length > 0;

    if (isDisputed) {
      allSignals.push('reputation_disputed');
      allFindings.push({
        id: crypto.randomUUID(),
        type: 'reputation_disputed',
        severity: 'medium',
        title: 'Conflicting Security Vendor Verdicts',
        description:
          'Reputation providers disagree on this URL. One vendor flags threats while another reports clean. Exercise elevated caution.',
        confidence: 'medium',
      });
    }

    // 5. Deterministic Signal Consolidation & Calibrated Risk Scoring (0–100)
    const consolidation = this.calculateConsolidation(allFindings, providerResults);

    // 6. Proportional Recommendations
    const recommendations = this.buildRecommendations(allFindings, consolidation.riskLevel, normalized);

    // 7. Apply Privacy Redaction Layer
    const sanitizedFindings = allFindings.map(f => ({
      ...f,
      description: redactSensitiveText(f.description),
    }));

    const sanitizedEvidence = allEvidence.map(ev => ({
      ...ev,
      snippet: ev.snippet ? redactSensitiveText(ev.snippet) : undefined,
      data: redactDataRecord(ev.data),
    }));

    // Universal safety boundary limitation
    allLimitations.push(
      'Absence of known threat records is not proof of absolute safety. Newly created phishing sites may not yet appear on threat feeds.'
    );

    const report: SafetyReport = {
      analysisId,
      inputType: 'url',
      status: 'completed',
      riskLevel: consolidation.riskLevel,
      confidenceLevel: consolidation.confidence,
      score: consolidation.riskScore,
      summary: consolidation.verdict,
      findings: sanitizedFindings,
      evidence: sanitizedEvidence,
      recommendations,
      limitations: Array.from(new Set(allLimitations)),
      analyzerResults: [
        {
          analyzerId: 'url-intelligence-engine',
          analyzerType: 'url',
          status: 'success',
          confidence: consolidation.confidence,
          findings: sanitizedFindings,
          evidence: sanitizedEvidence,
          limitations: Array.from(new Set(allLimitations)),
        },
      ],
      createdAt,
    };

    const providersSummary = providerResults.map(r => ({
      name: r.providerName,
      status: r.status,
      detectionStatus: r.detectionStatus,
      threatTypes: r.threatCategories,
    }));

    return {
      url: normalized.displayUrl,
      riskLevel: consolidation.riskLevel,
      riskScore: consolidation.riskScore,
      confidence: consolidation.confidence,
      verdict: consolidation.verdict,
      recommendation: recommendations[0]?.description || 'Exercise standard digital caution.',
      signals: Array.from(new Set(allSignals)),
      providers: providersSummary,
      findings: sanitizedFindings,
      evidence: sanitizedEvidence,
      limitations: Array.from(new Set(allLimitations)),
      report,
      createdAt,
    };
  }

  /**
   * Deterministically calculates calibrated risk score, risk level, and confidence.
   */
  private static calculateConsolidation(
    findings: Finding[],
    providerResults: ProviderReputationResult[]
  ): { riskLevel: RiskLevel; riskScore: number; confidence: ConfidenceLevel; verdict: string } {
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    for (const f of findings) {
      if (f.severity === 'critical') criticalCount++;
      else if (f.severity === 'high') highCount++;
      else if (f.severity === 'medium') mediumCount++;
      else if (f.severity === 'low') lowCount++;
    }

    // Calibrated score calculation:
    // Critical: 40 pts, High: 25 pts, Medium: 10 pts, Low: 3 pts
    const rawScore =
      criticalCount * 40 +
      highCount * 25 +
      mediumCount * 10 +
      lowCount * 3;

    const riskScore = Math.min(100, Math.max(0, rawScore));

    const availableProviders = providerResults.filter(r => r.detectionStatus !== 'unavailable');
    const allProvidersUnavailable = providerResults.length > 0 && availableProviders.length === 0;

    // Risk level determination
    let riskLevel: RiskLevel;
    if (criticalCount > 0 || (highCount >= 2 && riskScore >= 60)) {
      riskLevel = 'critical';
    } else if (highCount >= 1 || (mediumCount >= 2 && riskScore >= 25)) {
      riskLevel = 'high';
    } else if (mediumCount >= 1 || lowCount >= 2 || riskScore >= 10) {
      riskLevel = 'medium';
    } else if (allProvidersUnavailable && findings.length === 0) {
      // Combination D: Both configured providers unavailable and no structural signals
      riskLevel = 'unknown';
    } else {
      riskLevel = 'low';
    }

    // Confidence determination (decoupled from risk level)
    let confidence: ConfidenceLevel = 'high';
    if (allProvidersUnavailable && findings.length === 0) {
      confidence = 'low';
    } else if (allProvidersUnavailable || findings.some(f => f.confidence === 'low')) {
      confidence = 'medium';
    } else if (findings.length === 0) {
      // Clean analysis: medium confidence (absence of evidence != proof of safety)
      confidence = 'medium';
    }

    // Calibrated verdict phrasing (STRICT REQUIREMENT: Never say "100% safe" or "100% phishing")
    let verdict: string;
    if (riskLevel === 'critical') {
      verdict = 'High-risk malicious destination identified by active security intelligence feeds or multiple deceptive vectors.';
    } else if (riskLevel === 'high') {
      verdict = 'Elevated threat indicators or deceptive brand-spoofing patterns detected.';
    } else if (riskLevel === 'medium') {
      verdict = 'Moderate suspicion warranted due to anomalous URL structure, keywords, or vendor dispute.';
    } else if (riskLevel === 'unknown') {
      verdict = 'Threat intelligence feeds were unavailable or unconfigured, and no local structural anomalies were detected. Risk could not be reliably verified.';
    } else {
      verdict = 'No known threat indicators or anomalous structures detected based on available checks.';
    }

    return { riskLevel, riskScore, confidence, verdict };
  }

  /**
   * Generates actionable recommendations based on findings.
   */
  private static buildRecommendations(
    findings: Finding[],
    riskLevel: RiskLevel,
    normalized: NormalizedUrlResult
  ): Recommendation[] {
    const recs: Recommendation[] = [];
    const added = new Set<string>();

    const addRec = (rec: Recommendation) => {
      if (!added.has(rec.action)) {
        added.add(rec.action);
        recs.push(rec);
      }
    };

    if (riskLevel === 'critical' || riskLevel === 'high') {
      addRec({
        action: 'do_not_click',
        title: 'Do Not Visit This Destination',
        description: 'Avoid visiting this URL or following redirects. Do not enter passwords, payment cards, or credentials.',
        priority: 'high',
      });
    }

    if (normalized.hasCredentials) {
      addRec({
        action: 'do_not_enter_password',
        title: 'Do Not Submit Embedded Credentials',
        description: 'Never submit or transmit URLs containing embedded usernames or passwords (@ symbol).',
        priority: 'high',
      });
    }

    if (findings.some(f => f.type === 'lookalike_brand' || f.type === 'lookalike_domain')) {
      addRec({
        action: 'verify_domain',
        title: 'Navigate Directly to the Official Website',
        description: 'If you intended to visit a major service, open a new browser tab and type the official address directly.',
        priority: 'high',
      });
    }

    if (findings.some(f => f.type === 'shortened_url')) {
      addRec({
        action: 'verify_destination_host',
        title: 'Inspect Target Destination',
        description: 'Use a link expansion tool or check the destination preview before clicking shortened links.',
        priority: 'medium',
      });
    }

    if (findings.some(f => f.type === 'insecure_protocol')) {
      addRec({
        action: 'use_https',
        title: 'Use Encrypted HTTPS',
        description: 'Verify whether the website offers secure HTTPS before entering sensitive personal information.',
        priority: 'low',
      });
    }

    if (recs.length === 0) {
      addRec({
        action: 'no_action_needed',
        title: 'Exercise Standard Caution',
        description: 'No threat indicators were flagged, but standard online vigilance is always recommended before entering credentials.',
        priority: 'low',
      });
    }

    return recs;
  }

  private static buildInvalidResponse(
    rawInput: string,
    normalized: NormalizedUrlResult,
    analysisId: string,
    createdAt: string
  ): UrlIntelligenceResult {
    const errorMsg = normalized.error || 'Invalid or malformed URL.';
    const finding: Finding = {
      id: crypto.randomUUID(),
      type: 'syntax_anomaly',
      severity: 'medium',
      title: 'Malformed or Unsupported URL Syntax',
      description: errorMsg,
      confidence: 'high',
    };

    const rec: Recommendation = {
      action: 'proceed_with_caution',
      title: 'Verify URL Format',
      description: 'Ensure the provided link uses a valid http:// or https:// web address format.',
      priority: 'medium',
    };

    const report: SafetyReport = {
      analysisId,
      inputType: 'url',
      status: 'failed',
      riskLevel: 'unknown',
      confidenceLevel: 'low',
      score: 0,
      summary: `The provided URL could not be analyzed: ${errorMsg}`,
      findings: [finding],
      evidence: [],
      recommendations: [rec],
      limitations: [errorMsg],
      analyzerResults: [],
      createdAt,
    };

    return {
      url: rawInput,
      riskLevel: 'unknown',
      riskScore: 0,
      confidence: 'low',
      verdict: `Analysis could not be completed: ${errorMsg}`,
      recommendation: rec.description,
      signals: ['invalid_url'],
      providers: [],
      findings: [finding],
      evidence: [],
      limitations: [errorMsg],
      report,
      createdAt,
    };
  }
}
