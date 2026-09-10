import crypto from 'crypto';
import {
  SafetyInput,
  SafetyReport,
  Finding,
  Evidence,
  AnalyzerResult,
} from './types';
import { analyzerRegistry } from './analyzers/base';
import { InputClassifier } from './analyzers/input-classifier';
import { UrlAnalyzer } from './analyzers/url-analyzer';
import { MessageScamAnalyzer } from './analyzers/message-scam-analyzer';
import { CodeSecurityAnalyzer } from './analyzers/code-security-analyzer';
import { RiskEngine } from './risk-engine';
import { redactSensitiveText, redactDataRecord } from './redaction';
import { reputationRegistry, ReputationAggregator } from './reputation';

// Initialize and register default specialized analyzers
const defaultUrlAnalyzer = new UrlAnalyzer();
const defaultScamAnalyzer = new MessageScamAnalyzer();
const defaultCodeAnalyzer = new CodeSecurityAnalyzer();

analyzerRegistry.register(defaultUrlAnalyzer);
analyzerRegistry.register(defaultScamAnalyzer);
analyzerRegistry.register(defaultCodeAnalyzer);

/**
 * Server-side Safety & Security Analysis Service.
 * Central coordinator for input classification, analyzer dispatch, and report synthesis.
 */
export class SafetyService {
  /**
   * Performs an end-to-end deterministic safety analysis on untrusted user input.
   */
  static async analyze(input: SafetyInput): Promise<SafetyReport> {
    const analysisId = crypto.randomUUID();
    const createdAt = new Date().toISOString();

    // 1. Input Classification
    const inputType = input.type || InputClassifier.classify(input);
    const normalizedInput: SafetyInput = {
      ...input,
      type: inputType,
    };

    // 2. Analyzer Selection
    const analyzers = analyzerRegistry.getForInput(normalizedInput);

    const analyzerResults: AnalyzerResult[] = [];
    const allFindings: Finding[] = [];
    const allEvidence: Evidence[] = [];

    // 3. Execution of Analyzers
    for (const analyzer of analyzers) {
      try {
        const result = await analyzer.analyze(normalizedInput);
        analyzerResults.push(result);
        allFindings.push(...result.findings);
        allEvidence.push(...result.evidence);
      } catch (err: unknown) {
        analyzerResults.push({
          analyzerId: analyzer.id,
          analyzerType: analyzer.type,
          status: 'failed',
          confidence: 'low',
          findings: [],
          evidence: [],
          error: err instanceof Error ? err.message : 'Unknown analyzer failure',
          limitations: [`Analyzer ${analyzer.id} failed during execution.`],
        });
      }
    }

    // 3.1. Live URL Reputation Intelligence (Phase 4.8B)
    const activeProviders = reputationRegistry.getActive();
    if (activeProviders.length > 0) {
      let targetUrl: string | null = null;
      if (normalizedInput.type === 'url') {
        targetUrl = normalizedInput.rawContent.trim();
      } else {
        const urlMatch = normalizedInput.rawContent.match(/https?:\/\/[^\s<>"]+/i);
        if (urlMatch) {
          targetUrl = urlMatch[0];
        }
      }

      if (targetUrl) {
        try {
          const repResult = await ReputationAggregator.lookupAndAggregate(
            targetUrl,
            activeProviders
          );

          allFindings.push(...repResult.findings);
          allEvidence.push(...repResult.evidence);

          analyzerResults.push({
            analyzerId: 'reputation-aggregator',
            analyzerType: 'url',
            status: repResult.aggregateStatus === 'unavailable' ? 'partial' : 'success',
            confidence: repResult.confidence,
            findings: repResult.findings,
            evidence: repResult.evidence,
            limitations: repResult.limitations,
          });
        } catch {
          // Provider failures are non-fatal to Safety Checkup
        }
      }
    }

    // 4. Deterministic Risk Evaluation
    const evaluation = RiskEngine.evaluate(allFindings, analyzerResults);

    // 5. Synthesis of Natural Summary
    const summary = this.buildSummary(
      inputType,
      evaluation.riskLevel,
      allFindings.length
    );

    // 6. Apply Privacy Redaction Layer to all findings and evidence before returning
    const sanitizedFindings = allFindings.map(f => ({
      ...f,
      description: redactSensitiveText(f.description),
    }));

    const sanitizedEvidence = allEvidence.map(ev => ({
      ...ev,
      snippet: ev.snippet ? redactSensitiveText(ev.snippet) : undefined,
      data: redactDataRecord(ev.data),
    }));

    return {
      analysisId,
      inputType,
      status: 'completed',
      riskLevel: evaluation.riskLevel,
      confidenceLevel: evaluation.confidenceLevel,
      score: evaluation.score,
      summary,
      findings: sanitizedFindings,
      evidence: sanitizedEvidence,
      recommendations: evaluation.recommendations,
      limitations: evaluation.limitations,
      analyzerResults,
      createdAt,
    };
  }

  /**
   * Generates a readable, deterministic markdown response when Gemini is unavailable.
   */
  static generateFallbackResponse(report: SafetyReport): string {
    const riskBadge = report.riskLevel.toUpperCase();
    const confidence = report.confidenceLevel.toUpperCase();

    let content = `### Safety Checkup Result\n\n`;
    content += `**Risk Level**: ${riskBadge}  \n`;
    content += `**Confidence**: ${confidence}  \n`;
    if (typeof report.score === 'number') {
      content += `**Heuristic Risk Score**: ${report.score}/100  \n`;
    }
    content += `\n${report.summary}\n\n`;

    if (report.findings.length > 0) {
      content += `#### Detected Indicators\n`;
      for (const f of report.findings) {
        content += `- **${f.title}** (${f.severity.toUpperCase()}): ${f.description}\n`;
      }
      content += `\n`;
    } else {
      content += `#### Detected Indicators\n- No suspicious patterns or threats detected in this input.\n\n`;
    }

    if (report.recommendations.length > 0) {
      content += `#### Recommended Actions\n`;
      for (const r of report.recommendations) {
        content += `- **${r.title}**: ${r.description}\n`;
      }
      content += `\n`;
    }

    if (report.limitations.length > 0) {
      content += `#### Analysis Limitations\n`;
      for (const l of report.limitations) {
        content += `- ${l}\n`;
      }
    }

    return content.trim();
  }

  /**
   * Formats the structured SafetyReport into concise guidance context for Gemini.
   */
  static formatForGemini(report: SafetyReport): string {
    const findingsList =
      report.findings.length > 0
        ? report.findings
            .map(
              (f, i) =>
                `${i + 1}. [${f.severity.toUpperCase()}] ${f.title}: ${f.description}`
            )
            .join('\n')
        : 'No specific threat or scam indicators detected.';

    const recsList = report.recommendations
      .map((r, i) => `${i + 1}. ${r.title} — ${r.description}`)
      .join('\n');

    const limitationsList = report.limitations.map(l => `- ${l}`).join('\n');

    return [
      `=== SAFETY & SECURITY DETERMINISTIC ANALYSIS ===`,
      `Input Classification: ${report.inputType.toUpperCase()}`,
      `Assessed Risk Level: ${report.riskLevel.toUpperCase()}`,
      `Confidence Level: ${report.confidenceLevel.toUpperCase()}`,
      `Heuristic Score: ${report.score ?? 0}/100`,
      ``,
      `Key Findings / Signals:`,
      findingsList,
      ``,
      `Actionable Recommendations:`,
      recsList,
      ``,
      `Safety Boundaries & Limitations:`,
      limitationsList,
      `================================================`,
      `INSTRUCTION FOR ASSISTANT:`,
      `1. Clearly communicate the assessed risk level (${report.riskLevel.toUpperCase()}) and confidence.`,
      `2. Explain the specific observable signals without claiming absolute certainty (e.g. use "likely", "suspicious", "indicators suggest").`,
      `3. Emphasize the practical recommendations.`,
      `4. Do NOT invent external security vendor results, database lookups, or claim 100% safety.`,
    ].join('\n');
  }

  private static buildSummary(
    inputType: string,
    risk: string,
    findingCount: number
  ): string {
    if (findingCount === 0) {
      return `Analysis of the provided ${inputType} found no immediate suspicious signals. Standard digital vigilance is recommended.`;
    }
    return `Analysis of the provided ${inputType} identified ${findingCount} observable signal(s), resulting in a ${risk.toUpperCase()} risk assessment.`;
  }
}
