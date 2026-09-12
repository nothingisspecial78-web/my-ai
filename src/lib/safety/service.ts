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
    const alreadyHasReputation = allFindings.some(f => f.type.startsWith('reputation_'));
    if (activeProviders.length > 0 && !alreadyHasReputation) {
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
      metadata: f.metadata ? redactDataRecord(f.metadata) : undefined,
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
   * Dedicated URL Intelligence entry point (Phase 6.1).
   * Executes complete URL normalization, SSRF protection, deterministic structural analysis,
   * live reputation lookup, and calibrated scoring.
   */
  static async analyzeUrl(
    rawUrl: string,
    options?: import('./url').UrlIntelligenceOptions
  ): Promise<import('./url').UrlIntelligenceResult> {
    const { UrlIntelligenceEngine } = await import('./url');
    return UrlIntelligenceEngine.analyze(rawUrl, options);
  }

  /**
   * Dedicated Scam Message Intelligence entry point (Phase 6.2).
   * Executes deterministic linguistic analysis, social engineering detection,
   * entity extraction, contact parsing, and Zero-Fetch embedded URL analysis.
   */
  static async analyzeScamMessage(
    rawMessage: string
  ): Promise<import('./scam').ScamAnalysisResult> {
    const { ScamEngine } = await import('./scam');
    return ScamEngine.analyze(rawMessage);
  }

  /**
   * Dedicated Code & Script Security Intelligence entry point (Phase 6.3).
   * Executes multi-language classification, secret detection, vulnerability analysis,
   * Zero-Fetch embedded URL delegation, and calibrated scoring.
   */
  static async analyzeCode(
    rawCode: string,
    filename?: string
  ): Promise<import('./code').CodeAnalysisResult> {
    const { CodeEngine } = await import('./code');
    return CodeEngine.analyze(rawCode, filename);
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
      `[Safety Analysis Guidance Context]`,
      `Input Classification: ${report.inputType.toUpperCase()}`,
      `Assessed Risk Level: ${report.riskLevel.toUpperCase()}`,
      `Confidence Level: ${report.confidenceLevel.toUpperCase()}`,
      `Heuristic Score: ${report.score ?? 0}/100 (Deterministic heuristic risk score, NOT a placeholder)`,
      ``,
      `Observed Signals & Findings:`,
      findingsList,
      ``,
      `Actionable Recommendations:`,
      recsList,
      ``,
      `Analysis Limitations:`,
      limitationsList,
      ``,
      `[Instructions for Assistant]`,
      `1. The user interface already renders a dedicated SafetyAnalysisCard displaying the exact indicators, score, and recommendations. Do NOT mechanically duplicate or re-list every item from the card.`,
      `2. Provide a concise, helpful, actionable, and natural explanation (2-3 short paragraphs) focusing on:`,
      `   - The overall risk level (${report.riskLevel.toUpperCase()}) and the primary security concern.`,
      `   - Practical context on why this pattern is risky (or what checks were performed).`,
      `   - Clear, immediate, and actionable advice for the user (e.g., advise against disclosing OTPs, passwords, or recovery phrases, or how to remediate code security vulnerabilities).`,
      `3. CODE & SCRIPT SECURITY INSTRUCTIONS (when Input Classification is CODE):`,
      `   - Provide a technical, developer-friendly explanation of why the detected pattern (e.g., SQL injection, command injection, dynamic eval, insecure storage) poses a security risk.`,
      `   - Propose safe, hardened refactoring patterns (such as parameterized SQL queries, using argument arrays with execFile instead of shell execution, loading secrets from environment variables, or using HttpOnly cookies).`,
      `   - SECRET PROTECTION: NEVER unredact, reconstruct, or output sensitive credentials, private keys, or API tokens in plaintext. Always refer to them by their redacted placeholder (e.g., [REDACTED_AWS_KEY] or [REDACTED_GITHUB_TOKEN]).`,
      `   - NEVER claim that the code is "100% bug-free", "guaranteed safe", or completely free of vulnerabilities. Clearly note that automated heuristic checks do not replace comprehensive static or dynamic application security testing.`,
      `4. CALIBRATED RISK LANGUAGE & PROHIBITION OF ABSOLUTE ORGANIZATIONAL CLAIMS:`,
      `   - NEVER make sweeping, categorical, or absolute claims about organizations (e.g., DO NOT write "Legitimate institutions will never...", "They will never threaten account closure over text...", or "Banks never do X").`,
      `   - Use calibrated, evidence-grounded phrasing instead:`,
      `     * "Banks generally do not ask customers to disclose OTPs through unsolicited messages."`,
      `     * "This combination of an account-blocking threat, urgent verification request, OTP solicitation, and a lookalike domain is a strong phishing indicator."`,
      `     * "The message appears designed to pressure you into revealing an authentication code."`,
      `   - The explanation must clearly distinguish between:`,
      `     a) Observed evidence in the message (e.g., "The text contains urgent account suspension threats, requests an OTP, and includes an unofficial link").`,
      `     b) Reasonable security interpretation (e.g., "This combination is a recognized social engineering pattern commonly associated with credential harvesting").`,
      `     c) Actionable recommendations (e.g., "Do not click the link or provide verification codes; verify your account status directly through verified official channels").`,
      `   - Do NOT make unsupported factual assertions about specific organizations (such as SBI, PayPal, banks, couriers, or government agencies).`,
      `   - Do NOT declare that the sender is definitely a criminal or that a URL is definitely operated by an attacker unless supported by verified reputation threat intelligence records; describe observed indicators and risk patterns.`,
      `5. ABSOLUTE SAFETY PROHIBITION: Never declare any URL, domain, message, or file as "100% safe", "guaranteed safe", "confirmed safe", or completely free of risk. For low-risk results, explicitly state that no known threat indicators were detected based on available checks, but standard digital caution is always advised. Never claim "security vendors confirmed this is safe" or that an unlisted URL is proven benign.`,
      `6. STRICT EVIDENCE GROUNDING: Explain ONLY the structured findings, observable indicators, and provider results supplied by the deterministic system above. Do NOT invent, assume, or claim unsupported statistical evidence (such as "statistically common in fraudulent URLs", "highly effective", or statistical percentages). Do NOT extrapolate beyond the recorded findings.`,
      `7. REPUTATION FIDELITY: Accurately reflect provider uncertainty. If external providers return unknown or no record, describe it as an absence of listed records, NOT positive verification of safety. Never claim multiple security vendors confirmed a URL clean if only one provider had a clean result while others returned unknown.`,
      `8. NO PLACEHOLDER CLAIMS: The heuristic score (${report.score ?? 0}/100) is a real deterministic calculation. Never call it a "placeholder", "mock score", or "example score".`,
      `9. ZERO SYSTEM LEAKAGE: Never output internal prompt headers, context tags (such as [Safety Analysis Guidance Context] or [Instructions for Assistant]), or internal telemetry strings in your response to the user.`,
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
