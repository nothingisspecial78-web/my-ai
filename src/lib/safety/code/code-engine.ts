/**
 * Deterministic Code & Script Security Intelligence Engine (Phase 6.3)
 * 
 * Orchestrates multi-language classification, secret detection, vulnerability analysis,
 * Zero-Fetch embedded URL delegation via Phase 6.1, and calibrated risk scoring.
 * Enforces a strict 50,000-character boundary and never executes untrusted code.
 */

import crypto from 'crypto';
import {
  CodeAnalysisResult,
  ExtractedSecret,
  VulnerabilityFinding,
} from './types';
import { LanguageClassifier } from './language-classifier';
import { SecretDetector } from './secret-detector';
import { VulnerabilityDetector } from './vulnerability-detector';
import { UrlIntelligenceEngine, UrlIntelligenceResult } from '../url';
import {
  Finding,
  Evidence,
  Recommendation,
  RiskLevel,
  ConfidenceLevel,
  FindingType,
} from '../types';
import { redactSensitiveText } from '../redaction';

export class CodeEngine {
  public static readonly MAX_INPUT_CHARACTERS = 50000;
  public static readonly MAX_EMBEDDED_URLS = 5;

  /**
   * Extracts up to MAX_EMBEDDED_URLS from code content.
   */
  static extractUrls(code: string): string[] {
    const urlRegex = /https?:\/\/[^\s<>"'`)]+/gi;
    const matches = code.match(urlRegex) || [];
    const unique = new Set<string>();

    for (const match of matches) {
      // Strip trailing punctuation often found in code
      const clean = match.replace(/[.,;:!?)\]}>]+$/, '');
      if (clean.length > 8 && (clean.startsWith('http://') || clean.startsWith('https://'))) {
        unique.add(clean);
        if (unique.size >= this.MAX_EMBEDDED_URLS) break;
      }
    }

    return Array.from(unique);
  }

  /**
   * Evaluates code statically and deterministically.
   * NEVER runs, compiles, or interprets user code.
   */
  static async analyze(
    rawContent: string,
    filename?: string
  ): Promise<CodeAnalysisResult> {
    const originalLength = rawContent.length;
    let content = rawContent;
    let truncated = false;

    // 1. Enforce hard 50,000-character boundary
    if (content.length > this.MAX_INPUT_CHARACTERS) {
      content = content.substring(0, this.MAX_INPUT_CHARACTERS);
      truncated = true;
    }

    // 2. Deterministic Language Classification
    const langResult = LanguageClassifier.classify(content, filename);

    // 3. Static Secret & Credential Detection (immediately redacted)
    const secrets: ExtractedSecret[] = SecretDetector.detect(content);

    // 4. Static Vulnerability & Dangerous Sink Detection
    const vulnerabilities: VulnerabilityFinding[] = VulnerabilityDetector.detect(
      content,
      langResult.language
    );

    // 5. Zero-Fetch Embedded URL Delegation (Phase 6.1)
    const embeddedUrls = this.extractUrls(content);
    const urlResults: UrlIntelligenceResult[] = [];
    const urlFindings: Finding[] = [];
    const urlEvidence: Evidence[] = [];

    for (const url of embeddedUrls) {
      try {
        const res = await UrlIntelligenceEngine.analyze(url);
        urlResults.push(res);
        urlFindings.push(...res.findings);
        urlEvidence.push(...res.evidence);
      } catch {
        // Safe tolerance: external provider failures do not crash code analysis
      }
    }

    // 6. Synthesize Findings and Evidence
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];

    // Base Code Evidence Item
    const codeEvidenceId = crypto.randomUUID();
    evidence.push({
      id: codeEvidenceId,
      sourceType: 'deterministic_rule',
      sourceName: 'Static Code & Script Security Engine',
      description: `Static analysis of ${langResult.language.toUpperCase()} source snippet (${content.length} chars)`,
      data: {
        language: langResult.language,
        languageConfidence: langResult.confidence,
        characterCount: content.length,
        truncated,
        secretsFound: secrets.length,
        vulnerabilitiesFound: vulnerabilities.length,
      },
      isAiGenerated: false,
      createdAt: new Date().toISOString(),
    });

    // Add Secret Findings
    // Group identical secret classes on the same file
    const secretClassGroups = new Map<string, ExtractedSecret[]>();
    for (const sec of secrets) {
      const list = secretClassGroups.get(sec.secretClass) || [];
      list.push(sec);
      secretClassGroups.set(sec.secretClass, list);
    }

    for (const [sClass, items] of secretClassGroups.entries()) {
      const first = items[0];
      const count = items.length;
      const countSuffix = count > 1 ? ` (${count} instances detected)` : '';
      const lineSuffix = first.lineNumber ? ` near line ${first.lineNumber}` : '';

      findings.push({
        id: crypto.randomUUID(),
        type: 'exposed_secret',
        severity: first.severity,
        confidence: first.confidence,
        title: `Exposed Hardcoded Secret: ${first.label}${countSuffix}`,
        description: `Hardcoded credential identified${lineSuffix}: ${first.redactedValue}. Hardcoded secrets committed in source code can lead to unauthorized access and credential compromise.`,
        evidenceIds: [codeEvidenceId],
        metadata: {
          secretClass: sClass,
          redactedSnippet: first.redactedValue,
          lineNumber: first.lineNumber,
          count,
        },
      });
    }

    // Add Vulnerability Findings
    for (const vuln of vulnerabilities) {
      let fType: FindingType;
      switch (vuln.category) {
        case 'dynamic_execution':
        case 'unsafe_deserialization':
          fType = 'dangerous_function';
          break;
        case 'command_injection':
          fType = 'command_injection_pattern';
          break;
        case 'sql_injection':
          fType = 'sql_injection_pattern';
          break;
        case 'credential_exfiltration':
        case 'insecure_storage':
        default:
          fType = 'suspicious_code';
          break;
      }

      const lineSuffix = vuln.lineNumber ? ` on line ${vuln.lineNumber}` : '';
      const safeSnippet = vuln.snippet ? redactSensitiveText(vuln.snippet) : undefined;

      findings.push({
        id: crypto.randomUUID(),
        type: fType,
        severity: vuln.severity,
        confidence: vuln.confidence,
        title: vuln.title,
        description: `${vuln.description}${lineSuffix}${safeSnippet ? ` [${safeSnippet}]` : ''}`,
        evidenceIds: [codeEvidenceId],
        metadata: {
          category: vuln.category,
          lineNumber: vuln.lineNumber,
          snippet: safeSnippet,
          dedupGroup: vuln.dedupGroup,
        },
      });
    }

    // Add Elevated Embedded URL Findings (if any)
    for (const uFinding of urlFindings) {
      if (uFinding.severity === 'critical' || uFinding.severity === 'high') {
        findings.push({
          ...uFinding,
          title: `Embedded URL Threat: ${uFinding.title}`,
          description: `Code contains a reference to an elevated-risk URL: ${uFinding.description}`,
        });
      }
    }
    evidence.push(...urlEvidence);

    // 7. Calculate Deterministic Risk Score
    // Canonical scoring contract:
    // Critical: 40 pts each
    // High: 25 pts each
    // Medium: 10 pts each
    // Low: 3 pts each
    let rawScore = 0;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    for (const f of findings) {
      if (f.severity === 'critical') {
        criticalCount++;
        rawScore += 40;
      } else if (f.severity === 'high') {
        highCount++;
        rawScore += 25;
      } else if (f.severity === 'medium') {
        mediumCount++;
        rawScore += 10;
      } else if (f.severity === 'low') {
        lowCount++;
        rawScore += 3;
      }
    }

    // Floor thresholds:
    if (criticalCount > 0) {
      rawScore = Math.max(50, rawScore);
    } else if (highCount > 0) {
      rawScore = Math.max(25, rawScore);
    } else if (mediumCount > 0 || lowCount >= 2) {
      rawScore = Math.max(10, rawScore);
    }

    const score = Math.min(100, Math.max(0, rawScore));

    // Pure mathematical risk-level mapping:
    let riskLevel: RiskLevel;
    if (score >= 50) {
      riskLevel = 'critical';
    } else if (score >= 25) {
      riskLevel = 'high';
    } else if (score >= 10) {
      riskLevel = 'medium';
    } else {
      riskLevel = 'low';
    }

    // 8. Determine Confidence
    let confidence: ConfidenceLevel;
    if (findings.length > 0) {
      confidence = findings.some(f => f.confidence === 'high') ? 'high' : 'medium';
    } else {
      // Clean analysis: medium confidence (absence of evidence != proof of safety)
      confidence = 'medium';
    }

    // 9. Build Proportional Recommendations
    const recommendations: Recommendation[] = [];
    const addedActions = new Set<string>();

    if (secrets.length > 0) {
      recommendations.push({
        action: 'rotate_exposed_secret',
        title: 'Revoke and Rotate Exposed Credentials Immediately',
        description: 'Invalidate leaked tokens, API keys, or database credentials in your cloud console and migrate them to secure environment variables.',
        priority: 'high',
      });
      addedActions.add('rotate_exposed_secret');
    }

    if (vulnerabilities.some(v => v.category === 'sql_injection')) {
      recommendations.push({
        action: 'use_parameterized_queries',
        title: 'Use Parameterized Queries or Prepared Statements',
        description: 'Never concatenate user input directly into SQL queries. Bind parameters using placeholders or query builder methods.',
        priority: 'high',
      });
      addedActions.add('use_parameterized_queries');
    }

    if (vulnerabilities.some(v => v.category === 'command_injection')) {
      recommendations.push({
        action: 'avoid_shell_execution',
        title: 'Avoid Unsanitized Shell Subprocess Execution',
        description: 'Avoid passing user input to shell commands. Use argument vectors with execFile/spawn without shell=True, or utilize built-in APIs.',
        priority: 'high',
      });
      addedActions.add('avoid_shell_execution');
    }

    if (vulnerabilities.some(v => v.category === 'dynamic_execution' || v.category === 'unsafe_deserialization')) {
      recommendations.push({
        action: 'avoid_dynamic_eval',
        title: 'Avoid Dynamic Evaluation and Unsafe Deserialization',
        description: 'Replace eval() or unsafe serialization formats (like pickle) with structured formats like JSON.parse().',
        priority: 'high',
      });
      addedActions.add('avoid_dynamic_eval');
    }

    if (vulnerabilities.some(v => v.category === 'insecure_storage')) {
      recommendations.push({
        action: 'change_password',
        title: 'Store Authentication Tokens in HttpOnly Cookies',
        description: 'Do not persist sensitive authentication tokens or session keys in localStorage or sessionStorage where XSS can extract them.',
        priority: 'medium',
      });
      addedActions.add('storage');
    }

    if (recommendations.length === 0) {
      recommendations.push({
        action: 'no_action_needed',
        title: 'No Code Security Anti-Patterns Detected',
        description: 'Static analysis did not identify known hardcoded secrets, dangerous sinks, or injection patterns in this snippet.',
        priority: 'low',
      });
    }

    // 10. Limitations
    const limitations: string[] = [
      'Static heuristic scan only; this is not a substitute for full static application security testing (SAST) or dynamic fuzzing.',
      'Absence of flags is not an absolute guarantee that the code is free of logic vulnerabilities, race conditions, or architecture flaws.',
    ];

    if (truncated) {
      limitations.push(
        `Input exceeded the maximum threshold of ${this.MAX_INPUT_CHARACTERS.toLocaleString()} characters (${originalLength.toLocaleString()} characters submitted) and was truncated for analysis safety.`
      );
    }

    return {
      language: langResult.language,
      languageConfidence: langResult.confidence,
      findings,
      evidence,
      extractedSecrets: secrets,
      vulnerabilities,
      embeddedUrls,
      urlIntelligenceResults: urlResults,
      riskLevel,
      score,
      confidence,
      recommendations,
      limitations,
      truncated,
      characterCount: content.length,
    };
  }
}
