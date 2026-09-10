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
 * Deterministic Code Security Analyzer.
 * Detects hardcoded credentials/secrets, dangerous eval calls, raw SQL concatenation, and command execution.
 */
export class CodeSecurityAnalyzer implements SafetyAnalyzer {
  readonly id = 'code-security-analyzer';
  readonly type = 'code_security' as const;
  readonly supportedInputTypes = ['code'] as const;

  // Secret regex patterns
  private static SECRET_PATTERNS = [
    {
      name: 'Generic API Key / Secret Token',
      regex: /(api[_-]?key|secret|token|password|passwd|private[_-]?key)\s*[:=]\s*['"`][a-zA-Z0-9_\-.~]{16,}['"`]/i,
    },
    {
      name: 'AWS Access Key ID',
      regex: /\b(AKIA[0-9A-Z]{16})\b/,
    },
    {
      name: 'RSA / OpenSSH Private Key Header',
      regex: /-----BEGIN (RSA|EC|OPENSSH|DSA)? ?PRIVATE KEY-----/,
    },
    {
      name: 'GitHub Personal Access Token',
      regex: /\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b/,
    },
  ];

  // Dangerous sinks
  private static DANGEROUS_PATTERNS = [
    {
      type: 'dangerous_function' as const,
      name: 'Arbitrary Code Execution via eval() / Function()',
      regex: /\b(eval|exec|Function)\s*\(/,
      severity: 'high' as const,
      description: 'Using eval() or dynamic Function constructors allows arbitrary code execution if untrusted input reaches it.',
    },
    {
      type: 'sql_injection_pattern' as const,
      name: 'Potential SQL Injection via String Concatenation',
      regex: /(SELECT|INSERT|UPDATE|DELETE)\s+.*(\+|\.concat\()|\bquery\s*\(\s*['"`].*\$\{/i,
      severity: 'high' as const,
      description: 'Raw SQL queries assembled using dynamic string interpolation or concatenation are vulnerable to SQL injection.',
    },
    {
      type: 'command_injection_pattern' as const,
      name: 'Potential Command Injection via Child Process Execution',
      regex: /\b(child_process|execSync|spawnSync|system|popen)\s*\(/,
      severity: 'high' as const,
      description: 'Executing system shell commands with user-controllable input can permit command injection attacks.',
    },
  ];

  canAnalyze(input: SafetyInput): boolean {
    if (input.type && (this.supportedInputTypes as readonly string[]).includes(input.type)) {
      return true;
    }
    // Check if filename indicates a code file
    if (input.filename && /\.(js|ts|py|go|rs|c|cpp|php|rb|sh|sql)$/i.test(input.filename)) {
      return true;
    }
    return false;
  }

  async analyze(input: SafetyInput): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];
    const code = input.rawContent;

    const evidenceId = crypto.randomUUID();
    evidence.push({
      id: evidenceId,
      sourceType: 'deterministic_rule',
      sourceName: 'Static Heuristic Code Scanner',
      description: 'Pattern matching against common code security anti-patterns and exposed secret formats',
      data: { codeLength: code.length },
      isAiGenerated: false,
      createdAt: new Date().toISOString(),
    });

    // 1. Hardcoded Secrets Detection
    for (const secretPattern of CodeSecurityAnalyzer.SECRET_PATTERNS) {
      if (secretPattern.regex.test(code)) {
        findings.push({
          id: crypto.randomUUID(),
          type: 'exposed_secret',
          severity: 'critical',
          title: `Potential Hardcoded Secret: ${secretPattern.name}`,
          description: 'Hardcoded secrets, private keys, or API tokens committed in source code can lead to credential compromise.',
          evidenceIds: [evidenceId],
          confidence: 'high',
        });
        break; // Avoid spamming multiple secret findings
      }
    }

    // 2. Dangerous Sinks Detection
    for (const dangerous of CodeSecurityAnalyzer.DANGEROUS_PATTERNS) {
      if (dangerous.regex.test(code)) {
        findings.push({
          id: crypto.randomUUID(),
          type: dangerous.type,
          severity: dangerous.severity,
          title: dangerous.name,
          description: dangerous.description,
          evidenceIds: [evidenceId],
          confidence: 'high',
        });
      }
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
        'Heuristic scan only; this is not a substitute for full static application security testing (SAST) or taint analysis.',
        'False positives may occur if matching strings are contained inside comments, documentation, or mock test fixtures.',
      ],
    };
  }
}
