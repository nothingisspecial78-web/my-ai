import { SafetyAnalyzer } from './base';
import {
  SafetyInput,
  AnalyzerResult,
} from '../types';
import { CodeEngine } from '../code';

/**
 * Deterministic Code Security Analyzer (Phase 6.3).
 * Integrates the modular Code & Script Security Intelligence engine.
 * Never runs, executes, or sandboxes untrusted code.
 */
export class CodeSecurityAnalyzer implements SafetyAnalyzer {
  readonly id = 'code-security-analyzer';
  readonly type = 'code_security' as const;
  readonly supportedInputTypes = ['code'] as const;

  canAnalyze(input: SafetyInput): boolean {
    if (input.type && (this.supportedInputTypes as readonly string[]).includes(input.type)) {
      return true;
    }
    // Check if filename indicates a code file
    if (input.filename && /\.(js|mjs|cjs|ts|tsx|py|go|rs|c|cpp|php|rb|sh|bash|zsh|sql|json|ya?ml)$/i.test(input.filename)) {
      return true;
    }
    // Check if rawContent contains code signals
    if (input.rawContent && (
      /^#!.*\b(bash|sh|python|node|perl|ruby|php)\b/m.test(input.rawContent) ||
      /\b(eval|exec|Function)\s*\(/.test(input.rawContent) ||
      /\b(const|let|var|function|import|export|class|def|package|SELECT|INSERT|UPDATE|DELETE)\b/.test(input.rawContent)
    )) {
      return true;
    }
    return false;
  }

  async analyze(input: SafetyInput): Promise<AnalyzerResult> {
    const codeResult = await CodeEngine.analyze(input.rawContent, input.filename);

    return {
      analyzerId: this.id,
      analyzerType: this.type,
      status: 'success',
      confidence: codeResult.confidence,
      findings: codeResult.findings,
      evidence: codeResult.evidence,
      limitations: codeResult.limitations,
    };
  }
}
