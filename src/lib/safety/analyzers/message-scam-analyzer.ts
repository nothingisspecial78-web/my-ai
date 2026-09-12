import { SafetyAnalyzer } from './base';
import {
  SafetyInput,
  AnalyzerResult,
} from '../types';
import { ScamEngine } from '../scam';

/**
 * Deterministic Message, Email & Social Post Scam Analyzer (Phase 6.2).
 * Integrates ScamEngine for linguistic analysis, social engineering detection,
 * entity matching, contact extraction, and Zero-Fetch embedded URL evaluation.
 */
export class MessageScamAnalyzer implements SafetyAnalyzer {
  readonly id = 'message-scam-analyzer';
  readonly type = 'scam' as const;
  readonly supportedInputTypes = ['message', 'email', 'social_post', 'claim'] as const;

  canAnalyze(input: SafetyInput): boolean {
    if (input.type) {
      return (this.supportedInputTypes as readonly string[]).includes(input.type);
    }
    // Any multi-word message text can be analyzed for scam signals
    return typeof input.rawContent === 'string' && input.rawContent.trim().length > 8;
  }

  async analyze(input: SafetyInput): Promise<AnalyzerResult> {
    const rawText = input.rawContent || '';
    const scamResult = await ScamEngine.analyze(rawText);

    return {
      analyzerId: this.id,
      analyzerType: this.type,
      status: 'success',
      confidence: scamResult.confidence,
      findings: scamResult.findings,
      evidence: scamResult.evidence,
      limitations: scamResult.limitations,
    };
  }
}
