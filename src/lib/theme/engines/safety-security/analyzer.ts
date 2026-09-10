import { ThemeAnalyzer, ThemeContext } from '../../engine';
import { Message } from '@/lib/ai/types';
import { SafetyService } from '@/lib/safety/service';
import { SafetyThemeContextFacts } from './types';

export class SafetySecurityAnalyzer implements ThemeAnalyzer {
  async analyze(input: string, history: Message[]): Promise<Partial<ThemeContext>> {
    // 1. Run the deterministic SafetyService analysis
    const report = await SafetyService.analyze({
      rawContent: input,
      sourceContext: history.length > 0 ? 'conversation_turn' : 'direct_prompt',
    });

    const facts: SafetyThemeContextFacts = {
      inputType: report.inputType,
      riskLevel: report.riskLevel,
      confidenceLevel: report.confidenceLevel,
      findingCount: report.findings.length,
      report,
    };

    return {
      intent: 'safety_check',
      entities: [report.inputType],
      facts: facts as unknown as Record<string, unknown>,
      metadata: {
        analysisId: report.analysisId,
        score: report.score,
      },
    };
  }
}
