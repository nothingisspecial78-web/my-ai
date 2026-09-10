import { ThemeEngine, ThemeContext, ThemeResult } from '../../engine';
import { SafetyService } from '@/lib/safety/service';
import { SafetyThemeContextFacts } from './types';

export class SafetySecurityEngine implements ThemeEngine {
  async execute(context: ThemeContext): Promise<ThemeResult> {
    const facts = context.facts as unknown as SafetyThemeContextFacts;

    let explanationContext: string;
    if (facts?.report) {
      explanationContext = SafetyService.formatForGemini(facts.report);
    } else {
      explanationContext = 'Safety analysis could not be retrieved. Advise the user to exercise standard digital caution.';
    }

    return {
      success: true,
      result: facts?.report || null,
      warnings: [],
      errors: [],
      explanationContext,
      metadata: {
        analysisId: facts?.report?.analysisId,
        riskLevel: facts?.report?.riskLevel,
      },
    };
  }
}
