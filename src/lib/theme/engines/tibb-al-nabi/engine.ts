import { ThemeEngine, ThemeContext, ThemeResult } from '../../engine';
import { TibbAlNabiContext } from './types';
import { MANDATES } from './constants';

export class TibbAlNabiEngine implements ThemeEngine {
  async execute(context: ThemeContext): Promise<ThemeResult> {
    const facts = context.facts as unknown as TibbAlNabiContext['facts'];
    const parts: string[] = [];

    // 1. Unrelated Queries
    if (facts.primaryIntent === 'unrelated') {
      parts.push(MANDATES.UNRELATED);
      return this.buildResult(parts.join('\n\n'));
    }

    // 2. Base Integrity Rules (Apply to all domain queries)
    parts.push(MANDATES.BASE_SOURCE_INTEGRITY);

    // 3. Multilingual / Audience Guidance
    if (facts.language !== 'auto') {
      parts.push(`- The user's query or setting indicates a preference for: ${facts.language.toUpperCase()}. You may respond in this language but ensure scientific and classical terms are clear.`);
    }

    // 4. Medical Safety Injection
    if (
      facts.medicalSafety === 'diagnostic_request' ||
      facts.medicalSafety === 'treatment_request' ||
      facts.medicalSafety === 'dosage_request' ||
      facts.medicalSafety === 'image_health_request'
    ) {
      parts.push(MANDATES.MEDICAL_SAFETY_DIAGNOSIS);
      
      // If it's strictly a diagnosis/treatment block, we strongly guide the response
      // to focus purely on the safety aspect first.
      parts.push(`- The user explicitly requested: ${facts.medicalSafety}. Do NOT fulfill this clinical request.`);
    }

    // 5. Discussion Mode Injection
    if (facts.discussionMode === 'respectful_challenge') {
      parts.push(MANDATES.CHALLENGE_MODE);
    }

    // 6. Detected Entities Context (Placeholder for future RAG)
    if (facts.detectedEntities.length > 0) {
      parts.push(`- The following domain entities were detected in the query: ${facts.detectedEntities.join(', ')}.`);
      parts.push(`- NOTE: The retrieval layer is currently inactive. Do not fabricate Hadith texts for these entities.`);
    }

    return this.buildResult(parts.join('\n\n'));
  }

  private buildResult(explanationContext: string): ThemeResult {
    return {
      success: true,
      result: null,
      warnings: [],
      errors: [],
      explanationContext,
      metadata: {}
    };
  }
}
