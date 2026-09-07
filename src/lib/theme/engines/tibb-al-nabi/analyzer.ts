import { ThemeAnalyzer, ThemeContext } from '../../engine';
import { Message } from '@/lib/ai/types';
import {
  TibbAlNabiContext,
  PrimaryIntent,
  MedicalSafety,
  DiscussionMode,
  RequestLanguage,
  DomainEntity
} from './types';
import {
  ENTITY_KEYWORDS,
  REGEX_DIAGNOSTIC,
  REGEX_TREATMENT,
  REGEX_DOSAGE,
  REGEX_CHALLENGE,
  REGEX_DOMAIN_GENERAL
} from './constants';

export class TibbAlNabiAnalyzer implements ThemeAnalyzer {
  async analyze(input: string, history: Message[]): Promise<Partial<ThemeContext>> {
    // 1. Detect language
    let language: RequestLanguage = 'auto';
    if (/[\u0600-\u06FF]/.test(input)) language = 'arabic';
    else if (/[\u0D00-\u0D7F]/.test(input)) language = 'malayalam';
    else if (/[a-zA-Z]/.test(input)) language = 'english';

    // 2. Detect entities
    const detectedEntities: DomainEntity[] = [];
    const lowerInput = input.toLowerCase();
    for (const [entityKey, keywords] of Object.entries(ENTITY_KEYWORDS)) {
      if (keywords.some(kw => lowerInput.includes(kw))) {
        detectedEntities.push(entityKey as DomainEntity);
      }
    }

    // 3. Detect Medical Safety & Intent
    let medicalSafety: MedicalSafety = 'none';
    let primaryIntent: PrimaryIntent = 'informational';
    let discussionMode: DiscussionMode = 'normal';

    const hasImage = history.some(m => 
      m.role === 'user' && 
      (m.content.includes('data:image') || m.content.includes('cloudinary.com'))
    );

    if (REGEX_DIAGNOSTIC.test(input)) {
      medicalSafety = 'diagnostic_request';
      primaryIntent = 'informational'; // Though it's a diag request, intent is to get info
    } else if (REGEX_TREATMENT.test(input)) {
      medicalSafety = 'treatment_request';
    } else if (REGEX_DOSAGE.test(input)) {
      medicalSafety = 'dosage_request';
    } else if (hasImage && (REGEX_DOMAIN_GENERAL.test(input) || lowerInput.includes('what is this'))) {
      medicalSafety = 'image_health_request';
    } else if (lowerInput.includes('benefit') || lowerInput.includes('healthy')) {
      medicalSafety = 'health_information';
    }

    if (REGEX_CHALLENGE.test(input)) {
      primaryIntent = 'challenge';
      discussionMode = 'respectful_challenge';
    } else if (!REGEX_DOMAIN_GENERAL.test(input) && detectedEntities.length === 0 && medicalSafety === 'none') {
      primaryIntent = 'unrelated';
    } else if (lowerInput.includes('hadith') || lowerInput.includes('quran')) {
      primaryIntent = 'scholarly';
    }

    const facts: TibbAlNabiContext['facts'] = {
      primaryIntent,
      medicalSafety,
      sourceRequirement: 'exact_source_required', // Strict requirement for Phase 4.3
      evidenceRequirement: 'both',
      discussionMode,
      language,
      audience: 'general', // Default for now
      detectedEntities
    };

    return {
      intent: primaryIntent,
      entities: detectedEntities,
      facts: facts as unknown as Record<string, unknown>
    };
  }
}
