import { ThemeContext } from '../../engine';

export type PrimaryIntent =
  | 'informational'
  | 'scholarly'
  | 'challenge'
  | 'study'
  | 'research'
  | 'unrelated';

export type MedicalSafety =
  | 'none'
  | 'health_information'
  | 'diagnostic_request'
  | 'treatment_request'
  | 'dosage_request'
  | 'image_health_request';

export type SourceRequirement =
  | 'none'
  | 'source_preferred'
  | 'exact_source_required';

export type EvidenceRequirement =
  | 'none'
  | 'traditional_context'
  | 'scientific_context'
  | 'both';

export type DiscussionMode =
  | 'normal'
  | 'respectful_challenge';

export type RequestLanguage = 'arabic' | 'malayalam' | 'english' | 'auto';

export type AudienceLevel = 'child' | 'student' | 'general' | 'scholar';

export type DomainEntity =
  | 'honey'
  | 'black_seed'
  | 'dates'
  | 'olive'
  | 'olive_oil'
  | 'talbinah'
  | 'hijamah'
  | 'zamzam'
  | 'ruqyah'
  | 'hygiene'
  | 'sleep'
  | 'food'
  | 'drink'
  | 'herbs'
  | 'other';

export interface TibbAlNabiContext extends ThemeContext {
  facts: {
    primaryIntent: PrimaryIntent;
    medicalSafety: MedicalSafety;
    sourceRequirement: SourceRequirement;
    evidenceRequirement: EvidenceRequirement;
    discussionMode: DiscussionMode;
    language: RequestLanguage;
    audience: AudienceLevel;
    detectedEntities: DomainEntity[];
  };
}
