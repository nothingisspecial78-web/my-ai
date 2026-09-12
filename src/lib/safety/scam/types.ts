/**
 * Scam Message Intelligence Types (Phase 6.2)
 * 
 * Defines domain structures, threat taxonomy, social engineering tactics,
 * entity recognition models, and structured results for message analysis.
 */

import {
  Finding,
  Evidence,
  Recommendation,
  RiskLevel,
  ConfidenceLevel,
} from '../types';

export type ScamCategory =
  | 'phishing'
  | 'credential_harvesting'
  | 'otp_fraud'
  | 'financial_scam'
  | 'advance_fee'
  | 'prize_lottery'
  | 'job_employment'
  | 'delivery_parcel'
  | 'impersonation'
  | 'kyc_account_block'
  | 'payment_manipulation'
  | 'social_engineering';

export type SocialEngineeringTactic =
  | 'urgency'
  | 'fear_threat'
  | 'authority_pressure'
  | 'reward_temptation'
  | 'scarcity'
  | 'secrecy'
  | 'emotional_manipulation'
  | 'financial_pressure'
  | 'credential_pressure';

export type ClaimedEntityCategory =
  | 'banking'
  | 'technology'
  | 'government'
  | 'courier'
  | 'corporate_hr'
  | 'platform';

export interface ClaimedEntity {
  name: string;
  category: ClaimedEntityCategory;
  matchedText: string;
  description: string;
}

export interface ExtractedContacts {
  phoneNumbers: string[];
  emails: string[];
  urls: string[];
}

export interface ScamSignal {
  category: ScamCategory;
  tactic?: SocialEngineeringTactic;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  weight: number;
  title: string;
  description: string;
  evidenceSnippet?: string;
  dedupGroup: string; // Grouping key to prevent double-counting correlated phrases
}

export interface ScamAnalysisResult {
  riskLevel: RiskLevel;
  score: number;
  confidence: ConfidenceLevel;
  categories: ScamCategory[];
  tactics: SocialEngineeringTactic[];
  signals: ScamSignal[];
  findings: Finding[];
  evidence: Evidence[];
  claimedEntities: ClaimedEntity[];
  contacts: ExtractedContacts;
  warningSigns: string[];
  recommendations: Recommendation[];
  limitations: string[];
}
