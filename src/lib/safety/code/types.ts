/**
 * Code & Script Security Intelligence Types (Phase 6.3)
 * 
 * Defines domain types, vulnerability categories, secret classes,
 * language classifications, and structured results for static code analysis.
 */

import {
  Finding,
  Evidence,
  Recommendation,
  RiskLevel,
  ConfidenceLevel,
  FindingSeverity,
} from '../types';
import { UrlIntelligenceResult } from '../url';

export type ProgrammingLanguage =
  | 'javascript'
  | 'typescript'
  | 'python'
  | 'shell'
  | 'sql'
  | 'php'
  | 'go'
  | 'json'
  | 'yaml'
  | 'unknown';

export type SecretClass =
  | 'aws_access_key'
  | 'aws_secret_key'
  | 'github_token'
  | 'private_key'
  | 'stripe_key'
  | 'openai_key'
  | 'anthropic_key'
  | 'google_api_key'
  | 'database_uri'
  | 'slack_token'
  | 'discord_webhook'
  | 'bearer_token'
  | 'jwt_token'
  | 'generic_secret';

export type VulnerabilityCategory =
  | 'dynamic_execution'
  | 'command_injection'
  | 'sql_injection'
  | 'credential_exfiltration'
  | 'insecure_storage'
  | 'unsafe_deserialization'
  | 'path_traversal';

export interface ExtractedSecret {
  secretClass: SecretClass;
  label: string;
  redactedValue: string;
  lineNumber?: number;
  severity: FindingSeverity;
  confidence: ConfidenceLevel;
}

export interface VulnerabilityFinding {
  category: VulnerabilityCategory;
  title: string;
  description: string;
  severity: FindingSeverity;
  confidence: ConfidenceLevel;
  lineNumber?: number;
  snippet?: string;
  language?: ProgrammingLanguage;
  dedupGroup: string;
}

export interface CodeAnalysisResult {
  language: ProgrammingLanguage;
  languageConfidence: 'high' | 'medium' | 'low';
  findings: Finding[];
  evidence: Evidence[];
  extractedSecrets: ExtractedSecret[];
  vulnerabilities: VulnerabilityFinding[];
  embeddedUrls: string[];
  urlIntelligenceResults?: UrlIntelligenceResult[];
  riskLevel: RiskLevel;
  score: number;
  confidence: ConfidenceLevel;
  recommendations: Recommendation[];
  limitations: string[];
  truncated: boolean;
  characterCount: number;
}
