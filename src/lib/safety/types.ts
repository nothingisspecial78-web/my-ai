/**
 * Safety & Security Domain Types
 * 
 * Core domain taxonomy and data structures for MyAI Safety & Security analysis.
 * Explicitly separates deterministic signals, risk levels, and confidence levels.
 */

// Supported safety input classifications
export type SafetyInputType =
  | 'url'
  | 'message'
  | 'email'
  | 'image'
  | 'screenshot'
  | 'document'
  | 'file'
  | 'qr'
  | 'website'
  | 'code'
  | 'claim'
  | 'social_post';

// Specialized analyzer identifiers
export type AnalyzerType =
  | 'url'
  | 'phishing'
  | 'spam'
  | 'scam'
  | 'domain'
  | 'redirect'
  | 'qr'
  | 'image_ai'
  | 'image_manipulation'
  | 'document'
  | 'file'
  | 'email'
  | 'message'
  | 'claim'
  | 'code_security'
  | 'website';

// Deterministic risk level
// Note: Risk and confidence are distinct dimensions.
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical' | 'unknown';

// Assessment confidence level
export type ConfidenceLevel = 'low' | 'medium' | 'high';

// Severity of an individual finding
export type FindingSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

// Standardized finding types
export type FindingType =
  | 'suspicious_domain'
  | 'lookalike_domain'
  | 'lookalike_brand'
  | 'suspicious_keyword'
  | 'host_confusion'
  | 'private_network_host'
  | 'excessive_subdomains'
  | 'excessive_encoding'
  | 'suspicious_redirect'
  | 'insecure_protocol'
  | 'ip_as_host'
  | 'shortened_url'
  | 'credential_in_url'
  | 'credential_request'
  | 'urgency_language'
  | 'threat_coercion'
  | 'financial_request'
  | 'prize_lure'
  | 'otp_request'
  | 'authority_impersonation'
  | 'suspicious_attachment'
  | 'suspicious_qr'
  | 'possible_ai_generated'
  | 'possible_manipulation'
  | 'metadata_anomaly'
  | 'suspicious_code'
  | 'exposed_secret'
  | 'dangerous_function'
  | 'sql_injection_pattern'
  | 'command_injection_pattern'
  | 'phishing_indicator'
  | 'scam_indicator'
  | 'unverified_claim'
  | 'syntax_anomaly'
  | 'reputation_malicious'
  | 'reputation_suspicious'
  | 'reputation_disputed'
  | 'reputation_clean';

// Source of an evidence item
export type EvidenceSourceType =
  | 'deterministic_rule'
  | 'metadata'
  | 'url_analysis'
  | 'domain_analysis'
  | 'reputation_provider'
  | 'redirect_analysis'
  | 'image_analysis'
  | 'file_analysis'
  | 'content_analysis'
  | 'user_provided_context'
  | 'external_security_provider'
  | 'ai_assessment';

// Status of a safety analysis
export type AnalysisStatus = 'pending' | 'analyzing' | 'completed' | 'failed';

// Structured recommendation actions
export type RecommendationAction =
  | 'do_not_click'
  | 'do_not_download'
  | 'do_not_share_otp'
  | 'do_not_enter_password'
  | 'verify_sender'
  | 'verify_domain'
  | 'verify_destination_host'
  | 'verify_financial_claim'
  | 'use_https'
  | 'contact_official_source'
  | 'scan_file_before_opening'
  | 'change_password'
  | 'rotate_exposed_secret'
  | 'seek_security_professional_help'
  | 'avoid_known_malicious_url'
  | 'verify_reported_threat'
  | 'proceed_with_caution'
  | 'no_action_needed';

// Claim verification status for information/claim checking
export type ClaimVerificationStatus =
  | 'verified'
  | 'likely_true'
  | 'unverified'
  | 'disputed'
  | 'likely_false'
  | 'unknown';

// Probabilistic AI content assessment (never absolute)
export type AiContentAssessment =
  | 'likely_ai_generated'
  | 'possibly_ai_generated'
  | 'no_strong_ai_signal'
  | 'unknown';

/**
 * Raw or normalized safety input
 */
export interface SafetyInput {
  type?: SafetyInputType;
  rawContent: string;
  metadata?: Record<string, unknown>;
  mimeType?: string;
  filename?: string;
  sourceContext?: string;
}

/**
 * Individual observable finding discovered by an analyzer.
 */
export interface Finding {
  id: string;
  type: FindingType;
  severity: FindingSeverity;
  title: string;
  description: string;
  evidenceIds?: string[];
  confidence: ConfidenceLevel;
  metadata?: Record<string, unknown>;
}

/**
 * Evidence item backing a finding.
 * Explicitly tracks whether evidence was deterministically derived or AI-generated.
 */
export interface Evidence {
  id: string;
  sourceType: EvidenceSourceType;
  sourceName: string;
  label?: string;
  snippet?: string;
  description: string;
  data: Record<string, unknown>;
  isAiGenerated: boolean;
  createdAt: string;
}

/**
 * Structured, actionable recommendation for the user.
 */
export interface Recommendation {
  action: RecommendationAction;
  title: string;
  description: string;
  priority: 'low' | 'medium' | 'high';
}

/**
 * Output of a single specialized analyzer run.
 */
export interface AnalyzerResult {
  analyzerId: string;
  analyzerType: AnalyzerType;
  status: 'success' | 'partial' | 'failed' | 'skipped';
  confidence: ConfidenceLevel;
  findings: Finding[];
  evidence: Evidence[];
  metadata?: Record<string, unknown>;
  limitations?: string[];
  error?: string;
}

/**
 * Complete consolidated safety report.
 */
export interface SafetyReport {
  analysisId: string;
  inputType: SafetyInputType;
  status: AnalysisStatus;
  riskLevel: RiskLevel;
  confidenceLevel: ConfidenceLevel;
  score?: number; // Internal heuristic score (0-100), not an absolute certainty metric
  summary: string;
  findings: Finding[];
  evidence: Evidence[];
  recommendations: Recommendation[];
  limitations: string[];
  analyzerResults: AnalyzerResult[];
  createdAt: string;
}
