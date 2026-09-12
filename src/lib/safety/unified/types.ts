/**
 * Unified Security Intelligence Architecture — Types (Stage 8.1, 8.2, 8.3)
 *
 * Defines core unified evidence domains, source attribution models,
 * normalized unified evidence structures, privacy tags, consolidated findings,
 * and the Unified Security Report contract.
 *
 * Backward-compatible with existing SafetyReport, Finding, and Evidence types.
 */

import {
  Evidence,
  Finding,
  FindingSeverity,
  ConfidenceLevel,
  SafetyInputType,
  AnalysisStatus,
  Recommendation,
  AnalyzerResult,
  RiskLevel,
  SafetyReport,
} from '../types';

/**
 * Type-safe evidence domain classification.
 * Directly maps to existing specialized safety subsystems without duplication.
 */
export type UnifiedEvidenceDomain =
  | 'url'            // URL structural, lexical, and live reputation intelligence
  | 'scam'           // Scam message indicators, social engineering, entity impersonation
  | 'code'           // Code vulnerabilities, AST patterns, injection risks
  | 'secret'         // Exposed credentials, API keys, private tokens, entropy anomalies
  | 'image'          // Visual media metadata, dimensions, container integrity
  | 'ocr'            // Visual text and alphanumeric layout extracted via Gemini Vision
  | 'qr'             // Decoded QR payloads, URI schemes, quishing indicators
  | 'authenticity'   // Visual consistency, manipulation indicators, synthetic media cues
  | 'privacy'        // Redaction observations and privacy protection disclosures
  | 'system';        // Orchestration status, timeouts, processing limitations

/**
 * Origin type indicating the physical or logical source of evidence.
 */
export type SourceOriginType =
  | 'user_text'          // Primary user prompt or message body
  | 'code_block'         // Code snippet identified within message or attachment
  | 'image_attachment'   // Uploaded raster visual attachment
  | 'ocr_text'           // Text visually detected within an image
  | 'qr_code'            // Decoded payload from an optical matrix barcode
  | 'embedded_url'       // URL parsed out of message text, document, or code
  | 'file_attachment'    // Document, text, or file attachment
  | 'metadata'           // File header, EXIF, or structural container metadata
  | 'system';            // Pipeline runtime or orchestrator context

/**
 * Bounded, privacy-safe source attribution.
 * Identifies where evidence originated without leaking sensitive contents.
 */
export interface SourceAttribution {
  origin: SourceOriginType;
  domain: UnifiedEvidenceDomain;
  analyzerId?: string;
  attachmentName?: string;
  attachmentId?: string;
  lineRange?: { start: number; end: number };
  snippet?: string; // Bounded (<=200 chars), privacy-redacted preview
}

/**
 * Standardized privacy disclosure tags.
 */
export type PrivacyTag =
  | 'redacted_api_key'
  | 'redacted_auth_token'
  | 'redacted_password'
  | 'redacted_otp'
  | 'redacted_wifi_credentials'
  | 'redacted_otpauth_secret'
  | 'redacted_private_key'
  | 'redacted_db_uri'
  | 'redacted_url_params'
  | 'redacted_credit_card'
  | 'redacted_seed_phrase'
  | 'redacted_gps_coordinates'
  | 'redacted_device_id';

/**
 * Normalized Unified Evidence item.
 * Structurally compatible with the existing Evidence contract while providing
 * domain attribution, source origin, privacy disclosures, and deterministic ordering.
 */
export interface UnifiedEvidence extends Evidence {
  /** High-level intelligence domain */
  domain: UnifiedEvidenceDomain;
  /** Granular source attribution details */
  source: SourceAttribution;
  /** Domain category or signal classifier */
  category: string;
  /** Associated severity if provided by domain analyzer */
  severity?: FindingSeverity;
  /** Assessment confidence level */
  confidence?: ConfidenceLevel;
  /** Bounded, sanitized display value */
  sanitizedValue?: string;
  /** Active privacy protection flags */
  privacyTags: PrivacyTag[];
  /** Associated finding IDs if linked */
  relatedFindingIds?: string[];
  /** Associated entity or target token (e.g. domain name, secret type) */
  relatedEntity?: string;
}

/**
 * Options for normalizing evidence into the unified representation.
 */
export interface NormalizationOptions {
  domain?: UnifiedEvidenceDomain;
  origin?: SourceOriginType;
  category?: string;
  severity?: FindingSeverity;
  confidence?: ConfidenceLevel;
  analyzerId?: string;
  attachmentName?: string;
  attachmentId?: string;
  lineRange?: { start: number; end: number };
  relatedFindingIds?: string[];
  relatedEntity?: string;
  maxSnippetLength?: number;
  maxSummaryLength?: number;
  maxDescriptionLength?: number;
}

/**
 * A consolidated security finding representing a single canonical security issue or entity.
 * Directly compatible with Finding so RiskEngine can consume it without modification.
 */
export interface ConsolidatedFinding extends Finding {
  /** Deterministic canonical ID (e.g. fnd_<domain>_<hash16>) */
  id: string;
  /** Primary intelligence domain */
  domain: UnifiedEvidenceDomain;
  /** Canonical entity target (e.g. normalized URL, secret class, or tactic identifier) */
  targetEntity?: string;
  /** All source attributions that observed or contributed to this finding */
  sources: SourceAttribution[];
  /** Preserved IDs of all underlying evidence items */
  evidenceIds: string[];
  /** Correlated finding IDs that form an attack scenario cluster */
  correlatedFindingIds?: string[];
  /** Correlation explanation / tag if part of a multi-modal cluster */
  correlationTag?: string;
  /** Count of distinct observations collapsed into this finding */
  observationCount: number;
}

/**
 * Result of the finding and evidence consolidation pipeline.
 */
export interface ConsolidationResult {
  consolidatedFindings: ConsolidatedFinding[];
  consolidatedEvidence: UnifiedEvidence[];
  domainsInvolved: UnifiedEvidenceDomain[];
  totalRawObservations: number;
  totalConsolidatedFindings: number;
}

/**
 * Configuration options for the FindingConsolidator.
 */
export interface ConsolidationOptions {
  maxFindings?: number;
  maxEvidencePerFinding?: number;
  maxSourcesPerFinding?: number;
  maxCorrelatedPerFinding?: number;
}

/**
 * Unified Security Report (Stage 8.3)
 *
 * Orchestrated security intelligence presentation uniting all findings,
 * evidence, provenance, and actionable recommendations.
 *
 * The authoritative risk score and risk level are strictly derived from RiskEngine.
 */
export interface UnifiedSecurityReport {
  /** Deterministic report identifier */
  id: string;
  /** Primary classified input type */
  inputType: SafetyInputType;
  /** Status of analysis ('completed' | 'failed' | 'partial') */
  status: AnalysisStatus;
  /** Authoritative risk level from RiskEngine */
  riskLevel: RiskLevel;
  /** Authoritative risk score (0-100) from RiskEngine */
  score: number;
  /** Authoritative confidence level from RiskEngine */
  confidenceLevel: ConfidenceLevel;
  /** Concise plain-language primary security concern */
  primaryConcern: string;
  /** Executive narrative summary */
  summary: string;
  /** Deduplicated, source-attributed findings */
  findings: ConsolidatedFinding[];
  /** Normalized, bounded, privacy-redacted evidence */
  evidence: UnifiedEvidence[];
  /** Consolidated, deduplicated actionable recommendations */
  recommendations: Recommendation[];
  /** Transparent limitations and boundary disclaimers */
  limitations: string[];
  /** Participating intelligence domains */
  domainsInvolved: UnifiedEvidenceDomain[];
  /** Human-readable analyzer contribution summary */
  analyzerSummaries: string[];
  /** Human-readable correlation notes */
  correlationSummaries: string[];
  /** Affected target entities (domains, URLs, secret types) */
  affectedEntities: string[];
  /** Privacy disclosure tags applied across report content */
  privacyGuarantees: PrivacyTag[];
  /** Raw underlying analyzer results */
  analyzerResults: AnalyzerResult[];
  /** ISO timestamp */
  createdAt: string;
  /** Backward-compatible export to standard SafetyReport */
  toSafetyReport(): SafetyReport;
}

/**
 * Input arguments for building a UnifiedSecurityReport.
 */
export interface BuildReportOptions {
  inputType?: SafetyInputType;
  findings: Finding[];
  evidence?: (Evidence | UnifiedEvidence)[];
  analyzerResults?: AnalyzerResult[];
  limitations?: string[];
  sourceContext?: string;
  status?: AnalysisStatus;
  createdAt?: string;
}

/**
 * Execution options for multi-input orchestration (Stage 8.4).
 */
export interface OrchestrationExecutionOptions {
  /** Skip visual OCR (e.g. if Gemini API is disabled or not configured) */
  skipOcr?: boolean;
  /** Skip QR code scanning */
  skipQr?: boolean;
  /** Skip scam / social engineering analysis */
  skipScam?: boolean;
  /** Skip authenticity & manipulation heuristic analysis */
  skipAuthenticity?: boolean;
  /** Skip live reputation lookups */
  skipReputation?: boolean;
  /** Maximum attachments to process (default: 3) */
  maxAttachments?: number;
  /** Maximum character length for text input (default: 50,000) */
  maxTextLength?: number;
  /** Maximum URLs to extract and analyze (default: 15) */
  maxUrls?: number;
  /** Optional timeout override in milliseconds */
  timeoutMs?: number;
}

/**
 * Target input for the Multi-Input Security Orchestrator (Stage 8.4).
 */
export interface MultiInputTarget {
  /** Primary text, message content, or prompt */
  text?: string;
  /** Explicit safety input type if predetermined */
  inputType?: SafetyInputType;
  /** Media, image, or document attachments */
  attachments?: import('@/lib/ai/types').Attachment[];
  /** Originating context (e.g. 'direct_prompt', 'conversation_turn', 'attachment') */
  sourceContext?: string;
  /** Optional metadata dictionary */
  metadata?: Record<string, unknown>;
  /** Execution tuning options */
  options?: OrchestrationExecutionOptions;
}

/**
 * Result returned by the Multi-Input Security Orchestrator (Stage 8.4).
 */
export interface OrchestrationResult {
  /** Authoritative Unified Security Report */
  report: UnifiedSecurityReport;
  /** Analyzers that successfully contributed to the report */
  contributingAnalyzers: string[];
  /** Execution metrics and performance breakdown */
  executionStats: {
    durationMs: number;
    attachmentsProcessed: number;
    urlsAnalyzed: number;
    duplicateUrlsSkipped: number;
    errorsEncountered: number;
  };
}
