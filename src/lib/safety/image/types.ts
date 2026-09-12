import { Finding, Evidence, Recommendation, RiskLevel, ConfidenceLevel } from '@/lib/safety/types';
import { Attachment } from '@/lib/ai/types';
import { LoadedImageContent } from '@/lib/attachments/loader';

export interface ImageAnalysisInput {
  attachment: Attachment;
  loadedImage?: LoadedImageContent;
  sourceContext?: 'attachment' | 'direct_upload';
}

export interface VisualOcrLine {
  line: number;
  text: string;
}

export type DetectedAppType =
  | 'banking'
  | 'courier'
  | 'crypto_wallet'
  | 'chat'
  | 'payment_slip'
  | 'social_media'
  | 'system_dialog'
  | 'general';

export interface VisualOcrExtractionResult {
  hasText: boolean;
  rawText: string;
  lines: VisualOcrLine[];
  visualContext: {
    isScreenshot: boolean;
    detectedAppType?: DetectedAppType;
    suspiciousVisualCues: string[];
    possibleManipulationCues: string[];
  };
}

export interface SanitizedOcrResult {
  status: 'available' | 'unavailable' | 'empty';
  hasText: boolean;
  sanitizedText: string;
  lines: VisualOcrLine[];
  characterCount: number;
  lineCount: number;
  truncated: boolean;
  visualContext: {
    isScreenshot: boolean;
    detectedAppType?: DetectedAppType;
    suspiciousVisualCues: string[];
    possibleManipulationCues: string[];
  };
  extractedUrls: string[];
  limitations: string[];
}

export type QrPayloadType =
  | 'https_url'
  | 'http_url'
  | 'javascript_uri'
  | 'data_uri'
  | 'file_uri'
  | 'intent_uri'
  | 'mailto_uri'
  | 'tel_uri'
  | 'sms_uri'
  | 'wifi'
  | 'otpauth'
  | 'unknown_scheme'
  | 'plain_text';

export interface QrWifiMetadata {
  authType: 'WPA' | 'WEP' | 'nopass' | string;
  ssid: string;
  isHidden?: boolean;
}

export interface QrOtpauthMetadata {
  type: 'totp' | 'hotp' | string;
  account: string;
  issuer?: string;
  algorithm?: string;
  digits?: number;
  period?: number;
}

export interface SanitizedQrCode {
  id: string;
  rawPayload: string;
  sanitizedPayload: string;
  payloadType: QrPayloadType;
  characterCount: number;
  truncated: boolean;
  delegatedUrl?: string;
  wifiMetadata?: QrWifiMetadata;
  otpauthMetadata?: QrOtpauthMetadata;
  isDangerousScheme: boolean;
  hasEmbeddedCredentials?: boolean;
  quishingRisk?: 'critical' | 'high' | 'medium' | 'none';
}

export interface SanitizedQrAnalysisResult {
  status: 'available' | 'empty' | 'unsupported';
  detectedCount: number;
  qrCodes: SanitizedQrCode[];
  delegatedUrls: string[];
  limitations: string[];
}

export type VisualScamCategory =
  | 'fake_banking'
  | 'fake_courier'
  | 'account_suspension'
  | 'kyc_verification'
  | 'prize_reward'
  | 'crypto_fraud'
  | 'fake_customer_support'
  | 'login_credential_harvesting'
  | 'government_service_impersonation'
  | 'social_media_warning'
  | 'urgent_action_required'
  | 'suspicious_payment_slip'
  | 'general_visual_fraud';

export interface VisualScamSignal {
  category: VisualScamCategory;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  findingType: Finding['type'];
  confidence: ConfidenceLevel;
  evidenceSnippet?: string;
  dedupKey: string;
}

export interface SanitizedVisualScamResult {
  status: 'clean' | 'suspicious' | 'inconclusive';
  isScreenshot: boolean;
  detectedAppType?: DetectedAppType;
  detectedCategories: VisualScamCategory[];
  signals: VisualScamSignal[];
  findings: Finding[];
  evidence: Evidence[];
  recommendations: Recommendation[];
  limitations: string[];
}

export type AuthenticitySignalType =
  | 'possible_ai_generated'
  | 'possible_manipulation'
  | 'metadata_anomaly'
  | 'dimension_anomaly'
  | 'compression_anomaly';

export interface AuthenticitySignal {
  type: AuthenticitySignalType;
  findingType: Finding['type'];
  severity: 'medium' | 'low' | 'info';
  confidence: 'medium' | 'low';
  title: string;
  description: string;
  evidenceSnippet?: string;
  dedupKey: string;
}

export interface SanitizedMetadataSummary {
  hasExif: boolean;
  hasXmp: boolean;
  hasSoftwareTag: boolean;
  software?: string;
  cameraMake?: string;
  cameraModel?: string;
  createDate?: string;
  modifyDate?: string;
  hasGpsData: boolean; // Flagged true if GPS was present; coordinates are REDACTED and never exposed
  dimensionsConsistent: boolean;
  suspiciousChunks: string[];
}

export interface SanitizedAuthenticityResult {
  status: 'clean' | 'suspicious' | 'inconclusive';
  hasSyntheticIndicators: boolean;
  hasManipulationIndicators: boolean;
  signals: AuthenticitySignal[];
  findings: Finding[];
  evidence: Evidence[];
  metadataSummary: SanitizedMetadataSummary;
  recommendations: Recommendation[];
  limitations: string[];
}

export interface ImageEngineResult {
  status: 'completed' | 'failed';
  riskLevel: RiskLevel;
  confidenceLevel: ConfidenceLevel;
  score: number;
  summary: string;
  findings: Finding[];
  evidence: Evidence[];
  recommendations: Recommendation[];
  limitations: string[];
  metadata: {
    filename: string;
    mimeType: string;
    format: 'jpeg' | 'png' | 'webp' | 'unknown';
    sizeBytes: number;
    width?: number;
    height?: number;
    aspectRatio?: number;
    isDecompressionRisk?: boolean;
    stage: '7.1_foundation' | '7.2_ocr' | '7.3_qr' | '7.4_scam' | '7.5_authenticity';
    ocr?: {
      status: 'available' | 'unavailable' | 'empty';
      hasText: boolean;
      characterCount: number;
      lineCount: number;
      truncated: boolean;
      detectedAppType?: DetectedAppType;
      extractedUrlCount: number;
      extractedSnippet?: string;
    };
    qr?: {
      status: 'available' | 'empty' | 'unsupported';
      detectedCount: number;
      payloadTypes: QrPayloadType[];
      hasDangerousScheme: boolean;
      hasQuishingRisk: boolean;
    };
    visualScam?: {
      status: 'clean' | 'suspicious' | 'inconclusive';
      isScreenshot: boolean;
      categories: VisualScamCategory[];
      signalCount: number;
    };
    authenticity?: {
      status: 'clean' | 'suspicious' | 'inconclusive';
      hasSyntheticIndicators: boolean;
      hasManipulationIndicators: boolean;
      hasGpsData: boolean;
      signalCount: number;
    };
  };
}

