import type { RiskLevel, ConfidenceLevel, SafetyInputType, SafetyReport } from '@/lib/safety/types';
import type { UnifiedSecurityReport } from '@/lib/safety/unified/types';

export type IntegrationStatus = 'connected' | 'disconnected' | 'revoked' | 'error';

export type ExportableSecurityReport =
  | UnifiedSecurityReport
  | SafetyReport
  | (Record<string, unknown> & { id?: string; analysisId?: string });

export interface GoogleSheetsConfig {
  spreadsheetId: string;
  spreadsheetName?: string;
  sheetName: string;
}

export interface GoogleSheetsTokens {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;
  scope?: string;
}

export interface GoogleSheetsExportRow {
  timestamp: string;
  analysis_id: string;
  user_id_hash: string;
  input_type: SafetyInputType;
  theme: string;
  risk_level: RiskLevel;
  risk_score: number;
  confidence_level: ConfidenceLevel;
  primary_concern: string;
  domains_involved: string;
  finding_count: number;
  recommendation_count: number;
  analyzer_coverage: string;
  status: string;
  created_at: string;
}

export interface GoogleSheetsStatusResponse {
  connected: boolean;
  status: IntegrationStatus;
  spreadsheetId: string | null;
  spreadsheetName: string | null;
  sheetName: string;
  lastSyncedAt: string | null;
  lastError: string | null;
}

export interface GoogleOAuthStatePayload {
  userId: string;
  nonce: string;
  timestamp: number;
}
