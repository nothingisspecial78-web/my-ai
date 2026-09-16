import type { ExportableSecurityReport } from './types';
import { GoogleSheetsExportSanitizer } from './sanitizer';
import { GoogleSheetsRepository } from './repository';
import { GoogleSheetsClient } from './client';
import { decryptToken } from './crypto';

export interface ExportResult {
  exported: boolean;
  reason?: string;
  error?: string;
}

export type { ExportableSecurityReport };

export async function exportReportToGoogleSheets(
  report: ExportableSecurityReport,
  userId: string,
  themeSlug?: string
): Promise<ExportResult> {
  const r = report as { id?: string; analysisId?: string };
  const reportId = r?.id || r?.analysisId;
  if (!report || !reportId || !userId) {
    return { exported: false, reason: 'missing_report_or_user' };
  }
  try {
    const integration = await GoogleSheetsRepository.getIntegration(userId);
    if (!integration || integration.status !== 'connected' || !integration.spreadsheet_id) {
      return { exported: false, reason: 'not_connected' };
    }

    const alreadyExported = await GoogleSheetsRepository.isExported(userId, reportId);
    if (alreadyExported) {
      return { exported: false, reason: 'already_exported' };
    }

    if (!integration.encrypted_refresh_token || !integration.token_iv || !integration.token_tag) {
      await GoogleSheetsRepository.updateStatus(userId, 'error', 'Missing stored credentials');
      return { exported: false, reason: 'missing_credentials' };
    }

    let refreshToken: string;
    try {
      refreshToken = decryptToken(
        integration.encrypted_refresh_token,
        integration.token_iv,
        integration.token_tag
      );
    } catch {
      await GoogleSheetsRepository.updateStatus(userId, 'error', 'Failed to decrypt credentials');
      return { exported: false, reason: 'decryption_failure' };
    }

    let accessToken: string;
    try {
      const tokens = await GoogleSheetsClient.refreshAccessToken(refreshToken);
      accessToken = tokens.accessToken;
    } catch (tokenErr: unknown) {
      const errObj = tokenErr as { isInvalidGrant?: boolean; message?: string };
      if (errObj?.isInvalidGrant) {
        await GoogleSheetsRepository.updateStatus(userId, 'revoked', 'Google access revoked');
        return { exported: false, reason: 'revoked' };
      }
      await GoogleSheetsRepository.updateStatus(userId, 'error', 'Token refresh failed');
      return { exported: false, reason: 'token_refresh_failed' };
    }

    const sanitizedRow = GoogleSheetsExportSanitizer.sanitize(report, userId, themeSlug);
    const rowValues = GoogleSheetsExportSanitizer.toRowArray(sanitizedRow);

    const sheetName = integration.sheet_name || 'Security Telemetry';
    await GoogleSheetsClient.appendRow(accessToken, integration.spreadsheet_id, sheetName, rowValues);

    await GoogleSheetsRepository.recordExportSuccess(
      userId,
      reportId,
      integration.spreadsheet_id,
      sheetName
    );

    return { exported: true };
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err);
    console.warn('[GoogleSheetsExporter] Export failed non-critically:', errMsg);
    try {
      await GoogleSheetsRepository.updateStatus(userId, 'error', errMsg.slice(0, 200));
    } catch {
      // Non-critical
    }
    return { exported: false, reason: 'error', error: errMsg };
  }
}
