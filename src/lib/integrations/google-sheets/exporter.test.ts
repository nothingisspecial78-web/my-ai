import { describe, it, expect, vi, beforeEach } from 'vitest';
import { exportReportToGoogleSheets } from './exporter';
import { GoogleSheetsRepository } from './repository';
import { GoogleSheetsClient } from './client';
import * as cryptoModule from './crypto';
import type { UnifiedSecurityReport } from '@/lib/safety/unified/types';

vi.mock('./repository');
vi.mock('./client');

describe('exportReportToGoogleSheets', () => {
  const sampleReport: UnifiedSecurityReport = {
    id: 'report-xyz-999',
    inputType: 'url',
    status: 'completed',
    riskLevel: 'medium',
    score: 55,
    confidenceLevel: 'high',
    primaryConcern: 'Suspicious domain registration date.',
    summary: 'Medium risk domain.',
    findings: [],
    evidence: [],
    recommendations: [],
    limitations: [],
    domainsInvolved: ['url'],
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('fails safely if report or userId is missing', async () => {
    const res1 = await exportReportToGoogleSheets(null as unknown as UnifiedSecurityReport, 'user-1');
    expect(res1).toEqual({ exported: false, reason: 'missing_report_or_user' });

    const res2 = await exportReportToGoogleSheets(sampleReport, '');
    expect(res2).toEqual({ exported: false, reason: 'missing_report_or_user' });
  });

  it('fails safely if user has no connected Google Sheets integration', async () => {
    vi.mocked(GoogleSheetsRepository.getIntegration).mockResolvedValue(null);

    const res = await exportReportToGoogleSheets(sampleReport, 'user-1');
    expect(res).toEqual({ exported: false, reason: 'not_connected' });
  });

  it('skips export if analysis was already exported (idempotency)', async () => {
    vi.mocked(GoogleSheetsRepository.getIntegration).mockResolvedValue({
      id: 'int-1',
      user_id: 'user-1',
      status: 'connected',
      spreadsheet_id: 'sheet-123',
      sheet_name: 'Security Telemetry',
      spreadsheet_name: 'My Sheet',
      encrypted_refresh_token: 'enc',
      token_iv: 'iv',
      token_tag: 'tag',
      last_synced_at: null,
      last_error: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    vi.mocked(GoogleSheetsRepository.isExported).mockResolvedValue(true);

    const res = await exportReportToGoogleSheets(sampleReport, 'user-1');
    expect(res).toEqual({ exported: false, reason: 'already_exported' });
    expect(GoogleSheetsClient.appendRow).not.toHaveBeenCalled();
  });

  it('successfully exports when connected and not yet exported', async () => {
    vi.mocked(GoogleSheetsRepository.getIntegration).mockResolvedValue({
      id: 'int-1',
      user_id: 'user-1',
      status: 'connected',
      spreadsheet_id: 'sheet-123',
      sheet_name: 'Security Telemetry',
      spreadsheet_name: 'My Sheet',
      encrypted_refresh_token: 'enc',
      token_iv: 'iv',
      token_tag: 'tag',
      last_synced_at: null,
      last_error: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    vi.mocked(GoogleSheetsRepository.isExported).mockResolvedValue(false);
    vi.spyOn(cryptoModule, 'decryptToken').mockReturnValue('decrypted-refresh-token');
    vi.mocked(GoogleSheetsClient.refreshAccessToken).mockResolvedValue({
      accessToken: 'valid-access-token',
      expiresAt: Date.now() + 3600000,
    });
    vi.mocked(GoogleSheetsClient.appendRow).mockResolvedValue({ updatedRows: 1 });
    vi.mocked(GoogleSheetsRepository.recordExportSuccess).mockResolvedValue(true);

    const res = await exportReportToGoogleSheets(sampleReport, 'user-1', 'security-checkup');

    expect(res).toEqual({ exported: true });
    expect(GoogleSheetsClient.appendRow).toHaveBeenCalled();
    expect(GoogleSheetsRepository.recordExportSuccess).toHaveBeenCalledWith(
      'user-1',
      'report-xyz-999',
      'sheet-123',
      'Security Telemetry'
    );
  });

  it('updates status to revoked when refresh token returns invalid_grant', async () => {
    vi.mocked(GoogleSheetsRepository.getIntegration).mockResolvedValue({
      id: 'int-1',
      user_id: 'user-1',
      status: 'connected',
      spreadsheet_id: 'sheet-123',
      sheet_name: 'Security Telemetry',
      spreadsheet_name: 'My Sheet',
      encrypted_refresh_token: 'enc',
      token_iv: 'iv',
      token_tag: 'tag',
      last_synced_at: null,
      last_error: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    vi.mocked(GoogleSheetsRepository.isExported).mockResolvedValue(false);
    vi.spyOn(cryptoModule, 'decryptToken').mockReturnValue('decrypted-refresh-token');
    vi.mocked(GoogleSheetsClient.refreshAccessToken).mockRejectedValue({
      isInvalidGrant: true,
      message: 'invalid_grant',
    });

    const res = await exportReportToGoogleSheets(sampleReport, 'user-1');

    expect(res).toEqual({ exported: false, reason: 'revoked' });
    expect(GoogleSheetsRepository.updateStatus).toHaveBeenCalledWith('user-1', 'revoked', 'Google access revoked');
  });

  it('catches network/append errors safely without throwing to caller', async () => {
    vi.mocked(GoogleSheetsRepository.getIntegration).mockResolvedValue({
      id: 'int-1',
      user_id: 'user-1',
      status: 'connected',
      spreadsheet_id: 'sheet-123',
      sheet_name: 'Security Telemetry',
      spreadsheet_name: 'My Sheet',
      encrypted_refresh_token: 'enc',
      token_iv: 'iv',
      token_tag: 'tag',
      last_synced_at: null,
      last_error: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    vi.mocked(GoogleSheetsRepository.isExported).mockResolvedValue(false);
    vi.spyOn(cryptoModule, 'decryptToken').mockReturnValue('decrypted-token');
    vi.mocked(GoogleSheetsClient.refreshAccessToken).mockResolvedValue({
      accessToken: 'access-token',
      expiresAt: Date.now() + 3600000,
    });
    vi.mocked(GoogleSheetsClient.appendRow).mockRejectedValue(new Error('Google 500 Internal Error'));

    const res = await exportReportToGoogleSheets(sampleReport, 'user-1');

    expect(res.exported).toBe(false);
    expect(res.reason).toBe('error');
    expect(res.error).toContain('Google 500 Internal Error');
  });
});
