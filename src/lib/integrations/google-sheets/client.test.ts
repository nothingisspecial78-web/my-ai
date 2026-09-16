import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { GoogleSheetsClient } from './client';

describe('GoogleSheetsClient', () => {
  const originalFetch = global.fetch;
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env.GOOGLE_CLIENT_ID = 'test-client-id';
    process.env.GOOGLE_CLIENT_SECRET = 'test-client-secret';
  });

  afterEach(() => {
    global.fetch = originalFetch;
    process.env = { ...originalEnv };
    vi.restoreAllMocks();
  });

  describe('exchangeCodeForTokens', () => {
    it('exchanges authorization code for tokens successfully', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          access_token: 'ya29.access-token-test',
          refresh_token: '1//refresh-token-test',
          expires_in: 3600,
          scope: 'https://www.googleapis.com/auth/spreadsheets',
        }),
      });

      const result = await GoogleSheetsClient.exchangeCodeForTokens('auth-code-123', 'http://localhost:3000/callback');

      expect(result.accessToken).toBe('ya29.access-token-test');
      expect(result.refreshToken).toBe('1//refresh-token-test');
      expect(result.expiresAt).toBeGreaterThan(Date.now());
      expect(global.fetch).toHaveBeenCalledWith(
        'https://oauth2.googleapis.com/token',
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        })
      );
    });

    it('throws error when server credentials are missing', async () => {
      delete process.env.GOOGLE_CLIENT_ID;
      await expect(
        GoogleSheetsClient.exchangeCodeForTokens('code', 'http://localhost/cb')
      ).rejects.toThrow('Google OAuth credentials not configured');
    });

    it('throws descriptive error on HTTP failure', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        text: async () => 'invalid_grant',
      });

      await expect(
        GoogleSheetsClient.exchangeCodeForTokens('bad-code', 'http://localhost/cb')
      ).rejects.toThrow('Google token exchange failed: 400 invalid_grant');
    });
  });

  describe('refreshAccessToken', () => {
    it('refreshes access token successfully', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          access_token: 'ya29.new-access-token',
          expires_in: 3600,
        }),
      });

      const result = await GoogleSheetsClient.refreshAccessToken('valid-refresh-token');
      expect(result.accessToken).toBe('ya29.new-access-token');
      expect(result.expiresAt).toBeGreaterThan(Date.now());
    });

    it('identifies invalid_grant as token revocation', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        text: async () => JSON.stringify({ error: 'invalid_grant', error_description: 'Token has been expired or revoked.' }),
      });

      try {
        await GoogleSheetsClient.refreshAccessToken('revoked-refresh-token');
        expect.unreachable('Should have thrown');
      } catch (err: unknown) {
        const apiErr = err as { isInvalidGrant?: boolean; status?: number };
        expect(apiErr.isInvalidGrant).toBe(true);
        expect(apiErr.status).toBe(400);
      }
    });
  });

  describe('appendRow', () => {
    it('appends row with correct authorization and range', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          updates: { updatedRows: 1 },
        }),
      });

      const values = ['2026-09-13T00:00:00Z', 'analysis-123', 'abc', 'url', 'HIGH', 80];
      const res = await GoogleSheetsClient.appendRow(
        'valid-access-token',
        'sheet-id-xyz',
        'Security Telemetry',
        values
      );

      expect(res.updatedRows).toBe(1);
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('https://sheets.googleapis.com/v4/spreadsheets/sheet-id-xyz/values/'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            Authorization: 'Bearer valid-access-token',
            'Content-Type': 'application/json',
          }),
        })
      );
    });

    it('retries once on 429 rate limit or 503 service unavailable', async () => {
      let callCount = 0;
      global.fetch = vi.fn().mockImplementation(async () => {
        callCount++;
        if (callCount === 1) {
          return {
            ok: false,
            status: 429,
            text: async () => 'Rate limit exceeded',
          };
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({ updates: { updatedRows: 1 } }),
        };
      });

      const values = ['row-data'];
      const res = await GoogleSheetsClient.appendRow('token', 'sheet-id', 'Tab', values);

      expect(callCount).toBe(2);
      expect(res.updatedRows).toBe(1);
    });
  });

  describe('testConnection', () => {
    it('returns title and sheet list on success', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          properties: { title: 'My Security Sheet' },
          sheets: [
            { properties: { title: 'Security Telemetry' } },
            { properties: { title: 'Raw Logs' } },
          ],
        }),
      });

      const result = await GoogleSheetsClient.testConnection('token', 'sheet-123');
      expect(result.title).toBe('My Security Sheet');
      expect(result.sheets).toEqual(['Security Telemetry', 'Raw Logs']);
    });
  });

  describe('revokeToken', () => {
    it('calls revoke endpoint and returns true on success', async () => {
      global.fetch = vi.fn().mockResolvedValue({ ok: true });
      const success = await GoogleSheetsClient.revokeToken('token-to-revoke');
      expect(success).toBe(true);
    });

    it('returns false on error without throwing', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));
      const success = await GoogleSheetsClient.revokeToken('token-to-revoke');
      expect(success).toBe(false);
    });
  });
});
