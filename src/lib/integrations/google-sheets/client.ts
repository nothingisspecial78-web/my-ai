import { GoogleSheetsTokens } from './types';

const GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
const GOOGLE_REVOKE_ENDPOINT = 'https://oauth2.googleapis.com/revoke';
const GOOGLE_SHEETS_API_BASE = 'https://sheets.googleapis.com/v4/spreadsheets';
const DEFAULT_TIMEOUT_MS = 5000;

export interface GoogleApiError {
  status: number;
  message: string;
  code?: string;
  isInvalidGrant?: boolean;
  isRateLimit?: boolean;
}

export class GoogleSheetsClient {
  private static async fetchWithTimeout(
    url: string,
    options: RequestInit = {},
    timeoutMs = DEFAULT_TIMEOUT_MS
  ): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        ...options,
        signal: controller.signal,
      });
      return res;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  public static async exchangeCodeForTokens(
    code: string,
    redirectUri: string
  ): Promise<GoogleSheetsTokens> {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    if (!clientId || !clientSecret) {
      throw new Error('Google OAuth credentials not configured on server.');
    }
    const params = new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    });
    const res = await this.fetchWithTimeout(GOOGLE_TOKEN_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    if (!res.ok) {
      const errBody = await res.text().catch(() => '');
      throw new Error('Google token exchange failed: ' + res.status + ' ' + errBody);
    }
    const data = await res.json();
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresAt: Date.now() + ((data.expires_in || 3600) * 1000),
      scope: data.scope,
    };
  }

  public static async refreshAccessToken(refreshToken: string): Promise<{ accessToken: string; expiresAt: number }> {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    if (!clientId || !clientSecret) {
      throw new Error('Google OAuth credentials not configured on server.');
    }
    const params = new URLSearchParams({
      refresh_token: refreshToken,
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: 'refresh_token',
    });
    const res = await this.fetchWithTimeout(GOOGLE_TOKEN_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      const isGrant = text.includes('invalid_grant');
      const err: GoogleApiError = {
        status: res.status,
        message: 'Google token refresh failed: ' + text,
        isInvalidGrant: isGrant,
      };
      throw err;
    }
    const data = await res.json();
    return {
      accessToken: data.access_token,
      expiresAt: Date.now() + ((data.expires_in || 3600) * 1000),
    };
  }

  public static async revokeToken(token: string): Promise<boolean> {
    try {
      const params = new URLSearchParams({ token });
      const res = await this.fetchWithTimeout(GOOGLE_REVOKE_ENDPOINT + '?' + params.toString(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }, 3000);
      return res.ok;
    } catch {
      return false;
    }
  }

  public static async appendRow(
    accessToken: string,
    spreadsheetId: string,
    sheetName: string,
    values: (string | number)[]
  ): Promise<{ updatedRows: number }> {
    const cleanSpreadsheetId = encodeURIComponent(spreadsheetId.trim());
    const cleanSheetName = encodeURIComponent(sheetName.trim() || 'Security Telemetry');
    const url = GOOGLE_SHEETS_API_BASE + '/' + cleanSpreadsheetId + '/values/' + cleanSheetName + '!A1:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS';
    let res = await this.fetchWithTimeout(url, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + accessToken,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        values: [values],
      }),
    });
    if (res.status === 429 || res.status === 503) {
      await new Promise(r => setTimeout(r, 1000));
      res = await this.fetchWithTimeout(url, {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + accessToken,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ values: [values] }),
      });
    }
    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw {
        status: res.status,
        message: 'Google Sheets append failed: ' + res.status + ' ' + errText,
        isRateLimit: res.status === 429,
      };
    }
    const data = await res.json().catch(() => ({}));
    return { updatedRows: data?.updates?.updatedRows || 1 };
  }

  public static async testConnection(
    accessToken: string,
    spreadsheetId: string
  ): Promise<{ title: string; sheets: string[] }> {
    const cleanSpreadsheetId = encodeURIComponent(spreadsheetId.trim());
    const url = GOOGLE_SHEETS_API_BASE + '/' + cleanSpreadsheetId + '?fields=properties.title,sheets.properties.title';
    const res = await this.fetchWithTimeout(url, {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + accessToken },
    });
    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error('Test connection failed: ' + res.status + ' ' + errText);
    }
    const data = await res.json();
    const title = data?.properties?.title || 'Spreadsheet';
    const sheets = (data?.sheets || []).map((s: { properties?: { title?: string } }) => s.properties?.title || '').filter(Boolean);
    return { title, sheets };
  }
}
