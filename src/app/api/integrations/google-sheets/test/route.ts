import { NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { GoogleSheetsRepository } from '@/lib/integrations/google-sheets/repository';
import { GoogleSheetsClient } from '@/lib/integrations/google-sheets/client';
import { decryptToken } from '@/lib/integrations/google-sheets/crypto';

export async function POST(request: Request) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json().catch(() => ({}));
    const integration = await GoogleSheetsRepository.getIntegration(user.id);
    if (!integration || !integration.encrypted_refresh_token || !integration.token_iv || !integration.token_tag) {
      return NextResponse.json({ error: 'Google Sheets not connected' }, { status: 400 });
    }

    const spreadsheetId = (body.spreadsheetId || integration.spreadsheet_id || '').trim();
    if (!spreadsheetId) {
      return NextResponse.json({ error: 'Spreadsheet ID required for test' }, { status: 400 });
    }
    const sheetName = (body.sheetName || integration.sheet_name || 'Security Telemetry').trim();

    const refreshToken = decryptToken(
      integration.encrypted_refresh_token,
      integration.token_iv,
      integration.token_tag
    );
    const { accessToken } = await GoogleSheetsClient.refreshAccessToken(refreshToken);

    const connInfo = await GoogleSheetsClient.testConnection(accessToken, spreadsheetId);

    const now = new Date().toISOString();
    const testRow = [
      now,
      'TEST-CONNECTION-PING',
      'test_user',
      'url',
      'general',
      'LOW',
      0,
      'HIGH',
      'Verified test connection from Before You Click',
      'beforeyouclick.local',
      0,
      0,
      'test',
      'COMPLETED',
      now,
    ];
    await GoogleSheetsClient.appendRow(accessToken, spreadsheetId, sheetName, testRow);

    await GoogleSheetsRepository.saveIntegration(user.id, {
      spreadsheet_id: spreadsheetId,
      spreadsheet_name: connInfo.title,
      sheet_name: sheetName,
      status: 'connected',
      last_synced_at: now,
      last_error: null,
    });

    return NextResponse.json({
      success: true,
      spreadsheetTitle: connInfo.title,
      sheets: connInfo.sheets,
    });
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err);
    console.error('Google Sheets test connection failed:', errMsg);
    return NextResponse.json({ success: false, error: errMsg }, { status: 500 });
  }
}
