import { NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { GoogleSheetsRepository } from '@/lib/integrations/google-sheets/repository';
import type { GoogleSheetsStatusResponse } from '@/lib/integrations/google-sheets/types';

export async function GET() {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const integration = await GoogleSheetsRepository.getIntegration(user.id);
    if (!integration) {
      const resp: GoogleSheetsStatusResponse = {
        connected: false,
        status: 'disconnected',
        spreadsheetId: null,
        spreadsheetName: null,
        sheetName: 'Security Telemetry',
        lastSyncedAt: null,
        lastError: null,
      };
      return NextResponse.json(resp);
    }

    const resp: GoogleSheetsStatusResponse = {
      connected: integration.status === 'connected',
      status: integration.status,
      spreadsheetId: integration.spreadsheet_id,
      spreadsheetName: integration.spreadsheet_name,
      sheetName: integration.sheet_name || 'Security Telemetry',
      lastSyncedAt: integration.last_synced_at,
      lastError: integration.last_error,
    };
    return NextResponse.json(resp);
  } catch (err: unknown) {
    console.error('Failed to get Google Sheets status:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
