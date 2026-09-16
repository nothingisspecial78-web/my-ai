import { NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { GoogleSheetsRepository } from '@/lib/integrations/google-sheets/repository';

export async function POST(request: Request) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json().catch(() => ({}));
    const { spreadsheetId, spreadsheetName, sheetName } = body;
    if (!spreadsheetId || typeof spreadsheetId !== 'string') {
      return NextResponse.json({ error: 'Valid spreadsheetId is required' }, { status: 400 });
    }

    await GoogleSheetsRepository.saveIntegration(user.id, {
      spreadsheet_id: spreadsheetId.trim(),
      spreadsheet_name: spreadsheetName ? String(spreadsheetName).trim() : null,
      sheet_name: sheetName ? String(sheetName).trim() : 'Security Telemetry',
      status: 'connected',
    });

    return NextResponse.json({ success: true });
  } catch (err: unknown) {
    console.error('Failed to update spreadsheet settings:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
