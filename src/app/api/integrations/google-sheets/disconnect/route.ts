import { NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { GoogleSheetsRepository } from '@/lib/integrations/google-sheets/repository';
import { GoogleSheetsClient } from '@/lib/integrations/google-sheets/client';
import { decryptToken } from '@/lib/integrations/google-sheets/crypto';

export async function POST() {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const integration = await GoogleSheetsRepository.getIntegration(user.id);
    if (integration && integration.encrypted_refresh_token && integration.token_iv && integration.token_tag) {
      try {
        const refreshToken = decryptToken(
          integration.encrypted_refresh_token,
          integration.token_iv,
          integration.token_tag
        );
        await GoogleSheetsClient.revokeToken(refreshToken);
      } catch {
        // Best-effort token revocation
      }
    }

    await GoogleSheetsRepository.disconnect(user.id);
    return NextResponse.json({ success: true });
  } catch (err: unknown) {
    console.error('Google Sheets disconnect error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
