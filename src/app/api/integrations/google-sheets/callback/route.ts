import { NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { validateOAuthState, encryptToken } from '@/lib/integrations/google-sheets/crypto';
import { GoogleSheetsClient } from '@/lib/integrations/google-sheets/client';
import { GoogleSheetsRepository } from '@/lib/integrations/google-sheets/repository';

export async function GET(request: Request) {
  const requestUrl = new URL(request.url);
  const code = requestUrl.searchParams.get('code');
  const state = requestUrl.searchParams.get('state');
  const error = requestUrl.searchParams.get('error');
  const origin = requestUrl.origin;

  if (error) {
    console.warn('Google OAuth returned error:', error);
    return NextResponse.redirect(`${origin}/chat?google_sheets_error=${encodeURIComponent(error)}`);
  }

  if (!code || !state) {
    return NextResponse.redirect(`${origin}/chat?google_sheets_error=missing_parameters`);
  }

  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) {
      return NextResponse.redirect(`${origin}/login`);
    }

    const isValidState = validateOAuthState(state, user.id);
    if (!isValidState) {
      return NextResponse.redirect(`${origin}/chat?google_sheets_error=invalid_or_expired_state`);
    }

    const redirectUri = process.env.GOOGLE_OAUTH_REDIRECT_URI || `${origin}/api/integrations/google-sheets/callback`;
    const tokens = await GoogleSheetsClient.exchangeCodeForTokens(code, redirectUri);

    if (!tokens.refreshToken) {
      console.warn('No refresh token returned by Google (may require prompt=consent).');
      return NextResponse.redirect(`${origin}/chat?google_sheets_error=missing_refresh_token`);
    }

    const encrypted = encryptToken(tokens.refreshToken);
    await GoogleSheetsRepository.saveIntegration(user.id, {
      status: 'connected',
      encrypted_refresh_token: encrypted.ciphertext,
      token_iv: encrypted.iv,
      token_tag: encrypted.tag,
      sheet_name: 'Security Telemetry',
      last_error: null,
    });

    return NextResponse.redirect(`${origin}/chat?google_sheets=connected`);
  } catch (err: unknown) {
    console.error('Google OAuth callback error:', err);
    return NextResponse.redirect(`${origin}/chat?google_sheets_error=token_exchange_failed`);
  }
}
