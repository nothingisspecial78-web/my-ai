import { NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { createOAuthState } from '@/lib/integrations/google-sheets/crypto';

export async function GET(request: Request) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    const clientId = process.env.GOOGLE_CLIENT_ID;
    if (!clientId) {
      return NextResponse.json({ error: 'Google OAuth not configured on server' }, { status: 500 });
    }
    const urlObj = new URL(request.url);
    const redirectUri = process.env.GOOGLE_OAUTH_REDIRECT_URI || `${urlObj.origin}/api/integrations/google-sheets/callback`;
    const state = createOAuthState(user.id);
    const scope = 'https://www.googleapis.com/auth/spreadsheets';
    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${encodeURIComponent(scope)}&access_type=offline&prompt=consent&state=${encodeURIComponent(state)}`;
    return NextResponse.json({ url: authUrl });
  } catch (err: unknown) {
    console.error('Failed to initiate Google OAuth:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
