import { NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { getSafeDisplayConfig } from '@/lib/env';

export async function GET() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return new NextResponse('Unauthorized', { status: 401 });
  }

  // Only expose safe display values, never keys or secrets
  return NextResponse.json(getSafeDisplayConfig());
}
