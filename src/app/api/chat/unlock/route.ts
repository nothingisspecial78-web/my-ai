import { NextRequest } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { forceReleaseGenerationLock } from '@/lib/api/generation-lock';
import { jsonError } from '@/lib/api/validation';

export const dynamic = 'force-dynamic';

/**
 * POST /api/chat/unlock
 *
 * Force-releases a stale generation lock for the authenticated user's conversation.
 * This is called by the client when it receives a 409 (lock contention) and the user
 * wants to retry — indicating the previous generation crashed without releasing the lock.
 *
 * Body: { conversationId: string }
 */
export async function POST(req: NextRequest) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      return jsonError('Unauthorized', 401);
    }

    let body: { conversationId?: string };
    try {
      body = await req.json();
    } catch {
      return jsonError('Malformed request body', 400);
    }

    const { conversationId } = body;
    if (!conversationId || typeof conversationId !== 'string') {
      return jsonError('conversationId is required', 400);
    }

    // Verify the user owns this conversation via RLS
    const { data: conversation } = await supabase
      .from('conversations')
      .select('id')
      .eq('id', conversationId)
      .single();

    if (!conversation) {
      return jsonError('Conversation not found', 404);
    }

    const released = await forceReleaseGenerationLock(user.id, conversationId);

    return Response.json({ released });
  } catch (error) {
    console.error('Unlock route error:', error);
    return jsonError('Internal server error', 500);
  }
}
