import { NextRequest } from 'next/server';
import { getConversation, getMessages } from '@/lib/database';
import { createClient } from '@/lib/supabase/server';
import { getProvider } from '@/lib/ai/provider';
import { prepareContext } from '@/lib/ai/context';
import { validateChatRequest, sanitizeErrorForClient, jsonError, MAX_BODY_SIZE } from '@/lib/api/validation';
import { rateLimiter } from '@/lib/api/rate-limiter';
import { acquireGenerationLock, releaseGenerationLock } from '@/lib/api/generation-lock';
import { logger } from '@/lib/logger';
import { Message } from '@/lib/ai/types';

export const dynamic = 'force-dynamic';
export async function POST(req: NextRequest) {
  const startTime = Date.now();
  let userId: string | undefined;
  let conversationId: string | undefined;
  let lockToken: string | null = null;
  let streamTookOwnership = false;

  try {
    // 1. Body size check
    const contentLength = req.headers.get('content-length');
    if (contentLength && parseInt(contentLength, 10) > MAX_BODY_SIZE) {
      return jsonError('Request body too large', 413);
    }

    // 2. Authentication
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      return jsonError('Unauthorized', 401);
    }
    userId = user.id;

    // 3. Parse and validate request body
    let body: unknown;
    try {
      body = await req.json();
    } catch {
      return jsonError('Malformed request body', 400);
    }

    const validation = validateChatRequest(body);
    if (!validation.valid) {
      return jsonError(validation.error, validation.status);
    }

    conversationId = validation.data.conversationId;
    const { regenerateMessageId } = validation.data;

    // 4. Rate limiting
    const rateCheck = await rateLimiter.check(userId);
    if (!rateCheck.allowed) {
      logger.warn('api.chat', 'Rate limit exceeded', { userId, conversationId });
      return new Response(
        JSON.stringify({ error: 'Too many requests. Please wait a moment.' }),
        {
          status: 429,
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': String(rateCheck.retryAfter),
          },
        }
      );
    }

    // 5. Concurrent generation lock
    const acquiredLockToken = await acquireGenerationLock(userId, conversationId);
    if (!acquiredLockToken) {
      return jsonError('The AI is already generating a response for this conversation. Please wait a moment.', 409);
    }
    lockToken = acquiredLockToken;

    // 6. Validate conversation ownership via RLS
    const conversation = await getConversation(conversationId);
    if (!conversation) {
      return jsonError('Conversation not found', 404);
    }

    // 7. Retrieve full context
    const messages = await getMessages(conversationId);
    if (messages.length === 0) {
      return jsonError('No messages found in conversation', 400);
    }

    let messagesToUse = messages;
    if (regenerateMessageId) {
      const targetIndex = messages.findIndex(m => m.id === regenerateMessageId);
      if (targetIndex === -1) {
        return jsonError('Target message not found', 404);
      }
      if (messages[targetIndex].role !== 'assistant') {
        return jsonError('Can only regenerate assistant messages', 400);
      }
      messagesToUse = messages.slice(0, targetIndex);
      if (messagesToUse.length === 0) {
        return jsonError('No prior context available for regeneration', 400);
      }
    }

    // 7.5 Load Theme and Execute Deterministic Engine
    let systemInstruction: string | null = null;
    if (conversation.theme_id) {
      const { resolveAuthorizedTheme, buildThemeInstruction } = await import('@/lib/theme/resolver');
      const { processThemeRequest } = await import('@/lib/theme/processor');
      
      const theme = await resolveAuthorizedTheme(conversation.theme_id);
      systemInstruction = buildThemeInstruction(theme);

      if (theme) {
        // Find the most recent user message as the primary input
        let lastUserMessage = null;
        for (let i = messagesToUse.length - 1; i >= 0; i--) {
          if (messagesToUse[i].role === 'user') {
            lastUserMessage = messagesToUse[i];
            break;
          }
        }
        
        const input = lastUserMessage?.content || '';
        const engineResult = await processThemeRequest(theme, input, messagesToUse as unknown as Message[]);
        
        if (engineResult) {
          const contextAddition = `--- System Deterministic Context ---\n${engineResult.explanationContext}`;
          systemInstruction = systemInstruction 
            ? `${systemInstruction}\n\n${contextAddition}`
            : contextAddition;
        }
      }
    }

    // 8. Prepare context budget
    const contextMessages = prepareContext(messagesToUse as unknown as Message[]);

    // 9. Get provider
    let provider;
    try {
      provider = getProvider();
    } catch (err: unknown) {
      logger.error('api.chat', 'Provider instantiation failed', { userId, error: sanitizeErrorForClient(err) });
      return jsonError('AI service is currently unavailable', 500);
    }

    logger.info('api.chat', 'Generation started', {
      userId,
      conversationId,
      provider: provider.name,
      messageCount: contextMessages.length,
      isRegeneration: Boolean(regenerateMessageId),
    });

    // 10. Stream generation
    const currentUserId = userId;
    const currentConversationId = conversationId;
    const streamLockToken = acquiredLockToken;

    const stream = new ReadableStream({
      async start(controller) {
        // Stream aborted callback handler
        const abortHandler = () => {
          // Break is handled in the loop, but we can also force close if needed.
        };
        req.signal.addEventListener('abort', abortHandler);

        try {
          const generator = provider.generateStream(contextMessages, {
            userId: currentUserId,
            conversationId: currentConversationId,
            signal: req.signal,
            systemInstruction: systemInstruction || undefined,
          });

          for await (const event of generator) {
            if (req.signal.aborted) {
              break;
            }
            
            const chunk = new TextEncoder().encode(JSON.stringify(event) + '\n');
            controller.enqueue(chunk);
          }

          logger.info('api.chat', 'Generation completed', {
            userId: currentUserId,
            conversationId: currentConversationId,
            durationMs: Date.now() - startTime,
          });
        } catch (error: unknown) {
          const errName = error instanceof Error ? error.name : '';
          if (errName !== 'AbortError') {
            logger.error('api.chat', 'Generation failed', {
              userId: currentUserId,
              conversationId: currentConversationId,
              error: sanitizeErrorForClient(error),
              durationMs: Date.now() - startTime,
            });
            const errorEvent = { type: 'error', error: sanitizeErrorForClient(error) };
            controller.enqueue(new TextEncoder().encode(JSON.stringify(errorEvent) + '\n'));
          }
        } finally {
          req.signal.removeEventListener('abort', abortHandler);
          await releaseGenerationLock(currentUserId, currentConversationId, streamLockToken);
          try { controller.close(); } catch {}
        }
      },
      cancel() {
        // Handle client disconnect explicitly
        releaseGenerationLock(currentUserId, currentConversationId, streamLockToken).catch(err => {
          logger.error('api.chat', 'Failed to release lock on stream cancel', { error: String(err) });
        });
      }
    });

    streamTookOwnership = true;

    return new Response(stream, {
      headers: {
        'Content-Type': 'application/x-ndjson',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
      },
    });

  } catch (error) {
    console.error('!!! UNHANDLED ERROR IN ROUTE.TS !!!', error); logger.error('api.chat', 'Unhandled error', {
      userId,
      conversationId,
      error: sanitizeErrorForClient(error),
    });
    return jsonError('Internal server error', 500);
  } finally {
    // Safety: release lock if we exit before the stream takes ownership
    // or if an error occurred before stream creation
    if (lockToken && typeof streamTookOwnership === 'undefined') {
      await releaseGenerationLock(userId as string, conversationId as string, lockToken);
    } else if (lockToken && !streamTookOwnership) {
      await releaseGenerationLock(userId as string, conversationId as string, lockToken);
    }
  }
}
