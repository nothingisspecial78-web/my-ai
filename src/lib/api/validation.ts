/**
 * Request validation utilities for /api/chat.
 * Validates inputs and returns safe structured errors.
 */

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Maximum user message length in characters */
export const MAX_MESSAGE_LENGTH = 20_000;

/** Maximum request body size in bytes */
export const MAX_BODY_SIZE = 102_400; // 100KB

export function isValidUUID(id: string): boolean {
  return UUID_REGEX.test(id);
}

export interface ChatRequestBody {
  conversationId: string;
  regenerateMessageId?: string;
}

export interface ValidationResult {
  valid: true;
  data: ChatRequestBody;
}

export interface ValidationError {
  valid: false;
  error: string;
  status: number;
}

export function validateChatRequest(body: unknown): ValidationResult | ValidationError {
  if (!body || typeof body !== 'object') {
    return { valid: false, error: 'Invalid request body', status: 400 };
  }

  const { conversationId, regenerateMessageId } = body as Record<string, unknown>;

  if (!conversationId || typeof conversationId !== 'string') {
    return { valid: false, error: 'Missing or invalid conversation ID', status: 400 };
  }

  if (!isValidUUID(conversationId)) {
    return { valid: false, error: 'Invalid conversation ID format', status: 400 };
  }

  if (regenerateMessageId !== undefined) {
    if (typeof regenerateMessageId !== 'string' || !isValidUUID(regenerateMessageId)) {
      return { valid: false, error: 'Invalid regenerate message ID format', status: 400 };
    }
  }

  return {
    valid: true,
    data: {
      conversationId,
      regenerateMessageId: regenerateMessageId as string | undefined,
    },
  };
}

/**
 * Returns a safe error message for the client.
 * Strips stack traces, internal paths, and sensitive information.
 */
export function sanitizeErrorForClient(error: unknown): string {
  if (error instanceof Error) {
    const msg = error.message;
    // Strip internal details
    if (msg.includes('GEMINI_API_KEY') || msg.includes('API_KEY') || msg.includes('api_key')) {
      return 'AI service configuration error';
    }
    if (msg.includes('ECONNREFUSED') || msg.includes('ENOTFOUND') || msg.includes('fetch failed')) {
      return 'Could not reach the AI service';
    }
    if (msg.includes('timeout') || msg.includes('ETIMEDOUT')) {
      return 'AI service request timed out';
    }
    // Don't return raw error messages that might contain paths or internals
    if (msg.includes('/') || msg.includes('\\') || msg.includes('node_modules')) {
      return 'An internal error occurred';
    }
    // If the message is reasonably short and doesn't look like a stack trace, allow it
    if (msg.length < 200 && !msg.includes('\n') && !msg.includes('at ')) {
      return msg;
    }
    return 'An unexpected error occurred';
  }
  return 'An unexpected error occurred';
}

/**
 * Creates a JSON error response.
 */
export function jsonError(error: string, status: number): Response {
  return new Response(
    JSON.stringify({ error }),
    {
      status,
      headers: { 'Content-Type': 'application/json' },
    }
  );
}
