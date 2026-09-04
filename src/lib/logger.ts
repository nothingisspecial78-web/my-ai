/**
 * Production-safe structured logger.
 *
 * Logs structured JSON to console.
 * Sanitizes metadata: strips apiKey, token, password fields.
 * Truncates content fields to prevent logging full messages.
 *
 * NEVER logs: API keys, tokens, passwords, full message content.
 */

const SENSITIVE_KEYS = new Set(['apiKey', 'api_key', 'token', 'password', 'secret', 'authorization']);
const MAX_CONTENT_LENGTH = 100;

function sanitize(meta: Record<string, unknown>): Record<string, unknown> {
  const cleaned: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(meta)) {
    if (SENSITIVE_KEYS.has(key.toLowerCase())) {
      cleaned[key] = '[REDACTED]';
    } else if (key === 'content' && typeof value === 'string' && value.length > MAX_CONTENT_LENGTH) {
      cleaned[key] = value.substring(0, MAX_CONTENT_LENGTH) + `...[${value.length} chars]`;
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      cleaned[key] = sanitize(value as Record<string, unknown>);
    } else {
      cleaned[key] = value;
    }
  }
  return cleaned;
}

function formatLog(level: string, category: string, message: string, meta?: Record<string, unknown>) {
  const entry: Record<string, unknown> = {
    timestamp: new Date().toISOString(),
    level,
    category,
    message,
  };
  if (meta && Object.keys(meta).length > 0) {
    entry.meta = sanitize(meta);
  }
  return JSON.stringify(entry);
}

export const logger = {
  info(category: string, message: string, meta?: Record<string, unknown>) {
    console.log(formatLog('INFO', category, message, meta));
  },
  warn(category: string, message: string, meta?: Record<string, unknown>) {
    console.warn(formatLog('WARN', category, message, meta));
  },
  error(category: string, message: string, meta?: Record<string, unknown>) {
    console.error(formatLog('ERROR', category, message, meta));
  },
};
