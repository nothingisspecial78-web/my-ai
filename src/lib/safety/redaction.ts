/**
 * Safety & Privacy Redaction Engine
 * 
 * Sanitizes sensitive credentials, tokens, OTP codes, credit card numbers,
 * and confidential query parameters before analysis material is persisted or stored.
 */

// Parameter names that always contain sensitive values
const SENSITIVE_PARAM_NAMES = new Set([
  'password',
  'passwd',
  'pwd',
  'pass',
  'token',
  'auth_token',
  'authtoken',
  'access_token',
  'refresh_token',
  'api_key',
  'apikey',
  'secret',
  'client_secret',
  'otp',
  'pin',
  'session',
  'session_id',
  'sessionid',
  'verification_code',
  'code',
  'cvv',
  'ssn',
]);

/**
 * Redacts sensitive query parameters and user credentials embedded in a URL string.
 * Example:
 *   "https://example.com/?password=hello&user=test"
 *   -> "https://example.com/?password=[REDACTED]&user=test"
 *
 *   "https://user:secret123@example.com/"
 *   -> "https://user:[REDACTED]@example.com/"
 */
export function redactUrl(urlStr: string): string {
  if (!urlStr || typeof urlStr !== 'string') return urlStr;

  try {
    const hasProtocol = /^https?:\/\//i.test(urlStr);
    const parseable = hasProtocol ? urlStr : `http://${urlStr}`;
    const parsed = new URL(parseable);

    // 1. Redact embedded credentials in authority (user:password@host)
    if (parsed.password) {
      parsed.password = '[REDACTED]';
    }

    // 2. Redact sensitive search parameters
    const searchParams = new URLSearchParams(parsed.search);
    let mutated = false;

    for (const [key] of Array.from(searchParams.entries())) {
      const lowerKey = key.toLowerCase();
      if (SENSITIVE_PARAM_NAMES.has(lowerKey) || lowerKey.includes('token') || lowerKey.includes('secret')) {
        searchParams.set(key, '[REDACTED]');
        mutated = true;
      }
    }

    if (mutated) {
      parsed.search = searchParams.toString();
    }

    let result = parsed.toString().replace(/%5BREDACTED%5D/gi, '[REDACTED]');
    // If the input didn't have a protocol originally, preserve format
    if (!hasProtocol && result.startsWith('http://')) {
      result = result.substring('http://'.length);
    }
    return result;
  } catch {
    // If URL parsing fails, apply regex fallback for query parameters
    return urlStr.replace(
      /([?&](?:password|passwd|pwd|token|api[_-]?key|secret|otp|pin|session)=)([^&]+)/gi,
      '$1[REDACTED]'
    );
  }
}

/**
 * Redacts sensitive values (numerical OTPs, passwords, card numbers) from freeform text.
 * Example:
 *   "Your OTP is 123456." -> "Your OTP is [REDACTED]."
 *   "token: ghp_123456789012345678901234567890123456" -> "token: [REDACTED]"
 */
export function redactSensitiveText(text: string): string {
  if (!text || typeof text !== 'string') return text;

  let sanitized = text;

  // 1. Redact URLs in the text first
  sanitized = sanitized.replace(/https?:\/\/[^\s<>"]+/gi, match => redactUrl(match));

  // 2. Redact passwords in text
  sanitized = sanitized.replace(/\b(password|passwd|pwd)\s*=\s*([^\s&,;.]+)/gi, '$1=[REDACTED]');
  sanitized = sanitized.replace(/\b(password|passwd|pwd)\s+(?:is|:)\s*([^\s,;.]+)/gi, '$1 is [REDACTED]');

  // 3. Redact OTP / Verification code numbers (4 to 8 digits following keyword)
  sanitized = sanitized.replace(
    /\b(otp|one[-\s]?time[-\s]?password|verification[-\s]?code|security[-\s]?code|pin|2fa[-\s]?code)\s*[:=is-]*\s*(\b\d{4,8}\b)/gi,
    (match, prefix) => `${prefix} [REDACTED]`
  );

  // 4. Redact common token patterns (e.g. ghp_..., AKIA..., Bearer tokens)
  sanitized = sanitized.replace(/\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b/g, '[REDACTED]');
  sanitized = sanitized.replace(/\b(AKIA[0-9A-Z]{16})\b/g, '[REDACTED]');
  sanitized = sanitized.replace(/\bBearer\s+[a-zA-Z0-9_.\-~+/=]{20,}\b/gi, 'Bearer [REDACTED]');

  // 5. Redact potential 16-digit credit card numbers
  sanitized = sanitized.replace(/\b(?:\d{4}[-\s]?){3}\d{4}\b/g, '[REDACTED]');

  return sanitized;
}

/**
 * Recursively deep-sanitizes any object or data structure before database persistence.
 */
export function redactDataRecord<T>(data: T): T {
  if (data === null || data === undefined) return data;

  if (typeof data === 'string') {
    return redactSensitiveText(data) as unknown as T;
  }

  if (Array.isArray(data)) {
    return data.map(item => redactDataRecord(item)) as unknown as T;
  }

  if (typeof data === 'object') {
    const sanitizedObj: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(data as Record<string, unknown>)) {
      const lowerKey = key.toLowerCase();
      if (
        SENSITIVE_PARAM_NAMES.has(lowerKey) ||
        lowerKey.includes('token') ||
        lowerKey.includes('secret') ||
        lowerKey.includes('pass')
      ) {
        sanitizedObj[key] = '[REDACTED]';
      } else {
        sanitizedObj[key] = redactDataRecord(val);
      }
    }
    return sanitizedObj as T;
  }

  return data;
}
