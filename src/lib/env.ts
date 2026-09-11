/**
 * Server-only environment validation.
 * Validates and returns typed configuration.
 * Never exposes GEMINI_API_KEY in the return value.
 */

export interface AppEnv {
  supabaseUrl: string;
  supabaseAnonKey: string;
  aiMode: 'mock' | 'gemini';
  aiModel: string;
  /** Whether the Gemini API key is configured (never exposes the actual key) */
  hasGeminiKey: boolean;
}

let cachedEnv: AppEnv | null = null;

export function getEnv(): AppEnv {
  if (cachedEnv) return cachedEnv;

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!supabaseUrl) {
    throw new Error('Missing required environment variable: NEXT_PUBLIC_SUPABASE_URL');
  }
  if (!supabaseAnonKey) {
    throw new Error('Missing required environment variable: NEXT_PUBLIC_SUPABASE_ANON_KEY');
  }

  const rawMode = process.env.AI_MODE || 'mock';
  if (rawMode !== 'mock' && rawMode !== 'gemini') {
    throw new Error(`Invalid AI_MODE: "${rawMode}". Must be "mock" or "gemini".`);
  }
  const aiMode = rawMode as 'mock' | 'gemini';

  const aiModel = process.env.AI_MODEL || 'gemini-3.6-flash';
  const hasGeminiKey = Boolean(process.env.GEMINI_API_KEY?.trim());

  if (aiMode === 'gemini' && !hasGeminiKey) {
    throw new Error('AI_MODE is "gemini" but GEMINI_API_KEY is not configured.');
  }

  cachedEnv = {
    supabaseUrl,
    supabaseAnonKey,
    aiMode,
    aiModel,
    hasGeminiKey,
  };

  return cachedEnv;
}

/**
 * Returns safe display values for the About page.
 * Never includes API keys or secrets.
 */
export function getSafeDisplayConfig(): { mode: string; model: string; provider: string } {
  try {
    const env = getEnv();
    return {
      mode: env.aiMode,
      model: env.aiModel,
      provider: env.aiMode === 'gemini' ? 'Google Gemini' : 'Mock Provider',
    };
  } catch {
    return {
      mode: 'unknown',
      model: 'unknown',
      provider: 'Unknown',
    };
  }
}
