import { Message } from '@/lib/ai/types';
import { ThemeResult, ThemeContext } from './engine';
import { Theme } from './types';
import { themeRegistry } from './registry';

/**
 * Orchestrates the full deterministic pipeline for a conversation.
 * 
 * 1. Checks if a secure server-side deterministic engine is registered.
 * 2. Analyzes the input using the theme's analyzer.
 * 3. Executes the deterministic engine.
 * 4. Returns a structured result suitable for AI generation explanation.
 */
export async function processThemeRequest(
  theme: Theme,
  input: string,
  history: Message[]
): Promise<ThemeResult | null> {
  try {
    // 1. Confirm engine is registered
    const impl = themeRegistry.getEngine(theme.slug);
    if (!impl) {
      return null; // Theme exists but relies purely on Gemini, no deterministic engine
    }

    // 4. Analysis
    const partialContext = await impl.analyzer.analyze(input, history);
    
    // Construct full context
    const context: ThemeContext = {
      themeId: theme.id,
      themeSlug: theme.slug,
      rawInput: input,
      history,
      facts: partialContext.facts || {},
      entities: partialContext.entities || [],
      conditions: partialContext.conditions || [],
      intent: partialContext.intent || null,
      metadata: partialContext.metadata || {},
    };

    // 5. Deterministic Execution
    const result = await impl.engine.execute(context);
    return result;
  } catch (error: unknown) {
    console.error('[ThemeProcessor] Error executing theme engine:', error);
    
    // Safe structured fallback error
    return {
      success: false,
      result: null,
      warnings: [],
      errors: ['The deterministic engine encountered an internal error and could not complete the request.'],
      explanationContext: 'Deterministic engine failed. Advise the user that domain-specific calculation is currently unavailable.',
      metadata: {},
    };
  }
}
