import { Message } from '@/lib/ai/types';

export interface ThemeContext {
  themeId: string;
  themeSlug: string;
  rawInput: string;
  history: Message[];
  facts: Record<string, unknown>;
  entities: string[];
  conditions: string[];
  intent: string | null;
  metadata: Record<string, unknown>;
}

export interface ThemeResult {
  success: boolean;
  result: unknown;
  warnings: string[];
  errors: string[];
  explanationContext: string;
  metadata: Record<string, unknown>;
}

export interface ThemeAnalyzer {
  /**
   * Analyzes the conversation history and raw input to produce a structured context.
   */
  analyze(input: string, history: Message[]): Promise<Partial<ThemeContext>>;
}

export interface ThemeEngine {
  /**
   * Executes deterministic domain logic based on the structured context.
   */
  execute(context: ThemeContext): Promise<ThemeResult>;
}

export interface ThemeImplementation {
  analyzer: ThemeAnalyzer;
  engine: ThemeEngine;
}
