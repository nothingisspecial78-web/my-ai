import {
  AnalyzerType,
  SafetyInputType,
  SafetyInput,
  AnalyzerResult,
} from '../types';

/**
 * Base contract for all specialized safety and security analyzers.
 */
export interface SafetyAnalyzer {
  readonly id: string;
  readonly type: AnalyzerType;
  readonly supportedInputTypes: readonly SafetyInputType[];

  /**
   * Evaluates if the analyzer can handle the provided input.
   */
  canAnalyze(input: SafetyInput): boolean;

  /**
   * Executes deterministic or provider-backed analysis on the input.
   */
  analyze(input: SafetyInput): Promise<AnalyzerResult>;
}

/**
 * Extensible registry managing available safety analyzers.
 */
export class AnalyzerRegistry {
  private analyzers = new Map<string, SafetyAnalyzer>();

  register(analyzer: SafetyAnalyzer): void {
    if (this.analyzers.has(analyzer.id)) {
      console.warn(`[AnalyzerRegistry] Overwriting analyzer: ${analyzer.id}`);
    }
    this.analyzers.set(analyzer.id, analyzer);
  }

  get(id: string): SafetyAnalyzer | undefined {
    return this.analyzers.get(id);
  }

  getForInput(input: SafetyInput): SafetyAnalyzer[] {
    const matched: SafetyAnalyzer[] = [];
    for (const analyzer of this.analyzers.values()) {
      if (analyzer.canAnalyze(input)) {
        matched.push(analyzer);
      }
    }
    return matched;
  }

  getAll(): SafetyAnalyzer[] {
    return Array.from(this.analyzers.values());
  }

  clear(): void {
    this.analyzers.clear();
  }
}

// Global registry instance
export const analyzerRegistry = new AnalyzerRegistry();
