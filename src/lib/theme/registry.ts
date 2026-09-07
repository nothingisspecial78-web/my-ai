import { ThemeImplementation } from './engine';

class ThemeEngineRegistry {
  private engines = new Map<string, ThemeImplementation>();

  /**
   * Registers a deterministic theme engine to a known theme slug.
   * This explicitly runs on the server and prevents arbitrary code execution
   * driven by database content.
   */
  registerEngine(slug: string, impl: ThemeImplementation): void {
    if (this.engines.has(slug)) {
      console.warn(`[ThemeEngineRegistry] Overwriting existing engine for slug: ${slug}`);
    }
    this.engines.set(slug, impl);
  }

  /**
   * Retrieves a server-registered deterministic engine for a given theme slug.
   * Returns undefined if no deterministic engine is registered (e.g., General AI).
   */
  getEngine(slug: string): ThemeImplementation | undefined {
    return this.engines.get(slug);
  }

  /**
   * Clears the registry (useful for testing).
   */
  clear(): void {
    this.engines.clear();
  }
}

// Export a singleton instance
export const themeRegistry = new ThemeEngineRegistry();
