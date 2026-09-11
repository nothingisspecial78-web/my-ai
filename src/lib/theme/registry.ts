import { ThemeImplementation } from './engine';
import { ThemeDefinition } from './types';
import {
  GENERAL_AI_THEME,
  MATHEMATICS_THEME,
  PROGRAMMING_THEME,
  SAFETY_CHECKUP_THEME,
  SECURITY_CHECKUP_THEME,
  STUDY_THEME,
  TIBB_AL_NABI_THEME,
} from './catalog';
import { tibbAlNabiImpl } from './engines/tibb-al-nabi';
import { safetySecurityImpl } from './engines/safety-security';

class ThemeRegistry {
  private definitions = new Map<string, ThemeDefinition>();
  private engines = new Map<string, ThemeImplementation>();

  constructor() {
    this.registerDefaults();
  }

  /**
   * Registers a visual & intelligence definition (safe for client and server).
   */
  registerDefinition(definition: ThemeDefinition): void {
    this.definitions.set(definition.slug, definition);
  }

  /**
   * Retrieves a registered theme definition by slug.
   */
  getDefinition(slug: string): ThemeDefinition | undefined {
    return this.definitions.get(slug);
  }

  /**
   * Returns all registered theme definitions.
   */
  getAllDefinitions(): ThemeDefinition[] {
    return Array.from(this.definitions.values());
  }

  /**
   * Returns all active system theme definitions (enabled and isSystem).
   * Dormant themes like Tibb al-Nabi (enabled: false, isSystem: false) are excluded.
   */
  getAllActiveDefinitions(): ThemeDefinition[] {
    return Array.from(this.definitions.values()).filter(d => d.enabled && d.isSystem);
  }

  /**
   * Registers a deterministic theme engine to a known theme slug.
   * This explicitly runs on the server and prevents arbitrary code execution
   * driven by database content.
   */
  registerEngine(slug: string, impl: ThemeImplementation): void {
    if (this.engines.has(slug)) {
      console.warn(`[ThemeRegistry] Overwriting existing engine for slug: ${slug}`);
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
   * Clears all registrations. Used in test suites for clean state.
   */
  clear(): void {
    this.definitions.clear();
    this.engines.clear();
  }

  /**
   * Restores default canonical definitions and official engines.
   */
  registerDefaults(): void {
    // Canonical Theme Definitions
    this.registerDefinition(GENERAL_AI_THEME);
    this.registerDefinition(MATHEMATICS_THEME);
    this.registerDefinition(PROGRAMMING_THEME);
    this.registerDefinition(SAFETY_CHECKUP_THEME);
    this.registerDefinition(SECURITY_CHECKUP_THEME);
    this.registerDefinition(STUDY_THEME);
    this.registerDefinition(TIBB_AL_NABI_THEME);

    // Deterministic Engines
    this.registerEngine('tibb-al-nabi', tibbAlNabiImpl);
    this.registerEngine('safety-checkup', safetySecurityImpl);
    this.registerEngine('security-checkup', safetySecurityImpl);
    this.registerEngine('safety', safetySecurityImpl);
  }
}

// Export a singleton instance
export const themeRegistry = new ThemeRegistry();
