import { Database } from '@/types/database';

export type DBTheme = Database['public']['Tables']['themes']['Row'];

/**
 * Permitted Theme Archetypes in accordance with MyAI Theme Master Specification:
 * 1. visual_only: Custom palette & tokens, inherits General AI baseline prompt, no engine.
 * 2. visual_prompt: Custom palette & tokens, injected instructions & rules, no engine.
 * 3. deterministic_engine: Default or custom palette, runs server deterministic engine.
 */
export type ThemeArchetype = 'visual_only' | 'visual_prompt' | 'deterministic_engine';

/**
 * Slugs for all currently active user-facing themes.
 */
export type ActiveThemeSlug =
  | 'general'
  | 'mathematics'
  | 'programming'
  | 'safety-checkup'
  | 'security-checkup'
  | 'study';

/**
 * Broad theme slug including legacy/dormant themes or future extensions.
 */
export type ThemeSlug = ActiveThemeSlug | 'tibb-al-nabi' | (string & {});

/**
 * Visual design tokens governing client-side theme presentation.
 */
export interface ThemeVisualConfig {
  themeAttribute: string;               // e.g. 'safety-checkup'
  accentColor: string;                  // Primary accent hex
  iconName: string;                     // Lucide icon name
  avatarBg: string;                     // CSS variable or hex
  avatarFg: string;                     // CSS variable or hex
  badgeText: string;                    // Short badge title
}

/**
 * Contextual suggestion prompt for the Welcome Screen.
 */
export interface WelcomeSuggestion {
  title: string;
  prompt: string;
  iconName: string;
}

/**
 * Welcome screen configuration tailored to the theme.
 */
export interface WelcomeThemeConfig {
  heroTitle: string;
  heroSubtitle: string;
  heroIcon: string;
  suggestions: WelcomeSuggestion[];
}

/**
 * Declarative theme configuration stored in PostgreSQL JSONB.
 */
export interface ThemeConfig {
  instructions?: string;
  terminology?: Record<string, string>;
  rules?: string[];
  methods?: string[];
  conditions?: string[];
  exceptions?: string[];
  examples?: Array<{ input: string; output: string }>;
  explanation_style?: string;
}

/**
 * Presentation and UX configuration for theme-specific card and UI rendering.
 */
export interface ThemePresentationConfig {
  audience: 'general' | 'technical';
  tone: string;
  context: string;
  cardTitle?: string;
  findingsLabel?: string;
  telemetryLabel?: string;
  actionsLabel?: string;
  limitationsLabel?: string;
  emptyFindingsText?: string;
}

/**
 * Unified Theme Definition representing both Visual and Intelligence layers.
 */
export interface ThemeDefinition {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  icon: string | null;
  enabled: boolean;
  isSystem: boolean;
  archetype: ThemeArchetype;
  visual: ThemeVisualConfig;
  welcome: WelcomeThemeConfig;
  presentation?: ThemePresentationConfig;
  instructions?: string;
  rules?: string[];
  config?: ThemeConfig;
  createdAt?: string;
  updatedAt?: string;
}

/**
 * Backward-compatibility type alias: Theme is an alias for ThemeDefinition.
 */
export type Theme = ThemeDefinition;

/**
 * Parses a database row into a ThemeDefinition with safe default visual and welcome configs.
 */
export function parseTheme(dbTheme: DBTheme): ThemeDefinition {
  const dbConfig = (dbTheme.config as unknown as ThemeConfig) || {};
  return {
    id: dbTheme.id,
    name: dbTheme.name,
    slug: dbTheme.slug,
    description: dbTheme.description,
    icon: dbTheme.icon,
    enabled: dbTheme.enabled,
    isSystem: dbTheme.is_system,
    archetype: 'visual_prompt',
    visual: {
      themeAttribute: dbTheme.slug,
      accentColor: '#2563eb',
      iconName: dbTheme.icon || 'Globe',
      avatarBg: '#2563eb',
      avatarFg: '#ffffff',
      badgeText: dbTheme.name,
    },
    welcome: {
      heroTitle: `Welcome to ${dbTheme.name}`,
      heroSubtitle: dbTheme.description || 'How can I help you today?',
      heroIcon: dbTheme.icon || 'Sparkles',
      suggestions: [],
    },
    presentation: {
      audience: 'general',
      tone: 'versatile',
      context: dbTheme.name,
    },
    instructions: dbConfig.instructions,
    rules: dbConfig.rules,
    config: dbConfig,
    createdAt: dbTheme.created_at,
    updatedAt: dbTheme.updated_at,
  };
}
