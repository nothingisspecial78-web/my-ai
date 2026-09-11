import { getThemeById } from '@/lib/database';
import { ThemeDefinition, ThemeConfig, parseTheme } from '@/lib/theme/types';
import { GENERAL_AI_THEME } from '@/lib/theme/catalog';
import { themeRegistry } from '@/lib/theme/registry';

export { resolveThemeSync } from './catalog';

export async function resolveAuthorizedTheme(themeId: string | null | undefined): Promise<ThemeDefinition> {
  // 1. Canonical General AI baseline: theme_id is null or undefined.
  // Legacy 'general' slug and legacy UUID ('11111111-1111-1111-1111-111111111111') are accepted purely as fallback.
  if (!themeId || themeId === 'general' || themeId === '11111111-1111-1111-1111-111111111111') {
    return GENERAL_AI_THEME;
  }

  try {
    const dbTheme = await getThemeById(themeId);
    if (!dbTheme || !dbTheme.enabled || !dbTheme.is_system) {
      return GENERAL_AI_THEME;
    }

    const registered = themeRegistry.getDefinition(dbTheme.slug);
    if (registered) {
      const dbConfig = (dbTheme.config as unknown as ThemeConfig) || {};
      return {
        ...registered,
        id: dbTheme.id,
        name: dbTheme.name || registered.name,
        instructions: dbConfig.instructions || registered.instructions,
        rules: dbConfig.rules || registered.rules,
        config: dbConfig,
        createdAt: dbTheme.created_at,
        updatedAt: dbTheme.updated_at,
      };
    }

    return parseTheme(dbTheme);
  } catch (error) {
    console.error('Error resolving authorized theme:', error);
    return GENERAL_AI_THEME;
  }
}

export function buildThemeInstruction(theme: ThemeDefinition | null): string | null {
  if (!theme || theme.slug === 'general') return null;

  const parts: string[] = [];
  const instructions = theme.instructions || theme.config?.instructions;
  if (instructions) parts.push(instructions);

  const rules = theme.rules || theme.config?.rules;
  if (rules && rules.length > 0) {
    parts.push('Rules:\n' + rules.map((r: string) => `- ${r}`).join('\n'));
  }

  const methods = theme.config?.methods;
  if (methods && methods.length > 0) {
    parts.push('Methods:\n' + methods.map((m: string) => `- ${m}`).join('\n'));
  }

  return parts.join('\n\n') || null;
}

export async function resolveThemeInstruction(themeId: string | null | undefined): Promise<string | null> {
  const theme = await resolveAuthorizedTheme(themeId);
  return buildThemeInstruction(theme);
}
