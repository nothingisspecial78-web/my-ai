import { getThemeById } from '@/lib/database';
import { Theme, parseTheme } from '@/lib/theme/types';

export async function resolveAuthorizedTheme(themeId: string | null | undefined): Promise<Theme | null> {
  if (!themeId) {
    return null;
  }

  try {
    const dbTheme = await getThemeById(themeId);
    if (!dbTheme) {
      return null;
    }

    const theme = parseTheme(dbTheme);
    if (theme.enabled && theme.isSystem) {
      return theme;
    }

    return null;
  } catch (error) {
    console.error('Error resolving authorized theme:', error);
    return null;
  }
}

export function buildThemeInstruction(theme: Theme | null): string | null {
  if (!theme) return null;

  const parts = [];
  if (theme.config.instructions) parts.push(theme.config.instructions);
  if (theme.config.rules && theme.config.rules.length > 0) {
    parts.push('Rules:\n' + theme.config.rules.map((r: string) => `- ${r}`).join('\n'));
  }
  if (theme.config.methods && theme.config.methods.length > 0) {
    parts.push('Methods:\n' + theme.config.methods.map((m: string) => `- ${m}`).join('\n'));
  }
  return parts.join('\n\n') || null;
}

export async function resolveThemeInstruction(themeId: string | null | undefined): Promise<string | null> {
  const theme = await resolveAuthorizedTheme(themeId);
  return buildThemeInstruction(theme);
}
