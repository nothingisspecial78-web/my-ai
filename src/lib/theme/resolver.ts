import { getThemeById } from '@/lib/database';
import { parseTheme } from '@/lib/theme/types';

export async function resolveThemeInstruction(themeId: string | null | undefined): Promise<string | null> {
  if (!themeId) {
    return null; // Null/missing theme_id means General AI
  }

  try {
    const dbTheme = await getThemeById(themeId);
    
    // If not found, RLS blocked it (unauthorized) or it doesn't exist (invalid)
    if (!dbTheme) {
      return null;
    }

    const theme = parseTheme(dbTheme);

    // Explicitly enforce authorized Phase 4.1 access model:
    // Only enabled system themes are accessible for instruction injection
    if (theme.enabled && theme.isSystem) {
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

    // Disabled or non-system themes are inaccessible and fall back to General AI
    return null;
  } catch (error) {
    console.error('Error resolving theme instruction:', error);
    // Safely handle errors without crashing, fallback to General AI
    return null;
  }
}
