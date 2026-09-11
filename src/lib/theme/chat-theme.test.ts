import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { resolveAuthorizedTheme } from './resolver';
import { GENERAL_AI_THEME, CANONICAL_THEMES, CANONICAL_THEME_MAP } from './catalog';

describe('Phase 5.3: Chat UI Theme Integration & Token Scoping', () => {
  it('1. resolves null or undefined theme_id to General AI baseline with zero DB call', async () => {
    const themeFromNull = await resolveAuthorizedTheme(null);
    expect(themeFromNull).toBe(GENERAL_AI_THEME);
    expect(themeFromNull.slug).toBe('general');

    const themeFromUndefined = await resolveAuthorizedTheme(undefined);
    expect(themeFromUndefined).toBe(GENERAL_AI_THEME);
    expect(themeFromUndefined.slug).toBe('general');
  });

  it('2. correctly derives active theme slug for empty chat page from selectedThemeId', () => {
    // Baseline null
    const baselineSlug = (null && CANONICAL_THEME_MAP[null]?.slug) || 'general';
    expect(baselineSlug).toBe('general');

    // Specialized themes
    for (const theme of CANONICAL_THEMES) {
      if (theme.slug === 'general') continue;
      const derivedSlug = (theme.id && CANONICAL_THEME_MAP[theme.id]?.slug) || 'general';
      expect(derivedSlug).toBe(theme.slug);
    }

    // Invalid / unknown UUID
    const fallbackSlug = ('unknown-uuid' && CANONICAL_THEME_MAP['unknown-uuid']?.slug) || 'general';
    expect(fallbackSlug).toBe('general');
  });

  it('3. verifies /chat/[id]/page.tsx server hydration calls resolveAuthorizedTheme', () => {
    const pagePath = path.resolve(process.cwd(), 'src/app/chat/[id]/page.tsx');
    const content = fs.readFileSync(pagePath, 'utf-8');

    expect(content).toContain("import { resolveAuthorizedTheme } from '@/lib/theme/resolver';");
    expect(content).toContain('await resolveAuthorizedTheme(conversation.theme_id)');
    expect(content).toContain('theme={theme}');
  });

  it('4. verifies ChatClient.tsx accepts theme prop and applies data-theme and theme background', () => {
    const clientPath = path.resolve(process.cwd(), 'src/app/chat/[id]/ChatClient.tsx');
    const content = fs.readFileSync(clientPath, 'utf-8');

    expect(content).toContain("import { ThemeDefinition } from '@/lib/theme/types';");
    expect(content).toContain('theme?: ThemeDefinition;');
    expect(content).toContain("data-theme={theme?.slug || 'general'}");
    expect(content).toContain('bg-[var(--theme-bg)]');
    expect(content).toContain('from-[var(--theme-bg)] via-[var(--theme-bg)]');
  });

  it('5. verifies chat/page.tsx binds data-theme and theme background dynamically', () => {
    const pagePath = path.resolve(process.cwd(), 'src/app/chat/page.tsx');
    const content = fs.readFileSync(pagePath, 'utf-8');

    expect(content).toContain("import { CANONICAL_THEME_MAP } from '@/lib/theme/catalog';");
    expect(content).toContain("activeThemeSlug = (selectedThemeId && CANONICAL_THEME_MAP[selectedThemeId]?.slug) || 'general'");
    expect(content).toContain('data-theme={activeThemeSlug}');
    expect(content).toContain('bg-[var(--theme-bg)]');
    expect(content).toContain('from-[var(--theme-bg)] via-[var(--theme-bg)]');
  });

  it('6. verifies Message.tsx uses semantic theme tokens for avatar, card, user bubble, and thinking pulse', () => {
    const messagePath = path.resolve(process.cwd(), 'src/components/chat/Message.tsx');
    const content = fs.readFileSync(messagePath, 'utf-8');

    // Assistant avatar uses theme avatar tokens
    expect(content).toContain('bg-theme-avatar-bg text-theme-avatar-fg');
    expect(content).not.toContain('bg-blue-600 text-white shadow-sm mt-1');

    // Assistant card uses theme card and border
    expect(content).toContain('bg-[var(--theme-card)] border border-[var(--theme-border)]');

    // User message bubble uses theme bubble tokens
    expect(content).toContain('bg-[var(--theme-bubble-user)] text-[var(--theme-bubble-user-text)]');

    // Thinking dots use theme accent
    expect(content).toContain('bg-theme-accent animate-pulse');

    // Code block header and body use theme muted card and border
    expect(content).toContain('bg-[var(--theme-card-muted)] border-b border-[var(--theme-border)]');
    expect(content).toContain('bg-[var(--theme-card-muted)] text-sm');

    // Toolbar button uses theme accent subtle and focus ring
    expect(content).toContain('text-theme-accent bg-theme-subtle');
    expect(content).toContain('focus-visible:ring-theme-composer-focus');
  });

  it('7. verifies ChatComposer.tsx uses semantic theme tokens for border, card, focus rings, and send button', () => {
    const composerPath = path.resolve(process.cwd(), 'src/components/chat/ChatComposer.tsx');
    const content = fs.readFileSync(composerPath, 'utf-8');

    // Container border and card
    expect(content).toContain('border border-[var(--theme-composer-border)] bg-[var(--theme-card)]');
    expect(content).toContain('focus-within:ring-theme-composer-focus focus-within:border-theme-border');

    // Send button uses theme accent
    expect(content).toContain('bg-theme-accent hover:opacity-90');
    expect(content).toContain('focus-visible:ring-theme-composer-focus');

    // Upload loader
    expect(content).toContain('text-theme-accent mb-1');
  });
});
