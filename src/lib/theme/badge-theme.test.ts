import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import {
  GENERAL_AI_THEME,
  MATHEMATICS_THEME,
  PROGRAMMING_THEME,
  SAFETY_CHECKUP_THEME,
  SECURITY_CHECKUP_THEME,
  STUDY_THEME,
  CANONICAL_THEMES,
} from './catalog';
import { resolveAuthorizedTheme } from './resolver';

describe('Phase 5.5: Active Chat Theme Badge', () => {
  it('1. verifies General AI resolves to General AI badge metadata', () => {
    expect(GENERAL_AI_THEME.name).toBe('General AI');
    expect(GENERAL_AI_THEME.slug).toBe('general');
    expect(GENERAL_AI_THEME.icon).toBe('Globe');
    expect(GENERAL_AI_THEME.visual.iconName).toBe('Globe');
    expect(GENERAL_AI_THEME.visual.badgeText).toBe('General AI');
  });

  it('2. verifies Mathematics resolves to Mathematics badge metadata', () => {
    expect(MATHEMATICS_THEME.name).toBe('Mathematics');
    expect(MATHEMATICS_THEME.slug).toBe('mathematics');
    expect(MATHEMATICS_THEME.icon).toBe('Calculator');
    expect(MATHEMATICS_THEME.visual.iconName).toBe('Calculator');
    expect(MATHEMATICS_THEME.visual.badgeText).toBe('Mathematics');
  });

  it('3. verifies Programming resolves to Programming badge metadata', () => {
    expect(PROGRAMMING_THEME.name).toBe('Programming');
    expect(PROGRAMMING_THEME.slug).toBe('programming');
    expect(PROGRAMMING_THEME.icon).toBe('Code');
    expect(PROGRAMMING_THEME.visual.iconName).toBe('Code');
    expect(PROGRAMMING_THEME.visual.badgeText).toBe('Programming');
  });

  it('4. verifies Safety Checkup resolves to Safety Checkup badge metadata', () => {
    expect(SAFETY_CHECKUP_THEME.name).toBe('Safety Checkup');
    expect(SAFETY_CHECKUP_THEME.slug).toBe('safety-checkup');
    expect(SAFETY_CHECKUP_THEME.icon).toBe('ShieldCheck');
    expect(SAFETY_CHECKUP_THEME.visual.iconName).toBe('ShieldCheck');
    expect(SAFETY_CHECKUP_THEME.visual.badgeText).toBe('Safety Checkup');
  });

  it('5. verifies Security Checkup resolves to Security Checkup badge metadata', () => {
    expect(SECURITY_CHECKUP_THEME.name).toBe('Security Checkup');
    expect(SECURITY_CHECKUP_THEME.slug).toBe('security-checkup');
    expect(SECURITY_CHECKUP_THEME.icon).toBe('ShieldAlert');
    expect(SECURITY_CHECKUP_THEME.visual.iconName).toBe('ShieldAlert');
    expect(SECURITY_CHECKUP_THEME.visual.badgeText).toBe('Security Checkup');
  });

  it('6. verifies Study resolves to Study badge metadata', () => {
    expect(STUDY_THEME.name).toBe('Study');
    expect(STUDY_THEME.slug).toBe('study');
    expect(STUDY_THEME.icon).toBe('BookOpen');
    expect(STUDY_THEME.visual.iconName).toBe('BookOpen');
    expect(STUDY_THEME.visual.badgeText).toBe('Study');
  });

  it('7. verifies badge consumes semantic theme tokens and no hardcoded theme colors', () => {
    const badgePath = path.resolve(process.cwd(), 'src/components/chat/ThemeBadge.tsx');
    const content = fs.readFileSync(badgePath, 'utf-8');

    // Semantic theme token classes
    expect(content).toContain('bg-theme-badge-bg');
    expect(content).toContain('text-theme-badge-text');
    expect(content).toContain('text-theme-accent');
    expect(content).toContain('border-theme-border');

    // No hardcoded theme colors
    expect(content).not.toContain('#2563eb');
    expect(content).not.toContain('#0d9488');
    expect(content).not.toContain('#059669');
    expect(content).not.toContain('#e11d48');
    expect(content).not.toContain('#7c3aed');
    expect(content).not.toContain('bg-blue-');
    expect(content).not.toContain('bg-teal-');
    expect(content).not.toContain('bg-emerald-');
    expect(content).not.toContain('bg-rose-');
    expect(content).not.toContain('bg-purple-');
  });

  it('8. verifies ThemeBadge receives the canonical ThemeDefinition type', () => {
    const badgePath = path.resolve(process.cwd(), 'src/components/chat/ThemeBadge.tsx');
    const content = fs.readFileSync(badgePath, 'utf-8');

    expect(content).toContain("import { ThemeDefinition } from '@/lib/theme/types';");
    expect(content).toContain('theme?: ThemeDefinition | null;');
    expect(content).toContain('const activeTheme = theme || GENERAL_AI_THEME;');
  });

  it('9. verifies no duplicate theme registry is introduced in ThemeBadge', () => {
    const badgePath = path.resolve(process.cwd(), 'src/components/chat/ThemeBadge.tsx');
    const content = fs.readFileSync(badgePath, 'utf-8');

    // Does not define duplicate theme arrays or registries
    expect(content).not.toContain('themes = [');
    expect(content).not.toContain('THEMES = [');
    expect(content).not.toContain('THEME_LIST = [');
    expect(content).not.toContain('createClient');
    expect(content).not.toContain('supabase');
  });

  it('10. verifies zero database query is required for General AI resolution', async () => {
    const theme = await resolveAuthorizedTheme(null);
    expect(theme).toBe(GENERAL_AI_THEME);
    expect(theme.name).toBe('General AI');
  });

  it('11. verifies badge is informational and non-interactive', () => {
    const badgePath = path.resolve(process.cwd(), 'src/components/chat/ThemeBadge.tsx');
    const content = fs.readFileSync(badgePath, 'utf-8');

    // Role and accessibility
    expect(content).toContain('role="status"');
    expect(content).toContain('aria-label={`Active theme: ${themeName}`}');
    expect(content).toContain('aria-hidden="true"');

    // Not a button and no interactive handlers
    expect(content).not.toContain('<button');
    expect(content).not.toContain('onClick');
    expect(content).not.toContain('tabIndex');
    expect(content).not.toContain('cursor-pointer');
  });

  it('12. verifies mobile-safe structure with overflow prevention', () => {
    const badgePath = path.resolve(process.cwd(), 'src/components/chat/ThemeBadge.tsx');
    const content = fs.readFileSync(badgePath, 'utf-8');

    // Shrink prevention and truncation
    expect(content).toContain('shrink-0');
    expect(content).toContain('truncate');
    expect(content).toContain('max-w-[120px]');
    expect(content).toContain('select-none');

    // ChatClient desktop & mobile integration
    const clientPath = path.resolve(process.cwd(), 'src/app/chat/[id]/ChatClient.tsx');
    const clientContent = fs.readFileSync(clientPath, 'utf-8');

    // Both desktop and mobile header bars include ThemeBadge
    expect(clientContent).toContain("import { ThemeBadge } from '@/components/chat/ThemeBadge';");
    expect(clientContent).toContain('<ThemeBadge theme={theme} />');
    expect(clientContent).toContain('md:hidden flex items-center justify-between px-4 py-2');
  });

  it('13. verifies all 6 canonical themes have badge tokens defined in globals.css', () => {
    const cssPath = path.resolve(process.cwd(), 'src/app/globals.css');
    const cssContent = fs.readFileSync(cssPath, 'utf-8');

    for (const theme of CANONICAL_THEMES) {
      expect(cssContent).toContain(`[data-theme="${theme.slug}"]`);
      expect(cssContent).toContain('--theme-badge-bg:');
      expect(cssContent).toContain('--theme-badge-text:');
    }
  });
});
