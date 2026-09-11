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
import { resolveThemeSync } from './resolver';

describe('Phase 5.6: Sidebar Theme Indicators', () => {
  it('1. null or undefined theme_id resolves synchronously to General AI', () => {
    const fromNull = resolveThemeSync(null);
    expect(fromNull).toBe(GENERAL_AI_THEME);
    expect(fromNull.name).toBe('General AI');
    expect(fromNull.slug).toBe('general');
    expect(fromNull.icon).toBe('Globe');

    const fromUndefined = resolveThemeSync(undefined);
    expect(fromUndefined).toBe(GENERAL_AI_THEME);
  });

  it('2. Mathematics conversation resolves correctly to Mathematics', () => {
    const math = resolveThemeSync(MATHEMATICS_THEME.id);
    expect(math).toBe(MATHEMATICS_THEME);
    expect(math.name).toBe('Mathematics');
    expect(math.slug).toBe('mathematics');
    expect(math.icon).toBe('Calculator');
  });

  it('3. Programming conversation resolves correctly to Programming', () => {
    const prog = resolveThemeSync(PROGRAMMING_THEME.id);
    expect(prog).toBe(PROGRAMMING_THEME);
    expect(prog.name).toBe('Programming');
    expect(prog.slug).toBe('programming');
    expect(prog.icon).toBe('Code');
  });

  it('4. Safety Checkup conversation resolves correctly', () => {
    const safety = resolveThemeSync(SAFETY_CHECKUP_THEME.id);
    expect(safety).toBe(SAFETY_CHECKUP_THEME);
    expect(safety.name).toBe('Safety Checkup');
    expect(safety.slug).toBe('safety-checkup');
    expect(safety.icon).toBe('ShieldCheck');
  });

  it('5. Security Checkup conversation resolves correctly', () => {
    const security = resolveThemeSync(SECURITY_CHECKUP_THEME.id);
    expect(security).toBe(SECURITY_CHECKUP_THEME);
    expect(security.name).toBe('Security Checkup');
    expect(security.slug).toBe('security-checkup');
    expect(security.icon).toBe('ShieldAlert');
  });

  it('6. Study conversation resolves correctly', () => {
    const study = resolveThemeSync(STUDY_THEME.id);
    expect(study).toBe(STUDY_THEME);
    expect(study.name).toBe('Study');
    expect(study.slug).toBe('study');
    expect(study.icon).toBe('BookOpen');
  });

  it('7. Sidebar uses canonical ThemeDefinition metadata via resolveThemeSync', () => {
    const sidebarPath = path.resolve(process.cwd(), 'src/components/layout/Sidebar.tsx');
    const content = fs.readFileSync(sidebarPath, 'utf-8');

    expect(content).toContain("import { resolveThemeSync } from '@/lib/theme/catalog';");
    expect(content).toContain('resolveThemeSync(themeId)');
    expect(content).toContain('theme.name');
    expect(content).toContain('theme.slug');
  });

  it('8. Sidebar does not contain duplicate theme registries or hardcoded theme maps', () => {
    const sidebarPath = path.resolve(process.cwd(), 'src/components/layout/Sidebar.tsx');
    const content = fs.readFileSync(sidebarPath, 'utf-8');

    // Does not define duplicate theme arrays or registries
    expect(content).not.toContain('THEME_MAP = {');
    expect(content).not.toContain('THEMES = [');
    expect(content).not.toContain('THEME_LIST = [');

    // Does not query database for per-row theme resolution
    expect(content).not.toContain('getThemeById');
    expect(content).not.toContain('from(\'themes\')');
  });

  it('9. No per-conversation database query is introduced (pure synchronous in-memory resolution)', () => {
    // resolveThemeSync executes instantly in-memory without returning a promise
    let lastTheme: ThemeDefinition | undefined;
    const start = performance.now();
    for (let i = 0; i < 1000; i++) {
      lastTheme = resolveThemeSync(CANONICAL_THEMES[i % CANONICAL_THEMES.length].id);
    }
    const elapsed = performance.now() - start;
    expect(lastTheme).toBeDefined();
    expect(elapsed).toBeLessThan(50); // 1,000 lookups in under 50ms
  });

  it('10. Theme icon comes from canonical theme metadata', () => {
    const sidebarPath = path.resolve(process.cwd(), 'src/components/layout/Sidebar.tsx');
    const content = fs.readFileSync(sidebarPath, 'utf-8');

    expect(content).toContain('theme.visual?.iconName || theme.icon || \'Globe\'');
    expect(content).toContain('THEME_ICONS[iconKey] || Globe');
  });

  it('11. Theme name comes from canonical theme metadata', () => {
    const sidebarPath = path.resolve(process.cwd(), 'src/components/layout/Sidebar.tsx');
    const content = fs.readFileSync(sidebarPath, 'utf-8');

    expect(content).toContain('<span className="truncate">{theme.name}</span>');
  });

  it('12. Existing active conversation behavior remains unchanged', () => {
    const sidebarPath = path.resolve(process.cwd(), 'src/components/layout/Sidebar.tsx');
    const content = fs.readFileSync(sidebarPath, 'utf-8');

    // Active state highlighting preserved
    expect(content).toContain('pathname === `/chat/${chat.id}`');
    expect(content).toContain('bg-gray-200/80 dark:bg-gray-800 font-medium text-gray-900 dark:text-white shadow-sm');
  });

  it('13. Mobile-safe structure with truncation and proper padding', () => {
    const sidebarPath = path.resolve(process.cwd(), 'src/components/layout/Sidebar.tsx');
    const content = fs.readFileSync(sidebarPath, 'utf-8');

    // Both title and theme indicator have truncation
    expect(content).toContain('<span className="truncate text-sm leading-snug">{chat.title}</span>');
    expect(content).toContain('<span className="truncate">{theme.name}</span>');
    // Right padding ensures no collision with action buttons
    expect(content).toContain('pr-10');
  });

  it('14. Visual theme integration uses data-theme and semantic tokens', () => {
    const sidebarPath = path.resolve(process.cwd(), 'src/components/layout/Sidebar.tsx');
    const content = fs.readFileSync(sidebarPath, 'utf-8');

    expect(content).toContain('data-theme={theme.slug}');
    expect(content).toContain('text-theme-accent');
    // Zero hardcoded theme colors
    expect(content).not.toContain('text-teal-');
    expect(content).not.toContain('text-emerald-');
    expect(content).not.toContain('text-rose-');
    expect(content).not.toContain('text-purple-');
  });

  it('15. Indicator remains informational and non-interactive', () => {
    const sidebarPath = path.resolve(process.cwd(), 'src/components/layout/Sidebar.tsx');
    const content = fs.readFileSync(sidebarPath, 'utf-8');

    // Embedded inside the conversation Link as non-interactive elements
    expect(content).toContain('data-testid="sidebar-theme-indicator"');
    expect(content).toContain('aria-hidden="true"');
    // Indicator itself does not have click handlers or button tags
    expect(content).not.toContain('onClick={(e) => e.stopPropagation()}');
  });
});
