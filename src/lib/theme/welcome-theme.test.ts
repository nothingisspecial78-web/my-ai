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

describe('Phase 5.4: Theme-Aware Welcome Screen', () => {
  it('1. verifies all 6 active themes have distinct, canonical welcome configurations', () => {
    expect(CANONICAL_THEMES).toHaveLength(6);

    const expectedWelcomeData = [
      {
        theme: GENERAL_AI_THEME,
        heroTitle: 'Welcome to MyAI',
        heroSubtitle: 'How can I help you today?',
        heroIcon: 'Sparkles',
        firstSuggestion: 'Summarize this document',
      },
      {
        theme: MATHEMATICS_THEME,
        heroTitle: 'Mathematics Assistant',
        heroSubtitle: 'Exact derivations, step-by-step proofs, and algebraic problem-solving.',
        heroIcon: 'Calculator',
        firstSuggestion: 'Step-by-step calculus derivation',
      },
      {
        theme: PROGRAMMING_THEME,
        heroTitle: 'Software Engineering Copilot',
        heroSubtitle: 'Architecture, clean code, debugging, and security-first development.',
        heroIcon: 'Code',
        firstSuggestion: 'Debug a TypeScript error',
      },
      {
        theme: SAFETY_CHECKUP_THEME,
        heroTitle: 'Digital Safety Checkup',
        heroSubtitle: 'Analyze suspicious links, messages, emails, and scam requests.',
        heroIcon: 'ShieldCheck',
        firstSuggestion: 'Check a suspicious URL',
      },
      {
        theme: SECURITY_CHECKUP_THEME,
        heroTitle: 'Technical Security Inspection',
        heroSubtitle: 'Audit web endpoints, security headers, token leaks, and vulnerabilities.',
        heroIcon: 'ShieldAlert',
        firstSuggestion: 'Inspect URL structure and punycode',
      },
      {
        theme: STUDY_THEME,
        heroTitle: 'Socratic Learning Tutor',
        heroSubtitle: 'Deepen your understanding through guided questions, hints, and practice.',
        heroIcon: 'BookOpen',
        firstSuggestion: 'Guide me through quantum mechanics',
      },
    ];

    for (const item of expectedWelcomeData) {
      expect(item.theme.welcome.heroTitle).toBe(item.heroTitle);
      expect(item.theme.welcome.heroSubtitle).toBe(item.heroSubtitle);
      expect(item.theme.welcome.heroIcon).toBe(item.heroIcon);
      expect(item.theme.welcome.suggestions).toHaveLength(4);
      expect(item.theme.welcome.suggestions[0].title).toBe(item.firstSuggestion);
      expect(item.theme.welcome.suggestions[0].prompt).toBeTruthy();
      expect(item.theme.welcome.suggestions[0].iconName).toBeTruthy();
    }
  });

  it('2. verifies WelcomeScreen.tsx consumes active ThemeDefinition and semantic tokens', () => {
    const welcomePath = path.resolve(process.cwd(), 'src/components/chat/WelcomeScreen.tsx');
    const content = fs.readFileSync(welcomePath, 'utf-8');

    // Accepts theme prop
    expect(content).toContain('theme?: ThemeDefinition;');
    expect(content).toContain('activeTheme = theme || GENERAL_AI_THEME');

    // Semantic tokens for hero
    expect(content).toContain('bg-theme-avatar-bg text-theme-avatar-fg shadow-xl shadow-[var(--theme-glow)]');

    // Semantic tokens for suggestions
    expect(content).toContain('border border-[var(--theme-border)] bg-[var(--theme-card)]');
    expect(content).toContain('hover:bg-[var(--theme-card-muted)] hover:border-theme-border hover:shadow-md hover:shadow-[var(--theme-glow)]');
    expect(content).toContain('bg-theme-subtle text-theme-accent');

    // Suggestion click sends prompt or title
    expect(content).toContain('onClick={() => onSuggestionClick(s.prompt || s.title)}');

    // Zero hardcoded theme colors
    expect(content).not.toContain('bg-gradient-to-br from-blue-500 to-indigo-600');
    expect(content).not.toContain('hover:border-blue-300');
    expect(content).not.toContain('hover:border-blue-800');
    expect(content).not.toContain('text-blue-500');
    expect(content).not.toContain('text-purple-500');
    expect(content).not.toContain('text-green-500');
    expect(content).not.toContain('text-amber-500');
  });

  it('3. verifies chat/page.tsx passes active theme to WelcomeScreen and applies data-theme', () => {
    const chatPagePath = path.resolve(process.cwd(), 'src/app/chat/page.tsx');
    const content = fs.readFileSync(chatPagePath, 'utf-8');

    expect(content).toContain('const activeTheme = (selectedThemeId && CANONICAL_THEME_MAP[selectedThemeId]) || GENERAL_AI_THEME;');
    expect(content).toContain('data-theme={activeTheme.slug}');
    expect(content).toContain('<WelcomeScreen onSuggestionClick={handleSend} disabled={isNavigating} theme={activeTheme} />');
  });

  it('4. verifies ChatClient.tsx passes theme prop to WelcomeScreen', () => {
    const chatClientPath = path.resolve(process.cwd(), 'src/app/chat/[id]/ChatClient.tsx');
    const content = fs.readFileSync(chatClientPath, 'utf-8');

    expect(content).toContain('<WelcomeScreen onSuggestionClick={handleSend} disabled={isSending} theme={theme} />');
  });
});
