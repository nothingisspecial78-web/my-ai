import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { CANONICAL_THEMES } from './catalog';

describe('Phase 5.2: Visual Theme Tokens & Tailwind Bridge', () => {
  const cssPath = path.resolve(process.cwd(), 'src/app/globals.css');
  const cssContent = fs.readFileSync(cssPath, 'utf-8');

  const REQUIRED_TOKENS = [
    '--theme-bg',
    '--theme-card',
    '--theme-card-muted',
    '--theme-border',
    '--theme-border-strong',
    '--theme-accent',
    '--theme-accent-subtle',
    '--theme-accent-border',
    '--theme-accent-foreground',
    '--theme-avatar-bg',
    '--theme-avatar-fg',
    '--theme-bubble-user',
    '--theme-bubble-user-text',
    '--theme-composer-border',
    '--theme-composer-focus',
    '--theme-badge-bg',
    '--theme-badge-text',
    '--theme-glow',
    '--theme-risk-low',
    '--theme-risk-medium',
    '--theme-risk-high',
    '--theme-risk-critical',
  ];

  const ACTIVE_SLUGS = CANONICAL_THEMES.map(t => t.slug);

  it('1. defines all 6 active themes with data-theme scoping in globals.css', () => {
    for (const slug of ACTIVE_SLUGS) {
      expect(cssContent).toContain(`[data-theme="${slug}"]`);
      expect(cssContent).toContain(`.dark [data-theme="${slug}"]`);
    }
  });

  it('2. provides explicit values for all required tokens across all 6 active themes', () => {
    for (const slug of ACTIVE_SLUGS) {
      // Find light block
      const lightRegex = new RegExp(`\\[data-theme="${slug}"\\]\\s*\\{([^}]+)\\}`, 'm');
      const lightMatch = cssContent.match(lightRegex);
      expect(lightMatch, `Missing light block for theme ${slug}`).not.toBeNull();
      const lightBlock = lightMatch![1];

      for (const token of REQUIRED_TOKENS) {
        expect(lightBlock, `Theme ${slug} (light) missing token ${token}`).toContain(token);
      }

      // Find dark block
      const darkRegex = new RegExp(`\\.dark\\s+\\[data-theme="${slug}"\\]\\s*\\{([^}]+)\\}`, 'm');
      const darkMatch = cssContent.match(darkRegex);
      expect(darkMatch, `Missing dark block for theme ${slug}`).not.toBeNull();
      const darkBlock = darkMatch![1];

      for (const token of REQUIRED_TOKENS) {
        expect(darkBlock, `Theme ${slug} (dark) missing token ${token}`).toContain(token);
      }
    }
  });

  it('3. bridges required semantic theme colors into Tailwind v4 @theme inline', () => {
    const themeInlineMatch = cssContent.match(/@theme inline\s*\{([^}]+)\}/);
    expect(themeInlineMatch).not.toBeNull();
    const themeInlineBlock = themeInlineMatch![1];

    const EXPECTED_BRIDGE_TOKENS = [
      '--color-theme-accent: var(--theme-accent);',
      '--color-theme-subtle: var(--theme-accent-subtle);',
      '--color-theme-border: var(--theme-accent-border);',
      '--color-theme-avatar-bg: var(--theme-avatar-bg);',
      '--color-theme-avatar-fg: var(--theme-avatar-fg);',
      '--color-theme-badge-bg: var(--theme-badge-bg);',
      '--color-theme-badge-text: var(--theme-badge-text);',
      '--color-theme-composer-focus: var(--theme-composer-focus);',
    ];

    for (const bridgeToken of EXPECTED_BRIDGE_TOKENS) {
      expect(themeInlineBlock).toContain(bridgeToken);
    }
  });

  it('4. preserves next-themes light/dark mode separation without coupling to theme tokens', () => {
    expect(cssContent).toContain('.dark {');
    expect(cssContent).toContain('--background: #0a0a0a;');
    expect(cssContent).toContain('--foreground: #ededed;');
    expect(cssContent).toContain('@media (prefers-color-scheme: dark)');
  });
});
