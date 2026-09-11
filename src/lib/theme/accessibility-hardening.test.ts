import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import {
  CANONICAL_THEMES,
  GENERAL_AI_THEME,
  MATHEMATICS_THEME,
  PROGRAMMING_THEME,
  SAFETY_CHECKUP_THEME,
  SECURITY_CHECKUP_THEME,
  STUDY_THEME,
  getThemePresentation,
  resolveThemeSync,
} from './catalog';

describe('Phase 5.8: Mobile + Accessibility Hardening Regression Tests', () => {
  const sidebarFile = fs.readFileSync(path.resolve(process.cwd(), 'src/components/layout/Sidebar.tsx'), 'utf-8');
  const messageFile = fs.readFileSync(path.resolve(process.cwd(), 'src/components/chat/Message.tsx'), 'utf-8');
  const composerFile = fs.readFileSync(path.resolve(process.cwd(), 'src/components/chat/ChatComposer.tsx'), 'utf-8');
  const welcomeFile = fs.readFileSync(path.resolve(process.cwd(), 'src/components/chat/WelcomeScreen.tsx'), 'utf-8');
  const safetyCardFile = fs.readFileSync(path.resolve(process.cwd(), 'src/components/safety/SafetyAnalysisCard.tsx'), 'utf-8');
  const themeSelectorFile = fs.readFileSync(path.resolve(process.cwd(), 'src/components/chat/ThemeSelector.tsx'), 'utf-8');
  const chatClientFile = fs.readFileSync(path.resolve(process.cwd(), 'src/app/chat/[id]/ChatClient.tsx'), 'utf-8');
  const globalsCssFile = fs.readFileSync(path.resolve(process.cwd(), 'src/app/globals.css'), 'utf-8');

  // 1. Icon-only buttons have accessible names
  it('1. Icon-only buttons have accessible names (aria-label or title)', () => {
    // Sidebar buttons
    expect(sidebarFile).toContain('aria-label="Open sidebar menu"');
    expect(sidebarFile).toContain('aria-label="Close sidebar"');
    expect(sidebarFile).toContain('aria-label="Rename conversation"');
    expect(sidebarFile).toContain('aria-label="Delete conversation"');
    expect(sidebarFile).toContain('aria-label="User account menu"');

    // Message toolbar buttons
    expect(messageFile).toContain('aria-label="Copy code"');
    expect(messageFile).toContain('aria-label={label}');

    // ChatComposer buttons
    expect(composerFile).toContain('aria-label="Upload file or photo"');
    expect(composerFile).toContain('aria-label="Voice input"');
    expect(composerFile).toContain('aria-label="Send message"');
    expect(composerFile).toContain('aria-label="Remove image"');

    // Header buttons in ChatClient
    expect(chatClientFile).toContain('aria-label="Share conversation"');
    expect(chatClientFile).toContain('aria-label="More conversation options"');
    expect(chatClientFile).toContain('aria-label="Stop generation"');

    // SafetyAnalysisCard toggle button
    expect(safetyCardFile).toContain('aria-label={isExpanded ? \'Collapse analysis details\' : \'Expand analysis details\'}');
  });

  // 2. Decorative icons are hidden from assistive technology
  it('2. Decorative icons are hidden from assistive technology (aria-hidden="true")', () => {
    expect(sidebarFile).toContain('aria-hidden="true"');
    expect(messageFile).toContain('aria-hidden="true"');
    expect(welcomeFile).toContain('aria-hidden="true"');
    expect(safetyCardFile).toContain('aria-hidden="true"');
    expect(composerFile).toContain('aria-hidden="true"');
    expect(chatClientFile).toContain('aria-hidden="true"');
    expect(themeSelectorFile).toContain('aria-hidden="true"');
  });

  // 3. Expandable safety card exposes expanded state
  it('3. Expandable safety card exposes aria-expanded and aria-controls state', () => {
    expect(safetyCardFile).toContain('aria-expanded={isExpanded}');
    expect(safetyCardFile).toContain('aria-controls="safety-analysis-details"');
    expect(safetyCardFile).toContain('id="safety-analysis-details"');
  });

  // 4. ThemeBadge exposes active theme information
  it('4. ThemeBadge exposes active theme information via role="status" and aria-label', () => {
    const themeBadgeFile = fs.readFileSync(path.resolve(process.cwd(), 'src/components/chat/ThemeBadge.tsx'), 'utf-8');
    expect(themeBadgeFile).toContain('role="status"');
    expect(themeBadgeFile).toContain('aria-label={`Active theme: ${themeName}`}');
    expect(themeBadgeFile).toContain('aria-hidden="true"');
  });

  // 5. Theme identity and safety risk levels do not rely solely on color
  it('5. Theme identity and safety risk levels do not rely solely on color (text + icons)', () => {
    for (const theme of CANONICAL_THEMES) {
      expect(theme.name).toBeTruthy();
      expect(theme.icon).toBeTruthy();
      expect(theme.visual?.themeAttribute).toBe(theme.slug);
    }

    // Safety card risk levels specify explicit textual labels and distinct icons
    expect(safetyCardFile).toContain("label: 'CRITICAL RISK'");
    expect(safetyCardFile).toContain("label: 'HIGH RISK'");
    expect(safetyCardFile).toContain("label: 'MEDIUM RISK'");
    expect(safetyCardFile).toContain("label: 'LOW RISK'");
  });

  // 6. All six canonical themes resolve correctly
  it('6. All six canonical themes resolve correctly', () => {
    const slugs = ['general', 'mathematics', 'programming', 'safety-checkup', 'security-checkup', 'study'];
    for (const slug of slugs) {
      const resolved = resolveThemeSync(slug);
      expect(resolved.slug).toBe(slug);
      expect(resolved.name).toBeTruthy();
      expect(resolved.visual).toBeDefined();
    }
  });

  // 7. Mobile-safe wrapping classes and structure exist where needed
  it('7. Mobile-safe wrapping classes/structure exist where needed', () => {
    // User message bubble width and wrapping
    expect(messageFile).toContain('max-w-[85%] sm:max-w-[75%]');
    expect(messageFile).toContain('[overflow-wrap:anywhere]');

    // Safety analysis card wrapping
    expect(safetyCardFile).toContain('[overflow-wrap:anywhere]');
    expect(safetyCardFile).toContain('break-all');

    // Welcome screen responsive typography
    expect(welcomeFile).toContain('text-3xl sm:text-4xl md:text-5xl');

    // Mobile header title truncation
    expect(chatClientFile).toContain('truncate max-w-[150px] sm:max-w-[240px]');
  });

  // 8. Long content cannot force page-wide overflow; internal scrolling is preserved
  it('8. Markdown tables and code blocks preserve legitimate internal scrolling', () => {
    // ReactMarkdown custom table container with overflow-x-auto
    expect(messageFile).toContain('overflow-x-auto my-4 rounded-lg');
    expect(messageFile).toContain('<table {...props}');

    // Code block internal scroll container
    expect(messageFile).toContain('overflow-x-auto bg-[var(--theme-card-muted)] text-sm');
  });

  // 9. Composer controls remain available, accessible, and touch-sized
  it('9. Composer controls remain available, accessible, and touch-sized on mobile', () => {
    expect(composerFile).toContain('min-h-[44px]');
    expect(composerFile).toContain('h-10 w-10 sm:h-9 sm:w-9');
    expect(composerFile).toContain('h-10 sm:h-9');
    expect(composerFile).toContain('type="file"');
    expect(composerFile).toContain('placeholder="Message Before You Click..."');

    // Remove attachment button is accessible on touch devices
    expect(composerFile).toContain('opacity-100 sm:opacity-0 sm:group-hover:opacity-100');
  });

  // 10. Keyboard-accessible interactive controls remain native/usable with visible focus rings
  it('10. Keyboard-accessible interactive controls remain native/usable with visible focus rings', () => {
    // Focus visible rings in components
    expect(composerFile).toContain('focus-visible:ring-theme-composer-focus');
    expect(welcomeFile).toContain('focus-visible:ring-theme-composer-focus');
    expect(themeSelectorFile).toContain('focus-visible:ring-blue-500');
    expect(sidebarFile).toContain('focus-visible:ring-blue-500');
    expect(chatClientFile).toContain('focus-visible:ring-theme-composer-focus');

    // ThemeSelector listbox semantics
    expect(themeSelectorFile).toContain('role="listbox"');
    expect(themeSelectorFile).toContain('role="option"');
    expect(themeSelectorFile).toContain('aria-haspopup="listbox"');
    expect(themeSelectorFile).toContain('aria-expanded={isOpen}');
    expect(themeSelectorFile).toContain('onKeyDown={handleTriggerKeyDown}');
    expect(themeSelectorFile).toContain('onKeyDown={handleListboxKeyDown}');

    // Sidebar drawer dialog role and escape listener
    expect(sidebarFile).toContain('role="dialog"');
    expect(sidebarFile).toContain('aria-modal="true"');
    expect(sidebarFile).toContain('aria-label="Navigation drawer"');
  });

  // 11. Reduced-motion behavior exists where animation requires it
  it('11. Reduced-motion behavior exists where animation requires it', () => {
    // Global prefers-reduced-motion in globals.css
    expect(globalsCssFile).toContain('@media (prefers-reduced-motion: reduce)');
    expect(globalsCssFile).toContain('animation-duration: 0.01ms !important');

    // WelcomeScreen prefers-reduced-motion in styled jsx
    expect(welcomeFile).toContain('@media (prefers-reduced-motion: reduce)');
    expect(welcomeFile).toContain('animation: none !important');
  });

  // 12. Safety and Security cards preserve distinct presentation
  it('12. Safety and Security cards preserve distinct presentation', () => {
    expect(SAFETY_CHECKUP_THEME.slug).toBe('safety-checkup');
    expect(SECURITY_CHECKUP_THEME.slug).toBe('security-checkup');
    const safetyPres = getThemePresentation('safety-checkup');
    const secPres = getThemePresentation('security-checkup');

    expect(safetyPres.cardTitle).toBe('Safety Checkup');
    expect(secPres.cardTitle).toBe('Security Inspection');
    expect(safetyPres.findingsLabel).toBe('What We Found');
    expect(secPres.findingsLabel).toBe('Technical Findings & Indicators');
    expect(safetyPres.actionsLabel).toBe('What You Should Do');
    expect(secPres.actionsLabel).toBe('Remediation & Hardening Actions');
  });

  // 13. General, Mathematics, Programming, and Study remain unchanged
  it('13. General, Mathematics, Programming, and Study canonical configurations remain intact', () => {
    expect(GENERAL_AI_THEME.slug).toBe('general');
    expect(MATHEMATICS_THEME.slug).toBe('mathematics');
    expect(PROGRAMMING_THEME.slug).toBe('programming');
    expect(STUDY_THEME.slug).toBe('study');

    expect(GENERAL_AI_THEME.welcome.suggestions).toHaveLength(4);
    expect(MATHEMATICS_THEME.welcome.suggestions).toHaveLength(4);
    expect(PROGRAMMING_THEME.welcome.suggestions).toHaveLength(4);
    expect(STUDY_THEME.welcome.suggestions).toHaveLength(4);
  });
});
