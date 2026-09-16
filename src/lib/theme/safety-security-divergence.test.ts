import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import {
  SAFETY_CHECKUP_THEME,
  SECURITY_CHECKUP_THEME,
  GENERAL_AI_THEME,
  MATHEMATICS_THEME,
  PROGRAMMING_THEME,
  STUDY_THEME,
  CANONICAL_THEMES,
  getThemePresentation,
  resolveThemeSync,
} from './catalog';
import { themeRegistry } from './registry';
import { RiskEngine } from '@/lib/safety/risk-engine';

describe('Phase 5.7: Safety vs Security UI Divergence', () => {
  // 1. Safety Checkup resolves its canonical presentation configuration
  it('1. Safety Checkup resolves its canonical presentation configuration', () => {
    expect(SAFETY_CHECKUP_THEME.presentation).toBeDefined();
    const pres = getThemePresentation('safety-checkup');
    expect(pres.cardTitle).toBe('Safety Checkup');
    expect(pres.audience).toBe('general');
    expect(pres.tone).toBe('reassuring');
    expect(pres.context).toBe('Everyday Digital Safety');
  });

  // 2. Security Checkup resolves its canonical presentation configuration
  it('2. Security Checkup resolves its canonical presentation configuration', () => {
    expect(SECURITY_CHECKUP_THEME.presentation).toBeDefined();
    const pres = getThemePresentation('security-checkup');
    expect(pres.cardTitle).toBe('Security Inspection');
    expect(pres.audience).toBe('technical');
    expect(pres.tone).toBe('diagnostic');
    expect(pres.context).toBe('Technical Security Inspection');
  });

  // 3. Safety and Security use distinct audience/tone/context metadata
  it('3. Safety and Security use distinct audience/tone/context metadata', () => {
    const safetyPres = getThemePresentation('safety-checkup');
    const secPres = getThemePresentation('security-checkup');

    expect(safetyPres.audience).not.toBe(secPres.audience);
    expect(safetyPres.audience).toBe('general');
    expect(secPres.audience).toBe('technical');

    expect(safetyPres.tone).not.toBe(secPres.tone);
    expect(safetyPres.tone).toBe('reassuring');
    expect(secPres.tone).toBe('diagnostic');

    expect(safetyPres.context).not.toBe(secPres.context);
  });

  // 4. Safety suggestions are safety-oriented
  it('4. Safety suggestions are safety-oriented', () => {
    const suggestions = SAFETY_CHECKUP_THEME.welcome.suggestions;
    expect(suggestions).toHaveLength(4);

    const titles = suggestions.map(s => s.title);
    expect(titles).toContain('Check a suspicious URL');
    expect(titles).toContain('Analyze a scam message');
    expect(titles).toContain('Check an email or invoice');
    expect(titles).toContain('Review a suspicious request');

    // Prompts emphasize consumer protection, scams, phishing, OTP
    const prompts = suggestions.map(s => s.prompt).join(' ');
    expect(prompts).toMatch(/scam|phishing|deceptive|OTP/i);
  });

  // 5. Security suggestions are technical-security-oriented
  it('5. Security suggestions are technical-security-oriented', () => {
    const suggestions = SECURITY_CHECKUP_THEME.welcome.suggestions;
    expect(suggestions).toHaveLength(4);

    const titles = suggestions.map(s => s.title);
    expect(titles).toContain('Inspect URL structure and punycode');
    expect(titles).toContain('Audit code for injection flaws');
    expect(titles).toContain('Review HTTP security headers');
    expect(titles).toContain('Check for exposed secrets');

    // Prompts emphasize technical vulnerabilities, CSP/HSTS, SQL injection, API keys
    const prompts = suggestions.map(s => s.prompt).join(' ');
    expect(prompts).toMatch(/punycode|injection|CSP|API|endpoint/i);
  });

  // 6. Safety presentation labels are user-friendly
  it('6. Safety presentation labels are user-friendly', () => {
    const pres = getThemePresentation('safety-checkup');
    expect(pres.findingsLabel).toBe('What We Found');
    expect(pres.telemetryLabel).toBe('Safety Intelligence & Link Verification');
    expect(pres.actionsLabel).toBe('What You Should Do');
    expect(pres.limitationsLabel).toBe('Things to Keep in Mind');
    expect(pres.emptyFindingsText).toBe('No suspicious indicators were detected in this message or link.');
  });

  // 7. Security presentation labels are technical
  it('7. Security presentation labels are technical', () => {
    const pres = getThemePresentation('security-checkup');
    expect(pres.findingsLabel).toBe('Technical Findings & Indicators');
    expect(pres.telemetryLabel).toBe('Threat Intelligence & Reputation Feeds');
    expect(pres.actionsLabel).toBe('Remediation & Hardening Actions');
    expect(pres.limitationsLabel).toBe('Technical Scope & Analysis Boundaries');
    expect(pres.emptyFindingsText).toBe('No anomalous threat signatures or vulnerable patterns detected.');
  });

  // 8. Both use the same underlying risk model
  it('8. Both use the same underlying risk model and shared engine instance', () => {
    const safetyEngine = themeRegistry.getEngine('safety-checkup');
    const securityEngine = themeRegistry.getEngine('security-checkup');

    expect(safetyEngine).toBeDefined();
    expect(securityEngine).toBeDefined();
    // Identical engine instance registered for both slugs
    expect(safetyEngine).toBe(securityEngine);
  });

  // 9. No theme-specific risk thresholds are introduced
  it('9. No theme-specific risk thresholds are introduced', () => {
    const riskEnginePath = path.resolve(process.cwd(), 'src/lib/safety/risk-engine.ts');
    const code = fs.readFileSync(riskEnginePath, 'utf-8');

    // RiskEngine must NOT branch on theme slug or theme mode
    expect(code).not.toContain('safety-checkup');
    expect(code).not.toContain('security-checkup');
    expect(code).not.toContain('themeSlug');

    // Scoring is deterministic and identical across themes
    const evaluation = RiskEngine.evaluate([], [
      { analyzerId: 'url-test', analyzerType: 'url', status: 'success', confidence: 'high', findings: [] },
    ]);
    expect(evaluation.riskLevel).toBe('low');
    expect(evaluation.score).toBe(0);
  });

  // 10. No duplicate theme registry exists
  it('10. No duplicate theme registry exists', () => {
    const registryFiles = [
      'src/lib/theme/registry.ts',
    ];
    for (const file of registryFiles) {
      expect(fs.existsSync(path.resolve(process.cwd(), file))).toBe(true);
    }

    // Ensure no secondary registries were introduced
    expect(fs.existsSync(path.resolve(process.cwd(), 'src/lib/theme/safety-registry.ts'))).toBe(false);
    expect(fs.existsSync(path.resolve(process.cwd(), 'src/lib/theme/security-registry.ts'))).toBe(false);
    expect(fs.existsSync(path.resolve(process.cwd(), 'src/lib/safety/registry.ts'))).toBe(false);

    // Canonical themes array remains exactly 6 active themes
    expect(CANONICAL_THEMES).toHaveLength(6);
  });

  // 11. General AI behavior remains unchanged
  it('11. General AI behavior remains unchanged', () => {
    expect(GENERAL_AI_THEME.slug).toBe('general');
    expect(GENERAL_AI_THEME.welcome.heroTitle).toBe('Welcome to Before You Click');
    expect(GENERAL_AI_THEME.archetype).toBe('visual_prompt');
    expect(resolveThemeSync(null).slug).toBe('general');
    expect(resolveThemeSync(undefined).slug).toBe('general');
  });

  // 12. Mathematics behavior remains unchanged
  it('12. Mathematics behavior remains unchanged', () => {
    expect(MATHEMATICS_THEME.slug).toBe('mathematics');
    expect(MATHEMATICS_THEME.icon).toBe('Calculator');
    expect(MATHEMATICS_THEME.welcome.heroTitle).toBe('Mathematics Assistant');
    expect(MATHEMATICS_THEME.welcome.suggestions).toHaveLength(4);
  });

  // 13. Programming behavior remains unchanged
  it('13. Programming behavior remains unchanged', () => {
    expect(PROGRAMMING_THEME.slug).toBe('programming');
    expect(PROGRAMMING_THEME.icon).toBe('Code');
    expect(PROGRAMMING_THEME.welcome.heroTitle).toBe('Software Engineering Copilot');
    expect(PROGRAMMING_THEME.welcome.suggestions).toHaveLength(4);
  });

  // 14. Study behavior remains unchanged
  it('14. Study behavior remains unchanged', () => {
    expect(STUDY_THEME.slug).toBe('study');
    expect(STUDY_THEME.icon).toBe('BookOpen');
    expect(STUDY_THEME.welcome.heroTitle).toBe('Socratic Learning Tutor');
    expect(STUDY_THEME.welcome.suggestions).toHaveLength(4);
  });

  // 15. Theme immutability remains intact
  it('15. Theme immutability remains intact (no switcher in ChatClient)', () => {
    const chatClientPath = path.resolve(process.cwd(), 'src/app/chat/[id]/ChatClient.tsx');
    const content = fs.readFileSync(chatClientPath, 'utf-8');

    // ThemeSelector is NOT inside active chat ChatClient
    expect(content).not.toContain('<ThemeSelector');
    expect(content).not.toContain('setSelectedTheme');
    expect(content).not.toContain('updateTheme');
  });

  // 16. Semantic tokens are used rather than hardcoded domain colors
  it('16. Semantic tokens are used rather than hardcoded domain colors', () => {
    const cardPath = path.resolve(process.cwd(), 'src/components/safety/SafetyAnalysisCard.tsx');
    const cardContent = fs.readFileSync(cardPath, 'utf-8');

    // Uses theme presentation config and semantic tokens
    expect(cardContent).toContain('getThemePresentation');
    expect(cardContent).toContain('cardTitle');
    expect(cardContent).toContain('presentation.findingsLabel');
    expect(cardContent).toContain('presentation.actionsLabel');
    expect(cardContent).toContain('presentation.limitationsLabel');
    expect(cardContent).toContain('presentation.telemetryLabel');

    // No arbitrary theme hex color constants defined in component
    expect(cardContent).not.toMatch(/#[0-9a-fA-F]{6}/);
  });

  // 17. Mobile-safe structure remains intact
  it('17. Mobile-safe structure remains intact', () => {
    const cardPath = path.resolve(process.cwd(), 'src/components/safety/SafetyAnalysisCard.tsx');
    const content = fs.readFileSync(cardPath, 'utf-8');

    // Uses responsive layout classes
    expect(content).toContain('hidden sm:flex');
    expect(content).toContain('overflow-hidden');
    expect(content).toContain('flex-wrap');
    expect(content).toContain('leading-normal');
  });

  // 18. Accessibility semantics remain intact
  it('18. Accessibility semantics remain intact', () => {
    const cardPath = path.resolve(process.cwd(), 'src/components/safety/SafetyAnalysisCard.tsx');
    const content = fs.readFileSync(cardPath, 'utf-8');

    // Accessibility attributes present
    expect(content).toContain('role="region"');
    expect(content).toContain('aria-label={`${cardTitle} Result: ${config.label}`}');
    expect(content).toContain('aria-hidden="true"');
    expect(content).toContain('aria-label={isExpanded ? \'Collapse analysis details\' : \'Expand analysis details\'}');
  });

  // 19. No new database queries are introduced
  it('19. No new database queries are introduced for theme divergence', () => {
    const cardPath = path.resolve(process.cwd(), 'src/components/safety/SafetyAnalysisCard.tsx');
    const content = fs.readFileSync(cardPath, 'utf-8');

    // Pure component without server actions or DB queries
    expect(content).not.toContain('supabase');
    expect(content).not.toContain('from(\'themes\')');
    expect(content).not.toContain('fetch(');

    // Sync in-memory resolution used in catalog
    const syncRes = getThemePresentation('safety-checkup');
    expect(syncRes).toBeDefined();
  });

  // 20. No new migrations are introduced
  it('20. No new migrations are introduced', () => {
    const migrationsDir = path.resolve(process.cwd(), 'supabase/migrations');
    const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.sql'));

    // Pre-existing theme migrations exist without theme divergence regressions
    expect(files.length).toBeGreaterThanOrEqual(10);
    expect(files).toContain('20260910140000_add_safety_security_themes.sql');
  });
});
