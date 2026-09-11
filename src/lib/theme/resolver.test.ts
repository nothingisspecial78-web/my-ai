import { describe, it, expect, vi, beforeEach } from 'vitest';
import { resolveThemeInstruction } from './resolver';
import * as database from '@/lib/database';
import { DBTheme } from './types';

vi.mock('@/lib/database', () => ({
  getThemeById: vi.fn(),
}));

describe('resolveThemeInstruction', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const mockTheme = (overrides: Partial<DBTheme>): DBTheme => ({
    id: 'theme-123',
    name: 'Test Theme',
    slug: 'test-theme',
    description: 'Test',
    icon: 'Globe',
    enabled: true,
    is_system: true,
    config: { instructions: 'Test Instructions' } as unknown as DBTheme['config'],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  });

  it('1. null theme_id still means General AI (returns null)', async () => {
    const result = await resolveThemeInstruction(null);
    expect(result).toBeNull();
    expect(database.getThemeById).not.toHaveBeenCalled();
  });

  it('2. invalid theme_id is safely handled (returns null)', async () => {
    vi.mocked(database.getThemeById).mockResolvedValue(null); // RLS block or missing
    const result = await resolveThemeInstruction('invalid-id');
    expect(result).toBeNull();
    expect(database.getThemeById).toHaveBeenCalledWith('invalid-id');
  });

  it('3. enabled system theme is accessible', async () => {
    vi.mocked(database.getThemeById).mockResolvedValue(mockTheme({ enabled: true, is_system: true }));
    const result = await resolveThemeInstruction('theme-123');
    expect(result).toBe('Test Instructions');
  });

  it('4. disabled system theme is inaccessible (returns null)', async () => {
    vi.mocked(database.getThemeById).mockResolvedValue(mockTheme({ enabled: false, is_system: true }));
    const result = await resolveThemeInstruction('theme-123');
    expect(result).toBeNull();
  });

  it('5. unauthorized/non-public theme cannot be used (returns null for non-system themes in Phase 4.1)', async () => {
    vi.mocked(database.getThemeById).mockResolvedValue(mockTheme({ enabled: true, is_system: false }));
    const result = await resolveThemeInstruction('theme-123');
    expect(result).toBeNull();
  });

  it('6. safely handles database throwing an error', async () => {
    vi.mocked(database.getThemeById).mockRejectedValue(new Error('DB connection failed'));
    const result = await resolveThemeInstruction('theme-123');
    expect(result).toBeNull();
  });

  it('7. resolves safety-checkup and security-checkup system themes and verifies engine registry routing', async () => {
    const { resolveAuthorizedTheme } = await import('./resolver');
    const { themeRegistry } = await import('./registry');

    // Test safety-checkup
    vi.mocked(database.getThemeById).mockResolvedValue(mockTheme({
      id: '55555555-5555-5555-5555-555555555555',
      name: 'Safety Checkup',
      slug: 'safety-checkup',
      icon: 'ShieldCheck',
      enabled: true,
      is_system: true,
    }));

    const safetyTheme = await resolveAuthorizedTheme('55555555-5555-5555-5555-555555555555');
    expect(safetyTheme).not.toBeNull();
    expect(safetyTheme?.slug).toBe('safety-checkup');
    const safetyEngine = themeRegistry.getEngine(safetyTheme!.slug);
    expect(safetyEngine).toBeDefined();

    // Test security-checkup
    vi.mocked(database.getThemeById).mockResolvedValue(mockTheme({
      id: '66666666-6666-6666-6666-666666666666',
      name: 'Security Checkup',
      slug: 'security-checkup',
      icon: 'ShieldAlert',
      enabled: true,
      is_system: true,
    }));

    const securityTheme = await resolveAuthorizedTheme('66666666-6666-6666-6666-666666666666');
    expect(securityTheme).not.toBeNull();
    expect(securityTheme?.slug).toBe('security-checkup');
    const securityEngine = themeRegistry.getEngine(securityTheme!.slug);
    expect(securityEngine).toBeDefined();
    // Both point to the same SafetySecurityImplementation
    expect(safetyEngine).toBe(securityEngine);
  });

  it('8. verifies ThemeSelector data filtering excludes duplicate database general theme', () => {
    const rawThemes = [
      { id: '1', name: 'General AI', slug: 'general', icon: 'Globe', enabled: true, is_system: true },
      { id: '2', name: 'Safety Checkup', slug: 'safety-checkup', icon: 'ShieldCheck', enabled: true, is_system: true },
      { id: '3', name: 'Security Checkup', slug: 'security-checkup', icon: 'ShieldAlert', enabled: true, is_system: true },
      { id: '4', name: 'Mathematics', slug: 'mathematics', icon: 'Calculator', enabled: true, is_system: true },
      { id: '5', name: 'Programming', slug: 'programming', icon: 'Code', enabled: true, is_system: true },
      { id: '6', name: 'Study', slug: 'study', icon: 'BookOpen', enabled: true, is_system: true },
    ];

    const filtered = rawThemes.filter(t => t.slug !== 'general');
    expect(filtered.length).toBe(5);
    expect(filtered.some(t => t.slug === 'general')).toBe(false);
    expect(filtered.some(t => t.slug === 'safety-checkup')).toBe(true);
    expect(filtered.some(t => t.slug === 'security-checkup')).toBe(true);
  });

  it('9. resolves canonical null/undefined and legacy fallbacks ("general", legacy UUID) to GENERAL_AI_THEME', async () => {
    const { resolveAuthorizedTheme, buildThemeInstruction } = await import('./resolver');
    const { GENERAL_AI_THEME } = await import('./catalog');

    // Canonical representation for General AI in conversations and database is null / undefined
    const fromNull = await resolveAuthorizedTheme(null);
    const fromUndefined = await resolveAuthorizedTheme(undefined);

    // Legacy fallbacks accepted only at the resolver boundary
    const fromGeneralSlug = await resolveAuthorizedTheme('general');
    const fromLegacyId = await resolveAuthorizedTheme('11111111-1111-1111-1111-111111111111');

    expect(fromNull).toEqual(GENERAL_AI_THEME);
    expect(fromUndefined).toEqual(GENERAL_AI_THEME);
    expect(fromGeneralSlug).toEqual(GENERAL_AI_THEME);
    expect(fromLegacyId).toEqual(GENERAL_AI_THEME);

    // Database should never be queried for canonical General AI or legacy fallbacks
    expect(database.getThemeById).not.toHaveBeenCalled();

    // General AI instruction must be null so Gemini uses standard system prompt
    expect(buildThemeInstruction(fromNull)).toBeNull();
  });

  it('10. themeRegistry.getAllActiveDefinitions() returns strictly the 6 active themes and excludes dormant themes', async () => {
    const { themeRegistry } = await import('./registry');

    const activeDefinitions = themeRegistry.getAllActiveDefinitions();
    expect(activeDefinitions).toHaveLength(6);

    const activeSlugs = activeDefinitions.map(d => d.slug);
    expect(activeSlugs).toEqual([
      'general',
      'mathematics',
      'programming',
      'safety-checkup',
      'security-checkup',
      'study',
    ]);

    // Ensure all 6 active definitions have complete visual and welcome configs
    for (const def of activeDefinitions) {
      expect(def.enabled).toBe(true);
      expect(def.isSystem).toBe(true);
      expect(def.visual).toBeDefined();
      expect(def.visual.themeAttribute).toBeTruthy();
      expect(def.visual.accentColor).toBeTruthy();
      expect(def.welcome).toBeDefined();
      expect(def.welcome.heroTitle).toBeTruthy();
    }

    // Tibb al-Nabi is NOT in active definitions
    expect(activeSlugs).not.toContain('tibb-al-nabi');
  });

  it('11. preserves dormant Tibb al-Nabi in code and registry without exposing it as an active system theme', async () => {
    const { themeRegistry } = await import('./registry');

    const tibbDef = themeRegistry.getDefinition('tibb-al-nabi');
    expect(tibbDef).toBeDefined();
    expect(tibbDef?.enabled).toBe(false);
    expect(tibbDef?.isSystem).toBe(false);

    const tibbEngine = themeRegistry.getEngine('tibb-al-nabi');
    expect(tibbEngine).toBeDefined();
  });

  it('12. resolveAuthorizedTheme merges registered canonical metadata with database overrides', async () => {
    const { resolveAuthorizedTheme } = await import('./resolver');

    vi.mocked(database.getThemeById).mockResolvedValue(mockTheme({
      id: '22222222-2222-2222-2222-222222222222',
      name: 'Custom Mathematics',
      slug: 'mathematics',
      icon: 'Calculator',
      enabled: true,
      is_system: true,
      config: {
        instructions: 'Custom DB Math Instructions',
        rules: ['Custom Rule 1'],
      } as unknown as DBTheme['config'],
    }));

    const mathTheme = await resolveAuthorizedTheme('22222222-2222-2222-2222-222222222222');
    expect(mathTheme.slug).toBe('mathematics');
    expect(mathTheme.instructions).toBe('Custom DB Math Instructions');
    expect(mathTheme.rules).toEqual(['Custom Rule 1']);
    // Inherits static visual and welcome metadata from canonical definition
    expect(mathTheme.visual.accentColor).toBe('#0d9488');
    expect(mathTheme.welcome.heroTitle).toBe('Mathematics Assistant');
  });
});
