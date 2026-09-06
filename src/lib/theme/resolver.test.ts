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
});
