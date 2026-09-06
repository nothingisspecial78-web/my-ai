import { Database } from '@/types/database';

export type DBTheme = Database['public']['Tables']['themes']['Row'];

export interface ThemeConfig {
  instructions?: string;
  terminology?: Record<string, string>;
  rules?: string[];
  methods?: string[];
  conditions?: string[];
  exceptions?: string[];
  examples?: Array<{ input: string; output: string }>;
  explanation_style?: string;
}

export interface Theme {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  icon: string | null;
  enabled: boolean;
  isSystem: boolean;
  config: ThemeConfig;
  createdAt: string;
  updatedAt: string;
}

export function parseTheme(dbTheme: DBTheme): Theme {
  return {
    id: dbTheme.id,
    name: dbTheme.name,
    slug: dbTheme.slug,
    description: dbTheme.description,
    icon: dbTheme.icon,
    enabled: dbTheme.enabled,
    isSystem: dbTheme.is_system,
    config: (dbTheme.config as unknown as ThemeConfig) || {},
    createdAt: dbTheme.created_at,
    updatedAt: dbTheme.updated_at,
  };
}
