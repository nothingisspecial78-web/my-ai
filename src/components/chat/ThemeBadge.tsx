'use client';

import React from 'react';
import type { LucideIcon } from 'lucide-react';
import {
  Globe,
  Calculator,
  Code,
  ShieldCheck,
  ShieldAlert,
  BookOpen,
  Sparkles,
} from 'lucide-react';
import { ThemeDefinition } from '@/lib/theme/types';
import { GENERAL_AI_THEME } from '@/lib/theme/catalog';
import { cn } from '@/lib/utils';

interface ThemeBadgeProps {
  theme?: ThemeDefinition | null;
  className?: string;
}

const BADGE_ICONS: Record<string, LucideIcon> = {
  Globe,
  Calculator,
  Code,
  ShieldCheck,
  ShieldAlert,
  BookOpen,
  Sparkles,
};

export function ThemeBadge({ theme, className }: ThemeBadgeProps) {
  const activeTheme = theme || GENERAL_AI_THEME;
  const iconKey = activeTheme.visual?.iconName || activeTheme.icon || 'Globe';
  const IconComponent = BADGE_ICONS[iconKey] || Globe;
  const themeName = activeTheme.name || 'General AI';

  return (
    <div
      data-testid="theme-badge"
      className={cn(
        "inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full",
        "bg-theme-badge-bg text-theme-badge-text border border-theme-border/60",
        "text-xs font-medium shrink-0 select-none transition-colors",
        className
      )}
      role="status"
      aria-label={`Active theme: ${themeName}`}
    >
      <span className="shrink-0 flex items-center justify-center text-theme-accent" aria-hidden="true">
        <IconComponent size={12} strokeWidth={2.2} />
      </span>
      <span className="truncate max-w-[120px] sm:max-w-[160px] md:max-w-none">
        {themeName}
      </span>
    </div>
  );
}
