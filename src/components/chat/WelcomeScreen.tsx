'use client';

import type { LucideIcon } from 'lucide-react';
import {
  Sparkles,
  Calculator,
  Code,
  ShieldCheck,
  ShieldAlert,
  BookOpen,
  Globe,
  FileText,
  Mail,
  Lightbulb,
  Divide,
  Grid,
  Percent,
  Binary,
  Bug,
  Layers,
  Zap,
  Database,
  Link,
  MessageSquareWarning,
  Key,
  FileWarning,
  Terminal,
  FileCode,
  AlertTriangle,
  Atom,
  Compass,
} from 'lucide-react';
import { ThemeDefinition } from '@/lib/theme/types';
import { GENERAL_AI_THEME } from '@/lib/theme/catalog';

interface WelcomeScreenProps {
  onSuggestionClick: (text: string) => void;
  disabled?: boolean;
  theme?: ThemeDefinition;
}

const WELCOME_ICONS: Record<string, LucideIcon> = {
  Sparkles,
  Calculator,
  Code,
  ShieldCheck,
  ShieldAlert,
  BookOpen,
  Globe,
  FileText,
  Mail,
  Lightbulb,
  Divide,
  Grid,
  Percent,
  Binary,
  Bug,
  Layers,
  Zap,
  Database,
  Link,
  MessageSquareWarning,
  Key,
  FileWarning,
  Terminal,
  FileCode,
  AlertTriangle,
  Atom,
  Compass,
};

function renderWelcomeIcon(name?: string | null, size = 18, className?: string) {
  const IconComp = (name && WELCOME_ICONS[name]) || Sparkles;
  return <IconComp size={size} className={className} aria-hidden="true" />;
}

export function WelcomeScreen({ onSuggestionClick, disabled, theme }: WelcomeScreenProps) {
  const activeTheme = theme || GENERAL_AI_THEME;
  const welcomeConfig = activeTheme.welcome || GENERAL_AI_THEME.welcome;

  const heroTitle = welcomeConfig.heroTitle || activeTheme.name || 'Welcome to Before You Click';
  const heroSubtitle = welcomeConfig.heroSubtitle || activeTheme.description || 'How can I help you today?';
  const heroIconName = welcomeConfig.heroIcon || activeTheme.icon || 'Sparkles';
  const suggestions = welcomeConfig.suggestions && welcomeConfig.suggestions.length > 0
    ? welcomeConfig.suggestions
    : GENERAL_AI_THEME.welcome.suggestions;

  return (
    <div className="flex min-h-full w-full flex-col items-center relative p-4 py-6 sm:py-12">
      <div className="max-w-2xl w-full text-center space-y-4 sm:space-y-8 fade-in-up px-2 sm:px-4 my-auto">
        {/* Hero */}
        <div className="space-y-3 sm:space-y-4">
          <div className="mx-auto flex h-14 w-14 sm:h-20 sm:w-20 items-center justify-center rounded-2xl sm:rounded-3xl bg-theme-avatar-bg text-theme-avatar-fg shadow-xl shadow-[var(--theme-glow)] mb-3 sm:mb-6 transition-colors" aria-hidden="true">
            <span className="sm:hidden">{renderWelcomeIcon(heroIconName, 28)}</span>
            <span className="hidden sm:inline-flex">{renderWelcomeIcon(heroIconName, 40)}</span>
          </div>
          <h1 className="text-3xl sm:text-4xl md:text-5xl font-bold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-gray-900 to-gray-600 dark:from-white dark:to-gray-400 pb-2">
            {heroTitle}
          </h1>
          <p className="text-sm sm:text-lg text-gray-500 dark:text-gray-400 max-w-md mx-auto font-medium">
            {heroSubtitle}
          </p>
        </div>

        {/* Suggestions Grid */}
        <div className="pt-3 sm:pt-8">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 sm:gap-3 max-w-xl mx-auto">
            {suggestions.map((s, i) => (
              <button
                type="button"
                key={i}
                onClick={() => onSuggestionClick(s.prompt || s.title)}
                disabled={disabled}
                className="flex items-center gap-3 p-4 rounded-xl border border-[var(--theme-border)] bg-[var(--theme-card)] hover:bg-[var(--theme-card-muted)] hover:border-theme-border hover:shadow-md hover:shadow-[var(--theme-glow)] transition-all text-left group focus:outline-none focus-visible:ring-2 focus-visible:ring-theme-composer-focus focus-visible:ring-offset-2 dark:focus-visible:ring-offset-gray-900"
              >
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-theme-subtle text-theme-accent group-hover:scale-110 transition-transform" aria-hidden="true">
                  {renderWelcomeIcon(s.iconName, 18)}
                </div>
                <div className="font-medium text-gray-900 dark:text-gray-100 text-sm group-hover:text-theme-accent transition-colors">
                  {s.title}
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      <style jsx>{`
        .fade-in-up {
          animation: fadeInUp 0.6s ease-out forwards;
        }
        @keyframes fadeInUp {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @media (prefers-reduced-motion: reduce) {
          .fade-in-up {
            animation: none !important;
          }
        }
      `}</style>
    </div>
  );
}
