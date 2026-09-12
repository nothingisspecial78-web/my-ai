'use client';

import React from 'react';
import type { LucideIcon } from 'lucide-react';
import {
  Sparkles,
  Calculator,
  Code,
  ShieldCheck,
  ShieldAlert,
  Shield,
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
  Lock,
  EyeOff,
  ArrowRight,
  QrCode,
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
  Shield,
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
  Lock,
  EyeOff,
  QrCode,
};

function renderWelcomeIcon(name?: string | null, size = 18) {
  const IconComp = (name && WELCOME_ICONS[name]) || Shield;
  return <IconComp size={size} aria-hidden="true" />;
}

export function WelcomeScreen({ onSuggestionClick, disabled, theme }: WelcomeScreenProps) {
  const activeTheme = theme || GENERAL_AI_THEME;
  const heroTitle = activeTheme.welcome?.heroTitle || 'Before You Click';
  const heroSubtitle = activeTheme.welcome?.heroSubtitle || 'Pause. Check. Understand. Then Click.';
  const heroIconName = activeTheme.welcome?.heroIcon || 'ShieldCheck';
  const suggestions = activeTheme.welcome?.suggestions || [];

  return (
    <div className="flex min-h-full w-full flex-col items-center justify-center relative p-4 py-8 sm:py-12 select-none">
      <div className="max-w-2xl w-full text-center space-y-5 sm:space-y-6 px-2 sm:px-4 my-auto">
        
        {/* 1. Hero Emblem & Brand Header */}
        <div className="space-y-3 sm:space-y-4">
          <div className="relative mx-auto flex h-16 w-16 sm:h-20 sm:w-20 items-center justify-center rounded-2xl sm:rounded-3xl bg-theme-avatar-bg text-theme-avatar-fg shadow-xl shadow-[var(--theme-glow)] mb-2 sm:mb-4 transition-all">
            <span className="sm:hidden">{renderWelcomeIcon(heroIconName, 32)}</span>
            <span className="hidden sm:inline-flex">{renderWelcomeIcon(heroIconName, 40)}</span>
            {/* Subtle instrument scan ring */}
            <span className="absolute -inset-1 rounded-2xl sm:rounded-3xl border border-current opacity-20 animate-pulse pointer-events-none" />
          </div>

          <div className="space-y-1">
            <h1 className="text-3xl sm:text-4xl md:text-5xl font-extrabold tracking-tight text-gray-900 dark:text-white">
              {heroTitle}
            </h1>
            <p className="text-sm sm:text-base font-mono uppercase tracking-wider text-theme-accent font-semibold">
              {heroSubtitle}
            </p>
          </div>

          <p className="text-xs sm:text-sm text-gray-500 dark:text-gray-400 max-w-lg mx-auto leading-relaxed">
            Your digital safety companion. Paste any link, message, QR payload, image, or code snippet to inspect risks and verify confidence before you interact.
          </p>
        </div>

        {/* 2. Trust Badges Row */}
        <div className="flex flex-wrap items-center justify-center gap-2 sm:gap-3 text-[11px] font-mono text-gray-600 dark:text-gray-400">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-gray-100 dark:bg-gray-800/60 border border-gray-200 dark:border-gray-700">
            <ShieldCheck size={13} className="text-theme-accent" />
            <span>Evidence-Based</span>
          </span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-gray-100 dark:bg-gray-800/60 border border-gray-200 dark:border-gray-700">
            <Lock size={13} className="text-theme-accent" />
            <span>No Blind Link Visiting</span>
          </span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-gray-100 dark:bg-gray-800/60 border border-gray-200 dark:border-gray-700">
            <EyeOff size={13} className="text-theme-accent" />
            <span>Privacy by Design</span>
          </span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-gray-100 dark:bg-gray-800/60 border border-gray-200 dark:border-gray-700">
            <Zap size={13} className="text-theme-accent" />
            <span>Multi-Vector Defense</span>
          </span>
        </div>

        {/* 3. Visual Workflow Ribbon */}
        <div className="hidden sm:flex items-center justify-center gap-1.5 text-[10px] font-mono uppercase tracking-wider text-gray-400 dark:text-gray-500 py-1">
          <span className="font-semibold text-gray-700 dark:text-gray-300">INPUT</span>
          <ArrowRight size={10} />
          <span className="font-semibold text-gray-700 dark:text-gray-300">ANALYSIS</span>
          <ArrowRight size={10} />
          <span className="font-semibold text-gray-700 dark:text-gray-300">EVIDENCE</span>
          <ArrowRight size={10} />
          <span className="font-semibold text-theme-accent">RISK ≠ CONFIDENCE</span>
          <ArrowRight size={10} />
          <span className="font-semibold text-gray-700 dark:text-gray-300">DECISION</span>
        </div>

        {/* 4. Suggestions Grid */}
        <div className="pt-2 sm:pt-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 sm:gap-3 max-w-xl mx-auto text-left">
            {suggestions.map((s, i) => (
              <button
                type="button"
                key={i}
                onClick={() => onSuggestionClick(s.prompt || s.title)}
                disabled={disabled}
                className="flex items-center gap-3 p-3.5 sm:p-4 rounded-xl border border-[var(--theme-border)] bg-[var(--theme-card)] hover:bg-[var(--theme-card-muted)] hover:border-theme-border hover:shadow-md hover:shadow-[var(--theme-glow)] transition-all text-left group focus:outline-none focus-visible:ring-2 focus-visible:ring-theme-composer-focus focus-visible:ring-offset-2 dark:focus-visible:ring-offset-gray-900"
              >
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-theme-subtle text-theme-accent group-hover:scale-105 transition-transform" aria-hidden="true">
                  {renderWelcomeIcon(s.iconName, 17)}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-gray-900 dark:text-gray-100 text-sm group-hover:text-theme-accent transition-colors truncate">
                    {s.title}
                  </div>
                  {s.prompt && (
                    <p className="text-xs text-gray-500 dark:text-gray-400 line-clamp-1 mt-0.5">
                      {s.prompt}
                    </p>
                  )}
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
