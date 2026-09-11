'use client';

import { useEffect, useState, useRef, useId } from 'react';
import { getThemes } from '@/lib/database';
import { Theme, parseTheme } from '@/lib/theme/types';
import {
  Globe,
  Calculator,
  Code,
  BookOpen,
  ShieldCheck,
  ShieldAlert,
  ChevronDown,
  Check
} from 'lucide-react';

interface ThemeSelectorProps {
  selectedThemeId: string | null;
  onSelect: (themeId: string | null) => void;
  disabled?: boolean;
}

const ICONS: Record<string, React.ReactNode> = {
  Globe: <Globe size={16} aria-hidden="true" />,
  Calculator: <Calculator size={16} aria-hidden="true" />,
  Code: <Code size={16} aria-hidden="true" />,
  BookOpen: <BookOpen size={16} aria-hidden="true" />,
  ShieldCheck: <ShieldCheck size={16} className="text-emerald-500" aria-hidden="true" />,
  ShieldAlert: <ShieldAlert size={16} className="text-rose-500" aria-hidden="true" />,
};

export function ThemeSelector({ selectedThemeId, onSelect, disabled }: ThemeSelectorProps) {
  const [themes, setThemes] = useState<Theme[]>([]);
  const [isOpen, setIsOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [focusedIndex, setFocusedIndex] = useState<number>(-1);

  const triggerRef = useRef<HTMLButtonElement>(null);
  const listboxRef = useRef<HTMLDivElement>(null);
  const listboxId = useId();

  useEffect(() => {
    async function loadThemes() {
      try {
        const data = await getThemes();
        // Filter out duplicate database 'general' theme; the hardcoded option represents selectedThemeId = null
        const selectable = data.filter(t => t.slug !== 'general');
        setThemes(selectable.map(parseTheme));
      } catch (err) {
        console.error('Failed to load themes', err);
      } finally {
        setLoading(false);
      }
    }
    loadThemes();
  }, []);

  // Build the unified list of options: General AI + database themes
  const options = [
    { id: null as string | null, name: 'General AI', icon: 'Globe', description: 'General AI Assistant' },
    ...themes.map(t => ({ id: t.id as string | null, name: t.name, icon: t.icon, description: t.description })),
  ];

  const selectedTheme = themes.find(t => t.id === selectedThemeId) || null;

  const handleOpen = () => {
    const idx = options.findIndex(o => o.id === selectedThemeId);
    setFocusedIndex(idx >= 0 ? idx : 0);
    setIsOpen(true);
  };

  const handleToggle = () => {
    if (isOpen) {
      setIsOpen(false);
    } else {
      handleOpen();
    }
  };

  // Handle global Escape or outside clicks when open
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        setIsOpen(false);
        triggerRef.current?.focus();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen]);

  const handleSelectOption = (themeId: string | null) => {
    onSelect(themeId);
    setIsOpen(false);
    triggerRef.current?.focus();
  };

  const handleTriggerKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>) => {
    if (disabled || loading) return;

    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      handleOpen();
    } else if (e.key === 'Escape' && isOpen) {
      e.preventDefault();
      setIsOpen(false);
    }
  };

  const handleListboxKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (!isOpen) return;

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setFocusedIndex(prev => (prev + 1) % options.length);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setFocusedIndex(prev => (prev - 1 + options.length) % options.length);
    } else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      if (focusedIndex >= 0 && focusedIndex < options.length) {
        handleSelectOption(options[focusedIndex].id);
      }
    } else if (e.key === 'Tab') {
      setIsOpen(false);
    }
  };

  return (
    <div className="relative">
      <button
        ref={triggerRef}
        type="button"
        disabled={disabled || loading}
        onClick={handleToggle}
        onKeyDown={handleTriggerKeyDown}
        aria-haspopup="listbox"
        aria-expanded={isOpen}
        aria-controls={isOpen ? listboxId : undefined}
        aria-label="Select domain theme"
        className="flex items-center gap-2 px-3 py-2 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 text-sm font-medium hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 min-h-[40px]"
      >
        {selectedTheme ? (
          <>
            <span className="text-blue-500">{ICONS[selectedTheme.icon || 'Globe'] || <Globe size={16} aria-hidden="true" />}</span>
            <span className="text-gray-900 dark:text-gray-100">{selectedTheme.name}</span>
          </>
        ) : (
          <>
            <span className="text-gray-500"><Globe size={16} aria-hidden="true" /></span>
            <span className="text-gray-900 dark:text-gray-100">General AI</span>
          </>
        )}
        <ChevronDown size={14} className="text-gray-400 ml-1" aria-hidden="true" />
      </button>

      {isOpen && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setIsOpen(false)} aria-hidden="true" />
          <div
            id={listboxId}
            ref={listboxRef}
            role="listbox"
            aria-label="Domain themes"
            tabIndex={-1}
            onKeyDown={handleListboxKeyDown}
            className="absolute bottom-full mb-2 left-0 w-60 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl shadow-lg z-20 py-1 overflow-hidden focus:outline-none"
          >
            <div className="px-3 py-2 text-xs font-semibold text-gray-500 uppercase tracking-wider" aria-hidden="true">
              Theme
            </div>
            
            {options.map((opt, idx) => {
              const isSelected = selectedThemeId === opt.id;
              const isFocused = focusedIndex === idx;

              return (
                <button
                  key={opt.id ?? 'general'}
                  type="button"
                  role="option"
                  aria-selected={isSelected}
                  onClick={() => handleSelectOption(opt.id)}
                  onMouseEnter={() => setFocusedIndex(idx)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 min-h-[40px] text-sm text-gray-700 dark:text-gray-300 transition-colors focus:outline-none ${
                    isFocused ? 'bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-white' : 'hover:bg-gray-50 dark:hover:bg-gray-800/60'
                  }`}
                  title={opt.description || ''}
                >
                  <div className="flex items-center gap-2">
                    {ICONS[opt.icon || 'Globe'] || <Globe size={16} className="text-gray-500" aria-hidden="true" />}
                    <span>{opt.name}</span>
                  </div>
                  {isSelected && <Check size={14} className="text-blue-500 shrink-0" aria-hidden="true" />}
                </button>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}
