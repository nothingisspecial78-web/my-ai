'use client';

import { useEffect, useState } from 'react';
import { getThemes } from '@/lib/database';
import { Theme, parseTheme } from '@/lib/theme/types';
import { Globe, Calculator, Code, BookOpen, ChevronDown, Check } from 'lucide-react';

interface ThemeSelectorProps {
  selectedThemeId: string | null;
  onSelect: (themeId: string | null) => void;
  disabled?: boolean;
}

const ICONS: Record<string, React.ReactNode> = {
  Globe: <Globe size={16} />,
  Calculator: <Calculator size={16} />,
  Code: <Code size={16} />,
  BookOpen: <BookOpen size={16} />,
};

export function ThemeSelector({ selectedThemeId, onSelect, disabled }: ThemeSelectorProps) {
  const [themes, setThemes] = useState<Theme[]>([]);
  const [isOpen, setIsOpen] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadThemes() {
      try {
        const data = await getThemes();
        setThemes(data.map(parseTheme));
      } catch (err) {
        console.error('Failed to load themes', err);
      } finally {
        setLoading(false);
      }
    }
    loadThemes();
  }, []);

  const selectedTheme = themes.find(t => t.id === selectedThemeId) || null;

  return (
    <div className="relative">
      <button
        type="button"
        disabled={disabled || loading}
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 text-sm font-medium hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
      >
        {selectedTheme ? (
          <>
            <span className="text-blue-500">{ICONS[selectedTheme.icon || 'Globe'] || <Globe size={16} />}</span>
            <span className="text-gray-900 dark:text-gray-100">{selectedTheme.name}</span>
          </>
        ) : (
          <>
            <span className="text-gray-500"><Globe size={16} /></span>
            <span className="text-gray-900 dark:text-gray-100">General AI</span>
          </>
        )}
        <ChevronDown size={14} className="text-gray-400 ml-1" />
      </button>

      {isOpen && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setIsOpen(false)} />
          <div className="absolute bottom-full mb-2 left-0 w-56 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl shadow-lg z-20 py-1 overflow-hidden">
            <div className="px-3 py-2 text-xs font-semibold text-gray-500 uppercase tracking-wider">
              Theme
            </div>
            
            <button
              onClick={() => { onSelect(null); setIsOpen(false); }}
              className="w-full flex items-center justify-between px-3 py-2 hover:bg-gray-50 dark:hover:bg-gray-800 text-sm text-gray-700 dark:text-gray-300 transition-colors"
            >
              <div className="flex items-center gap-2">
                <Globe size={16} className="text-gray-500" />
                <span>General AI</span>
              </div>
              {selectedThemeId === null && <Check size={14} className="text-blue-500" />}
            </button>

            {themes.map(theme => (
              <button
                key={theme.id}
                onClick={() => { onSelect(theme.id); setIsOpen(false); }}
                className="w-full flex items-center justify-between px-3 py-2 hover:bg-gray-50 dark:hover:bg-gray-800 text-sm text-gray-700 dark:text-gray-300 transition-colors"
                title={theme.description || ''}
              >
                <div className="flex items-center gap-2">
                  {ICONS[theme.icon || 'Globe'] || <Globe size={16} className="text-gray-500" />}
                  <span>{theme.name}</span>
                </div>
                {selectedThemeId === theme.id && <Check size={14} className="text-blue-500" />}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
