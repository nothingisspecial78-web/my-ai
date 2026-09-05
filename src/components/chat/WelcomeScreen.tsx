'use client';

import { Sparkles, BookOpen, PenTool, Code } from 'lucide-react';

interface WelcomeScreenProps {
  onSuggestionClick: (text: string) => void;
  disabled?: boolean;
}

export function WelcomeScreen({ onSuggestionClick, disabled }: WelcomeScreenProps) {
  const suggestions = [
    { title: 'Explain React Server Components', icon: <Code size={18} className="text-blue-500" /> },
    { title: 'Help me debug a TypeScript error', icon: <PenTool size={18} className="text-purple-500" /> },
    { title: 'Best practices for API design', icon: <BookOpen size={18} className="text-green-500" /> },
    { title: 'Brainstorm marketing ideas', icon: <Sparkles size={18} className="text-amber-500" /> },
  ];

  return (
    <div className="flex h-full w-full flex-col items-center justify-center relative">
      <div className="max-w-2xl w-full text-center space-y-8 fade-in-up px-4 pb-12">
        {/* Hero */}
        <div className="space-y-4">
          <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-3xl bg-gradient-to-br from-blue-500 to-indigo-600 text-white shadow-xl shadow-blue-500/30 mb-6">
            <Sparkles size={40} />
          </div>
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-gray-900 to-gray-600 dark:from-white dark:to-gray-400 pb-2">
            Welcome to MyAI
          </h1>
          <p className="text-lg text-gray-500 dark:text-gray-400 max-w-md mx-auto font-medium">
            How can I help you today?
          </p>
        </div>

        {/* Suggestions Grid */}
        <div className="pt-8">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-w-xl mx-auto">
            {suggestions.map((s, i) => (
              <button
                key={i}
                onClick={() => onSuggestionClick(s.title)}
                disabled={disabled}
                className="flex items-center gap-3 p-4 rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900/50 hover:bg-gray-50 dark:hover:bg-gray-800 hover:border-blue-300 dark:hover:border-blue-800 transition-all text-left group"
              >
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-gray-100 dark:bg-gray-800 group-hover:scale-110 transition-transform">
                  {s.icon}
                </div>
                <div className="font-medium text-gray-900 dark:text-gray-100">{s.title}</div>
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
      `}</style>
    </div>
  );
}
