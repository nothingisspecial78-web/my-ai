'use client';

import { useState, useRef, useEffect } from 'react';
import { Send, Plus, Search, Mic, ArrowUp } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ChatComposerProps {
  onSend: (message: string) => void;
  disabled?: boolean;
  enterToSend?: boolean;
}

export function ChatComposer({ onSend, disabled, enterToSend = true }: ChatComposerProps) {
  const [content, setContent] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto-resize textarea using requestAnimationFrame to prevent layout thrashing
  useEffect(() => {
    let rafId: number;
    if (textareaRef.current) {
      rafId = requestAnimationFrame(() => {
        if (!textareaRef.current) return;
        textareaRef.current.style.height = 'auto';
        textareaRef.current.style.height = `${Math.min(textareaRef.current.scrollHeight, 200)}px`;
      });
    }
    return () => cancelAnimationFrame(rafId);
  }, [content]);

  // Capture global typing to focus textarea
  useEffect(() => {
    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      // Ignore if typing in another input or pressing modifier keys
      if (
        e.target instanceof HTMLInputElement || 
        e.target instanceof HTMLTextAreaElement ||
        e.ctrlKey || e.metaKey || e.altKey ||
        e.key.length > 1 // Ignore Enter, Shift, Backspace, etc.
      ) {
        return;
      }
      
      if (textareaRef.current && document.activeElement !== textareaRef.current) {
        textareaRef.current.focus();
      }
    };

    window.addEventListener('keydown', handleGlobalKeyDown);
    return () => window.removeEventListener('keydown', handleGlobalKeyDown);
  }, []);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (enterToSend) {
      // Enter sends, Shift+Enter for newline
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        handleSubmit();
      }
    } else {
      // Ctrl/Cmd+Enter sends
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        handleSubmit();
      }
    }
  };

  const handleSubmit = () => {
    if (content.trim() && !disabled) {
      onSend(content.trim());
      setContent('');
      if (textareaRef.current) {
        textareaRef.current.style.height = 'auto';
      }
    }
  };

  return (
    <div className="relative w-full max-w-4xl mx-auto px-4 pb-6 pt-2">
      <div className={cn(
        "relative flex flex-col w-full rounded-[24px] border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 shadow-[0_4px_24px_rgba(0,0,0,0.04)] dark:shadow-[0_4px_24px_rgba(0,0,0,0.2)] transition-all focus-within:ring-2 focus-within:ring-blue-500/20 focus-within:border-blue-500/50 focus-within:shadow-[0_8px_32px_rgba(0,0,0,0.08)] dark:focus-within:shadow-[0_8px_32px_rgba(0,0,0,0.3)] p-2",
        disabled && "opacity-60 cursor-not-allowed"
      )}>
        
        {/* Textarea */}
        <textarea
          ref={textareaRef}
          autoFocus
          value={content}
          onChange={(e) => setContent(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={disabled}
          aria-label="Message input"
          placeholder="Message MyAI..."
          className="max-h-[200px] min-h-[44px] w-full resize-none bg-transparent px-4 py-3 text-[16px] leading-relaxed text-gray-900 dark:text-gray-100 placeholder:text-gray-400 focus:outline-none disabled:cursor-not-allowed scrollbar-thin scrollbar-thumb-gray-200 dark:scrollbar-thumb-gray-700"
          rows={1}
        />

        {/* Bottom Toolbar */}
        <div className="flex items-center justify-between px-2 pb-1 pt-2">
          <div className="flex items-center gap-2">
            <label className="flex h-9 w-9 items-center justify-center rounded-full text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800 hover:text-gray-700 dark:hover:text-gray-300 transition-colors focus-within:ring-2 focus-within:ring-blue-500 cursor-pointer">
              <input type="file" className="hidden" aria-label="Upload file or photo" accept="image/*,.pdf,.doc,.docx,.txt" multiple onChange={() => { alert('File upload will be processed by the backend.'); }} />
              <Plus size={18} strokeWidth={2.5} />
            </label>
            <button 
              type="button"
              aria-label="Search"
              className="flex h-9 items-center gap-1.5 rounded-full border border-gray-200 dark:border-gray-700/60 px-3 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors text-xs font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              <Search size={14} />
              Search
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button 
              type="button"
              aria-label="Voice input"
              className="flex h-8 w-8 items-center justify-center rounded-full text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors focus:outline-none"
            >
              <Mic size={18} />
            </button>
            {/* Send Button */}
            <button
              onClick={handleSubmit}
              disabled={!content.trim() || disabled}
              aria-label="Send message"
              className={cn(
                "flex h-9 w-9 items-center justify-center rounded-full text-white transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-gray-900",
                content.trim() && !disabled 
                  ? "bg-blue-600 hover:bg-blue-700 shadow-sm" 
                  : "bg-gray-200 dark:bg-gray-700 text-gray-400 cursor-not-allowed"
              )}
            >
              <ArrowUp size={18} strokeWidth={2.5} />
            </button>
          </div>
        </div>
      </div>
      <div className="mt-3 text-center text-xs text-gray-400 dark:text-gray-500">
        MyAI can make mistakes. Check important info.
      </div>
    </div>
  );
}
