'use client';

import { useState, useRef, useEffect } from 'react';
import { Send, Paperclip } from 'lucide-react';
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
    return () => {
      if (rafId) cancelAnimationFrame(rafId);
    };
  }, [content]);

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
    <div className="relative w-full max-w-3xl mx-auto px-4 pb-6 pt-2">
      <div className={cn(
        "relative flex w-full items-end gap-2 rounded-2xl border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 p-2 shadow-sm transition-all focus-within:ring-2 focus-within:ring-blue-500/20 focus-within:border-blue-500",
        disabled && "opacity-60 cursor-not-allowed"
      )}>
        
        {/* Attachment Button */}
        <div className="group relative mb-[2px]">
          <button 
            type="button"
            disabled
            aria-label="Attach file (coming soon)"
            aria-disabled="true"
            className="flex h-9 w-9 items-center justify-center rounded-xl text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <Paperclip size={18} />
          </button>
          <div className="absolute bottom-full left-1/2 mb-2 -translate-x-1/2 rounded bg-gray-900 px-2 py-1 text-xs text-white opacity-0 transition-opacity group-hover:opacity-100 whitespace-nowrap pointer-events-none">
            Coming soon
          </div>
        </div>

        {/* Textarea */}
        <textarea
          ref={textareaRef}
          value={content}
          onChange={(e) => setContent(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={disabled}
          aria-label="Message input"
          placeholder="Ask anything..."
          className="max-h-[200px] min-h-[36px] w-full resize-none bg-transparent py-[8px] pl-1 pr-2 text-sm text-gray-900 dark:text-gray-100 placeholder:text-gray-500 focus:outline-none disabled:cursor-not-allowed scrollbar-thin scrollbar-thumb-gray-300 dark:scrollbar-thumb-gray-600"
          rows={1}
        />

        {/* Send Button */}
        <button
          onClick={handleSubmit}
          disabled={!content.trim() || disabled}
          aria-label="Send message"
          className={cn(
            "mb-[2px] flex h-9 w-9 items-center justify-center rounded-xl text-white transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-1 dark:focus-visible:ring-offset-gray-900",
            content.trim() && !disabled 
              ? "bg-blue-600 hover:bg-blue-700 shadow-sm" 
              : "bg-gray-200 dark:bg-gray-700 text-gray-400 cursor-not-allowed"
          )}
        >
          <Send size={16} className={content.trim() && !disabled ? "ml-0.5" : ""} />
        </button>
      </div>
      <div className="mt-2 text-center text-xs text-gray-500 dark:text-gray-400">
        {enterToSend ? 'Enter to send, Shift+Enter for newline' : 'Ctrl+Enter to send'} · AI can make mistakes.
      </div>
    </div>
  );
}
