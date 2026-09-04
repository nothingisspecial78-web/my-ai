import os

def write_file(path, content):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content.strip() + '\n')
    print(f"Updated {path}")

# --- Message.tsx ---
message_tsx = """
'use client';

import { useState, memo } from 'react';
import { 
  Copy, 
  RefreshCw, 
  Check, 
  BookOpen, 
  GitFork, 
  Volume2, 
  ThumbsUp, 
  ThumbsDown, 
  Share, 
  MoreHorizontal 
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { cn } from '@/lib/utils';

interface MessageProps {
  id?: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  isLast?: boolean;
  onRegenerate?: (id: string) => void;
  timestamp?: string | null;
  showTimestamp?: boolean;
  isThinking?: boolean;
}

function MessageComponent({ id, role, content, isLast, onRegenerate, timestamp, showTimestamp, isThinking }: MessageProps) {
  const isUser = role === 'user';
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleCopyCode = (code: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(code);
    }
  };

  function formatTimestamp(ts: string): string {
    try {
      const date = new Date(ts);
      return date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    } catch {
      return '';
    }
  }

  // --- User Message ---
  if (isUser) {
    return (
      <div className="group w-full py-4 px-4 md:px-0 flex justify-end">
        <div className="max-w-[70%] flex flex-col items-end gap-1">
          <div className="bg-blue-600 text-white px-5 py-3 rounded-2xl rounded-br-sm shadow-sm">
            <div className="whitespace-pre-wrap break-words text-[15px] leading-relaxed">
              {content}
            </div>
          </div>
          {showTimestamp && timestamp && (
            <div className="text-[11px] text-gray-400 mr-1 mt-1">
              {formatTimestamp(timestamp)}
            </div>
          )}
        </div>
      </div>
    );
  }

  // --- AI Message ---
  return (
    <div className="group w-full py-6 px-4 md:px-0 flex justify-start">
      <div className="max-w-4xl w-full flex gap-4">
        {/* Avatar */}
        <div className="shrink-0 flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600 text-white shadow-sm mt-1">
          <SparklesIcon />
        </div>

        {/* Content Box */}
        <div className="flex-1 min-w-0">
          <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl p-5 shadow-sm">
            {isThinking ? (
              <div className="flex items-center gap-1.5 h-6 opacity-70">
                <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse [animation-delay:-0.3s]"></div>
                <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse [animation-delay:-0.15s]"></div>
                <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></div>
              </div>
            ) : (
              <div className="prose prose-slate dark:prose-invert max-w-none break-words
                prose-p:leading-relaxed prose-pre:p-0 prose-pre:bg-transparent
                prose-code:bg-gray-100 dark:prose-code:bg-gray-800 prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded-md prose-code:font-normal
                prose-pre:border prose-pre:border-gray-200 dark:prose-pre:border-gray-800 prose-pre:rounded-xl overflow-hidden text-[15px]"
              >
                <ReactMarkdown 
                  remarkPlugins={[remarkGfm]}
                  components={{
                    pre({ children, ...props }) {
                      let codeString = '';
                      type ElementProps = { children?: React.ReactNode, className?: string };
                      
                      if (children && Array.isArray(children)) {
                        codeString = String((children[0] as React.ReactElement<ElementProps>)?.props?.children || '');
                      } else if (children && typeof children === 'object') {
                        codeString = String((children as React.ReactElement<ElementProps>).props?.children || '');
                      } else if (typeof children === 'string') {
                        codeString = children;
                      }

                      let language = '';
                      if (children && typeof children === 'object' && (children as React.ReactElement<ElementProps>).props?.className) {
                        const match = /language-(\w+)/.exec((children as React.ReactElement<ElementProps>).props.className || '');
                        if (match) language = match[1];
                      }

                      return (
                        <div className="relative my-4 group/code">
                          <div className="flex items-center justify-between px-4 py-2 bg-gray-50 dark:bg-gray-950 border-b border-gray-200 dark:border-gray-800 text-xs text-gray-500">
                            <span className="uppercase font-semibold tracking-wider">{language || 'Code'}</span>
                            <button
                              onClick={() => handleCopyCode(codeString)}
                              className="flex items-center gap-1.5 hover:text-gray-900 dark:hover:text-gray-300 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded px-1"
                              aria-label="Copy code"
                            >
                              <Copy size={14} />
                              <span>Copy</span>
                            </button>
                          </div>
                          <pre {...props} className="p-4 overflow-x-auto bg-gray-50 dark:bg-gray-950 text-sm">
                            {children}
                          </pre>
                        </div>
                      );
                    }
                  }}
                >
                  {content}
                </ReactMarkdown>
              </div>
            )}
          </div>
          
          {showTimestamp && timestamp && (
            <div className="text-[11px] text-gray-400 mt-2 ml-2">
              {formatTimestamp(timestamp)}
            </div>
          )}

          {/* AI Action Toolbar */}
          {!isThinking && (
            <div className="flex flex-wrap items-center gap-1.5 pt-3 pl-2 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
              <ToolbarButton icon={BookOpen} label="View sources" text="View sources" />
              <ToolbarButton icon={GitFork} label="Branch in new chat" text="Branch" />
              <ToolbarButton icon={Volume2} label="Read aloud" text="Read aloud" />
              
              <div className="w-px h-4 bg-gray-300 dark:bg-gray-700 mx-1"></div>
              
              <ToolbarButton icon={ThumbsUp} label="Like response" />
              <ToolbarButton icon={ThumbsDown} label="Dislike response" />
              <ToolbarButton icon={Share} label="Share" onClick={handleCopy} active={copied} />
              
              {isLast && onRegenerate && id && (
                <ToolbarButton icon={RefreshCw} label="Regenerate message" onClick={() => onRegenerate(id)} />
              )}
              
              <ToolbarButton icon={MoreHorizontal} label="More options" />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ToolbarButton({ 
  icon: Icon, 
  label, 
  text,
  onClick,
  active
}: { 
  icon: any, 
  label: string, 
  text?: string,
  onClick?: () => void,
  active?: boolean
}) {
  return (
    <button
      onClick={onClick}
      title={label}
      aria-label={label}
      className={cn(
        "flex items-center gap-1.5 px-2 py-1.5 rounded-lg text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 text-xs font-medium",
        active && "text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20"
      )}
    >
      <Icon size={14} />
      {text && <span className="hidden sm:inline">{text}</span>}
    </button>
  );
}

function SparklesIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M12 2L14.645 9.355L22 12L14.645 14.645L12 22L9.355 14.645L2 12L9.355 9.355L12 2Z" fill="currentColor"/>
    </svg>
  );
}

export const Message = memo(MessageComponent, (prev, next) => {
  return (
    prev.id === next.id &&
    prev.content === next.content &&
    prev.isLast === next.isLast &&
    prev.isThinking === next.isThinking &&
    prev.timestamp === next.timestamp
  );
});
"""

# --- ChatComposer.tsx ---
composer_tsx = """
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
        "relative flex flex-col w-full rounded-2xl border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 shadow-sm transition-all focus-within:ring-2 focus-within:ring-blue-500/20 focus-within:border-blue-500 p-2",
        disabled && "opacity-60 cursor-not-allowed"
      )}>
        
        {/* Textarea */}
        <textarea
          ref={textareaRef}
          value={content}
          onChange={(e) => setContent(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={disabled}
          aria-label="Message input"
          placeholder="Message MyAI..."
          className="max-h-[200px] min-h-[44px] w-full resize-none bg-transparent px-3 py-3 text-[15px] text-gray-900 dark:text-gray-100 placeholder:text-gray-500 focus:outline-none disabled:cursor-not-allowed scrollbar-thin scrollbar-thumb-gray-300 dark:scrollbar-thumb-gray-600"
          rows={1}
        />

        {/* Bottom Toolbar */}
        <div className="flex items-center justify-between px-2 pb-1 pt-2">
          <div className="flex items-center gap-2">
            <button 
              type="button"
              aria-label="Attach file"
              className="flex h-8 w-8 items-center justify-center rounded-full border border-gray-200 dark:border-gray-700 text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors focus:outline-none"
            >
              <Plus size={16} />
            </button>
            <button 
              type="button"
              aria-label="Search"
              className="flex h-8 items-center gap-1.5 rounded-full border border-gray-200 dark:border-gray-700 px-3 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors text-xs font-medium focus:outline-none"
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
"""

write_file('src/components/chat/Message.tsx', message_tsx)
write_file('src/components/chat/ChatComposer.tsx', composer_tsx)
