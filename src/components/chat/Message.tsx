'use client';

import { useState, memo } from 'react';
import { Copy, RefreshCw, Check } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { cn } from '@/lib/utils';
// Note: In a real app we'd use react-syntax-highlighter, but for simplicity in this milestone
// we'll just style the basic pre/code tags from markdown

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

  return (
    <div className={cn(
      "group w-full py-6 px-4 md:px-0",
      isUser ? "bg-transparent" : "bg-transparent"
    )}>
      <div className="max-w-3xl mx-auto flex gap-4 md:gap-6">
        {/* Avatar */}
        <div className={cn(
          "shrink-0 flex h-8 w-8 items-center justify-center rounded-lg mt-1",
          isUser 
            ? "bg-gray-200 dark:bg-gray-800 text-gray-700 dark:text-gray-300" 
            : "bg-blue-600 text-white shadow-sm"
        )}>
          {isUser ? (
            <span className="text-sm font-medium">U</span>
          ) : (
            <span className="text-sm font-bold">M</span>
          )}
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0 space-y-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-sm text-gray-900 dark:text-gray-100">
              {isUser ? 'You' : 'MyAI'}
            </span>
            {showTimestamp && timestamp && (
              <span className="text-xs text-gray-400 dark:text-gray-500">
                {formatTimestamp(timestamp)}
              </span>
            )}
          </div>
          
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
              prose-pre:border prose-pre:border-gray-200 dark:prose-pre:border-gray-800 prose-pre:rounded-xl overflow-hidden"
            >
              <ReactMarkdown 
                remarkPlugins={[remarkGfm]}
                components={{
                  pre({ children, ...props }) {
                    // Extract code string for copy button
                    let codeString = '';
                    type ElementProps = { children?: React.ReactNode, className?: string };
                    
                    if (children && Array.isArray(children)) {
                      codeString = String((children[0] as React.ReactElement<ElementProps>)?.props?.children || '');
                    } else if (children && typeof children === 'object') {
                      codeString = String((children as React.ReactElement<ElementProps>).props?.children || '');
                    } else if (typeof children === 'string') {
                      codeString = children;
                    }

                    // Extract language
                    let language = '';
                    if (children && typeof children === 'object' && (children as React.ReactElement<ElementProps>).props?.className) {
                      const match = /language-(\w+)/.exec((children as React.ReactElement<ElementProps>).props.className || '');
                      if (match) language = match[1];
                    }

                    return (
                      <div className="relative my-4 group/code">
                        <div className="flex items-center justify-between px-4 py-2 bg-gray-50 dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 text-xs text-gray-500">
                          <span className="uppercase font-semibold tracking-wider">{language || 'Code'}</span>
                          <button 
                            onClick={() => handleCopyCode(String(codeString))}
                            className="flex items-center gap-1.5 hover:text-gray-900 dark:hover:text-gray-100 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded px-1"
                            aria-label={`Copy ${language || ''} code`}
                          >
                            <Copy size={14} />
                            <span>Copy</span>
                          </button>
                        </div>
                        <div className="overflow-x-auto p-4 bg-gray-50/50 dark:bg-black/50 text-sm">
                          <pre {...props} className="!m-0 !p-0 !bg-transparent">
                            {children}
                          </pre>
                        </div>
                      </div>
                    );
                  }
                }}
              >
                {content}
              </ReactMarkdown>
            </div>
          )}

          {/* Message Actions */}
          {!isThinking && (
            <div className="flex items-center gap-1 pt-2 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
              <ActionButton 
                icon={copied ? Check : Copy} 
                label={copied ? "Copied message" : "Copy message"} 
                onClick={handleCopy} 
              />
              {!isUser && isLast && onRegenerate && id && (
                <ActionButton 
                  icon={RefreshCw} 
                  label="Regenerate message" 
                  onClick={() => onRegenerate(id)} 
                />
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export const Message = memo(MessageComponent, (prev, next) => {
  return (
    prev.id === next.id &&
    prev.role === next.role &&
    prev.content === next.content &&
    prev.isLast === next.isLast &&
    prev.timestamp === next.timestamp &&
    prev.showTimestamp === next.showTimestamp &&
    prev.isThinking === next.isThinking
  );
});

function ActionButton({ icon: Icon, label, onClick }: { icon: React.ElementType, label: string, onClick?: () => void }) {
  return (
    <button 
      onClick={onClick}
      title={label}
      aria-label={label}
      className="p-1.5 text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-md transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
    >
      <Icon size={16} />
    </button>
  );
}
