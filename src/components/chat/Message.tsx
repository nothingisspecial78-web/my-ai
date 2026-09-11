'use client';

import { useState, memo } from 'react';
import { 
  Copy, 
  RefreshCw, 
  Volume2, 
  ThumbsUp, 
  ThumbsDown,
  Pencil,
  FileText,
  FileCode,
  ExternalLink
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { cn } from '@/lib/utils';
import { Attachment } from '@/lib/ai/types';
import { formatFileSize } from '@/lib/attachments';
import { SafetyAnalysisCard } from '@/components/safety/SafetyAnalysisCard';
import { SafetyReport } from '@/lib/safety/types';
import { ThemeDefinition } from '@/lib/theme/types';

interface MessageProps {
  id?: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  isLast?: boolean;
  onRegenerate?: (id: string) => void;
  timestamp?: string | null;
  showTimestamp?: boolean;
  isThinking?: boolean;
  metadata?: Record<string, unknown>;
  theme?: ThemeDefinition;
}

function MessageComponent({ id, role, content, isLast, onRegenerate, timestamp, showTimestamp, isThinking, metadata, theme }: MessageProps) {
  const isUser = role === 'user';
  const [copied, setCopied] = useState(false);
  const [feedback, setFeedback] = useState<'like' | 'dislike' | null>(null);
  
  // Extract attachments from metadata if present
  const attachments = (metadata?.attachments as Attachment[]) || [];
  const imageAttachments = attachments.filter(a => a.type === 'image' && a.url);
  const documentAttachments = attachments.filter(a => a.type !== 'image' && a.url);
  const safetyReport = (metadata?.safetyReport as SafetyReport | undefined) || undefined;

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
      <div className="group w-full py-4 px-4 flex justify-end">
        <div className="max-w-[85%] sm:max-w-[75%] flex flex-col items-end gap-1">
          {imageAttachments.length > 0 && (
            <div className="flex flex-wrap justify-end gap-2 mb-1">
              {imageAttachments.map((att, idx) => (
                <div key={idx} className="relative rounded-xl overflow-hidden border border-gray-200 dark:border-gray-700 max-w-[200px] sm:max-w-[250px] shadow-sm">
                  <img src={att.url} alt="Uploaded image" className="w-full h-auto object-cover max-h-[300px]" />
                </div>
              ))}
            </div>
          )}
          {documentAttachments.length > 0 && (
            <div className="flex flex-wrap justify-end gap-2 mb-1">
              {documentAttachments.map((att, idx) => {
                const name = att.original_name || 'Document';
                const isPdf = att.type === 'pdf' || name.endsWith('.pdf');
                const isHtml = att.type === 'html' || name.endsWith('.html') || name.endsWith('.htm');

                return (
                  <a
                    key={idx}
                    href={att.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    download={name}
                    className="flex items-center gap-2.5 px-3 py-2 rounded-xl border border-gray-200 dark:border-gray-700 bg-[var(--theme-card)] hover:bg-gray-50 dark:hover:bg-gray-800/80 transition-colors shadow-sm max-w-[260px] text-xs group/doc"
                    aria-label={`Open or download ${name}`}
                  >
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 shrink-0">
                      {isPdf ? (
                        <FileText size={16} className="text-red-500" aria-hidden="true" />
                      ) : isHtml ? (
                        <FileCode size={16} className="text-amber-500" aria-hidden="true" />
                      ) : (
                        <FileText size={16} className="text-blue-500" aria-hidden="true" />
                      )}
                    </div>
                    <div className="flex flex-col min-w-0 flex-1">
                      <span className="font-medium text-gray-900 dark:text-gray-100 truncate group-hover/doc:underline">
                        {name}
                      </span>
                      <span className="text-[10px] text-gray-500 dark:text-gray-400">
                        {formatFileSize(att.size)}
                      </span>
                    </div>
                    <ExternalLink size={12} className="text-gray-400 shrink-0 opacity-0 group-hover/doc:opacity-100 transition-opacity" aria-hidden="true" />
                  </a>
                );
              })}
            </div>
          )}
          {content.trim() && (
            <div className="bg-[var(--theme-bubble-user)] text-[var(--theme-bubble-user-text)] px-5 py-3 rounded-2xl rounded-br-sm shadow-sm">
              <div className="whitespace-pre-wrap break-words [overflow-wrap:anywhere] text-[15px] leading-relaxed">
                {content}
              </div>
            </div>
          )}
          {showTimestamp && timestamp && (
            <div className="text-[11px] text-gray-400 mr-1 mt-1">
              {formatTimestamp(timestamp)}
            </div>
          )}

          {/* User Action Toolbar */}
          <div className="flex items-center gap-1.5 pt-1 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 sm:focus-within:opacity-100 focus-within:opacity-100 transition-opacity">
            <ToolbarButton 
              icon={Pencil} 
              label="Edit" 
              onClick={() => {
                // Future: Add real edit logic. For now, it copies the text to clipboard so they can paste and edit.
                navigator.clipboard.writeText(content);
              }} 
            />
            <ToolbarButton 
              icon={Copy} 
              label="Copy" 
              onClick={handleCopy} 
            />
          </div>
        </div>
      </div>
    );
  }

  // --- AI Message ---
  return (
    <div className="group w-full py-6 px-4 flex justify-start">
      <div className="w-full flex gap-4">
        {/* Avatar */}
        <div className="shrink-0 flex h-8 w-8 items-center justify-center rounded-lg bg-theme-avatar-bg text-theme-avatar-fg shadow-sm mt-1">
          <SparklesIcon />
        </div>

        {/* Content Box */}
        <div className="flex-1 min-w-0">
          <div className="bg-[var(--theme-card)] border border-[var(--theme-border)] rounded-2xl p-5 shadow-sm transition-colors">
            {safetyReport && (
              <SafetyAnalysisCard
                report={safetyReport}
                themeSlug={(metadata?.themeSlug as string | undefined) || theme?.slug}
                theme={theme}
              />
            )}
            {isThinking ? (
              <div className="flex items-center gap-1.5 h-6 opacity-70" role="status" aria-label="Thinking...">
                <span className="sr-only">Generating response...</span>
                <div className="w-2 h-2 rounded-full bg-theme-accent animate-pulse [animation-delay:-0.3s]" aria-hidden="true"></div>
                <div className="w-2 h-2 rounded-full bg-theme-accent animate-pulse [animation-delay:-0.15s]" aria-hidden="true"></div>
                <div className="w-2 h-2 rounded-full bg-theme-accent animate-pulse" aria-hidden="true"></div>
              </div>
            ) : (
              <div className="prose prose-slate dark:prose-invert max-w-none break-words [overflow-wrap:anywhere]
                prose-p:leading-relaxed prose-pre:p-0 prose-pre:bg-transparent
                prose-code:bg-gray-100 dark:prose-code:bg-gray-800 prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded-md prose-code:font-normal
                prose-pre:border prose-pre:border-[var(--theme-border)] prose-pre:rounded-xl overflow-hidden text-[15px] min-h-[1.5rem]"
              >
                <ReactMarkdown 
                  remarkPlugins={[remarkGfm]}
                  components={{
                    table({ children, ...props }) {
                      return (
                        <div className="w-full overflow-x-auto my-4 rounded-lg border border-[var(--theme-border)]">
                          <table {...props} className="w-full text-sm text-left border-collapse">
                            {children}
                          </table>
                        </div>
                      );
                    },
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
                          <div className="flex items-center justify-between px-4 py-2 bg-[var(--theme-card-muted)] border-b border-[var(--theme-border)] text-xs text-gray-500">
                            <span className="uppercase font-semibold tracking-wider">{language || 'Code'}</span>
                            <button
                              type="button"
                              onClick={() => handleCopyCode(codeString)}
                              className="flex items-center gap-1.5 hover:text-gray-900 dark:hover:text-gray-300 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-theme-composer-focus rounded px-2 py-1 min-h-[28px]"
                              aria-label="Copy code"
                            >
                              <Copy size={14} aria-hidden="true" />
                              <span>Copy</span>
                            </button>
                          </div>
                          <pre {...props} className="p-4 overflow-x-auto bg-[var(--theme-card-muted)] text-sm">
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
            <div className="flex flex-wrap items-center gap-1.5 pt-3 pl-2 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 sm:focus-within:opacity-100 focus-within:opacity-100 transition-opacity">
              <ToolbarButton 
                icon={Volume2} 
                label="Read aloud" 
                text="Read" 
                onClick={() => {
                  if ('speechSynthesis' in window) {
                    window.speechSynthesis.cancel();
                    const utterance = new SpeechSynthesisUtterance(content);
                    window.speechSynthesis.speak(utterance);
                  }
                }} 
              />
              <div className="w-px h-4 bg-gray-200 dark:bg-gray-800 mx-1" aria-hidden="true"></div>
              
              <ToolbarButton 
                icon={ThumbsUp} 
                label="Like response" 
                active={feedback === 'like'}
                onClick={() => setFeedback(prev => prev === 'like' ? null : 'like')}
              />
              <ToolbarButton 
                icon={ThumbsDown} 
                label="Dislike response" 
                active={feedback === 'dislike'}
                onClick={() => setFeedback(prev => prev === 'dislike' ? null : 'dislike')}
              />
              <ToolbarButton 
                icon={Copy} 
                label="Copy response" 
                onClick={handleCopy} 
                active={copied} 
              />
              
              {isLast && onRegenerate && id && (
                <ToolbarButton icon={RefreshCw} label="Regenerate message" onClick={() => onRegenerate(id)} />
              )}
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
  icon: React.ElementType, 
  label: string, 
  text?: string,
  onClick?: () => void,
  active?: boolean
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={label}
      aria-label={label}
      className={cn(
        "flex items-center justify-center gap-1.5 px-2.5 py-1.5 min-h-[36px] min-w-[36px] rounded-lg text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-theme-composer-focus text-xs font-medium",
        active && "text-theme-accent bg-theme-subtle"
      )}
    >
      <Icon size={14} aria-hidden="true" />
      {text && <span className="hidden sm:inline">{text}</span>}
    </button>
  );
}

function SparklesIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
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
    prev.timestamp === next.timestamp &&
    prev.metadata === next.metadata &&
    prev.theme?.slug === next.theme?.slug
  );
});
