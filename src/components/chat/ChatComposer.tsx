'use client';

import { useState, useRef, useEffect } from 'react';
import { Plus, Search, Mic, ArrowUp, X, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Attachment } from '@/lib/ai/types';

interface ChatComposerProps {
  onSend: (message: string, attachments?: Attachment[]) => void;
  disabled?: boolean;
  enterToSend?: boolean;
}

export function ChatComposer({ onSend, disabled, enterToSend = true }: ChatComposerProps) {
  const [content, setContent] = useState('');
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

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
      if (
        e.target instanceof HTMLInputElement || 
        e.target instanceof HTMLTextAreaElement ||
        e.ctrlKey || e.metaKey || e.altKey ||
        e.key.length > 1
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
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        handleSubmit();
      }
    } else {
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        handleSubmit();
      }
    }
  };

  const handleSubmit = () => {
    if ((content.trim() || attachments.length > 0) && !disabled && !isUploading) {
      onSend(content.trim(), attachments.length > 0 ? attachments : undefined);
      setContent('');
      setAttachments([]);
      setUploadError(null);
      if (textareaRef.current) {
        textareaRef.current.style.height = 'auto';
      }
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;
    const file = files[0];

    // Reset input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }

    setUploadError(null);

    // Validation
    const validTypes = ['image/jpeg', 'image/png', 'image/webp'];
    if (!validTypes.includes(file.type)) {
      setUploadError('Only JPEG, PNG, and WEBP images are supported.');
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      setUploadError('Image size must be less than 5MB.');
      return;
    }

    setIsUploading(true);
    
    try {
      // 1. Get Signature
      const signRes = await fetch('/api/upload/sign', { method: 'POST' });
      if (!signRes.ok) {
        throw new Error('Failed to get upload signature');
      }
      const { timestamp, signature, apiKey, cloudName, folder, allowed_formats } = await signRes.json();

      // 2. Upload to Cloudinary
      const formData = new FormData();
      formData.append('file', file);
      formData.append('api_key', apiKey);
      formData.append('timestamp', timestamp.toString());
      formData.append('signature', signature);
      formData.append('folder', folder);
      formData.append('allowed_formats', allowed_formats);

      const uploadRes = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/image/upload`, {
        method: 'POST',
        body: formData,
      });

      if (!uploadRes.ok) {
        const errText = await uploadRes.text();
        throw new Error(`Upload to Cloudinary failed: ${errText}`);
      }

      const data = await uploadRes.json();

      const newAttachment: Attachment = {
        type: 'image',
        url: data.secure_url,
        public_id: data.public_id,
        mime_type: data.format ? `image/${data.format}` : file.type,
        original_name: file.name,
        size: data.bytes,
        width: data.width,
        height: data.height
      };

      setAttachments(prev => [...prev, newAttachment]);
    } catch (error) {
      console.error('Upload error:', error);
      setUploadError('Failed to upload image. Please try again.');
    } finally {
      setIsUploading(false);
      // Auto-focus the textarea so the user can just press Enter after an upload
      if (textareaRef.current) {
        textareaRef.current.focus();
      }
    }
  };

  const removeAttachment = (index: number) => {
    setAttachments(prev => prev.filter((_, i) => i !== index));
  };

  const isSendDisabled = disabled || isUploading || (!content.trim() && attachments.length === 0);

  return (
    <div className="relative w-full max-w-4xl mx-auto px-4 pb-6 pt-2">
      <div className={cn(
        "relative flex flex-col w-full rounded-[24px] border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 shadow-[0_4px_24px_rgba(0,0,0,0.04)] dark:shadow-[0_4px_24px_rgba(0,0,0,0.2)] transition-all focus-within:ring-2 focus-within:ring-blue-500/20 focus-within:border-blue-500/50 focus-within:shadow-[0_8px_32px_rgba(0,0,0,0.08)] dark:focus-within:shadow-[0_8px_32px_rgba(0,0,0,0.3)] p-2",
        disabled && "opacity-60 cursor-not-allowed"
      )}>
        
        {/* Attachments Preview Area */}
        {(attachments.length > 0 || isUploading || uploadError) && (
          <div className="flex flex-wrap gap-3 px-4 pt-3 pb-1">
            {attachments.map((att, idx) => (
              <div key={idx} className="relative group w-16 h-16 rounded-xl overflow-hidden border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 shadow-sm shrink-0">
                <img src={att.url} alt="Attachment" className="w-full h-full object-cover" />
                <button
                  onClick={() => removeAttachment(idx)}
                  className="absolute top-1 right-1 p-0.5 rounded-full bg-black/50 text-white opacity-0 group-hover:opacity-100 transition-opacity hover:bg-black/70"
                  aria-label="Remove image"
                >
                  <X size={12} />
                </button>
              </div>
            ))}
            
            {isUploading && (
              <div className="w-16 h-16 rounded-xl border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 flex flex-col items-center justify-center shrink-0">
                <Loader2 size={18} className="animate-spin text-blue-500 mb-1" />
              </div>
            )}

            {uploadError && (
              <div className="flex items-center gap-2 text-sm text-red-500 bg-red-50 dark:bg-red-950/50 px-3 py-1.5 rounded-lg">
                <span>{uploadError}</span>
                <button onClick={() => setUploadError(null)} className="hover:text-red-700"><X size={14}/></button>
              </div>
            )}
          </div>
        )}

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
            <label className={cn("flex h-9 w-9 items-center justify-center rounded-full text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800 hover:text-gray-700 dark:hover:text-gray-300 transition-colors focus-within:ring-2 focus-within:ring-blue-500 cursor-pointer", isUploading && "opacity-50 pointer-events-none")}>
              <input ref={fileInputRef} type="file" className="hidden" aria-label="Upload file or photo" accept="image/jpeg,image/png,image/webp" onChange={handleFileUpload} disabled={isUploading} />
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
              disabled={isSendDisabled}
              aria-label="Send message"
              className={cn(
                "flex h-9 w-9 items-center justify-center rounded-full text-white transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-gray-900",
                !isSendDisabled
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
