'use client';

import { useState, useRef, useEffect } from 'react';
import { Plus, Search, Mic, ArrowUp, X, Loader2, Camera, Image as ImageIcon, Paperclip, FileText, FileCode } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Attachment } from '@/lib/ai/types';
import { MAX_ATTACHMENTS_PER_MESSAGE, validateAttachment, formatFileSize } from '@/lib/attachments';

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
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const cameraInputRef = useRef<HTMLInputElement>(null);
  const imageInputRef = useRef<HTMLInputElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const addButtonRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

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

      // Do not steal focus if active element is an interactive control or inside a modal/dialog
      if (e.target instanceof HTMLElement) {
        if (
          e.target.isContentEditable ||
          e.target.closest('button') ||
          e.target.closest('select') ||
          e.target.closest('[role="dialog"]') ||
          e.target.closest('[role="menu"]') ||
          e.target.closest('[role="listbox"]')
        ) {
          return;
        }
      }
      
      if (textareaRef.current && document.activeElement !== textareaRef.current) {
        textareaRef.current.focus();
      }
    };

    window.addEventListener('keydown', handleGlobalKeyDown);
    return () => window.removeEventListener('keydown', handleGlobalKeyDown);
  }, []);

  // Handle click outside to close attachment menu
  useEffect(() => {
    if (!isMenuOpen) return;
    const handleClickOutside = (e: MouseEvent) => {
      if (
        menuRef.current &&
        !menuRef.current.contains(e.target as Node) &&
        addButtonRef.current &&
        !addButtonRef.current.contains(e.target as Node)
      ) {
        setIsMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isMenuOpen]);

  // Focus first menuitem when attachment menu opens
  useEffect(() => {
    if (isMenuOpen && menuRef.current) {
      const firstItem = menuRef.current.querySelector<HTMLButtonElement>('button[role="menuitem"]');
      firstItem?.focus();
    }
  }, [isMenuOpen]);

  // Keyboard navigation for attachment menu
  const handleMenuKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      setIsMenuOpen(false);
      addButtonRef.current?.focus();
      return;
    }

    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const items = menuRef.current?.querySelectorAll<HTMLButtonElement>('button[role="menuitem"]');
      if (!items || items.length === 0) return;
      const currentIndex = Array.from(items).indexOf(document.activeElement as HTMLButtonElement);
      let nextIndex = 0;
      if (e.key === 'ArrowDown') {
        nextIndex = currentIndex >= items.length - 1 ? 0 : currentIndex + 1;
      } else {
        nextIndex = currentIndex <= 0 ? items.length - 1 : currentIndex - 1;
      }
      items[nextIndex]?.focus();
    }
  };

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

      if (typeof window !== 'undefined') {
        if ('ontouchstart' in window || navigator.maxTouchPoints > 0) {
          textareaRef.current?.blur();
        }
        window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
      }
    }
  };

/**
 * Fast client-side image downscaling/compression.
 * If image is over 300KB or dimensions > 1600px, downscales it to max 1600px
 * and compresses as high-quality JPEG.
 * This cuts upload payload by 80-95% (e.g. 2.5MB -> ~150KB), accelerating upload speeds by 5x-10x.
 */
async function optimizeImageForUpload(file: File): Promise<File | Blob> {
  if (file.size <= 300 * 1024) {
    return file;
  }

  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return file;
  }

  return new Promise((resolve) => {
    const img = new Image();
    const objectUrl = URL.createObjectURL(file);

    img.onload = () => {
      URL.revokeObjectURL(objectUrl);
      const MAX_DIM = 1600;
      let { width, height } = img;

      if (width <= MAX_DIM && height <= MAX_DIM && file.size <= 500 * 1024) {
        resolve(file);
        return;
      }

      if (width > MAX_DIM || height > MAX_DIM) {
        if (width > height) {
          height = Math.round((height * MAX_DIM) / width);
          width = MAX_DIM;
        } else {
          width = Math.round((width * MAX_DIM) / height);
          height = MAX_DIM;
        }
      }

      const canvas = document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d');
      if (!ctx) {
        resolve(file);
        return;
      }

      ctx.drawImage(img, 0, 0, width, height);
      canvas.toBlob(
        (blob) => {
          if (blob && blob.size < file.size) {
            const ext = file.name.replace(/\.[^.]+$/, '') + '.jpg';
            try {
              const optimizedFile = new File([blob], ext, { type: 'image/jpeg' });
              resolve(optimizedFile);
            } catch {
              resolve(blob);
            }
          } else {
            resolve(file);
          }
        },
        'image/jpeg',
        0.85
      );
    };

    img.onerror = () => {
      URL.revokeObjectURL(objectUrl);
      resolve(file);
    };

    img.src = objectUrl;
  });
}

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;
    const file = files[0];

    // Reset input value so same file can be re-selected if removed
    e.target.value = '';
    setUploadError(null);

    // Limit check: maximum 3 attachments
    if (attachments.length >= MAX_ATTACHMENTS_PER_MESSAGE) {
      setUploadError(`Maximum of ${MAX_ATTACHMENTS_PER_MESSAGE} attachments per message allowed.`);
      return;
    }

    // Validation using central validator
    const validation = validateAttachment({
      name: file.name,
      size: file.size,
      type: file.type,
    });

    if (!validation.valid || !validation.type) {
      setUploadError(validation.error || 'Invalid file.');
      return;
    }

    setIsUploading(true);

    try {
      if (validation.type === 'image') {
        // Concurrently get signature AND optimize image for upload
        const signPromise = (async () => {
          const signRes = await fetch('/api/upload/sign', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              resource_type: 'image',
              mime_type: file.type,
              file_size: file.size,
              filename: file.name,
            }),
          });
          if (!signRes.ok) {
            let errMsg = 'Failed to get upload signature';
            if (signRes.status === 401) {
              errMsg = 'Please sign in to upload images.';
            } else {
              try {
                const errData = await signRes.json();
                if (errData?.error) errMsg = errData.error;
              } catch {}
            }
            throw new Error(errMsg);
          }
          return signRes.json();
        })();

        const optimizePromise = optimizeImageForUpload(file);
        const [signData, uploadPayload] = await Promise.all([signPromise, optimizePromise]);
        const { timestamp, signature, apiKey, cloudName, folder, allowed_formats } = signData;

        const formData = new FormData();
        formData.append('file', uploadPayload, file.name);
        formData.append('api_key', apiKey);
        formData.append('timestamp', timestamp.toString());
        formData.append('signature', signature);
        formData.append('folder', folder);
        if (allowed_formats) {
          formData.append('allowed_formats', allowed_formats);
        }

        const uploadRes = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/image/upload`, {
          method: 'POST',
          body: formData,
        });

        if (!uploadRes.ok) {
          const errText = await uploadRes.text();
          throw new Error(`Upload failed: ${errText}`);
        }

        const data = await uploadRes.json();

        const newAttachment: Attachment = {
          id: data.public_id,
          type: 'image',
          url: data.secure_url,
          public_id: data.public_id,
          mime_type: data.format ? `image/${data.format}` : file.type,
          original_name: file.name,
          size: data.bytes,
          width: data.width,
          height: data.height,
        };

        setAttachments(prev => [...prev, newAttachment]);
      } else {
        // Document upload (PDF, TXT, HTML)
        const signRes = await fetch('/api/upload/sign', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            resource_type: 'raw',
            mime_type: file.type,
            file_size: file.size,
            filename: file.name,
          }),
        });

        if (!signRes.ok) {
          let errMsg = 'Failed to get upload signature';
          if (signRes.status === 401) {
            errMsg = 'Please sign in to upload files.';
          } else {
            try {
              const errData = await signRes.json();
              if (errData?.error) errMsg = errData.error;
            } catch {}
          }
          throw new Error(errMsg);
        }

        const signData = await signRes.json();
        const { timestamp, signature, apiKey, cloudName, folder } = signData;

        const formData = new FormData();
        const uploadFilename = validation.type === 'pdf'
          ? `${validation.sanitizedFilename || file.name}.dat`
          : (validation.sanitizedFilename || file.name);
        formData.append('file', file, uploadFilename);
        formData.append('api_key', apiKey);
        formData.append('timestamp', timestamp.toString());
        formData.append('signature', signature);
        formData.append('folder', folder);

        const uploadRes = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/raw/upload`, {
          method: 'POST',
          body: formData,
        });

        if (!uploadRes.ok) {
          const errText = await uploadRes.text();
          throw new Error(`Upload failed: ${errText}`);
        }

        const data = await uploadRes.json();

        const newAttachment: Attachment = {
          id: data.public_id,
          type: validation.type,
          url: data.secure_url,
          public_id: data.public_id,
          mime_type: file.type,
          original_name: validation.sanitizedFilename || file.name,
          size: data.bytes || file.size,
        };

        setAttachments(prev => [...prev, newAttachment]);
      }
    } catch (error) {
      console.error('Upload error:', error);
      setUploadError(error instanceof Error ? error.message : 'Failed to upload attachment. Please try again.');
    } finally {
      setIsUploading(false);
      // Auto-focus textarea so user can type immediately
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
      {/* Hidden inputs for camera, images, and documents */}
      <input
        ref={cameraInputRef}
        type="file"
        accept="image/jpeg,image/png,image/webp"
        capture="environment"
        className="hidden"
        aria-label="Take Photo"
        onChange={handleFileUpload}
        disabled={isUploading}
      />
      <input
        ref={imageInputRef}
        type="file"
        accept="image/jpeg,image/png,image/webp"
        className="hidden"
        aria-label="Upload Image"
        onChange={handleFileUpload}
        disabled={isUploading}
      />
      <input
        ref={fileInputRef}
        type="file"
        accept=".pdf,.txt,.html,.htm,application/pdf,text/plain,text/html"
        className="hidden"
        aria-label="Upload File"
        onChange={handleFileUpload}
        disabled={isUploading}
      />

      <div className={cn(
        "relative flex flex-col w-full rounded-[24px] border border-[var(--theme-composer-border)] bg-[var(--theme-card)] shadow-[0_4px_24px_rgba(0,0,0,0.04)] dark:shadow-[0_4px_24px_rgba(0,0,0,0.2)] transition-all focus-within:ring-2 focus-within:ring-theme-composer-focus focus-within:border-theme-border focus-within:shadow-[0_8px_32px_rgba(0,0,0,0.08)] dark:focus-within:shadow-[0_8px_32px_rgba(0,0,0,0.3)] p-2",
        disabled && "opacity-60 cursor-not-allowed"
      )}>
        
        {/* Attachments Preview Area */}
        {(attachments.length > 0 || isUploading || uploadError) && (
          <div className="flex flex-wrap items-center gap-2.5 px-4 pt-3 pb-1">
            {attachments.map((att, idx) => {
              const isImg = att.type === 'image';
              const name = att.original_name || (isImg ? 'Image' : 'Attachment');

              if (isImg) {
                return (
                  <div key={idx} className="relative group w-16 h-16 rounded-xl overflow-hidden border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 shadow-sm shrink-0">
                    <img src={att.url} alt={name} className="w-full h-full object-cover" />
                    <button
                      type="button"
                      onClick={() => removeAttachment(idx)}
                      className="absolute top-1 right-1 flex h-6 w-6 items-center justify-center rounded-full bg-black/60 text-white opacity-100 sm:opacity-0 sm:group-hover:opacity-100 sm:group-focus-within:opacity-100 focus:opacity-100 transition-opacity hover:bg-black/80 focus:outline-none focus-visible:ring-2 focus-visible:ring-white"
                      aria-label="Remove image"
                    >
                      <X size={12} aria-hidden="true" />
                    </button>
                  </div>
                );
              }

              return (
                <div
                  key={idx}
                  className="relative group flex items-center gap-2.5 px-3 py-2 rounded-xl border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-xs shadow-sm max-w-[220px] sm:max-w-[260px] shrink-0"
                >
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-200 shrink-0">
                    {att.type === 'pdf' ? (
                      <FileText size={16} className="text-red-500" aria-hidden="true" />
                    ) : att.type === 'html' ? (
                      <FileCode size={16} className="text-amber-500" aria-hidden="true" />
                    ) : (
                      <FileText size={16} className="text-blue-500" aria-hidden="true" />
                    )}
                  </div>
                  <div className="flex flex-col min-w-0 flex-1">
                    <span className="font-medium text-gray-900 dark:text-gray-100 truncate">
                      {name}
                    </span>
                    <span className="text-[10px] text-gray-500 dark:text-gray-400">
                      {formatFileSize(att.size)}
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => removeAttachment(idx)}
                    className="flex h-7 w-7 items-center justify-center rounded-full text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-theme-composer-focus shrink-0"
                    aria-label={`Remove ${name}`}
                  >
                    <X size={13} aria-hidden="true" />
                  </button>
                </div>
              );
            })}
            
            {isUploading && (
              <div className="w-16 h-16 rounded-xl border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 flex flex-col items-center justify-center shrink-0" role="status" aria-label="Uploading attachment">
                <Loader2 size={18} className="animate-spin text-theme-accent mb-1" aria-hidden="true" />
              </div>
            )}

            {uploadError && (
              <div className="flex items-center gap-2 text-sm text-red-500 bg-red-50 dark:bg-red-950/50 px-3 py-1.5 rounded-lg" role="alert">
                <span>{uploadError}</span>
                <button type="button" onClick={() => setUploadError(null)} aria-label="Dismiss error" className="hover:text-red-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 rounded"><X size={14} aria-hidden="true" /></button>
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
          placeholder="Message Before You Click..."
          className="max-h-[200px] min-h-[44px] w-full resize-none bg-transparent px-4 py-3 text-[16px] leading-relaxed text-gray-900 dark:text-gray-100 placeholder:text-gray-400 focus:outline-none disabled:cursor-not-allowed scrollbar-thin scrollbar-thumb-gray-200 dark:scrollbar-thumb-gray-700"
          rows={1}
        />

        {/* Bottom Toolbar */}
        <div className="flex items-center justify-between px-2 pb-1 pt-2">
          <div className="flex items-center gap-2">
            {/* Attachment Menu Button */}
            <div className="relative">
              <button
                ref={addButtonRef}
                type="button"
                onClick={() => setIsMenuOpen(prev => !prev)}
                aria-haspopup="menu"
                aria-expanded={isMenuOpen}
                aria-label="Upload file or photo"
                disabled={isUploading}
                className={cn(
                  "flex h-10 w-10 sm:h-9 sm:w-9 items-center justify-center rounded-full text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800 hover:text-gray-700 dark:hover:text-gray-300 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-theme-composer-focus cursor-pointer",
                  isUploading && "opacity-50 pointer-events-none"
                )}
              >
                <Plus size={18} strokeWidth={2.5} aria-hidden="true" />
              </button>

              {/* Accessible Popover Menu */}
              {isMenuOpen && (
                <div
                  ref={menuRef}
                  role="menu"
                  aria-orientation="vertical"
                  aria-label="Attachment options"
                  onKeyDown={handleMenuKeyDown}
                  className="absolute bottom-full left-0 mb-2 w-48 rounded-2xl border border-gray-200 dark:border-gray-700/80 bg-white dark:bg-gray-900 shadow-xl py-1.5 z-40 animate-in fade-in zoom-in-95 duration-100"
                >
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setIsMenuOpen(false);
                      cameraInputRef.current?.click();
                    }}
                    className="flex w-full items-center gap-2.5 px-3.5 py-2.5 text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors focus:bg-gray-100 dark:focus:bg-gray-800 focus:outline-none min-h-[44px]"
                  >
                    <Camera size={16} className="text-gray-500" aria-hidden="true" />
                    <span>Take Photo</span>
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setIsMenuOpen(false);
                      imageInputRef.current?.click();
                    }}
                    className="flex w-full items-center gap-2.5 px-3.5 py-2.5 text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors focus:bg-gray-100 dark:focus:bg-gray-800 focus:outline-none min-h-[44px]"
                  >
                    <ImageIcon size={16} className="text-gray-500" aria-hidden="true" />
                    <span>Upload Image</span>
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setIsMenuOpen(false);
                      fileInputRef.current?.click();
                    }}
                    className="flex w-full items-center gap-2.5 px-3.5 py-2.5 text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors focus:bg-gray-100 dark:focus:bg-gray-800 focus:outline-none min-h-[44px]"
                  >
                    <Paperclip size={16} className="text-gray-500" aria-hidden="true" />
                    <span>Upload File</span>
                  </button>
                </div>
              )}
            </div>

            <button 
              type="button"
              aria-label="Search"
              className="flex h-10 sm:h-9 items-center gap-1.5 rounded-full border border-gray-200 dark:border-gray-700/60 px-3.5 sm:px-3 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors text-xs font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-theme-composer-focus"
            >
              <Search size={14} aria-hidden="true" />
              Search
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button 
              type="button"
              aria-label="Voice input"
              className="flex h-10 w-10 sm:h-8 sm:w-8 items-center justify-center rounded-full text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-theme-composer-focus"
            >
              <Mic size={18} aria-hidden="true" />
            </button>
            {/* Send Button */}
            <button
              type="button"
              onClick={handleSubmit}
              disabled={isSendDisabled}
              aria-label="Send message"
              className={cn(
                "flex h-10 w-10 sm:h-9 sm:w-9 items-center justify-center rounded-full text-white transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-theme-composer-focus focus-visible:ring-offset-2 dark:focus-visible:ring-offset-gray-900",
                !isSendDisabled
                  ? "bg-theme-accent hover:opacity-90 shadow-sm"
                  : "bg-gray-200 dark:bg-gray-700 text-gray-400 cursor-not-allowed"
              )}
            >
              <ArrowUp size={18} strokeWidth={2.5} aria-hidden="true" />
            </button>
          </div>
        </div>
      </div>
      <div className="mt-3 text-center text-xs text-gray-400 dark:text-gray-500">
        Before You Click can make mistakes. Check important info.
      </div>
    </div>
  );
}
