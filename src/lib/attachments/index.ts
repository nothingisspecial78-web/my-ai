import { AttachmentType } from '@/lib/ai/types';

export const MAX_ATTACHMENTS_PER_MESSAGE = 3;
export const MAX_EXTRACTED_CONTEXT_CHARS = 50_000;

export const ATTACHMENT_LIMITS = {
  image: {
    maxSize: 5 * 1024 * 1024, // 5 MB
    mimeTypes: ['image/jpeg', 'image/png', 'image/webp'] as const,
    extensions: ['.jpg', '.jpeg', '.png', '.webp'] as const,
    label: 'Image (JPEG, PNG, WEBP)',
  },
  pdf: {
    maxSize: 10 * 1024 * 1024, // 10 MB
    mimeTypes: ['application/pdf'] as const,
    extensions: ['.pdf'] as const,
    label: 'PDF Document',
  },
  text: {
    maxSize: 2 * 1024 * 1024, // 2 MB
    mimeTypes: ['text/plain'] as const,
    extensions: ['.txt'] as const,
    label: 'Text Document',
  },
  html: {
    maxSize: 2 * 1024 * 1024, // 2 MB
    mimeTypes: ['text/html'] as const,
    extensions: ['.html', '.htm'] as const,
    label: 'HTML Document',
  },
} as const;

export const ALL_ALLOWED_MIME_TYPES = [
  ...ATTACHMENT_LIMITS.image.mimeTypes,
  ...ATTACHMENT_LIMITS.pdf.mimeTypes,
  ...ATTACHMENT_LIMITS.text.mimeTypes,
  ...ATTACHMENT_LIMITS.html.mimeTypes,
] as const;

export const ALL_ALLOWED_EXTENSIONS = [
  ...ATTACHMENT_LIMITS.image.extensions,
  ...ATTACHMENT_LIMITS.pdf.extensions,
  ...ATTACHMENT_LIMITS.text.extensions,
  ...ATTACHMENT_LIMITS.html.extensions,
] as const;

/**
 * Sanitizes a filename to prevent path traversal, null-byte injection,
 * control characters, and excessively long names.
 */
export function sanitizeFilename(rawName: string): string {
  if (!rawName || typeof rawName !== 'string') {
    return 'attachment';
  }

  // Remove null bytes and control characters (ASCII 0-31, 127)
  let clean = rawName.replace(/[\x00-\x1F\x7F]/g, '');

  // Strip path traversal indicators and directory separators
  clean = clean.replace(/(\.\.[\/\\])+/g, '');
  clean = clean.replace(/[\/\\]/g, '_');

  // Strip leading dots to avoid hidden files or extension confusion
  clean = clean.replace(/^\.+/, '');

  // Replace multiple underscores/spaces
  clean = clean.replace(/_{2,}/g, '_').trim();

  // If filename has an extension, preserve it cleanly
  const lastDot = clean.lastIndexOf('.');
  let baseName = clean;
  let ext = '';

  if (lastDot > 0 && lastDot < clean.length - 1) {
    baseName = clean.substring(0, lastDot);
    ext = clean.substring(lastDot);
  }

  // Sanitize characters in base and ext
  baseName = baseName.replace(/[^a-zA-Z0-9_\-\. ]/g, '_');
  baseName = baseName.replace(/_{2,}/g, '_').replace(/^_+|_+$/g, '').trim();
  ext = ext.replace(/[^a-zA-Z0-9_\-\.]/g, '').toLowerCase();

  if (!baseName) {
    baseName = 'attachment';
  }

  // Limit length to max 100 characters including extension
  const maxBaseLength = Math.max(1, 100 - ext.length);
  if (baseName.length > maxBaseLength) {
    baseName = baseName.substring(0, maxBaseLength);
  }

  return `${baseName}${ext}`;
}

/**
 * Classifies an attachment into a valid AttachmentType based on MIME type and filename.
 */
export function classifyAttachment(
  mimeType: string,
  filename?: string
): { type: AttachmentType | null; error?: string } {
  const normMime = (mimeType || '').trim().toLowerCase().split(';')[0];
  const normExt = filename
    ? filename.substring(filename.lastIndexOf('.')).toLowerCase()
    : '';

  // 1. Image
  if (
    (ATTACHMENT_LIMITS.image.mimeTypes as readonly string[]).includes(normMime) ||
    (normExt && (ATTACHMENT_LIMITS.image.extensions as readonly string[]).includes(normExt))
  ) {
    return { type: 'image' };
  }

  // 2. PDF
  if (
    (ATTACHMENT_LIMITS.pdf.mimeTypes as readonly string[]).includes(normMime) ||
    normExt === '.pdf'
  ) {
    return { type: 'pdf' };
  }

  // 3. Text
  if (
    (ATTACHMENT_LIMITS.text.mimeTypes as readonly string[]).includes(normMime) ||
    normExt === '.txt'
  ) {
    return { type: 'text' };
  }

  // 4. HTML
  if (
    (ATTACHMENT_LIMITS.html.mimeTypes as readonly string[]).includes(normMime) ||
    normExt === '.html' ||
    normExt === '.htm'
  ) {
    return { type: 'html' };
  }

  return {
    type: null,
    error: `Unsupported file type (${normMime || normExt || 'unknown'}). Supported formats: JPEG, PNG, WEBP, PDF, TXT, HTML.`,
  };
}

export interface AttachmentValidationResult {
  valid: boolean;
  type?: AttachmentType;
  error?: string;
  sanitizedFilename?: string;
}

/**
 * Authoritative attachment validator for both client and server sides.
 */
export function validateAttachment(file: {
  name: string;
  size: number;
  type?: string;
}): AttachmentValidationResult {
  const sanitizedFilename = sanitizeFilename(file.name);

  // Check extension
  const dotIndex = sanitizedFilename.lastIndexOf('.');
  const ext = dotIndex !== -1 ? sanitizedFilename.substring(dotIndex).toLowerCase() : '';

  if (!ext || !(ALL_ALLOWED_EXTENSIONS as readonly string[]).includes(ext)) {
    return {
      valid: false,
      error: `Unsupported file extension (${ext || 'none'}). Supported extensions: ${ALL_ALLOWED_EXTENSIONS.join(', ')}`,
      sanitizedFilename,
    };
  }

  // Classify
  const classification = classifyAttachment(file.type || '', sanitizedFilename);
  if (!classification.type) {
    return {
      valid: false,
      error: classification.error || 'Unsupported file type.',
      sanitizedFilename,
    };
  }

  const type = classification.type;

  // Size limit check per type
  let maxSize = 0;
  if (type === 'image') maxSize = ATTACHMENT_LIMITS.image.maxSize;
  else if (type === 'pdf') maxSize = ATTACHMENT_LIMITS.pdf.maxSize;
  else if (type === 'text') maxSize = ATTACHMENT_LIMITS.text.maxSize;
  else if (type === 'html') maxSize = ATTACHMENT_LIMITS.html.maxSize;

  if (file.size <= 0) {
    return {
      valid: false,
      error: 'File cannot be empty.',
      sanitizedFilename,
      type,
    };
  }

  if (file.size > maxSize) {
    const mbLimit = Math.round(maxSize / (1024 * 1024));
    return {
      valid: false,
      error: `File exceeds maximum size of ${mbLimit}MB for ${type.toUpperCase()} files.`,
      sanitizedFilename,
      type,
    };
  }

  return {
    valid: true,
    type,
    sanitizedFilename,
  };
}

/**
 * Formats bytes into a human-readable string (e.g., "142 KB", "2.1 MB").
 */
export function formatFileSize(bytes?: number): string {
  if (typeof bytes !== 'number' || isNaN(bytes) || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1).replace(/\.0$/, '')} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1).replace(/\.0$/, '')} MB`;
}

export * from './loader';

