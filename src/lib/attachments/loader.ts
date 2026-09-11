import { Attachment } from '@/lib/ai/types';
import { MAX_EXTRACTED_CONTEXT_CHARS, sanitizeFilename } from './index';
import { sanitizeHtmlToText, truncateExtractedText } from './extract';

export const MAX_DOCUMENT_DOWNLOAD_BYTES = 2 * 1024 * 1024; // 2 MB

export interface LoadedAttachmentContent {
  content: string;
  filename: string;
  mimeType: string;
  type: 'code' | 'document' | 'text' | 'html';
  rawSizeBytes: number;
  publicId: string;
  url: string;
}

const CODE_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs',
  '.ts', '.tsx', '.mts', '.cts',
  '.py',
  '.php',
  '.rb',
  '.go',
  '.rs',
  '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp',
  '.sql',
  '.sh', '.bash',
  '.json',
]);

const TEXT_EXTENSIONS = new Set([
  '.txt', '.text', '.md', '.markdown', '.log', '.csv',
]);

const HTML_EXTENSIONS = new Set([
  '.html', '.htm',
]);

/**
 * Checks whether an attachment is an analyzable text/code/markup file.
 * Specifically excludes images and binary files.
 */
export function isTextAnalyzableAttachment(att: Attachment): boolean {
  if (!att) return false;

  // Never analyze images as code or text
  if (att.type === 'image') return false;
  if (att.mime_type && att.mime_type.startsWith('image/')) return false;

  // PDFs are binary documents handled separately
  if (att.type === 'pdf') return false;
  if (att.original_name?.toLowerCase().endsWith('.pdf')) return false;
  if (att.mime_type === 'application/pdf') return false;

  const ext = getFileExtension(att.original_name);
  if (ext) {
    if (CODE_EXTENSIONS.has(ext) || TEXT_EXTENSIONS.has(ext) || HTML_EXTENSIONS.has(ext)) {
      return true;
    }
  }

  const mime = (att.mime_type || '').toLowerCase().split(';')[0].trim();
  if (mime) {
    if (
      mime.startsWith('text/') ||
      mime === 'application/javascript' ||
      mime === 'application/typescript' ||
      mime === 'application/json' ||
      mime === 'application/sql' ||
      mime === 'application/x-sh' ||
      mime === 'application/x-python-code'
    ) {
      return true;
    }
  }

  return att.type === 'text' || att.type === 'html';
}

/**
 * Checks whether an attachment is a PDF document.
 */
export function isPdfAttachment(att: Attachment): boolean {
  if (!att) return false;
  if (att.type === 'pdf') return true;
  if (att.original_name?.toLowerCase().endsWith('.pdf')) return true;
  if (att.mime_type === 'application/pdf') return true;
  return false;
}

/**
 * Extracts and normalizes the lowercase extension including leading dot.
 */
function getFileExtension(filename?: string): string {
  if (!filename) return '';
  const lastDot = filename.lastIndexOf('.');
  if (lastDot === -1) return '';
  return filename.substring(lastDot).toLowerCase();
}

/**
 * Determines the normalized domain input classification for the loaded attachment.
 */
export function classifyLoadedAttachment(
  filename: string,
  mimeType: string
): 'code' | 'document' | 'text' | 'html' {
  const ext = getFileExtension(filename);
  const normMime = (mimeType || '').toLowerCase().split(';')[0].trim();

  if (HTML_EXTENSIONS.has(ext) || normMime === 'text/html') {
    return 'html';
  }

  if (
    CODE_EXTENSIONS.has(ext) ||
    normMime === 'application/javascript' ||
    normMime === 'text/javascript' ||
    normMime === 'application/typescript' ||
    normMime === 'text/typescript' ||
    normMime === 'text/x-python' ||
    normMime === 'application/x-sh' ||
    normMime === 'application/sql' ||
    normMime === 'text/x-sql'
  ) {
    return 'code';
  }

  if (TEXT_EXTENSIONS.has(ext) || normMime === 'text/plain') {
    return 'text';
  }

  return 'document';
}

/**
 * Safely resolves and validates a Cloudinary publicId and fetch URL from an attachment.
 * Guarantees strict SSRF protection:
 * - HTTPS protocol
 * - Exact hostname res.cloudinary.com
 * - Configured Cloudinary cloud name
 * - my_ai_uploads upload namespace
 * - Path traversal (..) and consecutive slashes (//) rejection
 */
export function resolveSafeCloudinaryUrl(
  att: Attachment,
  cloudName?: string
): { publicId: string; fetchUrl: string } {
  const activeCloudName = cloudName || process.env.NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME;
  if (!activeCloudName) {
    throw new Error('Cloudinary config missing');
  }

  let publicId = att.public_id;

  if (!publicId) {
    if (!att.url) {
      throw new Error('Attachment URL missing');
    }

    let urlObj: URL;
    try {
      urlObj = new URL(att.url);
    } catch {
      throw new Error('Invalid attachment URL syntax');
    }

    if (urlObj.protocol !== 'https:' || urlObj.hostname !== 'res.cloudinary.com') {
      throw new Error('Invalid host');
    }

    const segments = urlObj.pathname.split('/').filter(Boolean);
    if (segments[0] !== activeCloudName || segments[1] !== 'raw' || segments[2] !== 'upload') {
      throw new Error('Invalid path');
    }

    const uploadIdx = segments.indexOf('upload');
    const remainder = segments.slice(uploadIdx + 1);
    if (remainder[0] && remainder[0].startsWith('v') && /\d/.test(remainder[0])) {
      remainder.shift();
    }
    publicId = remainder.join('/');
  }

  if (!publicId || !publicId.startsWith('my_ai_uploads/')) {
    throw new Error('Invalid upload namespace');
  }

  if (!/^my_ai_uploads\/[a-zA-Z0-9_\-\.\/]+$/.test(publicId) || publicId.includes('..') || publicId.includes('//')) {
    throw new Error('Invalid characters in public_id');
  }

  const fetchUrl = `https://res.cloudinary.com/${activeCloudName}/raw/upload/v1/${publicId}`;
  return { publicId, fetchUrl };
}

/**
 * Safely fetches and extracts text content from a text/code/markup attachment.
 * Enforces:
 * - 2MB download limit
 * - 50,000 character extraction limit
 * - Strict SSRF checks
 * - Safe HTML sanitization
 * - Linear, non-executable passive string decoding
 */
export async function loadAttachmentContent(
  att: Attachment,
  options?: { signal?: AbortSignal; cloudName?: string }
): Promise<LoadedAttachmentContent> {
  if (!att) {
    throw new Error('No attachment provided');
  }

  // Pre-extracted content cache reuse (optimization from Step 5)
  const cachedContent = (att as unknown as Record<string, unknown>).extractedContent;
  const filename = sanitizeFilename(att.original_name || 'attachment.txt');
  const mimeType = (att.mime_type || 'text/plain').toLowerCase();
  const classifiedType = classifyLoadedAttachment(filename, mimeType);

  if (typeof cachedContent === 'string' && cachedContent.length > 0) {
    return {
      content: cachedContent,
      filename,
      mimeType,
      type: classifiedType,
      rawSizeBytes: att.size || Buffer.byteLength(cachedContent, 'utf-8'),
      publicId: att.public_id || '',
      url: att.url || '',
    };
  }

  const { publicId, fetchUrl } = resolveSafeCloudinaryUrl(att, options?.cloudName);

  const res = await fetch(fetchUrl, { signal: options?.signal });
  if (!res.ok) {
    throw new Error(`Fetch failed: ${res.status}`);
  }

  const contentLength = res.headers.get('content-length');
  if (contentLength && parseInt(contentLength, 10) > MAX_DOCUMENT_DOWNLOAD_BYTES) {
    throw new Error('Document exceeds 2MB limit');
  }

  if (!res.body) {
    throw new Error('No response body');
  }

  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let downloaded = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        downloaded += value.length;
        if (downloaded > MAX_DOCUMENT_DOWNLOAD_BYTES) {
          reader.cancel().catch(() => {});
          throw new Error('Document exceeds 2MB limit during download');
        }
        chunks.push(value);
      }
    }
  } catch (readErr) {
    reader.cancel().catch(() => {});
    throw readErr;
  }

  const totalArray = new Uint8Array(downloaded);
  let offset = 0;
  for (const chunk of chunks) {
    totalArray.set(chunk, offset);
    offset += chunk.length;
  }

  const rawContent = Buffer.from(totalArray).toString('utf-8');

  let sanitizedContent: string;
  if (classifiedType === 'html') {
    sanitizedContent = sanitizeHtmlToText(rawContent);
  } else {
    sanitizedContent = truncateExtractedText(rawContent, MAX_EXTRACTED_CONTEXT_CHARS);
  }

  // Cache on attachment object in-memory to eliminate duplicate downloads
  (att as unknown as Record<string, unknown>).extractedContent = sanitizedContent;

  return {
    content: sanitizedContent,
    filename,
    mimeType,
    type: classifiedType,
    rawSizeBytes: downloaded,
    publicId,
    url: att.url || fetchUrl,
  };
}
