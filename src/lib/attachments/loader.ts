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

const IMAGE_EXTENSIONS = new Set(['.jpg', '.jpeg', '.png', '.webp']);
const IMAGE_MIMES = new Set(['image/jpeg', 'image/png', 'image/webp']);

/**
 * Checks whether an attachment is an image (JPEG, PNG, WEBP).
 */
export function isImageAttachment(att: Attachment): boolean {
  if (!att) return false;
  if (att.type === 'image') return true;
  const ext = getFileExtension(att.original_name);
  if (IMAGE_EXTENSIONS.has(ext)) return true;
  const mime = (att.mime_type || '').toLowerCase().split(';')[0].trim();
  if (IMAGE_MIMES.has(mime)) return true;
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
  cloudName?: string,
  preferredResourceType?: 'raw' | 'image'
): { publicId: string; fetchUrl: string; resourceType: 'raw' | 'image' } {
  const activeCloudName = cloudName || process.env.NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME;
  if (!activeCloudName) {
    throw new Error('Cloudinary config missing');
  }

  let publicId = att.public_id;
  let detectedResourceType: 'raw' | 'image' | undefined;

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
    const isValidResourceType = segments[1] === 'raw' || segments[1] === 'image';
    if (segments[0] !== activeCloudName || !isValidResourceType || segments[2] !== 'upload') {
      throw new Error('Invalid path');
    }

    detectedResourceType = segments[1] as 'raw' | 'image';

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

  const resourceType: 'raw' | 'image' =
    preferredResourceType ||
    detectedResourceType ||
    (isImageAttachment(att) ? 'image' : 'raw');

  const fetchUrl = `https://res.cloudinary.com/${activeCloudName}/${resourceType}/upload/v1/${publicId}`;
  return { publicId, fetchUrl, resourceType };
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

export const MAX_IMAGE_DOWNLOAD_BYTES = 5 * 1024 * 1024; // 5 MB

export interface LoadedImageContent {
  buffer: Buffer;
  rawSizeBytes: number;
  filename: string;
  mimeType: string;
  format: 'jpeg' | 'png' | 'webp';
  width?: number;
  height?: number;
  publicId: string;
  url: string;
  magicBytesValid: boolean;
}

/**
 * Detects image format from raw magic bytes (JPEG, PNG, WEBP).
 * Zero native dependencies, lightweight pure JS header inspection.
 */
export function detectImageFormat(buffer: Buffer): 'jpeg' | 'png' | 'webp' | null {
  if (!buffer || buffer.length < 12) return null;

  // JPEG: FF D8 FF
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
    return 'jpeg';
  }

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47 &&
    buffer[4] === 0x0D && buffer[5] === 0x0A && buffer[6] === 0x1A && buffer[7] === 0x0A
  ) {
    return 'png';
  }

  // WEBP: RIFF (bytes 0-3) + WEBP (bytes 8-11)
  if (
    buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46 &&
    buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50
  ) {
    return 'webp';
  }

  return null;
}

function extractPngDimensions(buffer: Buffer): { width: number; height: number } | undefined {
  if (buffer.length >= 24) {
    return {
      width: buffer.readUInt32BE(16),
      height: buffer.readUInt32BE(20),
    };
  }
  return undefined;
}

function extractJpegDimensions(buffer: Buffer): { width: number; height: number } | undefined {
  let offset = 2;
  while (offset < buffer.length - 8) {
    if (buffer[offset] !== 0xFF) break;
    const marker = buffer[offset + 1];
    // SOF0 (baseline), SOF1 (extended sequential), SOF2 (progressive)
    if (marker === 0xC0 || marker === 0xC1 || marker === 0xC2) {
      if (offset + 9 <= buffer.length) {
        return {
          height: buffer.readUInt16BE(offset + 5),
          width: buffer.readUInt16BE(offset + 7),
        };
      }
      break;
    }
    // Marker segment length
    if (offset + 3 >= buffer.length) break;
    const length = buffer.readUInt16BE(offset + 2);
    offset += 2 + length;
  }
  return undefined;
}

function extractWebpDimensions(buffer: Buffer): { width: number; height: number } | undefined {
  if (buffer.length < 30) return undefined;
  const chunkHeader = buffer.subarray(12, 16).toString('ascii');
  if (chunkHeader === 'VP8 ') {
    // Lossy VP8: keyframe header check
    if (buffer.length >= 30 && buffer[23] === 0x9d && buffer[24] === 0x01 && buffer[25] === 0x2a) {
      return {
        width: buffer.readUInt16LE(26) & 0x3fff,
        height: buffer.readUInt16LE(28) & 0x3fff,
      };
    }
  } else if (chunkHeader === 'VP8L') {
    // Lossless VP8L: signature byte at offset 20 is 0x2f
    if (buffer[20] === 0x2f) {
      const b1 = buffer[21];
      const b2 = buffer[22];
      const b3 = buffer[23];
      const b4 = buffer[24];
      const width = 1 + (((b2 & 0x3f) << 8) | b1);
      const height = 1 + (((b4 & 0x0f) << 10) | (b3 << 2) | ((b2 & 0xc0) >> 6));
      return { width, height };
    }
  } else if (chunkHeader === 'VP8X') {
    // Extended VP8X
    const width = 1 + buffer.readUIntLE(24, 3);
    const height = 1 + buffer.readUIntLE(27, 3);
    return { width, height };
  }
  return undefined;
}

/**
 * Safely fetches and inspects image content from Cloudinary under strict security rules:
 * - 5MB bounded download limit
 * - Strict SSRF checks (protocol, host, cloud name, namespace)
 * - Pure-JS magic-byte format detection (JPEG, PNG, WEBP)
 * - MIME spoofing detection
 * - Header dimension extraction
 */
export async function loadImageContent(
  att: Attachment,
  options?: { signal?: AbortSignal; cloudName?: string }
): Promise<LoadedImageContent> {
  if (!att) {
    throw new Error('No attachment provided');
  }

  // Pre-loaded memory cache check on attachment object
  const cached = (att as unknown as Record<string, unknown>).loadedImage as LoadedImageContent | undefined;
  if (cached && Buffer.isBuffer(cached.buffer)) {
    return cached;
  }

  const filename = sanitizeFilename(att.original_name || 'image.jpg');
  if (!isImageAttachment(att)) {
    throw new Error(`Unsupported image format (${filename})`);
  }

  const { publicId, fetchUrl } = resolveSafeCloudinaryUrl(att, options?.cloudName, 'image');

  const res = await fetch(fetchUrl, { signal: options?.signal });
  if (!res.ok) {
    throw new Error(`Fetch failed: ${res.status}`);
  }

  // Validate content-length header if provided
  const contentLength = res.headers.get('content-length');
  if (contentLength && parseInt(contentLength, 10) > MAX_IMAGE_DOWNLOAD_BYTES) {
    throw new Error('Image exceeds 5MB limit');
  }

  // Validate content-type header
  const rawContentType = res.headers.get('content-type') || '';
  const headerMime = rawContentType.split(';')[0].trim().toLowerCase();
  if (headerMime && !IMAGE_MIMES.has(headerMime) && headerMime !== 'application/octet-stream') {
    throw new Error(`Content-type mismatch: expected image but received "${headerMime}"`);
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
        if (downloaded > MAX_IMAGE_DOWNLOAD_BYTES) {
          reader.cancel().catch(() => {});
          throw new Error('Image exceeds 5MB limit during download');
        }
        chunks.push(value);
      }
    }
  } catch (readErr) {
    reader.cancel().catch(() => {});
    throw readErr;
  }

  if (downloaded === 0) {
    throw new Error('Downloaded image file is empty');
  }

  const totalArray = new Uint8Array(downloaded);
  let offset = 0;
  for (const chunk of chunks) {
    totalArray.set(chunk, offset);
    offset += chunk.length;
  }
  const buffer = Buffer.from(totalArray);

  // Inspect magic bytes
  const format = detectImageFormat(buffer);
  if (!format) {
    throw new Error('Corrupt or unsupported image format (invalid magic bytes)');
  }

  // Verify header content-type vs detected magic bytes
  const expectedMime = `image/${format === 'jpeg' ? 'jpeg' : format}`;
  if (headerMime && headerMime !== 'application/octet-stream') {
    const normHeaderMime = headerMime === 'image/jpg' ? 'image/jpeg' : headerMime;
    if (normHeaderMime !== expectedMime) {
      throw new Error(`MIME spoofing detected: header indicates "${headerMime}" but magic bytes indicate "${expectedMime}"`);
    }
  }

  // Extract dimensions
  let dimensions: { width: number; height: number } | undefined;
  if (format === 'png') {
    dimensions = extractPngDimensions(buffer);
  } else if (format === 'jpeg') {
    dimensions = extractJpegDimensions(buffer);
  } else if (format === 'webp') {
    dimensions = extractWebpDimensions(buffer);
  }

  const loadedResult: LoadedImageContent = {
    buffer,
    rawSizeBytes: downloaded,
    filename,
    mimeType: expectedMime,
    format,
    width: dimensions?.width,
    height: dimensions?.height,
    publicId,
    url: att.url || fetchUrl,
    magicBytesValid: true,
  };

  // Cache on attachment object for single request lifecycle
  (att as unknown as Record<string, unknown>).loadedImage = loadedResult;

  return loadedResult;
}
