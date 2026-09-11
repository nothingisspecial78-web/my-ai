import { AIProvider, Message, AIStreamEvent } from './types';
import { GoogleGenAI } from '@google/genai';
import { SYSTEM_INSTRUCTION } from './system-prompt';
import { getEnv } from '@/lib/env';
import { sanitizeFilename } from '@/lib/attachments';
import {
  sanitizeHtmlToText,
  truncateExtractedText,
  wrapDocumentContext,
  getEmptyPromptFallback,
} from '@/lib/attachments/extract';

function sanitizePromptLeakage(text: string): string {
  return text
    .replace(/--- System Deterministic Context ---\s*/gi, '')
    .replace(/===\s*SAFETY & SECURITY DETERMINISTIC ANALYSIS\s*===\s*/gi, '')
    .replace(/\[Safety Analysis Guidance Context\]\s*/gi, '')
    .replace(/\[Instructions for Assistant\]\s*/gi, '');
}

interface CachedImageData {
  mimeType: string;
  data: string;
}

const imageMemoryCache = new Map<string, CachedImageData>();
const MAX_IMAGE_CACHE = 50;

function getCachedImage(key: string): CachedImageData | undefined {
  if (process.env.NODE_ENV === 'test') return undefined;
  return imageMemoryCache.get(key);
}

function setCachedImage(key: string, data: CachedImageData): void {
  if (process.env.NODE_ENV === 'test') return;
  if (imageMemoryCache.size >= MAX_IMAGE_CACHE) {
    const oldestKey = imageMemoryCache.keys().next().value;
    if (oldestKey) imageMemoryCache.delete(oldestKey);
  }
  imageMemoryCache.set(key, data);
}

export class GeminiProvider implements AIProvider {
  name = 'gemini';
  private client: GoogleGenAI;
  private model: string;

  constructor() {
    const env = getEnv();
    if (!env.hasGeminiKey) {
      throw new Error('GEMINI_API_KEY is missing');
    }
    // We can safely assert the key exists because env.hasGeminiKey is true
    this.client = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY as string });
    this.model = env.aiModel;
  }

  async *generateStream(
    messages: Message[],
    options?: { userId?: string; conversationId?: string; signal?: AbortSignal; systemInstruction?: string }
  ): AsyncGenerator<AIStreamEvent, void, unknown> {
    
    // Start stream
    yield { type: 'start' };

    try {
      // Map messages to Gemini Content structure, resolving images and documents securely
      const processedMessages = [];
      let imageCount = 0;
      let docCount = 0;
      const maxImages = 4;
      const maxDocs = 4;
      const cloudName = process.env.NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME;

      for (let i = messages.length - 1; i >= 0; i--) {
        const msg = messages[i];
        const parts: Array<{ text?: string; inlineData?: { mimeType: string; data: string } }> = [];
        let allImagesFailed = false;
        let hasTriedImages = false;
        let allDocsFailed = false;
        let hasTriedDocuments = false;

        if (msg.metadata?.attachments && Array.isArray(msg.metadata.attachments)) {
          let imageSuccessCount = 0;
          let imageFailCount = 0;
          let docSuccessCount = 0;
          let docFailCount = 0;

          for (const att of msg.metadata.attachments) {
            const attType = att.type || 'image';

            if (attType === 'image' && att.url) {
              hasTriedImages = true;
              if (imageCount >= maxImages) {
                parts.push({ text: '[Attached image omitted due to context limits.]' });
                continue;
              }

              try {
                let publicId = att.public_id;
                if (!publicId) {
                  const urlObj = new URL(att.url);
                  if (urlObj.protocol !== 'https:' || urlObj.hostname !== 'res.cloudinary.com') {
                    throw new Error('Invalid host');
                  }
                  const segments = urlObj.pathname.split('/').filter(Boolean);
                  if (segments[0] !== cloudName || segments[1] !== 'image' || segments[2] !== 'upload') {
                    throw new Error('Invalid path');
                  }
                  const uploadIdx = segments.indexOf('upload');
                  const remainder = segments.slice(uploadIdx + 1);
                  if (remainder[0] && remainder[0].startsWith('v') && /\d/.test(remainder[0])) {
                    remainder.shift();
                  }
                  publicId = remainder.join('/');
                }

                if (!cloudName) throw new Error('Cloudinary config missing');
                
                // Structural validation: must belong to our upload namespace
                if (!publicId.startsWith('my_ai_uploads/')) {
                  throw new Error('Invalid upload namespace');
                }
                
                // Prevent path traversal and transformation injection
                if (!/^my_ai_uploads\/[a-zA-Z0-9_\-\.\/]+$/.test(publicId) || publicId.includes('..') || publicId.includes('//')) {
                  throw new Error('Invalid characters in public_id');
                }

                // Check cache first for faster response on multi-turn conversations
                const cached = getCachedImage(publicId);
                if (cached) {
                  parts.push({
                    inlineData: {
                      mimeType: cached.mimeType,
                      data: cached.data,
                    },
                  });
                  imageCount++;
                  imageSuccessCount++;
                  continue;
                }

                const fetchUrl = `https://res.cloudinary.com/${cloudName}/image/upload/w_800,c_limit,q_auto/v1/${publicId}`;
                const res = await fetch(fetchUrl, { signal: options?.signal });
                if (!res.ok) throw new Error(`Fetch failed: ${res.status}`);

                let contentType = res.headers.get('content-type') || '';
                contentType = contentType.split(';')[0].trim().toLowerCase();
                if (!['image/jpeg', 'image/png', 'image/webp'].includes(contentType)) {
                  throw new Error(`Unsupported MIME type: ${contentType}`);
                }

                const contentLength = res.headers.get('content-length');
                const MAX_SIZE = 5 * 1024 * 1024; // 5MB
                if (contentLength && parseInt(contentLength, 10) > MAX_SIZE) {
                  throw new Error('Image exceeds 5MB limit');
                }

                if (!res.body) throw new Error('No response body');

                const reader = res.body.getReader();
                const chunks = [];
                let downloaded = 0;

                while (true) {
                  const { done, value } = await reader.read();
                  if (done) break;
                  if (value) {
                    downloaded += value.length;
                    if (downloaded > MAX_SIZE) {
                      reader.cancel().catch(() => {});
                      throw new Error('Image exceeds 5MB limit during download');
                    }
                    chunks.push(value);
                  }
                }

                const totalArray = new Uint8Array(downloaded);
                let offset = 0;
                for (const chunk of chunks) {
                  totalArray.set(chunk, offset);
                  offset += chunk.length;
                }
                const base64 = Buffer.from(totalArray).toString('base64');

                setCachedImage(publicId, {
                  mimeType: contentType,
                  data: base64,
                });

                parts.push({
                  inlineData: {
                    mimeType: contentType,
                    data: base64
                  }
                });

                imageCount++;
                imageSuccessCount++;
              } catch (err) {
                const isAbort = err instanceof Error && (err.name === 'AbortError' || err.message === 'AbortError');
                if (isAbort) throw err;

                console.error('Image fetch error:', err);
                parts.push({ text: '[One attached image could not be loaded.]' });
                imageFailCount++;
              }
            } else if (
              (attType === 'pdf' || (attType === 'file' && (att.mime_type === 'application/pdf' || att.original_name?.endsWith('.pdf')))) &&
              att.url
            ) {
              // PDF Document attachment
              hasTriedDocuments = true;
              if (docCount >= maxDocs) {
                parts.push({ text: '[Attached document omitted due to context limits.]' });
                continue;
              }

              try {
                let publicId = att.public_id;
                if (!publicId) {
                  const urlObj = new URL(att.url);
                  if (urlObj.protocol !== 'https:' || urlObj.hostname !== 'res.cloudinary.com') {
                    throw new Error('Invalid host');
                  }
                  const segments = urlObj.pathname.split('/').filter(Boolean);
                  if (segments[0] !== cloudName || segments[1] !== 'raw' || segments[2] !== 'upload') {
                    throw new Error('Invalid path');
                  }
                  const uploadIdx = segments.indexOf('upload');
                  const remainder = segments.slice(uploadIdx + 1);
                  if (remainder[0] && remainder[0].startsWith('v') && /\d/.test(remainder[0])) {
                    remainder.shift();
                  }
                  publicId = remainder.join('/');
                }

                if (!cloudName) throw new Error('Cloudinary config missing');

                if (!publicId.startsWith('my_ai_uploads/')) {
                  throw new Error('Invalid upload namespace');
                }

                if (!/^my_ai_uploads\/[a-zA-Z0-9_\-\.\/]+$/.test(publicId) || publicId.includes('..') || publicId.includes('//')) {
                  throw new Error('Invalid characters in public_id');
                }

                const cached = getCachedImage(publicId);
                if (cached) {
                  parts.push({
                    inlineData: {
                      mimeType: 'application/pdf',
                      data: cached.data,
                    },
                  });
                  docCount++;
                  docSuccessCount++;
                  continue;
                }

                const fetchUrl = `https://res.cloudinary.com/${cloudName}/raw/upload/v1/${publicId}`;
                const res = await fetch(fetchUrl, { signal: options?.signal });
                if (!res.ok) throw new Error(`Fetch failed: ${res.status}`);

                let contentType = res.headers.get('content-type') || '';
                contentType = contentType.split(';')[0].trim().toLowerCase();
                if (
                  contentType &&
                  contentType !== 'application/pdf' &&
                  contentType !== 'application/octet-stream' &&
                  !att.original_name?.endsWith('.pdf')
                ) {
                  throw new Error(`Unsupported MIME type: ${contentType}`);
                }

                const contentLength = res.headers.get('content-length');
                const MAX_SIZE = 10 * 1024 * 1024; // 10MB
                if (contentLength && parseInt(contentLength, 10) > MAX_SIZE) {
                  throw new Error('Document exceeds 10MB limit');
                }

                if (!res.body) throw new Error('No response body');

                const reader = res.body.getReader();
                const chunks = [];
                let downloaded = 0;

                while (true) {
                  const { done, value } = await reader.read();
                  if (done) break;
                  if (value) {
                    downloaded += value.length;
                    if (downloaded > MAX_SIZE) {
                      reader.cancel().catch(() => {});
                      throw new Error('Document exceeds 10MB limit during download');
                    }
                    chunks.push(value);
                  }
                }

                const totalArray = new Uint8Array(downloaded);
                let offset = 0;
                for (const chunk of chunks) {
                  totalArray.set(chunk, offset);
                  offset += chunk.length;
                }
                const base64 = Buffer.from(totalArray).toString('base64');

                setCachedImage(publicId, {
                  mimeType: 'application/pdf',
                  data: base64,
                });

                parts.push({
                  inlineData: {
                    mimeType: 'application/pdf',
                    data: base64,
                  },
                });

                docCount++;
                docSuccessCount++;
              } catch (err) {
                const isAbort = err instanceof Error && (err.name === 'AbortError' || err.message === 'AbortError');
                if (isAbort) throw err;

                console.error('PDF fetch error:', err);
                parts.push({ text: '[One attached document could not be loaded.]' });
                docFailCount++;
              }
            } else if (
              (attType === 'text' || attType === 'html' || (attType === 'file' && (att.original_name?.endsWith('.txt') || att.original_name?.endsWith('.html') || att.original_name?.endsWith('.htm')))) &&
              att.url
            ) {
              // TXT or HTML Document attachment
              hasTriedDocuments = true;
              if (docCount >= maxDocs) {
                parts.push({ text: '[Attached document omitted due to context limits.]' });
                continue;
              }

              try {
                let publicId = att.public_id;
                if (!publicId) {
                  const urlObj = new URL(att.url);
                  if (urlObj.protocol !== 'https:' || urlObj.hostname !== 'res.cloudinary.com') {
                    throw new Error('Invalid host');
                  }
                  const segments = urlObj.pathname.split('/').filter(Boolean);
                  if (segments[0] !== cloudName || segments[1] !== 'raw' || segments[2] !== 'upload') {
                    throw new Error('Invalid path');
                  }
                  const uploadIdx = segments.indexOf('upload');
                  const remainder = segments.slice(uploadIdx + 1);
                  if (remainder[0] && remainder[0].startsWith('v') && /\d/.test(remainder[0])) {
                    remainder.shift();
                  }
                  publicId = remainder.join('/');
                }

                if (!cloudName) throw new Error('Cloudinary config missing');

                if (!publicId.startsWith('my_ai_uploads/')) {
                  throw new Error('Invalid upload namespace');
                }

                if (!/^my_ai_uploads\/[a-zA-Z0-9_\-\.\/]+$/.test(publicId) || publicId.includes('..') || publicId.includes('//')) {
                  throw new Error('Invalid characters in public_id');
                }

                const fetchUrl = `https://res.cloudinary.com/${cloudName}/raw/upload/v1/${publicId}`;
                const res = await fetch(fetchUrl, { signal: options?.signal });
                if (!res.ok) throw new Error(`Fetch failed: ${res.status}`);

                const contentLength = res.headers.get('content-length');
                const MAX_SIZE = 2 * 1024 * 1024; // 2MB
                if (contentLength && parseInt(contentLength, 10) > MAX_SIZE) {
                  throw new Error('Document exceeds 2MB limit');
                }

                if (!res.body) throw new Error('No response body');

                const reader = res.body.getReader();
                const chunks = [];
                let downloaded = 0;

                while (true) {
                  const { done, value } = await reader.read();
                  if (done) break;
                  if (value) {
                    downloaded += value.length;
                    if (downloaded > MAX_SIZE) {
                      reader.cancel().catch(() => {});
                      throw new Error('Document exceeds 2MB limit during download');
                    }
                    chunks.push(value);
                  }
                }

                const totalArray = new Uint8Array(downloaded);
                let offset = 0;
                for (const chunk of chunks) {
                  totalArray.set(chunk, offset);
                  offset += chunk.length;
                }

                const rawContent = Buffer.from(totalArray).toString('utf-8');
                const isHtml = attType === 'html' || att.original_name?.endsWith('.html') || att.original_name?.endsWith('.htm');
                const docName = sanitizeFilename(att.original_name || (isHtml ? 'page.html' : 'document.txt'));

                if (isHtml) {
                  const sanitized = sanitizeHtmlToText(rawContent);
                  parts.push({ text: wrapDocumentContext(docName, 'HTML', sanitized) });
                } else {
                  const truncated = truncateExtractedText(rawContent);
                  parts.push({ text: wrapDocumentContext(docName, 'Text', truncated) });
                }

                docCount++;
                docSuccessCount++;
              } catch (err) {
                const isAbort = err instanceof Error && (err.name === 'AbortError' || err.message === 'AbortError');
                if (isAbort) throw err;

                console.error('Document fetch error:', err);
                parts.push({ text: '[One attached document could not be loaded.]' });
                docFailCount++;
              }
            }
          }

          if (hasTriedImages && imageSuccessCount === 0 && imageFailCount > 0) {
            allImagesFailed = true;
          }
          if (hasTriedDocuments && docSuccessCount === 0 && docFailCount > 0) {
            allDocsFailed = true;
          }
        }

        if (msg.content?.trim()) {
          parts.push({ text: msg.content });
        } else if (parts.length > 0 && !allImagesFailed && !allDocsFailed) {
          const firstAtt = msg.metadata?.attachments?.[0];
          const firstType = firstAtt?.type || 'image';
          const firstName = firstAtt?.original_name || 'attachment';

          if (firstType === 'image') {
            parts.push({ text: '[Image attached. Please analyze or describe this image.]' });
          } else {
            parts.push({ text: getEmptyPromptFallback(firstType, firstName) });
          }
        }

        if (i === messages.length - 1 && !msg.content?.trim()) {
          if (hasTriedImages && allImagesFailed && !hasTriedDocuments) {
            throw new Error('All attached images failed to load. Please try again.');
          }
          if (hasTriedDocuments && allDocsFailed && !hasTriedImages) {
            throw new Error('All attached documents failed to load. Please try again.');
          }
          if ((hasTriedImages || hasTriedDocuments) && (allImagesFailed || allDocsFailed)) {
            throw new Error('All attached files failed to load. Please try again.');
          }
        }

        if (parts.length > 0) {
          processedMessages.unshift({
            role: msg.role === 'user' ? 'user' : 'model',
            parts
          });
        }
      }

      const contents = processedMessages;
      let responseStream;
      let retries = 0;
      const maxRetries = 3;

      const thinkingBudget = process.env.GEMINI_THINKING_BUDGET !== undefined
        ? parseInt(process.env.GEMINI_THINKING_BUDGET, 10)
        : 0;

      const modelConfig: Record<string, unknown> = {
        systemInstruction: options?.systemInstruction || SYSTEM_INSTRUCTION,
      };

      if (!isNaN(thinkingBudget)) {
        modelConfig.thinkingConfig = { thinkingBudget };
      }
      
      while (true) {
        if (options?.signal?.aborted) {
          throw new Error('AbortError');
        }
        try {
          responseStream = await this.client.models.generateContentStream({
            model: this.model,
            contents,
            config: modelConfig,
          });
          break;
        } catch (error: unknown) {
          const err = error as Error & { status?: number };
          if (
            retries < maxRetries &&
            (err.status === 429 || err.status === 503 || err.message?.toLowerCase().includes('quota') || err.message?.toLowerCase().includes('rate limit'))
          ) {
            retries++;
            // Respect abort signal during the wait
            let timeoutId: NodeJS.Timeout;
            await new Promise((resolve, reject) => {
              const onAbort = () => {
                clearTimeout(timeoutId);
                reject(new Error('AbortError'));
              };
              if (options?.signal?.aborted) {
                return onAbort();
              }
              options?.signal?.addEventListener('abort', onAbort);
              timeoutId = setTimeout(() => {
                options?.signal?.removeEventListener('abort', onAbort);
                resolve(true);
              }, Math.pow(2, retries - 1) * 1000);
            });
          } else {
            throw err;
          }
        }
      }

      let inputTokens = undefined;
      let outputTokens = undefined;
      let initialBuffer = '';
      let initialFlushed = false;
      const BUFFER_THRESHOLD = 80;

      for await (const chunk of responseStream) {
        if (options?.signal?.aborted) {
          throw new Error('AbortError');
        }

        if (chunk.text) {
          if (!initialFlushed) {
            initialBuffer += chunk.text;
            if (initialBuffer.length >= BUFFER_THRESHOLD || initialBuffer.includes('\n')) {
              const cleaned = sanitizePromptLeakage(initialBuffer);
              if (cleaned) {
                yield { type: 'chunk', text: cleaned };
              }
              initialFlushed = true;
              initialBuffer = '';
            }
          } else {
            const cleaned = sanitizePromptLeakage(chunk.text);
            if (cleaned) {
              yield { type: 'chunk', text: cleaned };
            }
          }
        }

        // Keep usage metadata if provided
        if (chunk.usageMetadata) {
          inputTokens = chunk.usageMetadata.promptTokenCount;
          outputTokens = chunk.usageMetadata.candidatesTokenCount;
        }
      }

      // Flush remaining initial buffer if stream ended before threshold or newline
      if (!initialFlushed && initialBuffer) {
        const cleaned = sanitizePromptLeakage(initialBuffer);
        if (cleaned) {
          yield { type: 'chunk', text: cleaned };
        }
        initialBuffer = '';
      }

      yield {
        type: 'done',
        usage: { input_tokens: inputTokens, output_tokens: outputTokens },
        metadata: { model: this.model, provider: this.name }
      };

    } catch (error: unknown) {
      const err = error as Error & { status?: number };
      const isAbort = err.name === 'AbortError' || err.message === 'AbortError';
      
      if (isAbort) {
        yield { type: 'error', error: 'Aborted by user' };
        return;
      }

      // Safe error mapping
      let safeError = 'Failed to generate response';
      
      if (err.status === 401 || err.status === 403 || err.message.includes('API key')) {
        safeError = 'AI service configuration error.';
      } else if (err.status === 429 || err.message.includes('quota') || err.message.includes('rate limit')) {
        safeError = 'AI service is temporarily busy. Please try again.';
      } else if (err.status === 500 || err.status === 503) {
        safeError = 'AI service is temporarily unavailable.';
      } else if (err.message.includes('fetch') || err.message.includes('network') || err.message.includes('timeout')) {
        safeError = 'Could not reach the AI service.';
      }

      yield { type: 'error', error: safeError };
    }
  }
}
