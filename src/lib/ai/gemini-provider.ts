import { AIProvider, Message, AIStreamEvent } from './types';
import { GoogleGenAI } from '@google/genai';
import { SYSTEM_INSTRUCTION } from './system-prompt';
import { getEnv } from '@/lib/env';

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
    options?: { userId?: string; conversationId?: string; signal?: AbortSignal }
  ): AsyncGenerator<AIStreamEvent, void, unknown> {
    
    // Start stream
    yield { type: 'start' };

    try {
      // Map messages to Gemini Content structure, resolving images securely
      const processedMessages = [];
      let imageCount = 0;
      const maxImages = 4;
      const cloudName = process.env.NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME;

      for (let i = messages.length - 1; i >= 0; i--) {
        const msg = messages[i];
        const parts: Array<{ text?: string; inlineData?: { mimeType: string; data: string } }> = [];
        let allImagesFailed = false;
        let hasTriedImages = false;

        if (msg.metadata?.attachments && Array.isArray(msg.metadata.attachments)) {
          let successCount = 0;
          let failCount = 0;

          for (const att of msg.metadata.attachments) {
            if (att.type === 'image' && att.url) {
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

                const fetchUrl = `https://res.cloudinary.com/${cloudName}/image/upload/w_800,c_limit,q_auto,f_auto/v1/${publicId}`;
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

                parts.push({
                  inlineData: {
                    mimeType: contentType,
                    data: base64
                  }
                });

                imageCount++;
                successCount++;
              } catch (err) {
                const isAbort = err instanceof Error && (err.name === 'AbortError' || err.message === 'AbortError');
                if (isAbort) throw err;

                console.error('Image fetch error:', err);
                parts.push({ text: '[One attached image could not be loaded.]' });
                failCount++;
              }
            }
          }

          if (hasTriedImages && successCount === 0 && failCount > 0) {
            allImagesFailed = true;
          }
        }

        if (msg.content?.trim()) {
          parts.push({ text: msg.content });
        }

        if (i === messages.length - 1 && !msg.content?.trim() && allImagesFailed) {
          throw new Error('All attached images failed to load. Please try again.');
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
      
      while (true) {
        if (options?.signal?.aborted) {
          throw new Error('AbortError');
        }
        try {
          responseStream = await this.client.models.generateContentStream({
            model: this.model,
            contents,
            config: {
              systemInstruction: SYSTEM_INSTRUCTION,
            },
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

      for await (const chunk of responseStream) {
        if (options?.signal?.aborted) {
          throw new Error('AbortError');
        }

        if (chunk.text) {
          yield { type: 'chunk', text: chunk.text };
        }

        // Keep usage metadata if provided
        if (chunk.usageMetadata) {
          inputTokens = chunk.usageMetadata.promptTokenCount;
          outputTokens = chunk.usageMetadata.candidatesTokenCount;
        }
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
