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
    
    // Map messages to Gemini Content structure
    const contents = messages.map(msg => ({
      role: msg.role === 'user' ? 'user' : 'model',
      parts: [{ text: msg.content }]
    }));

    // Start stream
    yield { type: 'start' };

    try {
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
