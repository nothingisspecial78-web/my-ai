import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import { GeminiProvider } from './gemini-provider';
import { Message } from './types';

// Mock getEnv
vi.mock('@/lib/env', () => ({
  getEnv: vi.fn(() => ({
    hasGeminiKey: true,
    aiModel: 'gemini-1.5-pro'
  }))
}));

// Mock process.env
const originalEnv = process.env;

// Mock GoogleGenAI
const mockGenerateContentStream = vi.fn();
vi.mock('@google/genai', () => {
  return {
    GoogleGenAI: class {
      models = {
        generateContentStream: mockGenerateContentStream
      };
    }
  };
});

// Mock fetch
const originalFetch = global.fetch;

describe('GeminiProvider', () => {
  let provider: GeminiProvider;

  beforeEach(() => {
    process.env = { ...originalEnv, GEMINI_API_KEY: 'test_key', NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME: 'testcloud' };
    provider = new GeminiProvider();
    
    // Default fetch mock (success text-only)
    global.fetch = vi.fn();
    
    // Default genai mock
    mockGenerateContentStream.mockReset();
    mockGenerateContentStream.mockImplementation(async function* () {
      yield { text: 'Test response chunk' };
    });
  });

  afterEach(() => {
    process.env = originalEnv;
    global.fetch = originalFetch;
    vi.clearAllMocks();
  });

  const createMockResponse = (options: { ok?: boolean, status?: number, contentType?: string, contentLength?: string, bodyChunks?: Uint8Array[], shouldAbort?: boolean }) => {
    let chunkIndex = 0;
    const reader = {
      read: vi.fn().mockImplementation(async () => {
        if (options.shouldAbort) throw new Error('AbortError');
        if (chunkIndex < (options.bodyChunks?.length || 0)) {
          return { done: false, value: options.bodyChunks![chunkIndex++] };
        }
        return { done: true };
      }),
      cancel: vi.fn().mockResolvedValue(undefined)
    };

    return {
      ok: options.ok ?? true,
      status: options.status ?? 200,
      headers: {
        get: (name: string) => {
          if (name.toLowerCase() === 'content-type') return options.contentType || 'image/jpeg';
          if (name.toLowerCase() === 'content-length') return options.contentLength || null;
          return null;
        }
      },
      body: {
        getReader: () => reader
      }
    };
  };

  it('1. Existing text-only request works without fetching Cloudinary', async () => {
    const messages: Message[] = [{ id: '1', role: 'user', content: 'hello', created_at: new Date(), conversation_id: '1' }];
    
    const generator = provider.generateStream(messages);
    const events = [];
    for await (const event of generator) {
      events.push(event);
    }

    expect(global.fetch).not.toHaveBeenCalled();
    expect(mockGenerateContentStream).toHaveBeenCalledWith(expect.objectContaining({
      contents: [{ role: 'user', parts: [{ text: 'hello' }] }]
    }));
    expect(events.length).toBeGreaterThan(0);
  });

  it('2. One JPEG + text', async () => {
    const messages: Message[] = [{ 
      id: '1', role: 'user', content: 'hello', created_at: new Date(), conversation_id: '1',
      metadata: { attachments: [{ type: 'image', url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/xyz.jpg', public_id: 'my_ai_uploads/xyz.jpg' }] } 
    }];

    (global.fetch as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce(createMockResponse({
      contentType: 'image/jpeg',
      bodyChunks: [new Uint8Array([255, 216, 255])] // Dummy JPEG bytes
    }));

    const generator = provider.generateStream(messages);
    for await (const _chunk of generator) {
      // exhaust generator
    }

    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(global.fetch).toHaveBeenCalledWith('https://res.cloudinary.com/testcloud/image/upload/w_800,c_limit,q_auto,f_auto/v1/my_ai_uploads/xyz.jpg', expect.any(Object));
    
    expect(mockGenerateContentStream).toHaveBeenCalledWith(expect.objectContaining({
      contents: [{ role: 'user', parts: [
        { inlineData: { mimeType: 'image/jpeg', data: Buffer.from([255, 216, 255]).toString('base64') } },
        { text: 'hello' }
      ] }]
    }));
  });

  it('5. Image-only message', async () => {
    const messages: Message[] = [{ 
      id: '1', role: 'user', content: '', created_at: new Date(), conversation_id: '1',
      metadata: { attachments: [{ type: 'image', url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/xyz.png', public_id: 'my_ai_uploads/xyz.png' }] } 
    }];

    (global.fetch as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce(createMockResponse({
      contentType: 'image/png',
      bodyChunks: [new Uint8Array([1, 2, 3])]
    }));

    const generator = provider.generateStream(messages);
    for await (const _chunk of generator) {
       // exhaust generator
    }

    expect(mockGenerateContentStream).toHaveBeenCalledWith(expect.objectContaining({
      contents: [{ role: 'user', parts: [
        { inlineData: { mimeType: 'image/png', data: Buffer.from([1, 2, 3]).toString('base64') } }
      ] }]
    }));
  });

  it('7. More images than server limit (4) truncates', async () => {
    const attachments = Array(5).fill(null).map((_, i) => ({
      type: 'image', url: `https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/xyz.jpg`, public_id: `my_ai_uploads/xyz.jpg`
    }));

    const messages: Message[] = [{ 
      id: '1', role: 'user', content: 'hello', created_at: new Date(), conversation_id: '1',
      metadata: { attachments } 
    }];

    (global.fetch as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(createMockResponse({
      contentType: 'image/jpeg',
      bodyChunks: [new Uint8Array([1])]
    }));

    const generator = provider.generateStream(messages);
    for await (const _chunk of generator) {
       // exhaust generator
    }

    // Only 4 fetches should happen
    expect(global.fetch).toHaveBeenCalledTimes(4);
    
    const callArgs = mockGenerateContentStream.mock.calls[0][0];
    const parts = callArgs.contents[0].parts;
    
    // 4 images + 1 omitted text + 1 normal text
    expect(parts.length).toBe(6);
    expect(parts[4].text).toContain('[Attached image omitted due to context limits.]');
  });

  it('9. External/non-Cloudinary URL is never fetched', async () => {
    const messages: Message[] = [{ 
      id: '1', role: 'user', content: 'hello', created_at: new Date(), conversation_id: '1',
      metadata: { attachments: [{ type: 'image', url: 'https://malicious.com/image.jpg' }] } 
    }];

    const generator = provider.generateStream(messages);
    for await (const _chunk of generator) {
      // exhaust generator
    }

    expect(global.fetch).not.toHaveBeenCalled();
    const callArgs = mockGenerateContentStream.mock.calls[0][0];
    const parts = callArgs.contents[0].parts;
    expect(parts[0].text).toContain('[One attached image could not be loaded.]');
  });

  it('9b. Malicious public_id is rejected', async () => {
    const maliciousIds = [
      'other_private_folder/image.jpg',
      '../something.jpg',
      'my_ai_uploads/../../etc/passwd',
      'my_ai_uploads/w_9999,c_limit/image.jpg', // comma is an invalid char
      'https://example.com/x'
    ];
    
    for (const badId of maliciousIds) {
      const messages: Message[] = [{ 
        id: '1', role: 'user', content: 'hello', created_at: new Date(), conversation_id: '1',
        metadata: { attachments: [{ type: 'image', url: `https://res.cloudinary.com/testcloud/image/upload/v1/${badId}`, public_id: badId }] } 
      }];

      const generator = provider.generateStream(messages);
      for await (const _chunk of generator) {}

      expect(global.fetch).not.toHaveBeenCalled();
    }
  });

  it('11. Unsupported Content-Type is rejected', async () => {
    const messages: Message[] = [{ 
      id: '1', role: 'user', content: 'hello', created_at: new Date(), conversation_id: '1',
      metadata: { attachments: [{ type: 'image', url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/bad.svg', public_id: 'my_ai_uploads/bad.svg' }] } 
    }];

    (global.fetch as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce(createMockResponse({
      contentType: 'image/svg+xml',
      bodyChunks: [new Uint8Array([1])]
    }));

    const generator = provider.generateStream(messages);
    for await (const _chunk of generator) {
       // exhaust generator
    }

    const callArgs = mockGenerateContentStream.mock.calls[0][0];
    const parts = callArgs.contents[0].parts;
    expect(parts[0].text).toContain('[One attached image could not be loaded.]');
  });

  it('13. Content-Length over limit', async () => {
    const messages: Message[] = [{ 
      id: '1', role: 'user', content: 'hello', created_at: new Date(), conversation_id: '1',
      metadata: { attachments: [{ type: 'image', url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/big.jpg', public_id: 'my_ai_uploads/big.jpg' }] } 
    }];

    (global.fetch as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce(createMockResponse({
      contentType: 'image/jpeg',
      contentLength: '6000000' // 6MB
    }));

    const generator = provider.generateStream(messages);
    for await (const _chunk of generator) {
       // exhaust generator
    }

    const callArgs = mockGenerateContentStream.mock.calls[0][0];
    const parts = callArgs.contents[0].parts;
    expect(parts[0].text).toContain('[One attached image could not be loaded.]');
  });

  it('15. Cloudinary 404 gracefully handles without crashing', async () => {
    const messages: Message[] = [{ 
      id: '1', role: 'user', content: 'hello', created_at: new Date(), conversation_id: '1',
      metadata: { attachments: [{ type: 'image', url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/missing.jpg', public_id: 'my_ai_uploads/missing.jpg' }] } 
    }];

    (global.fetch as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce(createMockResponse({
      ok: false, status: 404
    }));

    const generator = provider.generateStream(messages);
    for await (const _chunk of generator) {
       // exhaust generator
    }

    const callArgs = mockGenerateContentStream.mock.calls[0][0];
    const parts = callArgs.contents[0].parts;
    expect(parts[0].text).toContain('[One attached image could not be loaded.]');
    expect(parts[1].text).toBe('hello');
  });

  it('Returns top-level error if ALL images fail in an image-only message', async () => {
    const messages: Message[] = [{ 
      id: '1', role: 'user', content: '', created_at: new Date(), conversation_id: '1',
      metadata: { attachments: [{ type: 'image', url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/missing.jpg', public_id: 'my_ai_uploads/missing.jpg' }] } 
    }];

    (global.fetch as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce(createMockResponse({
      ok: false, status: 404
    }));

    const generator = provider.generateStream(messages);
    const events = [];
    for await (const event of generator) {
      events.push(event);
    }

    const errorEvent = events.find((e: unknown) => (e as { type?: string }).type === 'error') as unknown;
    expect(errorEvent).toBeDefined();
    // Re-mapped by the provider's catch block, but it catches our thrown Error
    expect(mockGenerateContentStream).not.toHaveBeenCalled();
  });

  it('16. Passes custom systemInstruction to Gemini when a theme provides one', async () => {
    mockGenerateContentStream.mockReturnValueOnce((async function* () {
      yield { text: 'Custom themed response', usageMetadata: { promptTokenCount: 5, candidatesTokenCount: 5 } };
    })());

    const messages = [{ id: '1', role: 'user', content: 'Hello', metadata: {} }] as unknown as Message[];
    const generator = provider.generateStream(messages, { systemInstruction: 'Custom Theme Instructions' });
    
    let result = '';
    for await (const event of generator) {
      if (event.type === 'chunk') result += (event as { text: string }).text;
    }

    expect(result).toBe('Custom themed response');
    expect(mockGenerateContentStream).toHaveBeenCalledWith(
      expect.objectContaining({
        config: expect.objectContaining({
          systemInstruction: 'Custom Theme Instructions'
        })
      })
    );
  });
});
