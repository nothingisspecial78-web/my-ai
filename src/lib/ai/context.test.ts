import { prepareContext } from './context';
import { Message } from './types';
import { describe, it, expect } from 'vitest';

describe('prepareContext', () => {
  it('filters out empty messages', () => {
    const messages: Message[] = [
      { id: '1', role: 'user', content: 'hello' },
      { id: '2', role: 'assistant', content: '   ' },
      { id: '3', role: 'user', content: 'world' }
    ] as unknown as Message[]; // Ignore missing DB fields for test

    const context = prepareContext(messages);
    expect(context).toHaveLength(2);
    expect(context[0].content).toBe('hello');
    expect(context[1].content).toBe('world');
  });

  it('respects character limit by truncating from the beginning', () => {
    const messages: Message[] = [
      { id: '1', role: 'user', content: 'a'.repeat(20000) },
      { id: '2', role: 'assistant', content: 'b'.repeat(5000) },
      { id: '3', role: 'user', content: 'c'.repeat(10000) }
    ] as unknown as Message[];

    const context = prepareContext(messages, { maxCharacters: 30000 });
    
    // Total is 35k. The 10k and 5k should be kept (15k), and the first one skipped because 15k+20k > 30k
    expect(context).toHaveLength(2);
    expect(context[0].content[0]).toBe('b');
    expect(context[1].content[0]).toBe('c');
  });

  it('preserves image-only messages', () => {
    const messages: Message[] = [
      { id: '1', role: 'user', content: '' }, // Should be stripped
      { id: '2', role: 'user', content: '', metadata: { attachments: [{ type: 'image', url: '...' }] } }, // Should be kept
      { id: '3', role: 'assistant', content: 'Response' }
    ] as unknown as Message[];

    const context = prepareContext(messages);
    expect(context).toHaveLength(2);
    expect(context[0].metadata?.attachments).toBeDefined();
    expect(context[1].content).toBe('Response');
  });
});
