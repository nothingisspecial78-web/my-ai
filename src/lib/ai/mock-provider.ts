
import { AIProvider, Message, AIStreamEvent } from './types';

export class MockProvider implements AIProvider {
  name = 'mock';

  async *generateStream(
    _messages: Message[],
    options?: { userId?: string, conversationId?: string, signal?: AbortSignal }
  ): AsyncGenerator<AIStreamEvent, void, unknown> {
    
    yield { type: 'start' };
    
    // Simulate delay
    await new Promise(r => setTimeout(r, 400));
    
    if (options?.signal?.aborted) {
      yield { type: 'error', error: 'Aborted' };
      return;
    }

    const words = 'This is a mock response from the premium MyAI assistant. Actual AI integration is running in Mock Mode.'.split(' ');
    
    for (const word of words) {
      if (options?.signal?.aborted) {
        yield { type: 'error', error: 'Aborted' };
        return;
      }
      yield { type: 'chunk', text: word + ' ' };
      await new Promise(r => setTimeout(r, 50));
    }

    if (!options?.signal?.aborted) {
      yield { 
        type: 'done',
        usage: { input_tokens: 10, output_tokens: 20 },
        metadata: { model: 'mock-model', provider: 'mock' }
      };
    }
  }
}
