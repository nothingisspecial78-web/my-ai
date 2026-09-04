import { AIProvider } from './types';
import { MockProvider } from './mock-provider';
import { GeminiProvider } from './gemini-provider';

export function getProvider(): AIProvider {
  const mode = process.env.AI_MODE || 'mock';
  
  if (mode === 'gemini') {
    return new GeminiProvider();
  }
  
  return new MockProvider();
}
