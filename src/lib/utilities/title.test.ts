import { extractConversationTitle } from './title';
import { describe, it, expect } from 'vitest';

describe('extractConversationTitle', () => {
  it('truncates to 6 words', () => {
    const prompt = 'this is a very long prompt with many words that should be truncated';
    expect(extractConversationTitle(prompt)).toBe('This is a very long prompt');
  });

  it('strips markdown characters', () => {
    const prompt = '# Hello **world**! Check this `code`';
    expect(extractConversationTitle(prompt)).toBe('Hello world Check this code');
  });

  it('removes common filler prefixes', () => {
    expect(extractConversationTitle('Can you tell me about the weather?')).toBe('About the weather');
    expect(extractConversationTitle('Please explain quantum computing')).toBe('Quantum computing');
  });

  it('returns New conversation for empty strings', () => {
    expect(extractConversationTitle('   ')).toBe('New conversation');
    expect(extractConversationTitle('')).toBe('New conversation');
  });
});
