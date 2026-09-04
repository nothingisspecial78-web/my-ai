import { validateChatRequest, sanitizeErrorForClient, isValidUUID } from './validation';
import { describe, it, expect } from 'vitest';

describe('validation utilities', () => {
  describe('isValidUUID', () => {
    it('returns true for valid UUIDs', () => {
      expect(isValidUUID('123e4567-e89b-12d3-a456-426614174000')).toBe(true);
      expect(isValidUUID('fc3c1f13-515a-4266-8efb-d116847c4ef6')).toBe(true);
    });

    it('returns false for invalid UUIDs', () => {
      expect(isValidUUID('123')).toBe(false);
      expect(isValidUUID('fc3c1f13-515a-4266-8efb-d116847c4ef')).toBe(false); // missing a char
      expect(isValidUUID('not-a-uuid')).toBe(false);
      expect(isValidUUID('')).toBe(false);
    });
  });

  describe('validateChatRequest', () => {
    it('validates a correct request', () => {
      const body = { conversationId: '123e4567-e89b-12d3-a456-426614174000' };
      const result = validateChatRequest(body);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.data.conversationId).toBe(body.conversationId);
      }
    });

    it('validates a request with regenerateMessageId', () => {
      const body = { 
        conversationId: '123e4567-e89b-12d3-a456-426614174000',
        regenerateMessageId: '123e4567-e89b-12d3-a456-426614174001'
      };
      const result = validateChatRequest(body);
      expect(result.valid).toBe(true);
    });

    it('rejects missing conversationId', () => {
      const result = validateChatRequest({});
      expect(result.valid).toBe(false);
    });

    it('rejects invalid conversationId format', () => {
      const result = validateChatRequest({ conversationId: '123' });
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toContain('format');
      }
    });

    it('rejects invalid regenerateMessageId format', () => {
      const result = validateChatRequest({ 
        conversationId: '123e4567-e89b-12d3-a456-426614174000',
        regenerateMessageId: 'invalid-id'
      });
      expect(result.valid).toBe(false);
    });
  });

  describe('sanitizeErrorForClient', () => {
    it('strips API keys', () => {
      const err = new Error('Failed to connect: GEMINI_API_KEY is invalid');
      expect(sanitizeErrorForClient(err)).toBe('AI service configuration error');
    });

    it('strips file paths and internals', () => {
      const err = new Error('File not found at /usr/src/app/node_modules/somelib/index.js');
      expect(sanitizeErrorForClient(err)).toBe('An internal error occurred');
    });

    it('preserves safe, short error messages', () => {
      const err = new Error('Conversation not found');
      expect(sanitizeErrorForClient(err)).toBe('Conversation not found');
    });
    
    it('masks unhandled unknown errors', () => {
      expect(sanitizeErrorForClient('Just a string error')).toBe('An unexpected error occurred');
    });
  });
});
