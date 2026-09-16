import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'crypto';
import {
  getEncryptionKey,
  encryptToken,
  decryptToken,
  createOAuthState,
  validateOAuthState,
  hashUserId,
} from './crypto';

describe('Google Sheets Crypto & OAuth State', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe('Token Encryption & Decryption (AES-256-GCM)', () => {
    it('encrypts and decrypts tokens successfully roundtrip', () => {
      const plaintext = 'ya29.a0AfH6SMD_test_refresh_token_xyz_12345';
      const encrypted = encryptToken(plaintext);

      expect(encrypted).toHaveProperty('ciphertext');
      expect(encrypted).toHaveProperty('iv');
      expect(encrypted).toHaveProperty('tag');
      expect(encrypted.ciphertext).not.toBe(plaintext);

      const decrypted = decryptToken(encrypted.ciphertext, encrypted.iv, encrypted.tag);
      expect(decrypted).toBe(plaintext);
    });

    it('generates unique IVs for identical plaintexts', () => {
      const plaintext = 'same-token-content';
      const enc1 = encryptToken(plaintext);
      const enc2 = encryptToken(plaintext);

      expect(enc1.iv).not.toBe(enc2.iv);
      expect(enc1.ciphertext).not.toBe(enc2.ciphertext);
      expect(decryptToken(enc1.ciphertext, enc1.iv, enc1.tag)).toBe(plaintext);
      expect(decryptToken(enc2.ciphertext, enc2.iv, enc2.tag)).toBe(plaintext);
    });

    it('throws when encrypting empty string', () => {
      expect(() => encryptToken('')).toThrow('Cannot encrypt empty plaintext');
    });

    it('throws when decrypting with missing arguments', () => {
      expect(() => decryptToken('', 'iv', 'tag')).toThrow('Missing ciphertext, iv, or tag');
      expect(() => decryptToken('cipher', '', 'tag')).toThrow('Missing ciphertext, iv, or tag');
      expect(() => decryptToken('cipher', 'iv', '')).toThrow('Missing ciphertext, iv, or tag');
    });

    it('fails decryption with tampered ciphertext or auth tag', () => {
      const plaintext = 'sensitive-token';
      const enc = encryptToken(plaintext);

      // Corrupt tag
      const corruptedTag = '0' + enc.tag.slice(1);
      expect(() => decryptToken(enc.ciphertext, enc.iv, corruptedTag)).toThrow();

      // Corrupt ciphertext
      const corruptedCipher = 'f' + enc.ciphertext.slice(1);
      expect(() => decryptToken(corruptedCipher, enc.iv, enc.tag)).toThrow();
    });
  });

  describe('OAuth State Signing & Validation (HMAC-SHA256)', () => {
    it('generates a valid signed OAuth state and validates it', () => {
      const userId = 'user-abc-123';
      const state = createOAuthState(userId);

      expect(state).toContain('.');
      const isValid = validateOAuthState(state, userId);
      expect(isValid).toBe(true);
    });

    it('rejects state if expected userId does not match', () => {
      const state = createOAuthState('user-1');
      expect(validateOAuthState(state, 'user-2')).toBe(false);
    });

    it('rejects state with tampered signature', () => {
      const state = createOAuthState('user-1');
      const [payload, sig] = state.split('.');
      const tampered = payload + '.' + sig.slice(0, -2) + 'xx';
      expect(validateOAuthState(tampered, 'user-1')).toBe(false);
    });

    it('rejects state with tampered payload', () => {
      const state = createOAuthState('user-1');
      const [, sig] = state.split('.');
      const fakePayload = Buffer.from(JSON.stringify({ userId: 'user-1', nonce: '123', timestamp: Date.now() })).toString('base64url');
      expect(validateOAuthState(fakePayload + '.' + sig, 'user-1')).toBe(false);
    });

    it('rejects expired state (> 10 minutes old)', () => {
      const userId = 'user-old';
      // Simulate state created 11 minutes ago
      const expiredPayload = {
        userId,
        nonce: 'nonce123',
        timestamp: Date.now() - (11 * 60 * 1000),
      };
      const payloadB64 = Buffer.from(JSON.stringify(expiredPayload)).toString('base64url');
      const key = getEncryptionKey();
      const signature = crypto.createHmac('sha256', key).update(payloadB64).digest('base64url');
      const expiredState = payloadB64 + '.' + signature;

      expect(validateOAuthState(expiredState, userId)).toBe(false);
    });

    it('rejects malformed states', () => {
      expect(validateOAuthState('', 'user-1')).toBe(false);
      expect(validateOAuthState('invalid-no-dot', 'user-1')).toBe(false);
      expect(validateOAuthState('a.b.c', 'user-1')).toBe(false);
    });
  });

  describe('Pseudonymous User ID Hashing', () => {
    it('produces deterministic 16-char hex hash', () => {
      const hash1 = hashUserId('user-12345');
      const hash2 = hashUserId('user-12345');
      expect(hash1).toBe(hash2);
      expect(hash1.length).toBe(16);
      expect(/^[0-9a-f]{16}$/.test(hash1)).toBe(true);
    });

    it('produces distinct hashes for distinct user IDs', () => {
      const hashA = hashUserId('user-A');
      const hashB = hashUserId('user-B');
      expect(hashA).not.toBe(hashB);
    });

    it('never contains the original userId', () => {
      const userId = 'my-secret-user-identifier';
      const hash = hashUserId(userId);
      expect(hash).not.toContain(userId);
    });
  });
});
