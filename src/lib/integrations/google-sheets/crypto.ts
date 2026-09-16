import crypto from 'crypto';
import { GoogleOAuthStatePayload } from './types';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const STATE_MAX_AGE_MS = 10 * 60 * 1000;

export function getEncryptionKey(): Buffer {
  const envKey = process.env.GOOGLE_SHEETS_ENCRYPTION_KEY;
  if (!envKey) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('GOOGLE_SHEETS_ENCRYPTION_KEY is required and missing in production.');
    }
    return crypto.createHash('sha256').update('dev-test-fallback-sheets-key-32b').digest();
  }
  if (envKey.length === 64 && /^[0-9a-fA-F]+$/.test(envKey)) {
    return Buffer.from(envKey, 'hex');
  }
  if (Buffer.from(envKey, 'base64').length === 32) {
    return Buffer.from(envKey, 'base64');
  }
  return crypto.createHash('sha256').update(envKey).digest();
}

export function encryptToken(plaintext: string): { ciphertext: string; iv: string; tag: string } {
  if (!plaintext) throw new Error('Cannot encrypt empty plaintext');
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag();
  return {
    ciphertext: encrypted,
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
  };
}

export function decryptToken(ciphertext: string, ivHex: string, tagHex: string): string {
  if (!ciphertext || !ivHex || !tagHex) {
    throw new Error('Missing ciphertext, iv, or tag for token decryption');
  }
  const key = getEncryptionKey();
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

export function createOAuthState(userId: string): string {
  const payload: GoogleOAuthStatePayload = {
    userId,
    nonce: crypto.randomBytes(16).toString('hex'),
    timestamp: Date.now(),
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const key = getEncryptionKey();
  const signature = crypto.createHmac('sha256', key).update(payloadB64).digest('base64url');
  return payloadB64 + '.' + signature;
}

export function validateOAuthState(state: string, expectedUserId: string): boolean {
  if (!state || !expectedUserId) return false;
  const parts = state.split('.');
  if (parts.length !== 2) return false;
  const [payloadB64, providedSig] = parts;
  const key = getEncryptionKey();
  const expectedSig = crypto.createHmac('sha256', key).update(payloadB64).digest('base64url');
  const providedBuf = Buffer.from(providedSig);
  const expectedBuf = Buffer.from(expectedSig);
  if (providedBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(providedBuf, expectedBuf)) {
    return false;
  }
  try {
    const raw = Buffer.from(payloadB64, 'base64url').toString('utf8');
    const payload = JSON.parse(raw) as GoogleOAuthStatePayload;
    if (!payload.userId || payload.userId !== expectedUserId) return false;
    if (typeof payload.timestamp !== 'number') return false;
    const age = Date.now() - payload.timestamp;
    if (age < 0 || age > STATE_MAX_AGE_MS) return false;
    return true;
  } catch {
    return false;
  }
}

export function hashUserId(userId: string): string {
  if (!userId) return 'anonymous';
  const salt = process.env.GOOGLE_SHEETS_USER_HASH_SALT || process.env.GOOGLE_SHEETS_ENCRYPTION_KEY || 'byc-user-hash-salt-fallback';
  return crypto.createHmac('sha256', salt).update(userId).digest('hex').substring(0, 16);
}
