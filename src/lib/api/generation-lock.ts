/**
 * Per-conversation generation lock.
 *
 * Prevents two simultaneous AI generations for the same user+conversation.
 * Uses an in-memory Map. Locks MUST be released in a finally block.
 *
 * For multi-instance production, migrate to a distributed lock.
 */

import { getRedis } from '../redis';
import { randomUUID } from 'crypto';

const activeLocks = new Map<string, { token: string, expiresAt: number }>(); // key -> data

function lockKey(userId: string, conversationId: string): string {
  return `lock:${userId}:${conversationId}`;
}

/**
 * Attempt to acquire a generation lock.
 * Returns lockToken if acquired, null if another generation is already active.
 */
export async function acquireGenerationLock(userId: string, conversationId: string): Promise<string | null> {
  const key = lockKey(userId, conversationId);
  const token = randomUUID();
  
  try {
    const redis = await getRedis();
    if (redis) {
      // Set lock with 5-minute expiration. 5 minutes is safely above Gemini's max timeout (~3 mins).
      const acquired = await redis.set(key, token, 'EX', 300, 'NX');
      return acquired === 'OK' ? token : null;
    }
  } catch (err) {
    // Redis failed — fall through to local memory fallback
    console.warn('Generation lock: Redis unavailable, using local fallback', err instanceof Error ? err.message : err);
  }

  // Local memory fallback
  const existing = activeLocks.get(key);
  if (existing && existing.expiresAt > Date.now()) {
    return null;
  }
  // 5 minutes TTL
  activeLocks.set(key, { token, expiresAt: Date.now() + 300_000 });
  return token;
}

/**
 * Release a generation lock safely (only if we own the token).
 */
export async function releaseGenerationLock(userId: string, conversationId: string, token: string): Promise<void> {
  const key = lockKey(userId, conversationId);
  
  try {
    const redis = await getRedis();
    if (redis) {
      // Lua script to safely delete only if the value matches our token
      const script = `
        if redis.call("get",KEYS[1]) == ARGV[1] then
            return redis.call("del",KEYS[1])
        else
            return 0
        end
      `;
      await redis.eval(script, 1, key, token);
      return;
    }
  } catch (err) {
    // Redis failed — fall through to local memory fallback
    console.warn('Generation lock release: Redis unavailable, using local fallback', err instanceof Error ? err.message : err);
  }

  // Local memory fallback
  const existing = activeLocks.get(key);
  if (existing && existing.token === token) {
    activeLocks.delete(key);
  }
}

/** For testing: reset all locks */
export async function resetAllLocks(): Promise<void> {
  activeLocks.clear();
}
