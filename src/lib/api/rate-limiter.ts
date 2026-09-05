/**
 * V1 in-memory rate limiter.
 *
 * Implements a sliding-window rate limit per authenticated user.
 * Suitable for single-instance development/staging.
 *
 * For multi-instance production deployment, migrate to a distributed
 * solution such as Redis, Upstash, or Vercel KV.
 *
 * Default: 10 generation requests per 60-second window per user.
 */

import { getRedis } from '../redis';

interface RateLimitEntry {
  timestamps: number[];
}

const DEFAULT_MAX_REQUESTS = 10;
const DEFAULT_WINDOW_MS = 60_000; // 60 seconds

export class RateLimiter {
  private store = new Map<string, RateLimitEntry>();
  private maxRequests: number;
  private windowMs: number;
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor(maxRequests = DEFAULT_MAX_REQUESTS, windowMs = DEFAULT_WINDOW_MS) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;

    // Periodic cleanup of expired entries every 5 minutes (for local memory store)
    if (typeof setInterval !== 'undefined') {
      this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60_000);
      if (this.cleanupInterval && typeof this.cleanupInterval === 'object' && 'unref' in this.cleanupInterval) {
        this.cleanupInterval.unref();
      }
    }
  }

  /**
   * Check if a request is allowed for the given user.
   */
  async check(userId: string): Promise<{ allowed: true } | { allowed: false; retryAfter: number }> {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    // Try Redis first
    try {
      const redis = await getRedis();
      if (redis) {
        const key = `ratelimit:${userId}`;
        const multi = redis.multi();
        multi.zremrangebyscore(key, '-inf', windowStart);
        multi.zcard(key);
        const results = await multi.exec();
        
        const count = (results?.[1]?.[1] as number) || 0;
        
        if (count >= this.maxRequests) {
          const oldestEntry = await redis.zrange(key, '0', '0', 'WITHSCORES');
          let retryAfter = 1;
          if (oldestEntry && oldestEntry.length === 2) {
            const oldestScore = parseInt(oldestEntry[1], 10);
            retryAfter = Math.ceil((oldestScore + this.windowMs - now) / 1000);
          }
          return { allowed: false, retryAfter: Math.max(1, retryAfter) };
        }
        
        const p = redis.multi();
        p.zadd(key, String(now), String(now) + '-' + String(Math.random()));
        p.expire(key, Math.ceil(this.windowMs / 1000) * 2);
        await p.exec();
        
        return { allowed: true };
      }
    } catch (err) {
      // Redis failed — fall through to local memory fallback
      console.warn('Rate limiter: Redis unavailable, using local fallback', err instanceof Error ? err.message : err);
    }

    // Local Memory Fallback
    let entry = this.store.get(userId);
    if (!entry) {
      entry = { timestamps: [] };
      this.store.set(userId, entry);
    }

    entry.timestamps = entry.timestamps.filter(t => t > windowStart);

    if (entry.timestamps.length >= this.maxRequests) {
      const oldestInWindow = entry.timestamps[0];
      const retryAfter = Math.ceil((oldestInWindow + this.windowMs - now) / 1000);
      return { allowed: false, retryAfter: Math.max(1, retryAfter) };
    }

    entry.timestamps.push(now);
    return { allowed: true };
  }

  /** Remove expired entries to prevent memory growth */
  private cleanup() {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    for (const [userId, entry] of this.store.entries()) {
      entry.timestamps = entry.timestamps.filter(t => t > windowStart);
      if (entry.timestamps.length === 0) {
        this.store.delete(userId);
      }
    }
  }

  /** For testing: reset all state */
  reset() {
    this.store.clear();
  }

  /** For testing: destroy cleanup interval */
  destroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}

// Singleton instance for the application
export const rateLimiter = new RateLimiter();
