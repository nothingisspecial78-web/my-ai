import { RateLimiter } from './rate-limiter';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

describe('RateLimiter', () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    // 5 requests per 1000ms window
    limiter = new RateLimiter(5, 1000);
    vi.useFakeTimers();
  });

  afterEach(() => {
    limiter.destroy();
    vi.useRealTimers();
  });

  it('allows requests within limit', async () => {
    const userId = 'user-1';
    for (let i = 0; i < 5; i++) {
      const result = await limiter.check(userId);
      expect(result.allowed).toBe(true);
    }
  });

  it('blocks requests over limit and provides retryAfter', async () => {
    const userId = 'user-1';
    
    // Use up the limit
    for (let i = 0; i < 5; i++) {
      await limiter.check(userId);
    }

    // Next request should be blocked
    const result = await limiter.check(userId);
    expect(result.allowed).toBe(false);
    
    if (!result.allowed) {
      expect(result.retryAfter).toBeGreaterThan(0);
      expect(result.retryAfter).toBeLessThanOrEqual(1); // 1000ms window = 1s max wait
    }
  });

  it('isolates limits per user', async () => {
    // User 1 uses up limit
    for (let i = 0; i < 5; i++) {
      await limiter.check('user-1');
    }
    expect((await limiter.check('user-1')).allowed).toBe(false);

    // User 2 should still be allowed
    expect((await limiter.check('user-2')).allowed).toBe(true);
  });

  it('resets limits after window expires', async () => {
    const userId = 'user-1';
    
    for (let i = 0; i < 5; i++) {
      await limiter.check(userId);
    }
    expect((await limiter.check(userId)).allowed).toBe(false);

    // Fast-forward time by 1001ms
    vi.advanceTimersByTime(1001);

    // Should be allowed again
    expect((await limiter.check(userId)).allowed).toBe(true);
  });
});
