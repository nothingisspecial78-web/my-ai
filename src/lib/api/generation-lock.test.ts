import { acquireGenerationLock, releaseGenerationLock, resetAllLocks } from './generation-lock';
import { describe, it, expect, beforeEach, vi } from 'vitest';

describe('Generation Lock', () => {
  beforeEach(() => {
    resetAllLocks();
  });

  it('allows acquiring an initial lock', async () => {
    const token = await acquireGenerationLock('user-1', 'conv-1');
    expect(typeof token).toBe('string');
  });

  it('prevents acquiring a lock that is already held', async () => {
    const firstToken = await acquireGenerationLock('user-1', 'conv-1');
    expect(firstToken).toBeTruthy();
    
    // Attempt second time
    const secondToken = await acquireGenerationLock('user-1', 'conv-1');
    expect(secondToken).toBeNull();
  });

  it('allows acquiring a lock after it is released', async () => {
    const token = await acquireGenerationLock('user-1', 'conv-1');
    expect(token).toBeTruthy();
    await releaseGenerationLock('user-1', 'conv-1', token!);
    
    // Should work again
    const secondToken = await acquireGenerationLock('user-1', 'conv-1');
    expect(typeof secondToken).toBe('string');
  });

  it('isolates locks per conversation and user', async () => {
    await acquireGenerationLock('user-1', 'conv-1');

    // Different conversation, same user -> allowed
    expect(typeof await acquireGenerationLock('user-1', 'conv-2')).toBe('string');

    // Same conversation, different user -> allowed
    expect(typeof await acquireGenerationLock('user-2', 'conv-1')).toBe('string');
  });

  it('verifies ownership token on release (a worker cannot release another worker\'s lock)', async () => {
    const token = await acquireGenerationLock('user-3', 'conv-3');
    expect(token).toBeTruthy();

    // Release with incorrect token should fail (or rather, just not delete the lock)
    await releaseGenerationLock('user-3', 'conv-3', 'incorrect-token-123');

    // Try to acquire again, should still be locked
    const secondToken = await acquireGenerationLock('user-3', 'conv-3');
    expect(secondToken).toBeNull();

    // Release with correct token
    await releaseGenerationLock('user-3', 'conv-3', token!);

    // Now it should be free
    const thirdToken = await acquireGenerationLock('user-3', 'conv-3');
    expect(thirdToken).toBeTruthy();
  });

  it('expires lock after TTL', async () => {
    vi.useFakeTimers();
    const token = await acquireGenerationLock('user-4', 'conv-4');
    expect(token).toBeTruthy();

    // Advance by 300,001 ms (5 mins + 1ms)
    vi.advanceTimersByTime(300_001);

    // Should be able to acquire again
    const newToken = await acquireGenerationLock('user-4', 'conv-4');
    expect(newToken).toBeTruthy();
    expect(newToken).not.toBe(token);
    vi.useRealTimers();
  });
});
