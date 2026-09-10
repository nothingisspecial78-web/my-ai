/**
 * Reputation Intelligence Caching Layer
 * 
 * Provides URL normalization, SHA-256 cache key generation, TTL handling,
 * and Redis-backed storage with an automated in-memory fallback.
 */

import crypto from 'crypto';
import { getRedis } from '../../redis';
import { redactUrl } from '../redaction';
import { ReputationCache, ReputationCacheEntry } from './types';

// Query parameter patterns that are tracking/analytics artifacts
const TRACKING_PARAM_PATTERNS = [
  /^utm_/i,
  /^fbclid$/i,
  /^gclid$/i,
  /^msclkid$/i,
  /^mc_cid$/i,
  /^mc_eid$/i,
  /^igshid$/i,
  /^_hsenc$/i,
  /^_hsmi$/i,
  /^ref$/i,
  /^referrer$/i,
];

/**
 * Normalizes a URL for deterministic reputation lookups and cache indexing.
 * 
 * - Canonicalizes protocol and hostname (lowercased)
 * - Strips standard default ports (:80, :443)
 * - Strips client-side hash fragments (#...)
 * - Strips tracking and analytics parameters (utm_*, fbclid, etc.)
 * - Applies privacy redaction to sensitive query params (password, token, otp, etc.)
 * - Sorts remaining search parameters deterministically
 * - Normalizes trailing slashes
 */
export function normalizeUrlForReputation(rawUrl: string): string {
  if (!rawUrl || typeof rawUrl !== 'string') return '';

  const trimmed = rawUrl.trim();
  if (!trimmed) return '';

  // 1. Redact credentials/tokens before parsing
  const redacted = redactUrl(trimmed);

  try {
    const hasProtocol = /^https?:\/\//i.test(redacted);
    const parseable = hasProtocol ? redacted : `https://${redacted}`;
    const parsed = new URL(parseable);

    // Canonicalize protocol
    const protocol = parsed.protocol.toLowerCase();

    // Canonicalize host
    const hostname = parsed.hostname.toLowerCase();

    // Strip standard ports
    let port = parsed.port;
    if ((protocol === 'http:' && port === '80') || (protocol === 'https:' && port === '443')) {
      port = '';
    }

    // Path normalization: remove duplicate slashes and redundant trailing slash (except root)
    let pathname = parsed.pathname.replace(/\/+/g, '/');
    if (pathname.length > 1 && pathname.endsWith('/')) {
      pathname = pathname.slice(0, -1);
    }
    if (!pathname) {
      pathname = '/';
    }

    // Filter and sort search params
    const filteredParams: [string, string][] = [];
    for (const [key, value] of Array.from(parsed.searchParams.entries())) {
      const isTracking = TRACKING_PARAM_PATTERNS.some(pattern => pattern.test(key));
      if (!isTracking) {
        filteredParams.push([key, value]);
      }
    }

    // Sort query keys alphabetically for canonical key order
    filteredParams.sort(([a], [b]) => a.localeCompare(b));

    const searchParams = new URLSearchParams();
    for (const [k, v] of filteredParams) {
      searchParams.append(k, v);
    }

    const searchStr = searchParams.toString() ? `?${searchParams.toString()}` : '';
    const portStr = port ? `:${port}` : '';

    const normalized = `${protocol}//${hostname}${portStr}${pathname}${searchStr}`;
    return normalized.replace(/%5BREDACTED%5D/gi, '[REDACTED]');
  } catch {
    // Fallback for non-parseable inputs: lowercase and strip tracking via regex
    let fallback = redacted.toLowerCase().trim();
    fallback = fallback.replace(/([?&])(?:utm_[^&=]+|fbclid|gclid|msclkid)=[^&]*&?/gi, '$1');
    fallback = fallback.replace(/[?&]$/, '');
    return fallback.replace(/%5BREDACTED%5D/gi, '[REDACTED]');
  }
}

/**
 * Generates a SHA-256 hashed cache key from a normalized URL.
 * Scoped by provider ID or 'agg' for aggregated results.
 */
export function generateUrlCacheKey(normalizedUrl: string, providerId?: string): string {
  const hash = crypto.createHash('sha256').update(normalizedUrl).digest('hex');
  const scope = providerId ? providerId.toLowerCase().trim() : 'agg';
  return `rep:${scope}:${hash}`;
}

/**
 * Redis-backed reputation cache with in-memory fallback.
 * Automatically switches to in-memory store if Redis is unavailable or fails.
 */
export class RedisReputationCache implements ReputationCache {
  // In-memory fallback map (stores entry and expiration timestamp ms)
  private inMemoryFallback = new Map<string, { entry: ReputationCacheEntry; expiresAt: number }>();

  // Default TTL: 3600 seconds (1 hour)
  private readonly defaultTtlSeconds: number;

  constructor(defaultTtlSeconds = 3600) {
    this.defaultTtlSeconds = defaultTtlSeconds;
  }

  /**
   * Retrieves a cached reputation entry.
   * Returns the entry if fresh or marks as stale if past expiration.
   */
  async get(key: string): Promise<ReputationCacheEntry | null> {
    try {
      const redis = await getRedis();
      if (redis) {
        const raw = await redis.get(key);
        if (raw) {
          const parsed = JSON.parse(raw) as ReputationCacheEntry;
          const now = Date.now();
          if (now > parsed.expiresAt) {
            parsed.stale = true;
          }
          return parsed;
        }
        return null;
      }
    } catch (err) {
      if (process.env.NODE_ENV === 'production') {
        console.warn('Reputation cache: Redis get failed, using local fallback', err instanceof Error ? err.message : err);
      }
    }

    // In-memory fallback check
    const local = this.inMemoryFallback.get(key);
    if (!local) return null;

    const now = Date.now();
    const isStale = now > local.expiresAt;
    return {
      ...local.entry,
      stale: isStale,
    };
  }

  /**
   * Caches a reputation entry with a TTL in seconds.
   */
  async set(key: string, entry: ReputationCacheEntry, ttlSeconds?: number): Promise<void> {
    const ttl = ttlSeconds ?? this.defaultTtlSeconds;
    const now = Date.now();
    const expiresAt = entry.expiresAt !== undefined ? entry.expiresAt : now + ttl * 1000;

    const updatedEntry: ReputationCacheEntry = {
      ...entry,
      cachedAt: entry.cachedAt || now,
      expiresAt,
      stale: now > expiresAt,
    };

    // Update in-memory fallback
    this.inMemoryFallback.set(key, {
      entry: updatedEntry,
      expiresAt,
    });

    try {
      const redis = await getRedis();
      if (redis) {
        await redis.set(key, JSON.stringify(updatedEntry), 'EX', ttl);
      }
    } catch (err) {
      if (process.env.NODE_ENV === 'production') {
        console.warn('Reputation cache: Redis set failed, using local fallback', err instanceof Error ? err.message : err);
      }
    }
  }

  /**
   * Deletes a cache entry by key.
   */
  async delete(key: string): Promise<void> {
    this.inMemoryFallback.delete(key);
    try {
      const redis = await getRedis();
      if (redis) {
        await redis.del(key);
      }
    } catch (err) {
      if (process.env.NODE_ENV === 'production') {
        console.warn('Reputation cache: Redis delete failed', err instanceof Error ? err.message : err);
      }
    }
  }

  /**
   * Clears all in-memory entries and flushes matching Redis keys.
   */
  async clear(): Promise<void> {
    this.inMemoryFallback.clear();
    try {
      const redis = await getRedis();
      if (redis) {
        const keys = await redis.keys('rep:*');
        if (keys.length > 0) {
          await redis.del(...keys);
        }
      }
    } catch (err) {
      if (process.env.NODE_ENV === 'production') {
        console.warn('Reputation cache: Redis clear failed', err instanceof Error ? err.message : err);
      }
    }
  }
}

// Global default cache instance
export const reputationCache = new RedisReputationCache();
