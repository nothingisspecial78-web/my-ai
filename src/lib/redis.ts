import Redis from 'ioredis';

const globalForRedis = global as unknown as { redis: Redis | null };

const createRedisClient = (): Redis | null => {
  if (!process.env.REDIS_URL) return null;
  return new Redis(process.env.REDIS_URL, {
    maxRetriesPerRequest: 3,
    enableOfflineQueue: false,
    lazyConnect: true,
  });
};

export const redis: Redis | null =
  globalForRedis.redis || createRedisClient();

if (process.env.NODE_ENV !== 'production' && redis) {
  globalForRedis.redis = redis;
}

/**
 * Returns a connected Redis client, or null if Redis is unavailable.
 * Handles the Vercel serverless cold-start race condition where
 * ioredis hasn't finished the TCP+TLS handshake before the first command.
 */
export async function getRedis(): Promise<Redis | null> {
  if (!redis) return null;

  // If already connected, return immediately
  if (redis.status === 'ready') return redis;

  // If not yet connecting, initiate connection
  if (redis.status === 'wait') {
    try {
      await redis.connect();
      return redis;
    } catch {
      return null;
    }
  }

  // If currently connecting, wait for it
  if (redis.status === 'connecting' || redis.status === 'reconnecting') {
    try {
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Redis connect timeout')), 5000);
        redis.once('ready', () => { clearTimeout(timeout); resolve(); });
        redis.once('error', (err) => { clearTimeout(timeout); reject(err); });
      });
      return redis;
    } catch {
      return null;
    }
  }

  // Any other status (end, close) — not usable
  return null;
}
