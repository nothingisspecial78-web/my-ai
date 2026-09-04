import Redis from 'ioredis';

const globalForRedis = global as unknown as { redis: Redis };

export const redis =
  globalForRedis.redis ||
  (process.env.REDIS_URL
    ? new Redis(process.env.REDIS_URL, {
        maxRetriesPerRequest: 3,
        // Disable automatic offline queueing so it fails fast if Redis is down
        enableOfflineQueue: false,
      })
    : null);

if (process.env.NODE_ENV !== 'production' && redis) {
  globalForRedis.redis = redis;
}
