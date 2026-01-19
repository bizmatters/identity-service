import Redis, { RedisOptions } from 'ioredis';

export function createCache(): Redis {
  // Use cluster Redis connection from Dragonfly
  const host = process.env['REDIS_HOST'] || process.env['DRAGONFLY_HOST'] || 'localhost';
  const port = parseInt(process.env['REDIS_PORT'] || process.env['DRAGONFLY_PORT'] || '6379', 10);
  const password = process.env['REDIS_PASSWORD'] || process.env['DRAGONFLY_PASSWORD'];

  const config: RedisOptions = {
    host,
    port,
    maxRetriesPerRequest: 3,
    lazyConnect: true,
  };

  if (password) {
    config.password = password;
  }

  const redis = new Redis(config);
  return redis;
}

// Health check
export async function checkCacheHealth(redis: Redis): Promise<boolean> {
  try {
    const result = await redis.ping();
    return result === 'PONG';
  } catch {
    return false;
  }
}