import Redis from 'ioredis';

export function createCache(): Redis {
  const config: any = {
    host: process.env['REDIS_HOST'] || 'localhost',
    port: parseInt(process.env['REDIS_PORT'] || '6379', 10),
    maxRetriesPerRequest: 3,
    lazyConnect: true,
  };

  if (process.env['REDIS_PASSWORD']) {
    config.password = process.env['REDIS_PASSWORD'];
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