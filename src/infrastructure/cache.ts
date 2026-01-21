import Redis, { RedisOptions } from 'ioredis';
import { infraLogger } from './logger.js';
import { resilientOperations } from './resilience.js';

export function createCache(): Redis {
  // Use cluster Redis connection from Dragonfly
  const host = process.env['REDIS_HOST'] || process.env['DRAGONFLY_HOST'] || 'localhost';
  const port = parseInt(process.env['REDIS_PORT'] || process.env['DRAGONFLY_PORT'] || '6379', 10);
  const password = process.env['REDIS_PASSWORD'] || process.env['DRAGONFLY_PASSWORD'];
  const username = process.env['REDIS_USERNAME'] || process.env['DRAGONFLY_USERNAME'];

  const config: RedisOptions = {
    host,
    port,
    maxRetriesPerRequest: 3,
    lazyConnect: true,
  };

  if (password) {
    config.password = password;
  }

  if (username) {
    config.username = username;
  }

  const redis = new Redis(config);
  
  // Log cache connection
  infraLogger.cacheConnected();
  
  return redis;
}

// Health check
export async function checkCacheHealth(redis: Redis): Promise<boolean> {
  try {
    // Use resilient cache operation for health check
    const result = await resilientOperations.cacheCall(async () => {
      return redis.ping();
    }, 'health_check');
    return result === 'PONG';
  } catch (error) {
    infraLogger.cacheError(error instanceof Error ? error : new Error(String(error)), 'health_check');
    return false;
  }
}