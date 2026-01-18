import { Redis } from 'ioredis';

export interface TokenCacheEntry {
  userId: string;
  orgId: string;
  role: string;
}

export class TokenCache {
  private redis: Redis;
  private readonly TTL_SECONDS = 60; // 60s TTL as per P2 requirement

  constructor(redis: Redis) {
    this.redis = redis;
  }

  /**
   * Get cached token data by token hash prefix
   * @param tokenHashPrefix - First 8 characters of token hash for cache key
   * @returns Token data or null if not found/expired
   */
  async get(tokenHashPrefix: string): Promise<TokenCacheEntry | null> {
    try {
      const cacheKey = `token:${tokenHashPrefix}`;
      const cached = await this.redis.get(cacheKey);
      
      if (!cached) {
        return null;
      }

      return JSON.parse(cached) as TokenCacheEntry;
    } catch (error) {
      console.error('Token cache get error:', error);
      return null; // Fail open - proceed to database lookup
    }
  }

  /**
   * Cache token data with TTL
   * @param tokenHashPrefix - First 8 characters of token hash for cache key
   * @param userId - User ID
   * @param orgId - Organization ID  
   * @param role - User role in organization
   */
  async set(tokenHashPrefix: string, userId: string, orgId: string, role: string): Promise<void> {
    try {
      const cacheKey = `token:${tokenHashPrefix}`;
      const entry: TokenCacheEntry = { userId, orgId, role };
      
      await this.redis.setex(cacheKey, this.TTL_SECONDS, JSON.stringify(entry));
    } catch (error) {
      console.error('Token cache set error:', error);
      // Fail silently - cache is performance optimization, not critical
    }
  }

  /**
   * Invalidate cached token data
   * @param tokenHashPrefix - First 8 characters of token hash
   */
  async invalidate(tokenHashPrefix: string): Promise<void> {
    try {
      const cacheKey = `token:${tokenHashPrefix}`;
      await this.redis.del(cacheKey);
    } catch (error) {
      console.error('Token cache invalidate error:', error);
      // Fail silently - invalidation is best effort
    }
  }
}