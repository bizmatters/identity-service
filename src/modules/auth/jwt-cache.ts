import type { Redis } from 'ioredis';

export interface JWTCacheConfig {
  bufferSeconds: number; // Buffer time before expiry to refresh JWT (default: 60s)
}

/**
 * JWT Cache for caching signed JWTs per session until near-expiry
 * Requirements: 2.9
 */
export class JWTCache {
  private readonly JWT_KEY_PREFIX = 'jwt:';

  constructor(
    private cache: Redis,
    private config: JWTCacheConfig
  ) {}

  /**
   * Get cached JWT for session and organization
   * Requirements: 2.9
   */
  async get(sessionId: string, orgId: string): Promise<string | null> {
    const key = this.getJWTKey(sessionId, orgId);
    
    try {
      return await this.cache.get(key);
    } catch (error) {
      // Return null on cache errors to allow fallback to JWT minting
      return null;
    }
  }

  /**
   * Cache JWT with TTL = exp - buffer seconds (P2)
   * Requirements: 2.9
   */
  async set(sessionId: string, orgId: string, jwt: string, expiresAt: number): Promise<void> {
    const key = this.getJWTKey(sessionId, orgId);
    
    try {
      // Calculate TTL: expiry time minus buffer seconds
      const now = Math.floor(Date.now() / 1000);
      const ttl = Math.max(0, expiresAt - now - this.config.bufferSeconds);
      
      if (ttl > 0) {
        await this.cache.setex(key, ttl, jwt);
      }
      // If TTL is 0 or negative, don't cache (JWT is already near expiry)
    } catch (error) {
      // Continue even if cache write fails
      console.warn(`Failed to cache JWT for ${sessionId}:${orgId}:`, error);
    }
  }

  /**
   * Invalidate cached JWT for session (all organizations)
   * Requirements: 2.9
   */
  async invalidate(sessionId: string): Promise<void> {
    try {
      const pattern = this.getJWTKey(sessionId, '*');
      const keys = await this.cache.keys(pattern);
      
      if (keys.length > 0) {
        await this.cache.del(...keys);
      }
    } catch (error) {
      // Continue even if cache delete fails
      console.warn(`Failed to invalidate JWT cache for session ${sessionId}:`, error);
    }
  }

  /**
   * Invalidate cached JWT for specific session and organization
   * Requirements: 2.9
   */
  async invalidateSpecific(sessionId: string, orgId: string): Promise<void> {
    const key = this.getJWTKey(sessionId, orgId);
    
    try {
      await this.cache.del(key);
    } catch (error) {
      // Continue even if cache delete fails
      console.warn(`Failed to invalidate JWT cache for ${sessionId}:${orgId}:`, error);
    }
  }

  /**
   * Check if JWT exists in cache and is not near expiry
   */
  async exists(sessionId: string, orgId: string): Promise<boolean> {
    const jwt = await this.get(sessionId, orgId);
    return jwt !== null;
  }

  /**
   * Get all cached JWTs for a session (useful for debugging)
   */
  async getSessionJWTs(sessionId: string): Promise<Record<string, string>> {
    try {
      const pattern = this.getJWTKey(sessionId, '*');
      const keys = await this.cache.keys(pattern);
      
      if (keys.length === 0) {
        return {};
      }

      const values = await this.cache.mget(...keys);
      const result: Record<string, string> = {};
      
      keys.forEach((key, index) => {
        const value = values[index];
        if (value) {
          // Extract orgId from key
          const orgId = key.split(':').pop();
          if (orgId) {
            result[orgId] = value;
          }
        }
      });

      return result;
    } catch (error) {
      console.warn(`Failed to get session JWTs for ${sessionId}:`, error);
      return {};
    }
  }

  /**
   * Clear all JWT cache entries (useful for testing)
   */
  async clear(): Promise<void> {
    try {
      const pattern = `${this.JWT_KEY_PREFIX}*`;
      const keys = await this.cache.keys(pattern);
      
      if (keys.length > 0) {
        await this.cache.del(...keys);
      }
    } catch (error) {
      console.warn('Failed to clear JWT cache:', error);
    }
  }

  /**
   * Get cache statistics (useful for monitoring)
   */
  async getStats(): Promise<{ totalKeys: number; keysBySession: Record<string, number> }> {
    try {
      const pattern = `${this.JWT_KEY_PREFIX}*`;
      const keys = await this.cache.keys(pattern);
      
      const keysBySession: Record<string, number> = {};
      
      keys.forEach(key => {
        // Extract sessionId from key (format: jwt:sessionId:orgId)
        const parts = key.split(':');
        if (parts.length >= 3) {
          const sessionId = parts[1];
          if (sessionId) {
            keysBySession[sessionId] = (keysBySession[sessionId] || 0) + 1;
          }
        }
      });

      return {
        totalKeys: keys.length,
        keysBySession,
      };
    } catch (error) {
      console.warn('Failed to get JWT cache stats:', error);
      return { totalKeys: 0, keysBySession: {} };
    }
  }

  /**
   * Generate Redis key for JWT cache
   */
  private getJWTKey(sessionId: string, orgId: string): string {
    return `${this.JWT_KEY_PREFIX}${sessionId}:${orgId}`;
  }
}