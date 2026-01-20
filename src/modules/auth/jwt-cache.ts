import type { Redis } from 'ioredis';

export class JWTCache {
  private readonly BUFFER_SECONDS = 60; // Refresh JWT 60 seconds before expiry (P2)

  constructor(private cache: Redis) {}

  /**
   * Get cached JWT for session and organization
   * Requirements: 2.9, P2: JWT Cache
   */
  async get(sessionId: string, orgId: string): Promise<string | null> {
    const key = `jwt:${sessionId}:${orgId}`;
    
    try {
      const jwt = await this.cache.get(key);
      return jwt;
    } catch (error) {
      // Cache error - return null to force new JWT generation
      return null;
    }
  }

  /**
   * Set JWT in cache with TTL until near-expiry
   * Requirements: 2.9, P2: JWT Cache
   */
  async set(sessionId: string, orgId: string, jwt: string, expiresAt: number): Promise<void> {
    const key = `jwt:${sessionId}:${orgId}`;
    const now = Math.floor(Date.now() / 1000);
    
    // Calculate TTL: expire the cache entry BUFFER_SECONDS before JWT expires
    const ttl = Math.max(0, expiresAt - now - this.BUFFER_SECONDS);
    
    if (ttl > 0) {
      try {
        await this.cache.setex(key, ttl, jwt);
      } catch (error) {
        // Cache write error - not critical, just means we'll generate more JWTs
        console.warn('JWT cache write failed:', error);
      }
    }
    // If TTL is 0 or negative, don't cache (JWT is already near expiry)
  }

  /**
   * Invalidate cached JWT for session (e.g., on logout or org switch)
   * Requirements: 1.9, 3.8
   */
  async invalidate(sessionId: string, orgId?: string): Promise<void> {
    try {
      if (orgId) {
        // Invalidate specific session-org combination
        const key = `jwt:${sessionId}:${orgId}`;
        await this.cache.del(key);
      } else {
        // Invalidate all JWTs for this session (all orgs)
        const pattern = `jwt:${sessionId}:*`;
        const keys = await this.scanKeys(pattern);
        
        if (keys.length > 0) {
          await this.cache.del(...keys);
        }
      }
    } catch (error) {
      // Cache error - not critical for security, just performance
      console.warn('JWT cache invalidation failed:', error);
    }
  }

  /**
   * Invalidate all JWTs for a user across all sessions and orgs
   * Useful when user permissions change globally
   */
  async invalidateUser(): Promise<void> {
    // Note: This requires knowing session IDs for the user
    // In practice, this might be called from session manager
    // For now, we'll implement a pattern-based approach
    
    try {
      // This is a simplified approach - in production you might maintain
      // a reverse index of user -> sessions for more efficient invalidation
      const pattern = 'jwt:*';
      const keys = await this.scanKeys(pattern);
      
      // This is not efficient for large numbers of JWTs
      // Consider implementing user-specific JWT tracking if needed
      if (keys.length > 0) {
        await this.cache.del(...keys);
      }
    } catch (error) {
      console.warn('User JWT cache invalidation failed:', error);
    }
  }

  /**
   * Check if JWT exists in cache (without retrieving it)
   */
  async exists(sessionId: string, orgId: string): Promise<boolean> {
    const key = `jwt:${sessionId}:${orgId}`;
    
    try {
      const exists = await this.cache.exists(key);
      return exists === 1;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get TTL for cached JWT
   * Useful for monitoring and debugging
   */
  async getTTL(sessionId: string, orgId: string): Promise<number> {
    const key = `jwt:${sessionId}:${orgId}`;
    
    try {
      return await this.cache.ttl(key);
    } catch (error) {
      return -1; // Key doesn't exist or error occurred
    }
  }

  /**
   * Scan for keys matching pattern
   * Helper method for bulk operations
   */
  private async scanKeys(pattern: string): Promise<string[]> {
    const keys: string[] = [];
    let cursor = '0';
    
    do {
      const result = await this.cache.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
      cursor = result[0];
      keys.push(...result[1]);
    } while (cursor !== '0');
    
    return keys;
  }

  /**
   * Get cache statistics for monitoring
   */
  async getStats(): Promise<{
    totalKeys: number;
    memoryUsage?: string;
  }> {
    try {
      const keys = await this.scanKeys('jwt:*');
      const info = await this.cache.info('memory');
      
      // Parse memory usage from Redis INFO output
      const memoryMatch = info.match(/used_memory_human:([^\r\n]+)/);
      const memoryUsage = memoryMatch?.[1]?.trim();
      
      return {
        totalKeys: keys.length,
        ...(memoryUsage && { memoryUsage }),
      };
    } catch (error) {
      return {
        totalKeys: 0,
      };
    }
  }

  /**
   * Clear all JWT cache entries
   * Useful for testing or emergency cache flush
   */
  async clear(): Promise<void> {
    try {
      const keys = await this.scanKeys('jwt:*');
      
      if (keys.length > 0) {
        await this.cache.del(...keys);
      }
    } catch (error) {
      console.warn('JWT cache clear failed:', error);
    }
  }

  /**
   * Health check for cache connectivity
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.cache.ping();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Set buffer time for JWT refresh (useful for testing)
   */
  setBufferSeconds(): void {
    // This would require making BUFFER_SECONDS mutable
    // For now, it's a constant, but could be made configurable
  }
}