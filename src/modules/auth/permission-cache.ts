import type { Redis } from 'ioredis';

export interface CachedPermission {
  role: string;
  version: number;
}

export class PermissionCache {
  private inflightRequests: Map<string, Promise<CachedPermission | null>> = new Map();
  private readonly TTL = 60; // 60 seconds (P1: Permission Cache)

  constructor(private cache: Redis) {}

  /**
   * Get cached permission with Singleflight pattern (P1: Request Collapsing)
   * Requirements: 6.1, 6.2
   */
  async get(userId: string, orgId: string): Promise<CachedPermission | null> {
    const key = `perm:${userId}:${orgId}`;
    
    // Check if there's already an inflight request for this key
    const inflightRequest = this.inflightRequests.get(key);
    if (inflightRequest) {
      return inflightRequest;
    }

    // Create new request and store it to prevent duplicate requests
    const request = this.fetchFromCache(key);
    this.inflightRequests.set(key, request);

    try {
      const result = await request;
      return result;
    } finally {
      // Clean up inflight request
      this.inflightRequests.delete(key);
    }
  }

  /**
   * Fetch permission from Redis cache
   */
  private async fetchFromCache(key: string): Promise<CachedPermission | null> {
    try {
      const data = await this.cache.get(key);
      if (!data) {
        return null;
      }

      const permission = JSON.parse(data) as CachedPermission;
      return permission;
    } catch (error) {
      // Invalid JSON or other error - treat as cache miss
      return null;
    }
  }

  /**
   * Set permission in cache with TTL
   * Requirements: 6.1, 6.2
   */
  async set(userId: string, orgId: string, role: string, version: number): Promise<void> {
    const key = `perm:${userId}:${orgId}`;
    const permission: CachedPermission = { role, version };
    
    await this.cache.setex(
      key,
      this.TTL,
      JSON.stringify(permission)
    );
  }

  /**
   * Invalidate cached permission (e.g., when role changes)
   * Requirements: 6.4
   */
  async invalidate(userId: string, orgId: string): Promise<void> {
    const key = `perm:${userId}:${orgId}`;
    await this.cache.del(key);
    
    // Also remove any inflight requests for this key
    this.inflightRequests.delete(key);
  }

  /**
   * Invalidate all permissions for a user (e.g., when user is deleted)
   */
  async invalidateUser(userId: string): Promise<void> {
    // Use Redis SCAN to find all keys for this user
    const pattern = `perm:${userId}:*`;
    const keys: string[] = [];
    
    let cursor = '0';
    do {
      const result = await this.cache.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
      cursor = result[0];
      keys.push(...result[1]);
    } while (cursor !== '0');

    if (keys.length > 0) {
      await this.cache.del(...keys);
    }

    // Clean up any inflight requests for this user
    for (const [key] of this.inflightRequests) {
      if (key.startsWith(`perm:${userId}:`)) {
        this.inflightRequests.delete(key);
      }
    }
  }

  /**
   * Get or fetch pattern with custom fetch function
   * Implements Singleflight pattern to prevent Thundering Herd effect
   */
  async getOrFetch(
    userId: string,
    orgId: string,
    fetchFn: () => Promise<CachedPermission | null>
  ): Promise<CachedPermission | null> {
    // First try to get from cache
    const cached = await this.get(userId, orgId);
    if (cached) {
      return cached;
    }

    const key = `perm:${userId}:${orgId}`;
    
    // Check if there's already an inflight fetch for this key
    const inflightRequest = this.inflightRequests.get(`fetch:${key}`);
    if (inflightRequest) {
      return inflightRequest;
    }

    // Create new fetch request and store it
    const fetchRequest = this.executeFetch(userId, orgId, fetchFn);
    this.inflightRequests.set(`fetch:${key}`, fetchRequest);

    try {
      const result = await fetchRequest;
      return result;
    } finally {
      // Clean up inflight request
      this.inflightRequests.delete(`fetch:${key}`);
    }
  }

  /**
   * Execute fetch function and cache result
   */
  private async executeFetch(
    userId: string,
    orgId: string,
    fetchFn: () => Promise<CachedPermission | null>
  ): Promise<CachedPermission | null> {
    try {
      const result = await fetchFn();
      
      if (result) {
        // Cache the result
        await this.set(userId, orgId, result.role, result.version);
      }
      
      return result;
    } catch (error) {
      // Don't cache errors, just return null
      return null;
    }
  }

  /**
   * Get cache statistics for monitoring
   */
  async getStats(): Promise<{
    inflightRequests: number;
    cacheKeys: number;
  }> {
    // Count permission cache keys
    let cacheKeys = 0;
    let cursor = '0';
    do {
      const result = await this.cache.scan(cursor, 'MATCH', 'perm:*', 'COUNT', 100);
      cursor = result[0];
      cacheKeys += result[1].length;
    } while (cursor !== '0');

    return {
      inflightRequests: this.inflightRequests.size,
      cacheKeys,
    };
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
   * Clear all inflight requests (useful for testing)
   */
  clearInflightRequests(): void {
    this.inflightRequests.clear();
  }
}