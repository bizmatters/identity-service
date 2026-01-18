import type { Redis } from 'ioredis';

export interface CachedPermission {
  role: string;
  version: number;
}

export interface PermissionCacheConfig {
  ttl: number; // TTL in seconds (default: 60s)
}

/**
 * Permission cache with Singleflight pattern to prevent Thundering Herd
 * Requirements: 6.1, 6.2
 */
export class PermissionCache {
  private readonly PERMISSION_KEY_PREFIX = 'perm:';
  private readonly inflightRequests: Map<string, Promise<CachedPermission | null>> = new Map();

  constructor(
    private cache: Redis,
    private config: PermissionCacheConfig
  ) { }

  /**
   * Get cached permission or null if not found
   * Requirements: 6.1, 6.2
   */
  async get(userId: string, orgId: string): Promise<CachedPermission | null> {
    const key = this.getPermissionKey(userId, orgId);

    try {
      const cachedData = await this.cache.get(key);
      if (!cachedData) {
        return null;
      }

      return JSON.parse(cachedData) as CachedPermission;
    } catch (error) {
      // Return null on cache errors to allow fallback to database
      return null;
    }
  }

  /**
   * Set permission in cache with TTL
   * Requirements: 6.1, 6.2
   */
  async set(userId: string, orgId: string, role: string, version: number): Promise<void> {
    const key = this.getPermissionKey(userId, orgId);
    const permission: CachedPermission = { role, version };

    try {
      await this.cache.setex(
        key,
        this.config.ttl,
        JSON.stringify(permission)
      );
    } catch (error) {
      // Continue even if cache write fails
      console.warn(`Failed to cache permission for ${userId}:${orgId}:`, error);
    }
  }

  /**
   * Invalidate cached permission
   * Requirements: 6.1, 6.2
   */
  async invalidate(userId: string, orgId: string): Promise<void> {
    const key = this.getPermissionKey(userId, orgId);

    try {
      await this.cache.del(key);
    } catch (error) {
      // Continue even if cache delete fails
      console.warn(`Failed to invalidate permission cache for ${userId}:${orgId}:`, error);
    }
  }

  /**
   * Get permission with Singleflight pattern (request collapsing)
   * Prevents Thundering Herd on cache expiry by coalescing concurrent requests
   * Requirements: 6.1, 6.2
   */
  async getOrFetch(
    userId: string,
    orgId: string,
    fetchFn: () => Promise<CachedPermission | null>
  ): Promise<CachedPermission | null> {
    // First try cache
    const cached = await this.get(userId, orgId);
    if (cached) {
      return cached;
    }

    // Use Singleflight pattern for cache miss
    const key = this.getPermissionKey(userId, orgId);

    // Check if there's already an inflight request for this key
    const existingRequest = this.inflightRequests.get(key);
    if (existingRequest) {
      return existingRequest;
    }

    // Create new request and store it
    const request = this.executeFetch(userId, orgId, fetchFn);
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
   * Execute the fetch function and cache the result
   */
  private async executeFetch(
    userId: string,
    orgId: string,
    fetchFn: () => Promise<CachedPermission | null>
  ): Promise<CachedPermission | null> {
    const permission = await fetchFn();

    if (permission) {
      // Cache the result
      await this.set(userId, orgId, permission.role, permission.version);
    }

    return permission;
  }

  /**
   * Invalidate all permissions for a user (useful when user is deleted)
   */
  async invalidateUser(userId: string): Promise<void> {
    try {
      const pattern = this.getPermissionKey(userId, '*');
      const keys = await this.cache.keys(pattern);

      if (keys.length > 0) {
        await this.cache.del(...keys);
      }
    } catch (error) {
      console.warn(`Failed to invalidate user permissions for ${userId}:`, error);
    }
  }

  /**
   * Invalidate all permissions for an organization (useful when org is deleted)
   */
  async invalidateOrganization(orgId: string): Promise<void> {
    try {
      const pattern = this.getPermissionKey('*', orgId);
      const keys = await this.cache.keys(pattern);

      if (keys.length > 0) {
        await this.cache.del(...keys);
      }
    } catch (error) {
      console.warn(`Failed to invalidate organization permissions for ${orgId}:`, error);
    }
  }

  /**
   * Get cache statistics (useful for monitoring)
   */
  getStats(): { inflightRequests: number } {
    return {
      inflightRequests: this.inflightRequests.size,
    };
  }

  /**
   * Generate Redis key for permission cache
   */
  private getPermissionKey(userId: string, orgId: string): string {
    return `${this.PERMISSION_KEY_PREFIX}${userId}:${orgId}`;
  }
}