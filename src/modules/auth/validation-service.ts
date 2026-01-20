import { SessionManager, SessionData } from './session-manager.js';
import { TokenManager, TokenValidationResult } from './token-manager.js';
import { PermissionCache, CachedPermission } from './permission-cache.js';
import { OrgRepository, UserRoleWithVersion } from '../org/org-repository.js';

export interface ValidationResult {
  userId: string;
  orgId: string;
  role: string;
  version: number;
}

export class ValidationError extends Error {
  constructor(message: string, public statusCode: number = 401) {
    super(message);
    this.name = 'ValidationError';
  }
}

export class ValidationService {
  constructor(
    private sessionManager: SessionManager,
    private tokenManager: TokenManager,
    private permissionCache: PermissionCache,
    private orgRepository: OrgRepository
  ) {}

  /**
   * Validate session with permission cache (P1)
   * Requirements: 2.3, 2.4, 2.5, 2.6, 2.7, 2.8
   */
  async validateSession(sessionId: string): Promise<ValidationResult> {
    // Get session data
    const sessionData = await this.sessionManager.getSession(sessionId);
    if (!sessionData) {
      throw new ValidationError('Invalid or expired session', 401);
    }

    // Update last accessed time (sliding expiration)
    await this.sessionManager.updateLastAccessed(sessionId);

    // Get user role with permission cache (P1)
    const permission = await this.getPermissionWithCache(
      sessionData.user_id,
      sessionData.org_id
    );

    return {
      userId: sessionData.user_id,
      orgId: sessionData.org_id,
      role: permission.role,
      version: permission.version,
    };
  }

  /**
   * Validate API token with token cache (P2)
   * Requirements: 4.8, 4.9, 4.10, 4.11
   */
  async validateApiToken(token: string): Promise<ValidationResult> {
    // Validate token format and get cached/database result
    const tokenResult = await this.tokenManager.validateApiToken(token);

    // Get user role with permission cache (P1)
    const permission = await this.getPermissionWithCache(
      tokenResult.userId,
      tokenResult.orgId
    );

    return {
      userId: tokenResult.userId,
      orgId: tokenResult.orgId,
      role: permission.role,
      version: permission.version,
    };
  }

  /**
   * Get user permission with caching and Singleflight pattern
   * Implements P1: Permission Cache with request collapsing
   */
  private async getPermissionWithCache(
    userId: string,
    orgId: string
  ): Promise<CachedPermission> {
    // Use permission cache with Singleflight pattern to prevent Thundering Herd
    const permission = await this.permissionCache.getOrFetch(
      userId,
      orgId,
      async () => {
        // Fetch from database if not in cache
        const userRole = await this.orgRepository.getUserRole(userId, orgId);
        if (!userRole) {
          return null; // User not found in organization
        }

        return {
          role: userRole.role,
          version: userRole.version,
        };
      }
    );

    if (!permission) {
      throw new ValidationError('User not found in organization', 401);
    }

    return permission;
  }

  /**
   * Invalidate user permissions (e.g., when role changes)
   * Requirements: 6.4
   */
  async invalidateUserPermissions(userId: string, orgId: string): Promise<void> {
    await this.permissionCache.invalidate(userId, orgId);
  }

  /**
   * Invalidate all permissions for a user (e.g., when user is deleted)
   */
  async invalidateAllUserPermissions(userId: string): Promise<void> {
    await this.permissionCache.invalidateUser(userId);
  }

  /**
   * Health check for all dependencies
   */
  async healthCheck(): Promise<{
    session: boolean;
    permission: boolean;
  }> {
    const [sessionHealth, permissionHealth] = await Promise.all([
      this.sessionManager.healthCheck(),
      this.permissionCache.healthCheck(),
    ]);

    return {
      session: sessionHealth,
      permission: permissionHealth,
    };
  }

  /**
   * Get validation statistics for monitoring
   */
  async getStats(): Promise<{
    permissionCache: {
      inflightRequests: number;
      cacheKeys: number;
    };
  }> {
    const permissionStats = await this.permissionCache.getStats();

    return {
      permissionCache: permissionStats,
    };
  }
}