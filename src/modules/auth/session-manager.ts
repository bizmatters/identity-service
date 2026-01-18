import { randomUUID } from 'crypto';
import type { Redis } from 'ioredis';

export interface SessionData {
  user_id: string;
  org_id: string;
  role: string;
  created_at: number;
  last_accessed: number;
  absolute_expiry: number; // 7 days from creation, never extended
}

export interface SessionConfig {
  sessionTTL: number; // 24 hours in seconds (sliding window)
  absoluteTTL: number; // 7 days in seconds (absolute maximum)
}

export class SessionManager {
  private readonly SESSION_KEY_PREFIX = 'session:';

  constructor(
    private cache: Redis,
    private config: SessionConfig
  ) { }

  /**
   * Create a new session in Hot_Cache
   * Requirements: 1.9, 2.4, 6.7
   */
  async createSession(userId: string, orgId: string, role: string): Promise<string> {
    const sessionId = randomUUID();
    const now = Date.now();

    const sessionData: SessionData = {
      user_id: userId,
      org_id: orgId,
      role,
      created_at: now,
      last_accessed: now,
      absolute_expiry: now + (this.config.absoluteTTL * 1000), // 7 days from creation
    };

    const key = this.getSessionKey(sessionId);

    try {
      // Store session with sliding TTL (24 hours)
      await this.cache.setex(
        key,
        this.config.sessionTTL,
        JSON.stringify(sessionData)
      );

      return sessionId;
    } catch (error) {
      throw new Error(`Failed to create session: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Regenerate session ID to prevent session fixation (P0)
   * Requirements: 1.9, 2.4
   */
  async regenerateSession(oldSessionId: string, userId: string, orgId: string, role: string): Promise<string> {
    // Delete old session
    await this.deleteSession(oldSessionId);

    // Create new session with same user context
    return this.createSession(userId, orgId, role);
  }

  /**
   * Get session data with TTL and absolute_expiry validation
   * Requirements: 2.5, 6.7
   */
  async getSession(sessionId: string): Promise<SessionData | null> {
    const key = this.getSessionKey(sessionId);

    try {
      const sessionJson = await this.cache.get(key);
      if (!sessionJson) {
        return null;
      }

      const sessionData = JSON.parse(sessionJson) as SessionData;

      // Check absolute expiry (7 days from creation, never extended)
      if (Date.now() > sessionData.absolute_expiry) {
        // Session has exceeded absolute expiry, delete it
        await this.deleteSession(sessionId);
        return null;
      }

      return sessionData;
    } catch (error) {
      throw new Error(`Failed to get session: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Update last accessed timestamp with sliding expiration (P2)
   * Respects absolute_expiry - won't extend beyond 7 days from creation
   * Requirements: 2.5, 6.7
   */
  async updateLastAccessed(sessionId: string): Promise<void> {
    const sessionData = await this.getSession(sessionId);
    if (!sessionData) {
      return; // Session doesn't exist or expired
    }

    const now = Date.now();

    // Check if we're still within absolute expiry window
    if (now > sessionData.absolute_expiry) {
      await this.deleteSession(sessionId);
      return;
    }

    // Update last accessed timestamp
    sessionData.last_accessed = now;

    const key = this.getSessionKey(sessionId);

    try {
      // Refresh sliding TTL (24 hours) but respect absolute expiry
      const remainingTime = Math.max(0, sessionData.absolute_expiry - now);
      const ttlSeconds = Math.min(this.config.sessionTTL, Math.floor(remainingTime / 1000));

      if (ttlSeconds > 0) {
        await this.cache.setex(
          key,
          ttlSeconds,
          JSON.stringify(sessionData)
        );
      } else {
        // Session has reached absolute expiry
        await this.deleteSession(sessionId);
      }
    } catch (error) {
      throw new Error(`Failed to update session: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Update session context (for organization switching)
   * Requirements: 3.8, 3.9
   */
  async updateSession(sessionId: string, updates: Partial<Pick<SessionData, 'org_id' | 'role'>>): Promise<void> {
    const sessionData = await this.getSession(sessionId);
    if (!sessionData) {
      throw new Error('Session not found or expired');
    }

    // Apply updates
    Object.assign(sessionData, updates);
    sessionData.last_accessed = Date.now();

    const key = this.getSessionKey(sessionId);

    try {
      // Calculate remaining TTL respecting absolute expiry
      const remainingTime = Math.max(0, sessionData.absolute_expiry - Date.now());
      const ttlSeconds = Math.min(this.config.sessionTTL, Math.floor(remainingTime / 1000));

      if (ttlSeconds > 0) {
        await this.cache.setex(
          key,
          ttlSeconds,
          JSON.stringify(sessionData)
        );
      } else {
        // Session has reached absolute expiry
        await this.deleteSession(sessionId);
        throw new Error('Session has expired');
      }
    } catch (error) {
      throw new Error(`Failed to update session: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Delete session from Hot_Cache
   * Requirements: 1.9
   */
  async deleteSession(sessionId: string): Promise<void> {
    const key = this.getSessionKey(sessionId);

    try {
      await this.cache.del(key);
    } catch (error) {
      throw new Error(`Failed to delete session: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Check if session exists and is valid
   */
  async sessionExists(sessionId: string): Promise<boolean> {
    const session = await this.getSession(sessionId);
    return session !== null;
  }

  /**
   * Get session key for Redis
   */
  private getSessionKey(sessionId: string): string {
    return `${this.SESSION_KEY_PREFIX}${sessionId}`;
  }
}