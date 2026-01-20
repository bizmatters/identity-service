import type { Redis } from 'ioredis';
import { randomUUID } from 'crypto';

export interface SessionData {
  user_id: string;
  org_id: string;
  role: string;
  created_at: number;
  last_accessed: number;
  absolute_expiry: number; // P2: 7 days from creation, never extended
}

export interface SessionConfig {
  sessionTTL: number;         // 24 hours in seconds (sliding window)
  absoluteTTL: number;        // 7 days in seconds (absolute maximum)
  cookieName: string;         // "__Host-platform_session"
}

export class SessionManager {
  constructor(
    private cache: Redis,
    private config: SessionConfig
  ) {}

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

    const key = `session:${sessionId}`;
    
    // Store in Redis with sliding TTL
    await this.cache.setex(
      key,
      this.config.sessionTTL,
      JSON.stringify(sessionData)
    );

    return sessionId;
  }

  /**
   * Regenerate session ID to prevent session fixation (P0)
   * Requirements: 1.9, P0: Session Fixation Fix
   */
  async regenerateSession(oldSessionId: string, userId: string, orgId: string, role: string): Promise<string> {
    // Delete old session
    await this.deleteSession(oldSessionId);
    
    // Create new session with same user context
    return this.createSession(userId, orgId, role);
  }

  /**
   * Get session data with TTL and absolute expiry validation
   * Requirements: 2.4, 2.5, 6.7
   */
  async getSession(sessionId: string): Promise<SessionData | null> {
    const key = `session:${sessionId}`;
    
    try {
      const data = await this.cache.get(key);
      if (!data) {
        return null;
      }

      const sessionData = JSON.parse(data) as SessionData;
      
      // Check absolute expiry (P2: Absolute Session Expiry)
      if (Date.now() > sessionData.absolute_expiry) {
        // Session has exceeded absolute expiry - delete it
        await this.deleteSession(sessionId);
        return null;
      }

      return sessionData;
    } catch (error) {
      // Invalid JSON or other error - treat as invalid session
      return null;
    }
  }

  /**
   * Update last accessed timestamp (P2: Sliding Expiration)
   * Respects absolute_expiry - won't extend beyond 7 days from creation
   * Requirements: 2.4, P2: Sliding Session Expiration
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

    // Update last accessed time
    sessionData.last_accessed = now;
    
    const key = `session:${sessionId}`;
    
    // Refresh TTL but respect absolute expiry
    const remainingTime = Math.floor((sessionData.absolute_expiry - now) / 1000);
    const ttl = Math.min(this.config.sessionTTL, remainingTime);
    
    if (ttl > 0) {
      await this.cache.setex(
        key,
        ttl,
        JSON.stringify(sessionData)
      );
    } else {
      // Session has reached absolute expiry
      await this.deleteSession(sessionId);
    }
  }

  /**
   * Update session data (e.g., org switching)
   * Requirements: 3.8
   */
  async updateSession(sessionId: string, updates: Partial<SessionData>): Promise<void> {
    const sessionData = await this.getSession(sessionId);
    if (!sessionData) {
      throw new Error('Session not found');
    }

    // Merge updates
    const updatedData = {
      ...sessionData,
      ...updates,
      last_accessed: Date.now(), // Always update last accessed
    };

    const key = `session:${sessionId}`;
    
    // Calculate remaining TTL respecting absolute expiry
    const now = Date.now();
    const remainingTime = Math.floor((updatedData.absolute_expiry - now) / 1000);
    const ttl = Math.min(this.config.sessionTTL, remainingTime);
    
    if (ttl > 0) {
      await this.cache.setex(
        key,
        ttl,
        JSON.stringify(updatedData)
      );
    } else {
      // Session has reached absolute expiry
      await this.deleteSession(sessionId);
      throw new Error('Session expired');
    }
  }

  /**
   * Delete session from Hot_Cache
   * Requirements: 1.9
   */
  async deleteSession(sessionId: string): Promise<void> {
    const key = `session:${sessionId}`;
    await this.cache.del(key);
  }

  /**
   * Check if session exists and is valid
   * Requirements: 2.5
   */
  async isValidSession(sessionId: string): Promise<boolean> {
    const sessionData = await this.getSession(sessionId);
    return sessionData !== null;
  }

  /**
   * Get session TTL information
   * Useful for debugging and monitoring
   */
  async getSessionTTL(sessionId: string): Promise<{ ttl: number; absoluteExpiry: number } | null> {
    const key = `session:${sessionId}`;
    const ttl = await this.cache.ttl(key);
    
    if (ttl <= 0) {
      return null; // Session doesn't exist or expired
    }

    const sessionData = await this.getSession(sessionId);
    if (!sessionData) {
      return null;
    }

    return {
      ttl,
      absoluteExpiry: sessionData.absolute_expiry,
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
}