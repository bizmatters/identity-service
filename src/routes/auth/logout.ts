import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { SessionManager } from '../../modules/auth/session-manager.js';
import { JWTCache } from '../../modules/auth/jwt-cache.js';
import { NeonAuthService } from '../../services/neon-auth.service.js';

interface LogoutConfig {
  cookieName: string;
  cookieSecure: boolean;
}

export function logoutRoutes(
  fastify: FastifyInstance,
  sessionManager: SessionManager,
  jwtCache: JWTCache,
  neonAuthService: NeonAuthService,
  config: LogoutConfig
): void {
  /**
   * Logout endpoint - terminate session and clear cookie
   * Requirements: 1.9
   */
  fastify.post('/auth/logout', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      // Extract session ID from cookie
      const sessionId = request.cookies[config.cookieName];

      if (sessionId) {
        // Get session data before deletion for cleanup
        const sessionData = await sessionManager.getSession(sessionId);
        
        // Delete session from Hot_Cache
        await sessionManager.deleteSession(sessionId);

        // Invalidate all cached JWTs for this session
        await jwtCache.invalidate(sessionId);

        // Log successful logout for audit
        if (sessionData) {
          void fastify.log.info({
            userId: sessionData.user_id,
            orgId: sessionData.org_id,
            sessionId,
            ip: request.ip,
          }, 'User logged out successfully');
        }
      }

      // Terminate session with Neon Auth (best effort)
      try {
        await neonAuthService.terminateSession();
      } catch (error) {
        // Don't fail logout if Neon Auth termination fails
        void fastify.log.warn({ error }, 'Failed to terminate Neon Auth session');
      }

      // Clear session cookie with Max-Age=0
      void reply.setCookie(config.cookieName, '', {
        path: '/',
        secure: config.cookieSecure,
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 0, // This sets Max-Age=0 in the header
      });

      return reply.status(200).send({
        message: 'Logged out successfully',
      });

    } catch (error) {
      fastify.log.error({ error }, 'Logout failed');
      
      // Still clear the cookie even if cleanup failed
      void reply.setCookie(config.cookieName, '', {
        path: '/',
        secure: config.cookieSecure,
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 0, // This sets Max-Age=0 in the header
      });

      return reply.status(500).send({
        error: 'logout_error',
        message: 'Logout failed, but session cleared',
      });
    }
  });
}