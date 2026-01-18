import { FastifyInstance } from 'fastify';
import '@fastify/cookie';
import type { SessionManager } from '../../modules/auth/session-manager.js';

export interface LogoutRouteConfig {
  sessionCookieName: string;
  cookieDomain: string;
  cookieSecure: boolean;
}

/**
 * Logout endpoint
 * Requirements: 1.9
 */
export function logoutRoutes(
  fastify: FastifyInstance,
  sessionManager: SessionManager,
  config: LogoutRouteConfig
): void {
  fastify.post('/auth/logout', async (request, reply): Promise<void> => {
    try {
      // Extract session ID from cookie
      const cookies = request.cookies as Record<string, string | undefined>;
      const sessionId = cookies[config.sessionCookieName];

      if (sessionId) {
        // Delete session from Hot_Cache
        await sessionManager.deleteSession(sessionId);

        fastify.log.info({
          sessionId: sessionId.substring(0, 8) + '...', // Log partial session ID
          ip: request.ip,
          userAgent: request.headers['user-agent'],
        }, 'User logged out successfully');
      }

      // Clear session cookie
      void reply.clearCookie(config.sessionCookieName, {
        path: '/',
        domain: config.cookieDomain,
        secure: config.cookieSecure,
        httpOnly: true,
        sameSite: 'lax',
      });

      // Return 200 OK
      return reply.status(200).send({
        message: 'Logged out successfully',
      });

    } catch (error) {
      fastify.log.error(error, 'Logout endpoint error');

      // Still clear the cookie even if session deletion fails
      void reply.clearCookie(config.sessionCookieName, {
        path: '/',
        domain: config.cookieDomain,
        secure: config.cookieSecure,
        httpOnly: true,
        sameSite: 'lax',
      });

      return reply.status(500).send({
        error: 'Logout processing failed',
        code: 'LOGOUT_FAILED',
        message: 'Failed to process logout request',
      });
    }
  });

  // Also support GET for logout (common pattern)
  fastify.get('/auth/logout', async (request, reply): Promise<void> => {
    try {
      // Extract session ID from cookie
      const cookies = request.cookies as Record<string, string | undefined>;
      const sessionId = cookies[config.sessionCookieName];

      if (sessionId) {
        // Delete session from Hot_Cache
        await sessionManager.deleteSession(sessionId);

        fastify.log.info({
          sessionId: sessionId.substring(0, 8) + '...', // Log partial session ID
          ip: request.ip,
          userAgent: request.headers['user-agent'],
        }, 'User logged out successfully (GET)');
      }

      // Clear session cookie
      void reply.clearCookie(config.sessionCookieName, {
        path: '/',
        domain: config.cookieDomain,
        secure: config.cookieSecure,
        httpOnly: true,
        sameSite: 'lax',
      });

      // Redirect to login page or return success message
      return reply.status(200).send({
        message: 'Logged out successfully',
      });

    } catch (error) {
      fastify.log.error(error, 'Logout endpoint error (GET)');

      // Still clear the cookie even if session deletion fails
      void reply.clearCookie(config.sessionCookieName, {
        path: '/',
        domain: config.cookieDomain,
        secure: config.cookieSecure,
        httpOnly: true,
        sameSite: 'lax',
      });

      return reply.status(500).send({
        error: 'Logout processing failed',
        code: 'LOGOUT_FAILED',
        message: 'Failed to process logout request',
      });
    }
  });
}