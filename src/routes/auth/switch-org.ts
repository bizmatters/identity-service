import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import '@fastify/cookie';
import { Type } from '@sinclair/typebox';
import type { SessionManager } from '../../modules/auth/session-manager.js';
import type { OrgRepository } from '../../modules/org/org-repository.js';
import type { JWTCache } from '../../modules/auth/jwt-cache.js';

const SwitchOrgBodySchema = Type.Object({
  org_id: Type.String(),
});

export interface SwitchOrgRouteConfig {
  sessionCookieName: string;
}

/**
 * Organization Switch endpoint
 * Requirements: 3.8, 3.9
 */
export function switchOrgRoutes(
  fastify: FastifyInstance,
  sessionManager: SessionManager,
  orgRepository: OrgRepository,
  jwtCache: JWTCache,
  config: SwitchOrgRouteConfig
): void {
  fastify.post('/auth/switch-org', {
    schema: {
      body: SwitchOrgBodySchema,
    },
  }, async (request: FastifyRequest<{ Body: typeof SwitchOrgBodySchema.static }>, reply: FastifyReply): Promise<void> => {
    try {
      const { org_id } = request.body;

      // Extract session ID from cookie
      const cookies = request.cookies as Record<string, string | undefined>;
      const sessionId = cookies[config.sessionCookieName];

      if (!sessionId) {
        return reply.status(401).send({
          error: 'No active session',
          code: 'NO_SESSION',
          message: 'No active session found',
        });
      }

      // Get current session
      const session = await sessionManager.getSession(sessionId);
      if (!session) {
        return reply.status(401).send({
          error: 'Invalid or expired session',
          code: 'SESSION_INVALID',
          message: 'Session is invalid or has expired',
        });
      }

      // Validate user membership in target organization
      const membership = await orgRepository.getUserRole(session.user_id, org_id);
      if (!membership) {
        fastify.log.warn({
          userId: session.user_id,
          targetOrgId: org_id,
          currentOrgId: session.org_id,
          sessionId: sessionId.substring(0, 8) + '...',
        }, 'User attempted to switch to unauthorized organization');

        return reply.status(403).send({
          error: 'Access denied',
          code: 'ORG_ACCESS_DENIED',
          message: 'You do not have access to this organization',
        });
      }

      // Update session context in Hot_Cache with new org_id
      await sessionManager.updateSession(sessionId, {
        org_id: org_id,
        role: membership.role,
      });

      // Invalidate JWT cache for session (force new JWT mint)
      await jwtCache.invalidate(sessionId);

      fastify.log.info({
        userId: session.user_id,
        fromOrgId: session.org_id,
        toOrgId: org_id,
        newRole: membership.role,
        sessionId: sessionId.substring(0, 8) + '...',
        ip: request.ip,
      }, 'User switched organization');

      // Return 200 OK with updated context
      return reply.status(200).send({
        message: 'Organization switched successfully',
        context: {
          user_id: session.user_id,
          org_id: org_id,
          role: membership.role,
          version: membership.version,
        },
      });

    } catch (error) {
      fastify.log.error(error, 'Switch organization endpoint error');

      return reply.status(500).send({
        error: 'Organization switch failed',
        code: 'SWITCH_ORG_FAILED',
        message: 'Failed to switch organization',
      });
    }
  });

  // Get current session context (useful for frontend)
  fastify.get('/auth/context', async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    try {
      // Extract session ID from cookie
      const cookies = request.cookies as Record<string, string | undefined>;
      const sessionId = cookies[config.sessionCookieName];

      if (!sessionId) {
        return reply.status(401).send({
          error: 'No active session',
          code: 'NO_SESSION',
          message: 'No active session found',
        });
      }

      // Get current session
      const session = await sessionManager.getSession(sessionId);
      if (!session) {
        return reply.status(401).send({
          error: 'Invalid or expired session',
          code: 'SESSION_INVALID',
          message: 'Session is invalid or has expired',
        });
      }

      // Get current membership info
      const membership = await orgRepository.getUserRole(session.user_id, session.org_id);
      if (!membership) {
        return reply.status(403).send({
          error: 'Access denied',
          code: 'ORG_ACCESS_DENIED',
          message: 'You do not have access to the current organization',
        });
      }

      return reply.status(200).send({
        context: {
          user_id: session.user_id,
          org_id: session.org_id,
          role: session.role,
          version: membership.version,
          created_at: session.created_at,
          last_accessed: session.last_accessed,
          absolute_expiry: session.absolute_expiry,
        },
      });

    } catch (error) {
      fastify.log.error(error, 'Get context endpoint error');

      return reply.status(500).send({
        error: 'Failed to get session context',
        code: 'CONTEXT_FAILED',
        message: 'Failed to retrieve session context',
      });
    }
  });
}