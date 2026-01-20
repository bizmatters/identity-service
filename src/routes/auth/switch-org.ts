import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Type } from '@sinclair/typebox';
import { SessionManager } from '../../modules/auth/session-manager.js';
import { JWTCache } from '../../modules/auth/jwt-cache.js';
import { OrgRepository } from '../../modules/org/org-repository.js';

const SwitchOrgBodySchema = Type.Object({
  org_id: Type.String(),
});

type SwitchOrgBody = {
  org_id: string;
};

interface SwitchOrgConfig {
  cookieName: string;
}

export function switchOrgRoutes(
  fastify: FastifyInstance,
  sessionManager: SessionManager,
  jwtCache: JWTCache,
  orgRepository: OrgRepository,
  config: SwitchOrgConfig
): void {
  /**
   * Organization Switch endpoint
   * Requirements: 3.8, 3.9
   */
  fastify.post<{ Body: SwitchOrgBody }>(
    '/auth/switch-org',
    {
      schema: {
        body: SwitchOrgBodySchema,
      },
    },
    async (request: FastifyRequest<{ Body: SwitchOrgBody }>, reply: FastifyReply) => {
      try {
        const { org_id } = request.body;

        // Extract session ID from cookie
        const sessionId = request.cookies[config.cookieName];
        if (!sessionId) {
          return reply.status(401).send({
            error: 'unauthorized',
            message: 'No active session',
          });
        }

        // Get current session data
        const sessionData = await sessionManager.getSession(sessionId);
        if (!sessionData) {
          return reply.status(401).send({
            error: 'unauthorized',
            message: 'Invalid or expired session',
          });
        }

        // Validate user membership in target organization
        const membership = await orgRepository.getUserRole(sessionData.user_id, org_id);
        if (!membership) {
          return reply.status(403).send({
            error: 'forbidden',
            message: 'User is not a member of the target organization',
          });
        }

        // Update session context with new org_id and role
        await sessionManager.updateSession(sessionId, {
          org_id: org_id,
          role: membership.role,
        });

        // Invalidate JWT cache for this session (force new JWT mint with new org context)
        await jwtCache.invalidate(sessionId);

        // Log organization switch for audit
        fastify.log.info({
          userId: sessionData.user_id,
          fromOrgId: sessionData.org_id,
          toOrgId: org_id,
          newRole: membership.role,
          sessionId,
          ip: request.ip,
        }, 'User switched organization');

        return reply.status(200).send({
          message: 'Organization switched successfully',
          org_id: org_id,
          role: membership.role,
          version: membership.version,
        });

      } catch (error) {
        fastify.log.error({ error, body: request.body }, 'Organization switch failed');

        if (error instanceof Error && error.message === 'Session expired') {
          return reply.status(401).send({
            error: 'session_expired',
            message: 'Session has expired',
          });
        }

        return reply.status(500).send({
          error: 'switch_org_error',
          message: 'Failed to switch organization',
        });
      }
    }
  );
}