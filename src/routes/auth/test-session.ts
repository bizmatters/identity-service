import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Type } from '@sinclair/typebox';
import { SessionManager } from '../../modules/auth/session-manager.js';
import { UserRepository } from '../../modules/user/user-repository.js';
import { OrgRepository } from '../../modules/org/org-repository.js';

const TestSessionRequestSchema = Type.Object({
  external_id: Type.String(),
  email: Type.String({ format: 'email' }),
  organization_name: Type.String(),
});

const TestSessionResponseSchema = Type.Object({
  status: Type.Literal('success'),
  user_id: Type.String(),
  org_id: Type.String(),
  session_id: Type.String(),
});

type TestSessionRequest = {
  external_id: string;
  email: string;
  organization_name: string;
};

type TestSessionResponse = {
  status: 'success';
  user_id: string;
  org_id: string;
  session_id: string;
};

interface TestSessionConfig {
  cookieSecure: boolean;
}

export function testSessionRoutes(
  fastify: FastifyInstance,
  sessionManager: SessionManager,
  userRepository: UserRepository,
  orgRepository: OrgRepository,
  config: TestSessionConfig
): void {
  /**
   * Create test session for validation purposes
   * Available in all environments for testing
   * Requirements: 3.1, 3.2, 3.3, 7.1
   */
  fastify.post<{ Body: TestSessionRequest }>(
    '/auth/test-session',
    {
      schema: {
        body: TestSessionRequestSchema,
        response: {
          200: TestSessionResponseSchema,
        },
      },
    },
    async (request: FastifyRequest<{ Body: TestSessionRequest }>, reply: FastifyReply): Promise<TestSessionResponse | void> => {
      const { external_id, email, organization_name } = request.body;

      try {
        // Generate organization slug from name
        const orgSlug = organization_name
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/^-+|-+$/g, '');

        // Execute JIT provisioning logic (same as OAuth flow)
        let user = await userRepository.findByExternalId(external_id);
        let orgId: string;

        if (!user) {
          // Create new user with default organization
          const result = await userRepository.createUserWithDefaultOrg(
            external_id,
            email,
            organization_name,
            orgSlug
          );
          user = result.user;
          orgId = result.organization.id;
        } else {
          // User exists - update profile and use default org
          await userRepository.updateUserProfile(user.id, { email });
          orgId = user.default_org_id!;
        }

        // Get user role in organization
        const userRole = await orgRepository.getUserRole(user.id, orgId);
        if (!userRole) {
          throw new Error('User role not found');
        }

        // Generate valid session in Hot_Cache
        const sessionId = await sessionManager.createSession(
          user.id,
          orgId,
          userRole.role
        );

        // Set secure session cookie
        const cookieOptions = {
          path: '/',
          secure: config.cookieSecure,
          httpOnly: true,
          sameSite: 'lax' as const,
          maxAge: 24 * 60 * 60, // 24 hours
        };

        void reply.setCookie('__Host-platform_session', sessionId, cookieOptions);

        // Log test session creation for audit
        fastify.log.info({
          userId: user.id,
          orgId,
          role: userRole.role,
          sessionId,
          external_id,
          email,
          event_type: 'test_session_created',
          timestamp: new Date().toISOString(),
        }, 'Test session created successfully');

        return {
          status: 'success',
          user_id: user.id,
          org_id: orgId,
          session_id: sessionId,
        };

      } catch (error) {
        fastify.log.error({
          error: error instanceof Error ? error.message : String(error),
          external_id,
          email,
          organization_name,
          event_type: 'test_session_creation_failed',
          timestamp: new Date().toISOString(),
        }, 'Test session creation failed');

        throw new Error('Failed to create test session');
      }
    }
  );
}