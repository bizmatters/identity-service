import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Type } from '@sinclair/typebox';

const OrganizationResponseSchema = Type.Object({
  organizations: Type.Array(Type.Object({
    id: Type.String(),
    name: Type.String(),
    slug: Type.String(),
    role: Type.Union([
      Type.Literal('owner'),
      Type.Literal('admin'),
      Type.Literal('developer'),
      Type.Literal('viewer'),
    ]),
    is_default: Type.Boolean(),
    created_at: Type.String({ format: 'date-time' }),
  })),
});

export async function organizationRoutes(fastify: FastifyInstance): Promise<void> {
  // Get dependencies from Fastify context
  const validationService = fastify.validationService;
  const orgRepository = fastify.orgRepository;

  /**
   * List user's organizations
   * Requirements: 10.7, 10.8, 10.9, 10.10, 10.11, 10.12
   */
  fastify.get('/auth/organizations', {
    schema: {
      response: {
        200: OrganizationResponseSchema,
        401: Type.Object({
          error: Type.String(),
          code: Type.String(),
        }),
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      // Require valid session cookie
      const cookieHeader = request.headers.cookie;
      if (!cookieHeader) {
        return reply.status(401).send({
          error: 'Authentication required',
          code: 'NO_SESSION',
        });
      }

      const sessionId = extractSessionFromCookie(cookieHeader);
      if (!sessionId) {
        return reply.status(401).send({
          error: 'Invalid session cookie',
          code: 'INVALID_SESSION',
        });
      }

      // Validate session and get user context
      const validation = await validationService.validateSession(sessionId);

      // Get user's organizations
      const organizations = await orgRepository.getUserOrganizations(validation.userId);

      return reply.status(200).send({
        organizations: organizations.map(org => ({
          id: org.id,
          name: org.name,
          slug: org.slug,
          role: org.role,
          is_default: org.is_default,
          created_at: org.created_at.toISOString(),
        })),
      });

    } catch (error) {
      fastify.log.error(error, 'Organization listing error');
      
      if (error instanceof Error && error.message.includes('Invalid or expired session')) {
        return reply.status(401).send({
          error: 'Session expired',
          code: 'SESSION_EXPIRED',
        });
      }

      return reply.status(500).send({
        error: 'Failed to list organizations',
        code: 'ORGANIZATION_LISTING_FAILED',
      });
    }
  });
}

/**
 * Extract session ID from cookie header
 * Looks for __Host-platform_session cookie
 */
function extractSessionFromCookie(cookieHeader: string): string | null {
  const cookies = cookieHeader.split(';').map(c => c.trim());
  
  for (const cookie of cookies) {
    const [name, value] = cookie.split('=');
    if (name === '__Host-platform_session' && value) {
      return value;
    }
  }
  
  return null;
}