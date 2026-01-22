import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Type } from '@sinclair/typebox';
import { SessionManager } from '../../modules/auth/session-manager.js';
import { TokenManager } from '../../modules/auth/token-manager.js';
import { TokenRepository } from '../../modules/token/token-repository.js';

const CreateTokenSchema = Type.Object({
  description: Type.String({ minLength: 1, maxLength: 255 }),
  expiresAt: Type.Optional(Type.String({ format: 'date-time' })),
});

const DeleteTokenParamsSchema = Type.Object({
  id: Type.String({ format: 'uuid' }),
});

type CreateTokenBody = {
  description: string;
  expiresAt?: string;
};

type DeleteTokenParams = {
  id: string;
};

export function tokenRoutes(
  fastify: FastifyInstance,
  sessionManager: SessionManager,
  tokenManager: TokenManager,
  tokenRepository: TokenRepository
): void {
  /**
   * Create API token
   * Requirements: 4.1, 4.2, 4.3, 4.4, 4.5
   */
  fastify.post<{ Body: CreateTokenBody }>(
    '/auth/tokens',
    {
      schema: {
        body: CreateTokenSchema,
      },
    },
    async (request: FastifyRequest<{ Body: CreateTokenBody }>, reply: FastifyReply) => {
      try {
        // Extract session from cookie
        const cookieHeader = request.headers.cookie;
        if (!cookieHeader) {
          return reply.status(401).send({
            error: 'unauthorized',
            message: 'Session required to create API token',
          });
        }

        const sessionId = extractSessionFromCookie(cookieHeader);
        if (!sessionId) {
          return reply.status(401).send({
            error: 'unauthorized',
            message: 'Invalid session cookie',
          });
        }

        // Validate session
        const sessionData = await sessionManager.getSession(sessionId);
        if (!sessionData) {
          return reply.status(401).send({
            error: 'unauthorized',
            message: 'Invalid or expired session',
          });
        }

        // Parse expiration date if provided
        let expiresAt: Date | undefined;
        if (request.body.expiresAt) {
          expiresAt = new Date(request.body.expiresAt);
          if (isNaN(expiresAt.getTime())) {
            return reply.status(400).send({
              error: 'invalid_request',
              message: 'Invalid expiresAt date format',
            });
          }
        }

        // Create API token
        const tokenResult = await tokenManager.createApiToken(
          sessionData.user_id,
          sessionData.org_id,
          request.body.description,
          expiresAt
        );

        return reply.status(201).send({
          id: tokenResult.tokenId,
          token: tokenResult.token,
          description: tokenResult.description,
          expiresAt: tokenResult.expiresAt,
          message: 'Token created successfully. Save this token securely - it will not be shown again.',
        });
      } catch (error) {
        fastify.log.error(error, 'Token creation failed');
        return reply.status(500).send({
          error: 'server_error',
          message: 'Failed to create API token',
        });
      }
    }
  );

  /**
   * List user's API tokens
   * Requirements: 4.14
   */
  fastify.get(
    '/auth/tokens',
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        // Extract session from cookie
        const cookieHeader = request.headers.cookie;
        if (!cookieHeader) {
          return reply.status(401).send({
            error: 'unauthorized',
            message: 'Session required to list API tokens',
          });
        }

        const sessionId = extractSessionFromCookie(cookieHeader);
        if (!sessionId) {
          return reply.status(401).send({
            error: 'unauthorized',
            message: 'Invalid session cookie',
          });
        }

        // Validate session
        const sessionData = await sessionManager.getSession(sessionId);
        if (!sessionData) {
          return reply.status(401).send({
            error: 'unauthorized',
            message: 'Invalid or expired session',
          });
        }

        // List tokens for current organization
        const tokens = await tokenRepository.listUserTokens(
          sessionData.user_id,
          sessionData.org_id
        );

        return reply.status(200).send({
          tokens: tokens.map(token => ({
            id: token.id,
            description: token.description,
            expiresAt: token.expires_at,
            createdAt: token.created_at,
            lastUsedAt: token.last_used_at,
          })),
        });
      } catch (error) {
        fastify.log.error(error, 'Token listing failed');
        return reply.status(500).send({
          error: 'server_error',
          message: 'Failed to list API tokens',
        });
      }
    }
  );

  /**
   * Revoke API token
   * Requirements: 4.15
   */
  fastify.delete<{ Params: DeleteTokenParams }>(
    '/auth/tokens/:id',
    {
      schema: {
        params: DeleteTokenParamsSchema,
      },
    },
    async (request: FastifyRequest<{ Params: DeleteTokenParams }>, reply: FastifyReply) => {
      try {
        // Extract session from cookie
        const cookieHeader = request.headers.cookie;
        if (!cookieHeader) {
          return reply.status(401).send({
            error: 'unauthorized',
            message: 'Session required to revoke API token',
          });
        }

        const sessionId = extractSessionFromCookie(cookieHeader);
        if (!sessionId) {
          return reply.status(401).send({
            error: 'unauthorized',
            message: 'Invalid session cookie',
          });
        }

        // Validate session
        const sessionData = await sessionManager.getSession(sessionId);
        if (!sessionData) {
          return reply.status(401).send({
            error: 'unauthorized',
            message: 'Invalid or expired session',
          });
        }

        // Verify token ownership and delete
        const deleted = await tokenRepository.deleteUserToken(
          request.params.id,
          sessionData.user_id,
          sessionData.org_id
        );

        if (!deleted) {
          return reply.status(404).send({
            error: 'not_found',
            message: 'Token not found or does not belong to current organization',
          });
        }

        return reply.status(200).send({
          message: 'Token revoked successfully',
        });
      } catch (error) {
        fastify.log.error(error, 'Token revocation failed');
        return reply.status(500).send({
          error: 'server_error',
          message: 'Failed to revoke API token',
        });
      }
    }
  );
}

/**
 * Extract session ID from cookie header
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
