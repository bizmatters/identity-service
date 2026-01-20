import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Type } from '@sinclair/typebox';
import { TokenManager } from '../../modules/auth/token-manager.js';
import { ValidationService } from '../../modules/auth/validation-service.js';

const CreateTokenSchema = Type.Object({
  description: Type.String({ minLength: 1, maxLength: 255 }),
  expiresAt: Type.Optional(Type.String({ format: 'date-time' })),
});

const TokenResponseSchema = Type.Object({
  tokenId: Type.String(),
  token: Type.String(),
  description: Type.String(),
  expiresAt: Type.Union([Type.String({ format: 'date-time' }), Type.Null()]),
  createdAt: Type.String({ format: 'date-time' }),
});

interface CreateTokenRequest extends FastifyRequest {
  body: {
    description: string;
    expiresAt?: string;
  };
  headers: {
    cookie?: string;
  };
}

export async function tokenRoutes(fastify: FastifyInstance) {
  // Get dependencies from Fastify context
  const tokenManager = fastify.tokenManager as TokenManager;
  const validationService = fastify.validationService as ValidationService;

  /**
   * Create API Token endpoint
   * Requirements: 4.2, 4.3, 4.4, 4.5
   */
  fastify.post('/auth/tokens', {
    schema: {
      body: CreateTokenSchema,
      response: {
        201: TokenResponseSchema,
        401: Type.Object({
          error: Type.String(),
          code: Type.String(),
        }),
        400: Type.Object({
          error: Type.String(),
          code: Type.String(),
        }),
      },
    },
  }, async (request: CreateTokenRequest, reply: FastifyReply) => {
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

      // Parse optional expiration date
      let expiresAt: Date | undefined;
      if (request.body.expiresAt) {
        expiresAt = new Date(request.body.expiresAt);
        
        // Validate expiration is in the future
        if (expiresAt <= new Date()) {
          return reply.status(400).send({
            error: 'Expiration date must be in the future',
            code: 'INVALID_EXPIRATION',
          });
        }

        // Validate expiration is not too far in the future (max 1 year)
        const maxExpiration = new Date();
        maxExpiration.setFullYear(maxExpiration.getFullYear() + 1);
        
        if (expiresAt > maxExpiration) {
          return reply.status(400).send({
            error: 'Expiration date cannot be more than 1 year in the future',
            code: 'EXPIRATION_TOO_FAR',
          });
        }
      }

      // Create API token
      const tokenResult = await tokenManager.createApiToken(
        validation.userId,
        validation.orgId,
        request.body.description,
        expiresAt
      );

      // Return token data (plaintext token returned only once)
      return reply.status(201).send({
        tokenId: tokenResult.tokenId,
        token: tokenResult.token, // This is the only time the plaintext token is returned
        description: tokenResult.description,
        expiresAt: tokenResult.expiresAt?.toISOString() || null,
        createdAt: new Date().toISOString(),
      });

    } catch (error) {
      fastify.log.error('Token creation error:', error);
      
      if (error instanceof Error && error.message.includes('Invalid or expired session')) {
        return reply.status(401).send({
          error: 'Session expired',
          code: 'SESSION_EXPIRED',
        });
      }

      return reply.status(500).send({
        error: 'Failed to create token',
        code: 'TOKEN_CREATION_FAILED',
      });
    }
  });

  /**
   * List user's API tokens (without plaintext values)
   * Requirements: 4.4
   */
  fastify.get('/auth/tokens', {
    schema: {
      response: {
        200: Type.Object({
          tokens: Type.Array(Type.Object({
            tokenId: Type.String(),
            description: Type.String(),
            expiresAt: Type.Union([Type.String({ format: 'date-time' }), Type.Null()]),
            createdAt: Type.String({ format: 'date-time' }),
            lastUsed: Type.Union([Type.String({ format: 'date-time' }), Type.Null()]),
          })),
        }),
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

      // TODO: Implement token listing in TokenRepository
      // For now, return empty array
      return reply.status(200).send({
        tokens: [],
      });

    } catch (error) {
      fastify.log.error('Token listing error:', error);
      
      if (error instanceof Error && error.message.includes('Invalid or expired session')) {
        return reply.status(401).send({
          error: 'Session expired',
          code: 'SESSION_EXPIRED',
        });
      }

      return reply.status(500).send({
        error: 'Failed to list tokens',
        code: 'TOKEN_LISTING_FAILED',
      });
    }
  });

  /**
   * Revoke API token
   * Requirements: 4.4
   */
  fastify.delete('/auth/tokens/:tokenId', {
    schema: {
      params: Type.Object({
        tokenId: Type.String(),
      }),
      response: {
        200: Type.Object({
          message: Type.String(),
        }),
        401: Type.Object({
          error: Type.String(),
          code: Type.String(),
        }),
        404: Type.Object({
          error: Type.String(),
          code: Type.String(),
        }),
      },
    },
  }, async (request: FastifyRequest<{ Params: { tokenId: string } }>, reply: FastifyReply) => {
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

      // TODO: Add authorization check - user can only revoke their own tokens
      // This would require TokenRepository.findByTokenId to check ownership

      // Revoke the token
      await tokenManager.revokeApiToken(request.params.tokenId);

      return reply.status(200).send({
        message: 'Token revoked successfully',
      });

    } catch (error) {
      fastify.log.error('Token revocation error:', error);
      
      if (error instanceof Error && error.message.includes('Invalid or expired session')) {
        return reply.status(401).send({
          error: 'Session expired',
          code: 'SESSION_EXPIRED',
        });
      }

      if (error instanceof Error && error.message.includes('not found')) {
        return reply.status(404).send({
          error: 'Token not found',
          code: 'TOKEN_NOT_FOUND',
        });
      }

      return reply.status(500).send({
        error: 'Failed to revoke token',
        code: 'TOKEN_REVOCATION_FAILED',
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