import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Type } from '@sinclair/typebox';

const JWKSResponseSchema = Type.Object({
  keys: Type.Array(Type.Object({
    kid: Type.String(),
    kty: Type.String(),
    alg: Type.String(),
    use: Type.String(),
    n: Type.String(),
    e: Type.String(),
  })),
});

export async function jwksRoutes(fastify: FastifyInstance): Promise<void> {
  // Get dependencies from Fastify context
  const jwtManager = fastify.jwtManager;

  /**
   * JWKS endpoint for public key distribution
   * Requirements: 7.8, 8.2, P1: Key Rotation Support
   */
  fastify.get('/.well-known/jwks.json', {
    schema: {
      response: {
        200: JWKSResponseSchema,
        500: Type.Object({
          error: Type.String(),
          code: Type.String(),
        }),
      },
    },
  }, async (_request: FastifyRequest, reply: FastifyReply) => {
    try {
      // Get JWKS with current and previous keys (P1: Key Rotation Support)
      const jwks = jwtManager.getJWKS();

      // Set appropriate cache headers
      void reply.headers({
        'Cache-Control': 'public, max-age=3600', // Cache for 1 hour
        'Content-Type': 'application/json',
      });

      return reply.status(200).send(jwks);

    } catch (error) {
      fastify.log.error(error, 'JWKS endpoint error');

      return reply.status(500).send({
        error: 'Failed to retrieve JWKS',
        code: 'JWKS_ERROR',
      });
    }
  });

  /**
   * Alternative JWKS endpoint path (some systems expect this path)
   */
  fastify.get('/jwks.json', async (_request: FastifyRequest, reply: FastifyReply) => {
    // Redirect to the standard path
    return reply.redirect(301, '/.well-known/jwks.json');
  });

  /**
   * OpenID Connect Discovery endpoint (optional)
   * Provides metadata about the identity provider
   */
  fastify.get('/.well-known/openid_configuration', {
    schema: {
      response: {
        200: Type.Object({
          issuer: Type.String(),
          jwks_uri: Type.String(),
          token_endpoint: Type.String(),
          authorization_endpoint: Type.String(),
          response_types_supported: Type.Array(Type.String()),
          subject_types_supported: Type.Array(Type.String()),
          id_token_signing_alg_values_supported: Type.Array(Type.String()),
        }),
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const baseUrl = `${request.protocol}://${request.hostname}`;
      
      const openidConfig = {
        issuer: baseUrl,
        jwks_uri: `${baseUrl}/.well-known/jwks.json`,
        token_endpoint: `${baseUrl}/auth/machine`, // Service token endpoint
        authorization_endpoint: `${baseUrl}/auth/login`, // User login endpoint
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
      };

      // Set appropriate cache headers
      void reply.headers({
        'Cache-Control': 'public, max-age=86400', // Cache for 24 hours
        'Content-Type': 'application/json',
      });

      return reply.status(200).send(openidConfig);

    } catch (error) {
      fastify.log.error(error, 'OpenID configuration endpoint error');

      return reply.status(500).send({
        error: 'Failed to retrieve OpenID configuration',
        code: 'OPENID_CONFIG_ERROR',
      });
    }
  });

  /**
   * Health check for JWKS functionality
   */
  fastify.get('/.well-known/health', async (_request: FastifyRequest, reply: FastifyReply) => {
    try {
      // Test JWT manager functionality
      const isHealthy = jwtManager.healthCheck();
      
      if (isHealthy) {
        return reply.status(200).send({
          status: 'healthy',
          jwks: 'available',
          timestamp: new Date().toISOString(),
        });
      } else {
        return reply.status(503).send({
          status: 'unhealthy',
          jwks: 'unavailable',
          timestamp: new Date().toISOString(),
        });
      }

    } catch (error) {
      fastify.log.error(error, 'JWKS health check error');

      return reply.status(503).send({
        status: 'error',
        error: 'Health check failed',
        timestamp: new Date().toISOString(),
      });
    }
  });
}