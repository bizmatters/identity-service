import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

class ValidationError extends Error {
  constructor(message: string, public statusCode: number = 401) {
    super(message);
    this.name = 'ValidationError';
  }
}

export async function validateRoutes(fastify: FastifyInstance): Promise<void> {
  // Get dependencies from Fastify context
  const validationService = fastify.validationService;
  const jwtManager = fastify.jwtManager;
  const jwtCache = fastify.jwtCache;

  /**
   * HTTP extAuthz endpoint for AgentGateway
   * Requirements: 2.1, 2.2, 2.3, 2.11, 4.6, 4.7, 4.12, 4.13, 8.1
   * 
   * STABLE FIX: Use .all() to accept any HTTP method (GET, POST, PUT, DELETE, etc.)
   * AgentGateway HTTP extAuthz forwards the original client request method to this endpoint.
   * The Trust Broker pattern is method-agnostic - we validate WHO is calling, not WHAT they're calling.
   */
  fastify.all('/internal/validate', {
    // No body schema validation - we only check headers regardless of HTTP method
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const requestId = request.headers['x-request-id'] || 'unknown';
    let sessionId: string | null = null;
    
    // Log ALL requests to this endpoint
    fastify.log.info({
      requestId,
      method: request.method,
      url: request.url,
      headers: Object.keys(request.headers),
      cookieHeader: request.headers.cookie ? 'present' : 'missing',
      authHeader: request.headers.authorization ? 'present' : 'missing'
    }, 'extAuthz validation request received');
    
    try {
      let validationResult;

      // Extract authentication from Cookie or Authorization header
      const cookieHeader = request.headers.cookie;
      const authHeader = request.headers.authorization;

      fastify.log.info({
        requestId,
        cookieHeader: cookieHeader ? `${cookieHeader.substring(0, 50)}...` : null,
        authHeader: authHeader ? `${authHeader.substring(0, 20)}...` : null,
        method: request.method,
        url: request.url,
        headers: Object.keys(request.headers)
      }, 'extAuthz validation request received');

      if (cookieHeader) {
        // Session-based authentication via cookie
        sessionId = extractSessionFromCookie(cookieHeader);
        fastify.log.info({ requestId, sessionId }, 'Extracted session ID from cookie');
        
        if (!sessionId) {
          fastify.log.warn({ requestId, cookieHeader }, 'Failed to extract session ID from cookie');
          return reply.status(401).send({ error: 'Invalid session cookie' });
        }

        fastify.log.info({ requestId, sessionId }, 'Validating session');
        validationResult = await validationService.validateSession(sessionId);
        fastify.log.info({ 
          requestId, 
          sessionId, 
          userId: validationResult.userId,
          orgId: validationResult.orgId,
          role: validationResult.role 
        }, 'Session validation successful');
        
      } else if (authHeader) {
        // Token-based authentication via Authorization header
        const token = extractTokenFromAuthHeader(authHeader);
        if (!token) {
          return reply.status(401).send({ error: 'Invalid authorization header' });
        }

        validationResult = await validationService.validateApiToken(token);
      } else {
        fastify.log.warn({ requestId }, 'No authentication provided');
        return reply.status(401).send({ error: 'No authentication provided' });
      }

      // Check for cached Platform JWT or mint new one
      let platformJWT: string;
      
      if (sessionId) {
        // Try to get cached JWT for session-based auth
        const cachedJWT = await jwtCache.get(sessionId, validationResult.orgId);
        
        if (cachedJWT) {
          platformJWT = cachedJWT;
        } else {
          // Mint new Platform JWT
          platformJWT = jwtManager.mintPlatformJWT(
            validationResult.userId,
            validationResult.orgId,
            validationResult.role,
            validationResult.version
          );

          // Cache the JWT until near-expiry
          const payload = jwtManager.verifyPlatformJWT(platformJWT);
          await jwtCache.set(sessionId, validationResult.orgId, platformJWT, payload.exp);
        }
      } else {
        // For API tokens, always mint fresh JWT (no caching for security)
        platformJWT = jwtManager.mintPlatformJWT(
          validationResult.userId,
          validationResult.orgId,
          validationResult.role,
          validationResult.version
        );
      }

      // Return success with headers for AgentGateway
      return reply
        .status(200)
        .headers({
          'Authorization': `Bearer ${platformJWT}`,
          'X-Auth-User-Id': validationResult.userId,
          'X-Auth-Org-Id': validationResult.orgId,
          'X-Auth-Role': validationResult.role,
        })
        .send({ 
          status: 'authorized',
          userId: validationResult.userId,
          orgId: validationResult.orgId,
          role: validationResult.role,
        });

    } catch (error) {
      const requestId = request.headers['x-request-id'] || 'unknown';
      
      if (error instanceof ValidationError) {
        fastify.log.warn({
          requestId,
          error: error.message,
          statusCode: error.statusCode,
          sessionId: sessionId || 'none'
        }, 'Validation failed with ValidationError');
        
        return reply.status(error.statusCode).send({ 
          error: error.message,
          code: 'VALIDATION_FAILED',
        });
      }

      // Log unexpected errors with full details
      fastify.log.error({
        requestId,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        sessionId: sessionId || 'none'
      }, 'Validation endpoint unexpected error');
      
      return reply.status(401).send({ 
        error: 'Authentication failed',
        code: 'AUTH_ERROR',
      });
    }
  });

  /**
   * Health check endpoint for extAuthz service
   */
  fastify.get('/internal/health', async (_request, reply) => {
    try {
      const health = await validationService.healthCheck();
      const jwtHealth = jwtManager.healthCheck();

      if (health.session && health.permission && jwtHealth) {
        return reply.status(200).send({
          status: 'healthy',
          services: {
            session: health.session,
            permission: health.permission,
            jwt: jwtHealth,
          },
        });
      } else {
        return reply.status(503).send({
          status: 'unhealthy',
          services: {
            session: health.session,
            permission: health.permission,
            jwt: jwtHealth,
          },
        });
      }
    } catch (error) {
      fastify.log.error(error, 'Health check error');
      return reply.status(503).send({
        status: 'error',
        error: 'Health check failed',
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

/**
 * Extract token from Authorization header
 * Supports "Bearer <token>" format
 */
function extractTokenFromAuthHeader(authHeader: string): string | null {
  const match = authHeader.match(/^Bearer\s+(.+)$/);
  return match?.[1] || null;
}