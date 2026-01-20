import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Type } from '@sinclair/typebox';
import { JWTManager } from '../../modules/auth/jwt-manager.js';

const ServiceTokenRequestSchema = Type.Object({
  serviceId: Type.String({ minLength: 1, maxLength: 100 }),
  orgId: Type.String({ format: 'uuid' }),
  permissions: Type.Array(Type.String()),
  expirationHours: Type.Optional(Type.Number({ minimum: 1, maximum: 24 })),
});

const ServiceTokenResponseSchema = Type.Object({
  token: Type.String(),
  expiresAt: Type.String({ format: 'date-time' }),
  serviceId: Type.String(),
  orgId: Type.String(),
  permissions: Type.Array(Type.String()),
});

interface ServiceTokenRequest extends FastifyRequest {
  body: {
    serviceId: string;
    orgId: string;
    permissions: string[];
    expirationHours?: number;
  };
  headers: {
    'x-api-key'?: string;
    'x-service-identity'?: string;
  };
}

export async function machineRoutes(fastify: FastifyInstance) {
  // Get dependencies from Fastify context
  const jwtManager = fastify.jwtManager as JWTManager;

  /**
   * Service Account Token endpoint
   * Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.7
   */
  fastify.post('/auth/machine', {
    schema: {
      body: ServiceTokenRequestSchema,
      response: {
        200: ServiceTokenResponseSchema,
        401: Type.Object({
          error: Type.String(),
          code: Type.String(),
        }),
        403: Type.Object({
          error: Type.String(),
          code: Type.String(),
        }),
        400: Type.Object({
          error: Type.String(),
          code: Type.String(),
        }),
      },
    },
  }, async (request: ServiceTokenRequest, reply: FastifyReply) => {
    try {
      // Validate service identity using multiple methods
      const isAuthorized = await validateServiceIdentity(request, fastify);
      
      if (!isAuthorized) {
        return reply.status(401).send({
          error: 'Service authentication failed',
          code: 'SERVICE_AUTH_FAILED',
        });
      }

      // Validate permissions array
      const validPermissions = validatePermissions(request.body.permissions);
      if (!validPermissions.isValid) {
        return reply.status(400).send({
          error: `Invalid permissions: ${validPermissions.error}`,
          code: 'INVALID_PERMISSIONS',
        });
      }

      // Default to 12 hours if not specified
      const expirationHours = request.body.expirationHours || 12;

      // Mint service account JWT
      const serviceToken = jwtManager.mintServiceJWT(
        request.body.serviceId,
        request.body.orgId,
        request.body.permissions,
        expirationHours
      );

      // Calculate expiration timestamp
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + expirationHours);

      // Log service token issuance for audit
      fastify.log.info('Service token issued', {
        serviceId: request.body.serviceId,
        orgId: request.body.orgId,
        permissions: request.body.permissions,
        expirationHours,
        expiresAt: expiresAt.toISOString(),
        requestIP: request.ip,
        userAgent: request.headers['user-agent'],
      });

      return reply.status(200).send({
        token: serviceToken,
        expiresAt: expiresAt.toISOString(),
        serviceId: request.body.serviceId,
        orgId: request.body.orgId,
        permissions: request.body.permissions,
      });

    } catch (error) {
      fastify.log.error('Service token creation error:', {
        error: error instanceof Error ? error.message : 'Unknown error',
        serviceId: request.body?.serviceId,
        orgId: request.body?.orgId,
      });

      return reply.status(500).send({
        error: 'Failed to create service token',
        code: 'SERVICE_TOKEN_CREATION_FAILED',
      });
    }
  });

  /**
   * Service token validation endpoint (for debugging)
   */
  fastify.post('/auth/machine/validate', {
    schema: {
      body: Type.Object({
        token: Type.String(),
      }),
      response: {
        200: Type.Object({
          valid: Type.Boolean(),
          payload: Type.Optional(Type.Object({
            sub: Type.String(),
            org: Type.String(),
            role: Type.String(),
            permissions: Type.Array(Type.String()),
            exp: Type.Number(),
          })),
        }),
        400: Type.Object({
          error: Type.String(),
          code: Type.String(),
        }),
      },
    },
  }, async (request: FastifyRequest<{ Body: { token: string } }>, reply: FastifyReply) => {
    try {
      const payload = jwtManager.verifyPlatformJWT(request.body.token);
      
      // Check if it's a service token
      if (!payload.sub.startsWith('service:')) {
        return reply.status(400).send({
          error: 'Not a service token',
          code: 'NOT_SERVICE_TOKEN',
        });
      }

      return reply.status(200).send({
        valid: true,
        payload: {
          sub: payload.sub,
          org: payload.org,
          role: payload.role,
          permissions: (payload as any).permissions || [],
          exp: payload.exp,
        },
      });

    } catch (error) {
      return reply.status(200).send({
        valid: false,
      });
    }
  });
}

/**
 * Validate service identity using multiple authentication methods
 * Requirements: 9.1, 9.2
 */
async function validateServiceIdentity(
  request: ServiceTokenRequest,
  fastify: FastifyInstance
): Promise<boolean> {
  // Method 1: API Key authentication
  const apiKey = request.headers['x-api-key'];
  if (apiKey) {
    const validApiKey = process.env.SERVICE_API_KEY;
    if (validApiKey && apiKey === validApiKey) {
      return true;
    }
  }

  // Method 2: Service identity header (for internal network)
  const serviceIdentity = request.headers['x-service-identity'];
  if (serviceIdentity) {
    // In a real implementation, this would validate against a service registry
    // For now, accept any service identity from internal network
    const isInternalNetwork = isInternalIP(request.ip);
    if (isInternalNetwork && serviceIdentity.match(/^[a-zA-Z0-9-]+$/)) {
      return true;
    }
  }

  // Method 3: Mutual TLS (mTLS)
  // This would be handled at the ingress/gateway level
  // For now, check for a header that indicates mTLS was validated
  const mtlsValidated = request.headers['x-mtls-validated'];
  if (mtlsValidated === 'true') {
    return true;
  }

  // Method 4: Internal network without additional auth (least secure)
  // Only allow for development/testing
  if (process.env.NODE_ENV === 'development' && isInternalIP(request.ip)) {
    fastify.log.warn('Allowing service token request from internal network without authentication (development mode)', {
      ip: request.ip,
      serviceId: request.body.serviceId,
    });
    return true;
  }

  return false;
}

/**
 * Check if IP address is from internal network
 */
function isInternalIP(ip: string): boolean {
  // Check for common internal network ranges
  const internalRanges = [
    /^127\./, // localhost
    /^10\./, // 10.0.0.0/8
    /^172\.(1[6-9]|2[0-9]|3[01])\./, // 172.16.0.0/12
    /^192\.168\./, // 192.168.0.0/16
    /^::1$/, // IPv6 localhost
    /^fc00:/, // IPv6 unique local addresses
  ];

  return internalRanges.some(range => range.test(ip));
}

/**
 * Validate permissions array
 * Requirements: 9.4
 */
function validatePermissions(permissions: string[]): { isValid: boolean; error?: string } {
  if (!Array.isArray(permissions)) {
    return { isValid: false, error: 'Permissions must be an array' };
  }

  if (permissions.length === 0) {
    return { isValid: false, error: 'At least one permission is required' };
  }

  if (permissions.length > 50) {
    return { isValid: false, error: 'Too many permissions (max 50)' };
  }

  // Define allowed permission patterns
  const allowedPatterns = [
    /^read:/, // read:users, read:orgs, etc.
    /^write:/, // write:users, write:orgs, etc.
    /^admin:/, // admin:users, admin:orgs, etc.
    /^system:/, // system:health, system:metrics, etc.
  ];

  for (const permission of permissions) {
    if (typeof permission !== 'string') {
      return { isValid: false, error: 'All permissions must be strings' };
    }

    if (permission.length > 100) {
      return { isValid: false, error: 'Permission names too long (max 100 chars)' };
    }

    const isValidPattern = allowedPatterns.some(pattern => pattern.test(permission));
    if (!isValidPattern) {
      return { isValid: false, error: `Invalid permission format: ${permission}` };
    }
  }

  // Check for duplicate permissions
  const uniquePermissions = new Set(permissions);
  if (uniquePermissions.size !== permissions.length) {
    return { isValid: false, error: 'Duplicate permissions not allowed' };
  }

  return { isValid: true };
}