import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Type } from '@sinclair/typebox';
import { ValidationService } from '../modules/auth/validation-service.js';
import { JWTManager } from '../modules/auth/jwt-manager.js';
import { Kysely } from 'kysely';
import { Database } from '../types/database.js';

const HealthResponseSchema = Type.Object({
  status: Type.Union([Type.Literal('healthy'), Type.Literal('unhealthy'), Type.Literal('degraded')]),
  timestamp: Type.String({ format: 'date-time' }),
  services: Type.Object({
    database: Type.Object({
      status: Type.Union([Type.Literal('healthy'), Type.Literal('unhealthy')]),
      responseTime?: Type.Number(),
      error?: Type.String(),
    }),
    cache: Type.Object({
      status: Type.Union([Type.Literal('healthy'), Type.Literal('unhealthy')]),
      responseTime?: Type.Number(),
      error?: Type.String(),
    }),
    jwt: Type.Object({
      status: Type.Union([Type.Literal('healthy'), Type.Literal('unhealthy')]),
      error?: Type.String(),
    }),
  }),
  version?: Type.String(),
});

export async function healthRoutes(fastify: FastifyInstance) {
  // Get dependencies from Fastify context
  const validationService = fastify.validationService as ValidationService;
  const jwtManager = fastify.jwtManager as JWTManager;
  const db = fastify.db as Kysely<Database>;

  /**
   * Health check endpoint
   * Requirements: 8.8
   */
  fastify.get('/health', {
    schema: {
      response: {
        200: HealthResponseSchema,
        503: HealthResponseSchema,
      },
    },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const timestamp = new Date().toISOString();
    const checks = await Promise.allSettled([
      checkDatabaseHealth(db),
      checkCacheHealth(validationService),
      checkJWTHealth(jwtManager),
    ]);

    const [dbResult, cacheResult, jwtResult] = checks;

    const dbHealth = dbResult.status === 'fulfilled' ? dbResult.value : {
      status: 'unhealthy' as const,
      error: dbResult.status === 'rejected' ? String(dbResult.reason) : 'Unknown error',
    };

    const cacheHealth = cacheResult.status === 'fulfilled' ? cacheResult.value : {
      status: 'unhealthy' as const,
      error: cacheResult.status === 'rejected' ? String(cacheResult.reason) : 'Unknown error',
    };

    const jwtHealth = jwtResult.status === 'fulfilled' ? jwtResult.value : {
      status: 'unhealthy' as const,
      error: jwtResult.status === 'rejected' ? String(jwtResult.reason) : 'Unknown error',
    };

    // Determine overall status
    const allHealthy = dbHealth.status === 'healthy' && 
                      cacheHealth.status === 'healthy' && 
                      jwtHealth.status === 'healthy';

    const anyHealthy = dbHealth.status === 'healthy' || 
                      cacheHealth.status === 'healthy' || 
                      jwtHealth.status === 'healthy';

    let overallStatus: 'healthy' | 'unhealthy' | 'degraded';
    let statusCode: number;

    if (allHealthy) {
      overallStatus = 'healthy';
      statusCode = 200;
    } else if (anyHealthy) {
      overallStatus = 'degraded';
      statusCode = 200; // Still accepting traffic but with degraded performance
    } else {
      overallStatus = 'unhealthy';
      statusCode = 503;
    }

    const response = {
      status: overallStatus,
      timestamp,
      services: {
        database: dbHealth,
        cache: cacheHealth,
        jwt: jwtHealth,
      },
      version: process.env.npm_package_version || 'unknown',
    };

    return reply.status(statusCode).send(response);
  });

  /**
   * Readiness probe endpoint (Kubernetes)
   * Returns 200 only when all critical services are ready
   */
  fastify.get('/ready', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const [dbHealthy, cacheHealthy, jwtHealthy] = await Promise.all([
        checkDatabaseConnectivity(db),
        checkCacheConnectivity(validationService),
        checkJWTFunctionality(jwtManager),
      ]);

      if (dbHealthy && cacheHealthy && jwtHealthy) {
        return reply.status(200).send({
          status: 'ready',
          timestamp: new Date().toISOString(),
        });
      } else {
        return reply.status(503).send({
          status: 'not_ready',
          timestamp: new Date().toISOString(),
          services: {
            database: dbHealthy,
            cache: cacheHealthy,
            jwt: jwtHealthy,
          },
        });
      }
    } catch (error) {
      return reply.status(503).send({
        status: 'error',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      });
    }
  });

  /**
   * Liveness probe endpoint (Kubernetes)
   * Returns 200 if the application is running (even if dependencies are down)
   */
  fastify.get('/live', async (request: FastifyRequest, reply: FastifyReply) => {
    return reply.status(200).send({
      status: 'alive',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
    });
  });
}

/**
 * Check database health with response time
 */
async function checkDatabaseHealth(db: Kysely<Database>): Promise<{
  status: 'healthy' | 'unhealthy';
  responseTime?: number;
  error?: string;
}> {
  const startTime = Date.now();
  
  try {
    // Simple query to test database connectivity
    await db.selectFrom('users').select('id').limit(1).execute();
    
    const responseTime = Date.now() - startTime;
    
    return {
      status: 'healthy',
      responseTime,
    };
  } catch (error) {
    const responseTime = Date.now() - startTime;
    
    return {
      status: 'unhealthy',
      responseTime,
      error: error instanceof Error ? error.message : 'Database connection failed',
    };
  }
}

/**
 * Check cache health with response time
 */
async function checkCacheHealth(validationService: ValidationService): Promise<{
  status: 'healthy' | 'unhealthy';
  responseTime?: number;
  error?: string;
}> {
  const startTime = Date.now();
  
  try {
    const health = await validationService.healthCheck();
    const responseTime = Date.now() - startTime;
    
    if (health.session && health.permission) {
      return {
        status: 'healthy',
        responseTime,
      };
    } else {
      return {
        status: 'unhealthy',
        responseTime,
        error: 'Cache connectivity issues',
      };
    }
  } catch (error) {
    const responseTime = Date.now() - startTime;
    
    return {
      status: 'unhealthy',
      responseTime,
      error: error instanceof Error ? error.message : 'Cache health check failed',
    };
  }
}

/**
 * Check JWT functionality
 */
async function checkJWTHealth(jwtManager: JWTManager): Promise<{
  status: 'healthy' | 'unhealthy';
  error?: string;
}> {
  try {
    const isHealthy = jwtManager.healthCheck();
    
    if (isHealthy) {
      return { status: 'healthy' };
    } else {
      return {
        status: 'unhealthy',
        error: 'JWT sign/verify test failed',
      };
    }
  } catch (error) {
    return {
      status: 'unhealthy',
      error: error instanceof Error ? error.message : 'JWT health check failed',
    };
  }
}

/**
 * Simple database connectivity check (for readiness probe)
 */
async function checkDatabaseConnectivity(db: Kysely<Database>): Promise<boolean> {
  try {
    await db.selectFrom('users').select('id').limit(1).execute();
    return true;
  } catch {
    return false;
  }
}

/**
 * Simple cache connectivity check (for readiness probe)
 */
async function checkCacheConnectivity(validationService: ValidationService): Promise<boolean> {
  try {
    const health = await validationService.healthCheck();
    return health.session && health.permission;
  } catch {
    return false;
  }
}

/**
 * Simple JWT functionality check (for readiness probe)
 */
async function checkJWTFunctionality(jwtManager: JWTManager): Promise<boolean> {
  try {
    return jwtManager.healthCheck();
  } catch {
    return false;
  }
}