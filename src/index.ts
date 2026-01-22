// Identity Service entry point
import 'dotenv/config';
import Fastify from 'fastify';
import { createDatabase } from './infrastructure/database.js';
import { createCache } from './infrastructure/cache.js';
import { logger, requestCorrelationMiddleware, infraLogger } from './infrastructure/logger.js';
import { errorHandler } from './middleware/error-handler.js';
import { getCircuitBreakerHealth } from './infrastructure/resilience.js';
import { NeonAuthClient } from './modules/auth/neon-auth-client.js';
import { SessionManager } from './modules/auth/session-manager.js';
import { JWTManager } from './modules/auth/jwt-manager.js';
import { JWTCache } from './modules/auth/jwt-cache.js';
import { UserRepository } from './modules/user/user-repository.js';
import { OrgRepository } from './modules/org/org-repository.js';
import { NeonAuthService } from './services/neon-auth.service.js';
import { loginRoutes } from './routes/auth/login.js';
import { callbackRoutes } from './routes/auth/callback.js';
import { logoutRoutes } from './routes/auth/logout.js';
import { switchOrgRoutes } from './routes/auth/switch-org.js';
import { testSessionRoutes } from './routes/auth/test-session.js';

const fastify = Fastify({
  logger: {
    level: process.env['LOG_LEVEL'] || 'info',
    serializers: {
      req: (req) => ({
        method: req.method,
        url: req.url,
        headers: req.headers,
      }),
      res: (res) => ({
        statusCode: res.statusCode,
      }),
    },
  },
  disableRequestLogging: true, // We'll handle request logging via middleware
});

// Register cookie support
await fastify.register(import('@fastify/cookie'));

// Register request correlation middleware
fastify.addHook('onRequest', requestCorrelationMiddleware);

// Register error handler
fastify.setErrorHandler(errorHandler);

// Initialize infrastructure
const db = createDatabase();
const cache = createCache();

// Log infrastructure initialization
infraLogger.databaseConnected();
infraLogger.cacheConnected();

import { CONFIG } from './config/index.js';

// Initialize services
const neonAuthClient = new NeonAuthClient({
  baseURL: process.env['NEON_AUTH_URL']!,
  redirectUri: CONFIG.NEON_AUTH_REDIRECT_URI,
});

const sessionManager = new SessionManager(cache, {
  sessionTTL: CONFIG.SESSION_TTL,
  absoluteTTL: CONFIG.SESSION_ABSOLUTE_TTL,
  cookieName: CONFIG.SESSION_COOKIE_NAME,
});

const jwtManager = new JWTManager({
  privateKey: process.env['JWT_PRIVATE_KEY']!,
  publicKey: process.env['JWT_PUBLIC_KEY']!,
  keyId: process.env['JWT_KEY_ID'] || CONFIG.JWT_KEY_ID_DEFAULT,
  expiration: CONFIG.JWT_EXPIRATION,
  ...(process.env['JWT_PREVIOUS_PRIVATE_KEY'] && {
    previousPrivateKey: process.env['JWT_PREVIOUS_PRIVATE_KEY'],
  }),
  ...(process.env['JWT_PREVIOUS_PUBLIC_KEY'] && {
    previousPublicKey: process.env['JWT_PREVIOUS_PUBLIC_KEY'],
  }),
  ...(process.env['JWT_PREVIOUS_KEY_ID'] && {
    previousKeyId: process.env['JWT_PREVIOUS_KEY_ID'],
  }),
});

const jwtCache = new JWTCache(cache);

const userRepository = new UserRepository(db);
const orgRepository = new OrgRepository(db);

const neonAuthService = new NeonAuthService(
  {
    baseURL: process.env['NEON_AUTH_URL']!,
    redirectUri: CONFIG.NEON_AUTH_REDIRECT_URI,
  },
  userRepository,
  orgRepository
);

// Configuration
const loginConfig = {
  allowedRedirectUris: [...CONFIG.ALLOWED_REDIRECT_URIS],
  defaultRedirectUri: CONFIG.DEFAULT_REDIRECT_URI,
  neonAuthClientId: CONFIG.NEON_AUTH_CLIENT_ID,
};

const callbackConfig = {
  allowedRedirectUris: [...CONFIG.ALLOWED_REDIRECT_URIS],
  defaultRedirectUri: CONFIG.DEFAULT_REDIRECT_URI,
  cookieDomain: CONFIG.COOKIE_DOMAIN,
  cookieSecure: process.env['NODE_ENV'] === 'production',
};

const logoutConfig = {
  cookieName: CONFIG.SESSION_COOKIE_NAME,
  cookieSecure: process.env['NODE_ENV'] === 'production',
};

const switchOrgConfig = {
  cookieName: CONFIG.SESSION_COOKIE_NAME,
};

const testSessionConfig = {
  cookieSecure: process.env['NODE_ENV'] === 'production',
};

// Register routes
loginRoutes(fastify, neonAuthClient, sessionManager, userRepository, orgRepository, loginConfig);
callbackRoutes(fastify, neonAuthService, sessionManager, jwtManager, jwtCache, callbackConfig);
logoutRoutes(fastify, sessionManager, jwtCache, neonAuthService, logoutConfig);
switchOrgRoutes(fastify, sessionManager, jwtCache, orgRepository, switchOrgConfig);
testSessionRoutes(fastify, sessionManager, userRepository, orgRepository, testSessionConfig);

// Health check endpoint
fastify.get('/health', async (request): Promise<{ status: string; service: string; circuit_breakers?: any }> => {
  try {
    // Test database connection with timeout
    const dbPromise = db.selectFrom('users').select('id').limit(1).execute();
    await Promise.race([
      dbPromise,
      new Promise((_, reject) => setTimeout(() => reject(new Error('Database timeout')), 5000))
    ]);

    // Test cache connection with timeout
    const cachePromise = cache.ping();
    await Promise.race([
      cachePromise,
      new Promise((_, reject) => setTimeout(() => reject(new Error('Cache timeout')), 3000))
    ]);

    request.log.debug({
      message: 'Health check passed',
      event_type: 'health_check_success',
      timestamp: new Date().toISOString(),
    });

    // Include circuit breaker status in health response
    const circuitBreakerHealth = getCircuitBreakerHealth();

    return { 
      status: 'healthy', 
      service: 'identity-service',
      circuit_breakers: circuitBreakerHealth,
    };
  } catch (error) {
    request.log.error({
      message: 'Health check failed',
      event_type: 'health_check_failed',
      error: error instanceof Error ? error.message : String(error),
      timestamp: new Date().toISOString(),
    });
    throw new Error('Service unhealthy');
  }
});

// Ready check endpoint  
fastify.get('/ready', (): { status: string; service: string } => {
  return { status: 'ready', service: 'identity-service' };
});

// Basic info endpoint
fastify.get('/', (): { service: string; version: string; status: string } => {
  return {
    service: 'identity-service',
    version: '1.0.0',
    status: 'running'
  };
});

const start = async (): Promise<void> => {
  try {
    const PORT = process.env['PORT'] || 3000;
    await fastify.listen({ port: Number(PORT), host: '0.0.0.0' });
    logger.info({
      message: 'Identity Service started successfully',
      event_type: 'service_started',
      port: Number(PORT),
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    logger.error({
      message: 'Failed to start Identity Service',
      event_type: 'service_start_failed',
      error: err instanceof Error ? err.message : String(err),
      timestamp: new Date().toISOString(),
    });
    process.exit(1);
  }
};

void start();
