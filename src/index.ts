// Identity Service entry point
import 'dotenv/config';
import Fastify from 'fastify';
import { createDatabase } from './infrastructure/database.js';
import { createCache } from './infrastructure/cache.js';
import { logger, requestCorrelationMiddleware, infraLogger } from './infrastructure/logger.js';
import { errorHandler } from './middleware/error-handler.js';
import { piiRedactionHook } from './middleware/pii-redaction.js';
import { validateEnvironmentConfig } from './config/validation.js';
import { NeonAuthClient } from './modules/auth/neon-auth-client.js';
import { SessionManager } from './modules/auth/session-manager.js';
import { JWTManager } from './modules/auth/jwt-manager.js';
import { JWTCache } from './modules/auth/jwt-cache.js';
import { ValidationService } from './modules/auth/validation-service.js';
import { TokenManager } from './modules/auth/token-manager.js';
import { PermissionCache } from './modules/auth/permission-cache.js';
import { TokenCache } from './modules/auth/token-cache.js';
import { UserRepository } from './modules/user/user-repository.js';
import { OrgRepository } from './modules/org/org-repository.js';
import { TokenRepository } from './modules/token/token-repository.js';
import { NeonAuthService } from './services/neon-auth.service.js';
import { loginRoutes } from './routes/auth/login.js';
import { callbackRoutes } from './routes/auth/callback.js';
import { logoutRoutes } from './routes/auth/logout.js';
import { switchOrgRoutes } from './routes/auth/switch-org.js';
import { testSessionRoutes } from './routes/auth/test-session.js';
import { tokenRoutes } from './routes/auth/tokens.js';
import { validateRoutes } from './routes/internal/validate.js';

// Validate environment configuration at startup (fail-fast)
validateEnvironmentConfig();

// Extend Fastify instance with our services for TypeScript
declare module 'fastify' {
  interface FastifyInstance {
    validationService: ValidationService;
    jwtManager: JWTManager;
    jwtCache: JWTCache;
  }
}

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

// Add content-type parser for empty POST bodies (extAuthz compatibility)
fastify.addContentTypeParser('application/json', { parseAs: 'string' }, (_req, body, done) => {
  try {
    const json = body === '' ? {} : JSON.parse(body as string);
    done(null, json);
  } catch (err) {
    done(err as Error, undefined);
  }
});

// Add global request logging hook
fastify.addHook('onRequest', async (request) => {
  request.log.info({
    method: request.method,
    url: request.url,
    headers: Object.keys(request.headers),
    ip: request.ip
  }, 'Incoming request');
});

// Register cookie support
await fastify.register(import('@fastify/cookie'));

// Initialize infrastructure
const db = createDatabase();
const cache = createCache();

// Log infrastructure initialization
infraLogger.databaseConnected();
infraLogger.cacheConnected();

// Initialize repositories
const userRepository = new UserRepository(db);
const orgRepository = new OrgRepository(db);
const tokenRepository = new TokenRepository(db);

// Initialize caches
const permissionCache = new PermissionCache(cache);
const jwtCache = new JWTCache(cache);
const tokenCache = new TokenCache(cache);

// Initialize session manager - same as integration tests
const sessionManager = new SessionManager(cache, {
  sessionTTL: parseInt(process.env['SESSION_TTL'] || '86400'), // 24 hours
  absoluteTTL: parseInt(process.env['ABSOLUTE_TTL'] || '604800'), // 7 days
  cookieName: process.env['COOKIE_NAME'] || '__Host-platform_session',
});

// Initialize JWT manager - same as integration tests
const jwtManager = new JWTManager({
  privateKey: process.env['JWT_PRIVATE_KEY']!.replace(/\\n/g, '\n'),
  publicKey: process.env['JWT_PUBLIC_KEY']!.replace(/\\n/g, '\n'),
  keyId: process.env['JWT_KEY_ID']!,
  expiration: process.env['JWT_EXPIRATION'] || '10m',
});

// Initialize token manager
const tokenManager = new TokenManager(tokenRepository, tokenCache, process.env['TOKEN_PEPPER']!);

// Initialize validation service - same as integration tests
const validationService = new ValidationService(
  sessionManager,
  tokenManager,
  permissionCache,
  orgRepository
);

// Decorate fastify instance with only the services needed by validate routes
fastify.decorate('validationService', validationService);
fastify.decorate('jwtManager', jwtManager);
fastify.decorate('jwtCache', jwtCache);

// Register request correlation middleware
fastify.addHook('onRequest', requestCorrelationMiddleware);

// Register PII redaction middleware
fastify.addHook('onRequest', piiRedactionHook);

// Register error handler
fastify.setErrorHandler(errorHandler);

import { CONFIG } from './config/index.js';

// Initialize services
const neonAuthClient = new NeonAuthClient({
  baseURL: process.env['NEON_AUTH_URL']!,
  redirectUri: CONFIG.NEON_AUTH_REDIRECT_URI,
});

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
  cookieSecure: true,
};

const logoutConfig = {
  cookieName: CONFIG.SESSION_COOKIE_NAME,
  cookieSecure: true,
};

const switchOrgConfig = {
  cookieName: CONFIG.SESSION_COOKIE_NAME,
};

const testSessionConfig = {
  cookieSecure: true,
};

// Register routes
loginRoutes(fastify, neonAuthClient, sessionManager, userRepository, orgRepository, loginConfig);
callbackRoutes(fastify, neonAuthService, sessionManager, jwtManager, jwtCache, callbackConfig);
logoutRoutes(fastify, sessionManager, jwtCache, neonAuthService, logoutConfig);
switchOrgRoutes(fastify, sessionManager, jwtCache, orgRepository, switchOrgConfig);
testSessionRoutes(fastify, sessionManager, userRepository, orgRepository, testSessionConfig);

// Register token routes
tokenRoutes(fastify, sessionManager, tokenManager, tokenRepository);

// Register validate routes
await validateRoutes(fastify);

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

    return { 
      status: 'healthy', 
      service: 'identity-service',
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
