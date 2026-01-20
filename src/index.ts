// Identity Service entry point
import Fastify from 'fastify';
import { createDatabase } from './infrastructure/database.js';
import { createCache } from './infrastructure/cache.js';
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

const fastify = Fastify({
  logger: true
});

// Register cookie support
await fastify.register(import('@fastify/cookie'));

// Initialize infrastructure
const db = createDatabase();
const cache = createCache();

// Initialize services
const neonAuthClient = new NeonAuthClient({
  baseURL: process.env['NEON_AUTH_URL'] || 'https://ep-late-cherry-afaerbwj.neonauth.c-2.us-west-2.aws.neon.tech/neondb/auth',
  secret: process.env['NEON_AUTH_SECRET'] || '',
  redirectUri: process.env['NEON_AUTH_REDIRECT_URI'] || 'http://localhost:3000/auth/callback',
});

const sessionManager = new SessionManager(cache, {
  sessionTTL: parseInt(process.env['SESSION_TTL'] || '86400'),
  absoluteTTL: parseInt(process.env['SESSION_ABSOLUTE_TTL'] || '604800'),
  cookieName: process.env['SESSION_COOKIE_NAME'] || '__Host-platform_session',
});

const jwtManager = new JWTManager({
  privateKey: process.env['JWT_PRIVATE_KEY'] || '',
  publicKey: process.env['JWT_PUBLIC_KEY'] || '',
  keyId: process.env['JWT_KEY_ID'] || 'default',
  expiration: process.env['JWT_EXPIRATION'] || '10m',
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
    baseURL: process.env['NEON_AUTH_URL'] || 'https://ep-late-cherry-afaerbwj.neonauth.c-2.us-west-2.aws.neon.tech/neondb/auth',
    secret: process.env['NEON_AUTH_SECRET'] || '',
    redirectUri: process.env['NEON_AUTH_REDIRECT_URI'] || 'http://localhost:3000/auth/callback',
  },
  userRepository,
  orgRepository
);

// Configuration
const loginConfig = {
  allowedRedirectUris: (process.env['ALLOWED_REDIRECT_URIS'] || 'http://localhost:3000/dashboard').split(','),
  defaultRedirectUri: process.env['DEFAULT_REDIRECT_URI'] || 'http://localhost:3000/dashboard',
};

const callbackConfig = {
  allowedRedirectUris: (process.env['ALLOWED_REDIRECT_URIS'] || 'http://localhost:3000/dashboard').split(','),
  defaultRedirectUri: process.env['DEFAULT_REDIRECT_URI'] || 'http://localhost:3000/dashboard',
  cookieDomain: process.env['COOKIE_DOMAIN'] || '',
  cookieSecure: process.env['NODE_ENV'] === 'production',
};

const logoutConfig = {
  cookieName: process.env['SESSION_COOKIE_NAME'] || '__Host-platform_session',
  cookieSecure: process.env['NODE_ENV'] === 'production',
};

const switchOrgConfig = {
  cookieName: process.env['SESSION_COOKIE_NAME'] || '__Host-platform_session',
};

// Register routes
loginRoutes(fastify, neonAuthClient, sessionManager, userRepository, orgRepository, loginConfig);
callbackRoutes(fastify, neonAuthService, sessionManager, jwtManager, jwtCache, callbackConfig);
logoutRoutes(fastify, sessionManager, jwtCache, neonAuthService, logoutConfig);
switchOrgRoutes(fastify, sessionManager, jwtCache, orgRepository, switchOrgConfig);

// Health check endpoint
fastify.get('/health', async (): Promise<{ status: string; service: string }> => {
  try {
    // Test database connection
    await db.selectFrom('users').select('id').limit(1).execute();
    
    // Test cache connection
    await cache.ping();
    
    return { status: 'healthy', service: 'identity-service' };
  } catch (error) {
    fastify.log.error(error, 'Health check failed');
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
    console.log(`Identity Service running on port ${PORT}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

void start();
