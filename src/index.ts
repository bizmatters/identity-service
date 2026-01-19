// Identity Service entry point
import Fastify from 'fastify';
import { createDatabase } from './infrastructure/database.js';
import { createCache } from './infrastructure/cache.js';
import { OIDCClient } from './modules/oidc/oidc-client.js';
import { SessionManager } from './modules/auth/session-manager.js';
import { UserRepository } from './modules/user/user-repository.js';
import { OrgRepository } from './modules/org/org-repository.js';
import { JWTManager } from './modules/auth/jwt-manager.js';
import { JWTCache } from './modules/auth/jwt-cache.js';
import { loginRoutes } from './routes/auth/login.js';
import { callbackRoutes } from './routes/auth/callback.js';

const fastify = Fastify({
  logger: true
});

// Register cookie support
await fastify.register(import('@fastify/cookie'));

// Initialize infrastructure
const db = createDatabase();
const cache = createCache();

// Initialize services
const oidcClient = new OIDCClient({
  issuer: process.env['OIDC_ISSUER'] || 'https://accounts.google.com',
  clientId: process.env['OIDC_CLIENT_ID'] || '',
  clientSecret: process.env['OIDC_CLIENT_SECRET'] || '',
  redirectUri: process.env['OIDC_REDIRECT_URI'] || 'http://localhost:3000/auth/callback',
}, cache);

const sessionManager = new SessionManager(cache, {
  sessionTTL: parseInt(process.env['SESSION_TTL'] || '86400'),
  absoluteTTL: parseInt(process.env['SESSION_ABSOLUTE_TTL'] || '604800'),
});

const userRepository = new UserRepository(db);
const orgRepository = new OrgRepository(db);

const jwtManager = new JWTManager({
  privateKey: process.env['JWT_PRIVATE_KEY'] || '',
  publicKey: process.env['JWT_PUBLIC_KEY'] || '',
  keyId: process.env['JWT_KEY_ID'] || 'default',
  expiration: process.env['JWT_EXPIRATION'] || '10m',
});

const jwtCache = new JWTCache(cache, {
  bufferSeconds: parseInt(process.env['JWT_CACHE_BUFFER'] || '60'),
});

// Configuration
const loginConfig = {
  allowedRedirectUris: (process.env['ALLOWED_REDIRECT_URIS'] || 'http://localhost:3000/dashboard').split(','),
  defaultRedirectUri: process.env['DEFAULT_REDIRECT_URI'] || 'http://localhost:3000/dashboard',
};

const callbackConfig = {
  sessionCookieName: process.env['SESSION_COOKIE_NAME'] || '__Host-platform_session',
  cookieDomain: process.env['COOKIE_DOMAIN'] || 'localhost',
  cookieSecure: process.env['COOKIE_SECURE'] === 'true',
  dashboardUrl: process.env['DASHBOARD_URL'] || 'http://localhost:3000/dashboard',
};

// Register routes
loginRoutes(fastify, oidcClient, cache, loginConfig);
callbackRoutes(fastify, oidcClient, sessionManager, userRepository, orgRepository, jwtManager, jwtCache, cache, callbackConfig);

// Health check endpoint
fastify.get('/health', async () => {
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
fastify.get('/ready', async () => {
  return { status: 'ready', service: 'identity-service' };
});

// Basic info endpoint
fastify.get('/', async () => {
  return { 
    service: 'identity-service',
    version: '1.0.0',
    status: 'running'
  };
});

const start = async () => {
  try {
    const PORT = process.env['PORT'] || 3000;
    await fastify.listen({ port: Number(PORT), host: '0.0.0.0' });
    console.log(`Identity Service running on port ${PORT}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
