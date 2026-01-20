import { FastifyPluginAsync } from 'fastify';
import fp from 'fastify-plugin';
import { Kysely } from 'kysely';
import { Redis } from 'ioredis';
import { Database } from '../types/database.js';
import { ValidationService } from '../modules/auth/validation-service.js';
import { JWTManager, JWTConfig } from '../modules/auth/jwt-manager.js';
import { JWTCache } from '../modules/auth/jwt-cache.js';
import { TokenManager } from '../modules/auth/token-manager.js';
import { SessionManager, SessionConfig } from '../modules/auth/session-manager.js';
import { PermissionCache } from '../modules/auth/permission-cache.js';
import { TokenCache } from '../modules/auth/token-cache.js';
import { UserRepository } from '../modules/user/user-repository.js';
import { OrgRepository } from '../modules/org/org-repository.js';
import { TokenRepository } from '../modules/token/token-repository.js';

// Extend Fastify instance with our services
declare module 'fastify' {
  interface FastifyInstance {
    db: Kysely<Database>;
    cache: Redis;
    validationService: ValidationService;
    jwtManager: JWTManager;
    jwtCache: JWTCache;
    tokenManager: TokenManager;
    sessionManager: SessionManager;
    permissionCache: PermissionCache;
    tokenCache: TokenCache;
    userRepository: UserRepository;
    orgRepository: OrgRepository;
    tokenRepository: TokenRepository;
  }
}

const servicesPlugin: FastifyPluginAsync = async (fastify): Promise<void> => {
  // Database and cache should be registered elsewhere
  const db = fastify.db;
  const cache = fastify.cache;

  // Initialize repositories
  const userRepository = new UserRepository(db);
  const orgRepository = new OrgRepository(db);
  const tokenRepository = new TokenRepository(db);

  // Initialize caches
  const permissionCache = new PermissionCache(cache);
  const jwtCache = new JWTCache(cache);
  const tokenCache = new TokenCache(cache);

  // Initialize session manager
  const sessionConfig: SessionConfig = {
    sessionTTL: parseInt(process.env['SESSION_TTL'] || '86400'), // 24 hours
    absoluteTTL: parseInt(process.env['ABSOLUTE_TTL'] || '604800'), // 7 days
    cookieName: process.env['COOKIE_NAME'] || '__Host-platform_session',
  };
  const sessionManager = new SessionManager(cache, sessionConfig);

  // Initialize JWT manager
  const jwtConfig: JWTConfig = {
    privateKey: process.env['JWT_PRIVATE_KEY']!.replace(/\\n/g, '\n'),
    publicKey: process.env['JWT_PUBLIC_KEY']!.replace(/\\n/g, '\n'),
    keyId: process.env['JWT_KEY_ID']!,
    expiration: process.env['JWT_EXPIRATION'] || '10m',
  };
  const jwtManager = new JWTManager(jwtConfig);

  // Initialize token manager
  const tokenManager = new TokenManager(tokenRepository, tokenCache, process.env['TOKEN_PEPPER']!);

  // Initialize validation service
  const validationService = new ValidationService(
    sessionManager,
    tokenManager,
    permissionCache,
    orgRepository
  );

  // Decorate fastify instance
  fastify.decorate('validationService', validationService);
  fastify.decorate('jwtManager', jwtManager);
  fastify.decorate('jwtCache', jwtCache);
  fastify.decorate('tokenManager', tokenManager);
  fastify.decorate('sessionManager', sessionManager);
  fastify.decorate('permissionCache', permissionCache);
  fastify.decorate('tokenCache', tokenCache);
  fastify.decorate('userRepository', userRepository);
  fastify.decorate('orgRepository', orgRepository);
  fastify.decorate('tokenRepository', tokenRepository);
};

export default fp(servicesPlugin, {
  name: 'services',
  dependencies: ['database', 'cache'],
});