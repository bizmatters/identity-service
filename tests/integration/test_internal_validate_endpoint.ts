import { describe, it, expect, beforeEach } from 'vitest';
import { db, cache } from './conftest.js';
import { TestHelpers } from '../mock/test-helpers.js';
import Fastify, { FastifyInstance } from 'fastify';

// Import production service classes
import { SessionManager, SessionConfig } from '../../src/modules/auth/session-manager.js';
import { ValidationService } from '../../src/modules/auth/validation-service.js';
import { JWTManager, JWTConfig } from '../../src/modules/auth/jwt-manager.js';
import { JWTCache } from '../../src/modules/auth/jwt-cache.js';
import { PermissionCache } from '../../src/modules/auth/permission-cache.js';
import { TokenManager } from '../../src/modules/auth/token-manager.js';
import { TokenCache } from '../../src/modules/auth/token-cache.js';
import { OrgRepository } from '../../src/modules/org/org-repository.js';
import { TokenRepository } from '../../src/modules/token/token-repository.js';
import { validateRoutes } from '../../src/routes/internal/validate.js';

describe('/internal/validate Endpoint Integration Test', () => {
  let app: FastifyInstance;
  let sessionManager: SessionManager;
  let validationService: ValidationService;
  let jwtManager: JWTManager;
  let jwtCache: JWTCache;
  let testUser: { id: string; external_id: string; email: string };
  let testOrg: { id: string; name: string; slug: string };

  beforeEach(async () => {
    // Create test data
    const testData = await TestHelpers.createTestUser(db);
    testUser = testData.user;
    testOrg = testData.organization;

    // Initialize services
    const sessionConfig: SessionConfig = {
      sessionTTL: 86400,
      absoluteTTL: 604800,
      cookieName: '__Host-platform_session',
    };

    const privateKey = process.env.JWT_PRIVATE_KEY!.replace(/\\n/g, '\n');
    const publicKey = process.env.JWT_PUBLIC_KEY!.replace(/\\n/g, '\n');

    const jwtConfig: JWTConfig = {
      privateKey,
      publicKey,
      keyId: process.env.JWT_KEY_ID!,
      expiration: '10m',
    };

    sessionManager = new SessionManager(cache, sessionConfig);
    jwtManager = new JWTManager(jwtConfig);
    jwtCache = new JWTCache(cache);
    const permissionCache = new PermissionCache(cache);
    const orgRepository = new OrgRepository(db);
    const tokenRepository = new TokenRepository(db);
    const tokenCache = new TokenCache(cache);
    const tokenManager = new TokenManager(tokenRepository, tokenCache, 'test-pepper');

    validationService = new ValidationService(
      sessionManager,
      tokenManager,
      permissionCache,
      orgRepository
    );

    // Create Fastify app
    app = Fastify({ logger: false });

    // Attach services to Fastify instance
    app.decorate('validationService', validationService);
    app.decorate('jwtManager', jwtManager);
    app.decorate('jwtCache', jwtCache);

    // Register routes
    await app.register(validateRoutes);
    await app.ready();
  });

  afterEach(async () => {
    await app.close();
  });

  describe('POST /internal/validate - No Authentication', () => {
    it('should return 401 when no Cookie or Authorization header provided', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/internal/validate',
      });

      expect(response.statusCode).toBe(401);
      expect(response.json()).toEqual({
        error: 'No authentication provided',
      });
    });
  });

  describe('POST /internal/validate - Cookie Authentication', () => {
    it('should return 401 for invalid session cookie', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/internal/validate',
        headers: {
          cookie: '__Host-platform_session=invalid-session-id',
        },
      });

      expect(response.statusCode).toBe(401);
      expect(response.json()).toHaveProperty('error');
    });

    it('should return 200 with headers for valid session cookie', async () => {
      // Create valid session
      const sessionId = await sessionManager.createSession(
        testUser.id,
        testOrg.id,
        'owner'
      );

      const response = await app.inject({
        method: 'POST',
        url: '/internal/validate',
        headers: {
          cookie: `__Host-platform_session=${sessionId}`,
        },
      });

      expect(response.statusCode).toBe(200);

      const body = response.json();
      expect(body.status).toBe('authorized');
      expect(body.userId).toBe(testUser.id);
      expect(body.orgId).toBe(testOrg.id);
      expect(body.role).toBe('owner');

      // Verify response headers
      expect(response.headers['authorization']).toMatch(/^Bearer .+$/);
      expect(response.headers['x-auth-user-id']).toBe(testUser.id);
      expect(response.headers['x-auth-org-id']).toBe(testOrg.id);
    });

    it('should return cached JWT on second request', async () => {
      const sessionId = await sessionManager.createSession(
        testUser.id,
        testOrg.id,
        'owner'
      );

      // First request
      const response1 = await app.inject({
        method: 'POST',
        url: '/internal/validate',
        headers: {
          cookie: `__Host-platform_session=${sessionId}`,
        },
      });

      expect(response1.statusCode).toBe(200);
      const jwt1 = response1.headers['authorization'];

      // Second request should return same JWT from cache
      const response2 = await app.inject({
        method: 'POST',
        url: '/internal/validate',
        headers: {
          cookie: `__Host-platform_session=${sessionId}`,
        },
      });

      expect(response2.statusCode).toBe(200);
      const jwt2 = response2.headers['authorization'];

      expect(jwt1).toBe(jwt2);
    });
  });

  describe('POST /internal/validate - Authorization Header', () => {
    it('should return 401 for invalid Bearer token', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/internal/validate',
        headers: {
          authorization: 'Bearer invalid-token',
        },
      });

      expect(response.statusCode).toBe(401);
      expect(response.json()).toHaveProperty('error');
    });

    it('should return 401 for malformed Authorization header', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/internal/validate',
        headers: {
          authorization: 'InvalidFormat token123',
        },
      });

      expect(response.statusCode).toBe(401);
      expect(response.json()).toEqual({
        error: 'Invalid authorization header',
      });
    });
  });

  describe('POST /internal/validate - Cookie Extraction', () => {
    it('should extract session from cookie with multiple cookies', async () => {
      const sessionId = await sessionManager.createSession(
        testUser.id,
        testOrg.id,
        'owner'
      );

      const response = await app.inject({
        method: 'POST',
        url: '/internal/validate',
        headers: {
          cookie: `other_cookie=value1; __Host-platform_session=${sessionId}; another=value2`,
        },
      });

      expect(response.statusCode).toBe(200);
      expect(response.json().userId).toBe(testUser.id);
    });

    it('should return 401 when session cookie is missing from multiple cookies', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/internal/validate',
        headers: {
          cookie: 'other_cookie=value1; another=value2',
        },
      });

      expect(response.statusCode).toBe(401);
      expect(response.json()).toEqual({
        error: 'Invalid session cookie',
      });
    });
  });

  describe('GET /internal/health', () => {
    it('should return 200 with healthy status', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/internal/health',
      });

      expect(response.statusCode).toBe(200);

      const body = response.json();
      expect(body.status).toBe('healthy');
      expect(body.services).toHaveProperty('session');
      expect(body.services).toHaveProperty('permission');
      expect(body.services).toHaveProperty('jwt');
    });
  });

  describe('AgentGateway Simulation', () => {
    it('should simulate complete extAuthz flow: Cookie → validate → JWT headers', async () => {
      // Step 1: Create session (simulates user login)
      const sessionId = await sessionManager.createSession(
        testUser.id,
        testOrg.id,
        'owner'
      );

      // Step 2: AgentGateway calls /internal/validate with Cookie header
      const response = await app.inject({
        method: 'POST',
        url: '/internal/validate',
        headers: {
          cookie: `__Host-platform_session=${sessionId}`,
        },
      });

      // Step 3: Verify response
      expect(response.statusCode).toBe(200);

      // Step 4: Verify AgentGateway receives correct headers
      const authHeader = response.headers['authorization'];
      expect(authHeader).toMatch(/^Bearer .+$/);

      const jwt = authHeader!.replace('Bearer ', '');
      const payload = jwtManager.verifyPlatformJWT(jwt);

      expect(payload.sub).toBe(testUser.id);
      expect(payload.org).toBe(testOrg.id);
      expect(payload.role).toBe('owner');

      // Step 5: Verify X-Auth headers
      expect(response.headers['x-auth-user-id']).toBe(testUser.id);
      expect(response.headers['x-auth-org-id']).toBe(testOrg.id);
    });

    it('should return 401 for unauthenticated request (no cookie)', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/internal/validate',
      });

      expect(response.statusCode).toBe(401);
      expect(response.json()).toEqual({
        error: 'No authentication provided',
      });
    });

    it('should return 401 for expired session', async () => {
      // Create session with short TTL
      const shortSessionConfig: SessionConfig = {
        sessionTTL: 1,
        absoluteTTL: 2,
        cookieName: '__Host-platform_session',
      };

      const shortSessionManager = new SessionManager(cache, shortSessionConfig);
      const sessionId = await shortSessionManager.createSession(
        testUser.id,
        testOrg.id,
        'owner'
      );

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 2500));

      const response = await app.inject({
        method: 'POST',
        url: '/internal/validate',
        headers: {
          cookie: `__Host-platform_session=${sessionId}`,
        },
      });

      expect(response.statusCode).toBe(401);
    });
  });
});
