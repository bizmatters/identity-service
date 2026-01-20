import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Fastify from 'fastify';
// Import PRODUCTION service classes - same as used in production
import { NeonAuthClient } from '../../src/modules/auth/neon-auth-client.js';
import { SessionManager } from '../../src/modules/auth/session-manager.js';
import { JWTManager } from '../../src/modules/auth/jwt-manager.js';
import { JWTCache } from '../../src/modules/auth/jwt-cache.js';
import { UserRepository } from '../../src/modules/user/user-repository.js';
import { OrgRepository } from '../../src/modules/org/org-repository.js';
import { NeonAuthService } from '../../src/services/neon-auth.service.js';
// Import PRODUCTION route handlers - same as used in production
import { loginRoutes } from '../../src/routes/auth/login.js';
import { callbackRoutes } from '../../src/routes/auth/callback.js';
import { logoutRoutes } from '../../src/routes/auth/logout.js';
import { switchOrgRoutes } from '../../src/routes/auth/switch-org.js';
// Import REAL infrastructure and test helpers
import { db, cache, mockNeonAuth } from './conftest.js';
import { TestHelpers } from '../mock/test-helpers.js';

describe('Neon Auth Login Flow Integration Test', () => {
  let app: ReturnType<typeof Fastify>;
  // Use PRODUCTION service classes - same dependency injection as production
  let sessionManager: SessionManager;
  let jwtManager: JWTManager;
  let jwtCache: JWTCache;
  let userRepository: UserRepository;
  let orgRepository: OrgRepository;
  let neonAuthService: NeonAuthService;

  beforeEach(async () => {
    // Create Fastify app with PRODUCTION configuration
    app = Fastify({ logger: false });
    await app.register(import('@fastify/cookie'));

    // Initialize PRODUCTION services with REAL infrastructure
    // This uses the same service initialization as production
    sessionManager = new SessionManager(cache, {
      sessionTTL: 86400,
      absoluteTTL: 604800,
      cookieName: '__Host-platform_session',
    });

    // Use environment variables like production (SSM in prod)
    // Keys are stored with \n escape sequences, convert to actual newlines
    const privateKey = process.env.JWT_PRIVATE_KEY!.replace(/\\n/g, '\n');
    const publicKey = process.env.JWT_PUBLIC_KEY!.replace(/\\n/g, '\n');
    
    jwtManager = new JWTManager({
      privateKey,
      publicKey,
      keyId: process.env.JWT_KEY_ID!,
      expiration: '10m',
    });

    jwtCache = new JWTCache(cache); // Uses REAL Redis
    userRepository = new UserRepository(db); // Uses REAL PostgreSQL
    orgRepository = new OrgRepository(db); // Uses REAL PostgreSQL

    // NeonAuthClient points to mock via environment variable override pattern
    const neonAuthClient = new NeonAuthClient({
      baseURL: process.env['NEON_AUTH_URL'] || mockNeonAuth.getBaseURL(),
      secret: 'test-secret',
      redirectUri: 'http://localhost:3000/auth/callback',
    });

    neonAuthService = new NeonAuthService(
      {
        baseURL: process.env['NEON_AUTH_URL'] || mockNeonAuth.getBaseURL(),
        secret: 'test-secret',
        redirectUri: 'http://localhost:3000/auth/callback',
      },
      userRepository, // REAL database access
      orgRepository   // REAL database access
    );

    // Register PRODUCTION routes with REAL services
    const loginConfig = {
      allowedRedirectUris: ['http://localhost:3000/dashboard'],
      defaultRedirectUri: 'http://localhost:3000/dashboard',
    };

    const callbackConfig = {
      allowedRedirectUris: ['http://localhost:3000/dashboard'],
      defaultRedirectUri: 'http://localhost:3000/dashboard',
      cookieDomain: '',
      cookieSecure: false,
    };

    const logoutConfig = {
      cookieName: '__Host-platform_session',
      cookieSecure: false,
    };

    const switchOrgConfig = {
      cookieName: '__Host-platform_session',
    };

    // Register PRODUCTION routes - same as production
    loginRoutes(app, neonAuthClient, sessionManager, userRepository, orgRepository, loginConfig);
    callbackRoutes(app, neonAuthService, sessionManager, jwtManager, jwtCache, callbackConfig);
    logoutRoutes(app, sessionManager, jwtCache, neonAuthService, logoutConfig);
    switchOrgRoutes(app, sessionManager, jwtCache, orgRepository, switchOrgConfig);

    await app.ready();
  });

  afterEach(async () => {
    if (app) {
      await app.close();
    }
  });

  it('should serve HTML login page with Continue with Google button', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/auth/login',
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/html');
    expect(response.body).toContain('Continue with Google');
    expect(response.body).toContain('Welcome back');
    expect(response.body).toContain('/auth/login/google');
  });

  it('should validate redirect_uri against allowlist', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/auth/login?redirect_uri=https://malicious.com',
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.error).toBe('invalid_redirect_uri');
  });

  it('should initiate Google OAuth flow via Neon Auth', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/auth/login/google',
    });

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toContain('accounts.google.com');
  });

  it('should handle OAuth callback and create platform session', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/auth/callback?sessionVerifier=valid-verifier',
    });

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe('http://localhost:3000/dashboard');

    // Verify secure cookie is set
    const cookies = response.cookies;
    const sessionCookie = cookies.find((c: any) => c.name === '__Host-platform_session');
    expect(sessionCookie).toBeDefined();
    expect(sessionCookie?.httpOnly).toBe(true);
    expect(sessionCookie?.sameSite).toBe('Lax');
    expect(sessionCookie?.path).toBe('/');

    // Verify session is stored in REAL Redis cache
    const sessionId = sessionCookie?.value;
    expect(sessionId).toBeDefined();
    
    const sessionData = await sessionManager.getSession(sessionId!);
    expect(sessionData).toBeDefined();
    expect(sessionData?.user_id).toBeDefined();
    expect(sessionData?.org_id).toBeDefined();
    expect(sessionData?.role).toBe('owner');

    // Verify user was JIT provisioned in REAL PostgreSQL database
    const user = await userRepository.findByExternalId('test-user-456');
    expect(user).toBeDefined();
    expect(user?.email).toBe('test@example.com');
    expect(user?.default_org_id).toBeDefined();

    // Verify organization was created in REAL PostgreSQL database
    const membership = await orgRepository.getUserRole(user!.id, user!.default_org_id!);
    expect(membership).toBeDefined();
    expect(membership?.role).toBe('owner');
    expect(membership?.version).toBe(1);

    // Validate persistence through direct database query (final validation)
    const dbUser = await db
      .selectFrom('users')
      .selectAll()
      .where('external_id', '=', 'test-user-456')
      .executeTakeFirst();
    expect(dbUser).toBeDefined();
    expect(dbUser?.email).toBe('test@example.com');
  });

  it('should handle OAuth callback errors', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/auth/callback?error=access_denied&error_description=User%20denied%20access',
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.error).toBe('oauth_error');
  });

  it('should handle invalid session verifier', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/auth/callback?sessionVerifier=invalid-verifier',
    });

    expect(response.statusCode).toBe(500);
    expect(response.headers['content-type']).toContain('text/html');
    expect(response.body).toContain('Authentication Failed');
  });

  it('should logout and clear session', async () => {
    // First, create a session by going through the callback flow using REAL services
    const callbackResponse = await app.inject({
      method: 'GET',
      url: '/auth/callback?sessionVerifier=valid-verifier',
    });

    const cookies = callbackResponse.cookies;
    const sessionCookie = cookies.find((c: any) => c.name === '__Host-platform_session');
    const sessionId = sessionCookie?.value;

    // Verify session exists in REAL Redis
    let sessionData = await sessionManager.getSession(sessionId!);
    expect(sessionData).toBeDefined();

    // Logout using PRODUCTION endpoint
    const logoutResponse = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      cookies: {
        '__Host-platform_session': sessionId!,
      },
    });

    expect(logoutResponse.statusCode).toBe(200);
    const body = JSON.parse(logoutResponse.body);
    expect(body.message).toBe('Logged out successfully');

    // Verify session is deleted from REAL Redis
    sessionData = await sessionManager.getSession(sessionId!);
    expect(sessionData).toBeNull();

    // Verify cookie is cleared
    const clearCookies = logoutResponse.cookies;
    const clearedCookie = clearCookies.find((c: any) => c.name === '__Host-platform_session');
    expect(clearedCookie?.value).toBe('');
  });

  it('should switch organization context', async () => {
    // Setup: Create test data using REAL database
    const testData = await TestHelpers.createTestUser(db);
    
    // Create a second organization in REAL database
    const secondOrg = await db
      .insertInto('organizations')
      .values({
        name: 'Second Organization',
        slug: 'second-org',
      })
      .returningAll()
      .executeTakeFirstOrThrow();

    // Add user to second organization in REAL database
    await db
      .insertInto('memberships')
      .values({
        user_id: testData.user.id,
        org_id: secondOrg.id,
        role: 'developer',
        version: 1,
      })
      .execute();

    // Create session using REAL Redis
    const sessionId = await sessionManager.createSession(
      testData.user.id,
      testData.organization.id,
      'owner'
    );

    // Switch to second organization using PRODUCTION endpoint
    const response = await app.inject({
      method: 'POST',
      url: '/auth/switch-org',
      cookies: {
        '__Host-platform_session': sessionId,
      },
      payload: {
        org_id: secondOrg.id,
      },
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.message).toBe('Organization switched successfully');
    expect(body.org_id).toBe(secondOrg.id);
    expect(body.role).toBe('developer');

    // Verify session context was updated in REAL Redis
    const updatedSession = await sessionManager.getSession(sessionId);
    expect(updatedSession?.org_id).toBe(secondOrg.id);
    expect(updatedSession?.role).toBe('developer');
  });

  it('should reject organization switch for non-member', async () => {
    // Setup: Create test data using REAL database
    const testData = await TestHelpers.createTestUser(db);
    
    // Create a second organization (user is not a member) in REAL database
    const secondOrg = await db
      .insertInto('organizations')
      .values({
        name: 'Second Organization',
        slug: 'second-org',
      })
      .returningAll()
      .executeTakeFirstOrThrow();

    // Create session using REAL Redis
    const sessionId = await sessionManager.createSession(
      testData.user.id,
      testData.organization.id,
      'owner'
    );

    // Try to switch to organization user is not a member of
    const response = await app.inject({
      method: 'POST',
      url: '/auth/switch-org',
      cookies: {
        '__Host-platform_session': sessionId,
      },
      payload: {
        org_id: secondOrg.id,
      },
    });

    expect(response.statusCode).toBe(403);
    const body = JSON.parse(response.body);
    expect(body.error).toBe('forbidden');
  });

  it('should cache Platform JWT until near-expiry', async () => {
    // Setup: Create test data and session using REAL infrastructure
    const testData = await TestHelpers.createTestUser(db);
    const sessionId = await sessionManager.createSession(
      testData.user.id,
      testData.organization.id,
      'owner'
    );

    // Mint and cache JWT using PRODUCTION services
    const jwt = jwtManager.mintPlatformJWT(
      testData.user.id,
      testData.organization.id,
      'owner',
      1
    );

    const payload = jwtManager.verifyPlatformJWT(jwt);
    await jwtCache.set(sessionId, testData.organization.id, jwt, payload.exp);

    // Verify JWT is cached in REAL Redis
    const cachedJWT = await jwtCache.get(sessionId, testData.organization.id);
    expect(cachedJWT).toBe(jwt);

    // Verify JWT structure using PRODUCTION JWT manager
    expect(payload.sub).toBe(testData.user.id);
    expect(payload.org).toBe(testData.organization.id);
    expect(payload.role).toBe('owner');
    expect(payload.ver).toBe(1);
    expect(payload.exp - payload.iat).toBe(600); // 10 minutes
  });
});