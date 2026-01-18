import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify from 'fastify';
import { testDb, testCache, testHelpers } from './conftest.js';
import { OIDCClient } from '../../src/modules/oidc/oidc-client.js';
import { SessionManager } from '../../src/modules/auth/session-manager.js';
import { UserRepository } from '../../src/modules/user/user-repository.js';
import { OrgRepository } from '../../src/modules/org/org-repository.js';
import { MockOIDCProvider } from '../mock/mock-oidc-provider.js';
import { loginRoutes } from '../../src/routes/auth/login.js';
import { callbackRoutes } from '../../src/routes/auth/callback.js';

/**
 * Integration test for complete OIDC login flow
 * Requirements: 1.1-1.12, 3.5, 3.6
 */
describe('OIDC Login Flow Integration', () => {
  let mockProvider: MockOIDCProvider;
  let oidcClient: OIDCClient;
  let sessionManager: SessionManager;
  let userRepository: UserRepository;
  let orgRepository: OrgRepository;
  let app: any;

  const MOCK_OIDC_CONFIG = {
    issuer: 'http://localhost:3001',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    port: 3001,
  };

  const SESSION_CONFIG = {
    sessionTTL: 24 * 60 * 60, // 24 hours
    absoluteTTL: 7 * 24 * 60 * 60, // 7 days
  };

  const LOGIN_CONFIG = {
    allowedRedirectUris: ['http://localhost:3000/dashboard', 'http://localhost:3000/app'],
    defaultRedirectUri: 'http://localhost:3000/dashboard',
  };

  const CALLBACK_CONFIG = {
    sessionCookieName: '__Host-platform_session',
    cookieDomain: 'localhost',
    cookieSecure: false, // false for testing
    dashboardUrl: 'http://localhost:3000/dashboard',
  };

  beforeAll(async () => {
    // Setup mock OIDC provider
    const mockApp = Fastify({ logger: false });
    mockProvider = new MockOIDCProvider(MOCK_OIDC_CONFIG);
    await mockProvider.start(mockApp);

    // Setup OIDC client
    oidcClient = new OIDCClient({
      issuer: MOCK_OIDC_CONFIG.issuer,
      clientId: MOCK_OIDC_CONFIG.clientId,
      clientSecret: MOCK_OIDC_CONFIG.clientSecret,
      redirectUri: 'http://localhost:3000/auth/callback',
    }, testCache);

    // Setup services
    sessionManager = new SessionManager(testCache, SESSION_CONFIG);
    userRepository = new UserRepository(testDb);
    orgRepository = new OrgRepository(testDb);

    // Setup test app
    app = Fastify({ logger: false });
    
    // Register cookie support
    await app.register(import('@fastify/cookie'));

    // Register routes
    await loginRoutes(app, oidcClient, testCache, LOGIN_CONFIG);
    await callbackRoutes(app, oidcClient, sessionManager, userRepository, orgRepository, testCache, CALLBACK_CONFIG);

    await app.listen({ port: 3000, host: '127.0.0.1' });
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
    if (mockProvider) {
      await mockProvider.stop();
    }
  });

  it('should complete full OIDC login flow with JIT user provisioning', async () => {
    const testData = testHelpers.generateTestData();

    // Step 1: Initiate login
    const loginResponse = await app.inject({
      method: 'GET',
      url: '/auth/login?redirect_uri=http://localhost:3000/dashboard',
    });

    expect(loginResponse.statusCode).toBe(302);
    expect(loginResponse.headers.location).toContain(MOCK_OIDC_CONFIG.issuer);
    expect(loginResponse.headers.location).toContain('response_type=code');
    expect(loginResponse.headers.location).toContain('code_challenge');
    expect(loginResponse.headers.location).toContain('code_challenge_method=S256');

    // Extract state and other parameters from redirect URL
    const redirectUrl = new URL(loginResponse.headers.location);
    const state = redirectUrl.searchParams.get('state');
    const nonce = redirectUrl.searchParams.get('nonce');
    
    expect(state).toBeTruthy();
    expect(nonce).toBeTruthy();

    // Verify OIDC state is stored in cache
    const storedState = await testCache.get(`oidc:state:${state}`);
    expect(storedState).toBeTruthy();
    
    const oidcState = JSON.parse(storedState!);
    expect(oidcState.state).toBe(state);
    expect(oidcState.nonce).toBe(nonce);
    expect(oidcState.redirect_uri).toBe('http://localhost:3000/dashboard');

    // Step 2: Simulate OIDC provider callback
    const callbackResponse = await app.inject({
      method: 'GET',
      url: `/auth/callback?code=mock-auth-code-${Date.now()}&state=${state}`,
    });

    expect(callbackResponse.statusCode).toBe(302);
    expect(callbackResponse.headers.location).toBe('http://localhost:3000/dashboard');

    // Verify secure cookie is set
    const cookies = callbackResponse.cookies;
    const sessionCookie = cookies.find(c => c.name === '__Host-platform_session');
    expect(sessionCookie).toBeTruthy();
    expect(sessionCookie!.httpOnly).toBe(true);
    expect(sessionCookie!.sameSite).toBe('Lax');
    expect(sessionCookie!.path).toBe('/');

    const sessionId = sessionCookie!.value;

    // Step 3: Verify session persistence in Dragonfly
    const session = await sessionManager.getSession(sessionId);
    expect(session).toBeTruthy();
    expect(session!.user_id).toBeTruthy();
    expect(session!.org_id).toBeTruthy();
    expect(session!.role).toBe('owner');
    expect(session!.absolute_expiry).toBeGreaterThan(Date.now());

    // Step 4: Verify user JIT provisioning in PostgreSQL
    const user = await userRepository.findByExternalId('550e8400-e29b-41d4-a716-446655440000');
    expect(user).toBeTruthy();
    expect(user!.email).toBe('test@example.com');
    expect(user!.default_org_id).toBe(session!.org_id);

    // Step 5: Verify organization creation
    const org = await testDb
      .selectFrom('organizations')
      .selectAll()
      .where('id', '=', session!.org_id)
      .executeTakeFirst();
    
    expect(org).toBeTruthy();
    expect(org!.name).toContain('test');

    // Step 6: Verify membership creation
    const membership = await orgRepository.getUserRole(session!.user_id, session!.org_id);
    expect(membership).toBeTruthy();
    expect(membership!.role).toBe('owner');
    expect(membership!.version).toBe(1);

    // Step 7: Verify OIDC state cleanup
    const cleanedState = await testCache.get(`oidc:state:${state}`);
    expect(cleanedState).toBeNull();
  });

  it('should handle existing user login with profile sync', async () => {
    // Pre-create user
    const { user, organization } = await testHelpers.createTestUser(
      '550e8400-e29b-41d4-a716-446655440000',
      'old@example.com',
      'Existing Organization'
    );

    // Initiate login
    const loginResponse = await app.inject({
      method: 'GET',
      url: '/auth/login',
    });

    const redirectUrl = new URL(loginResponse.headers.location);
    const state = redirectUrl.searchParams.get('state');

    // Simulate callback
    const callbackResponse = await app.inject({
      method: 'GET',
      url: `/auth/callback?code=mock-auth-code-${Date.now()}&state=${state}`,
    });

    expect(callbackResponse.statusCode).toBe(302);

    // Verify user profile was updated (email sync)
    const updatedUser = await userRepository.findByExternalId('550e8400-e29b-41d4-a716-446655440000');
    expect(updatedUser!.email).toBe('test@example.com'); // Updated from mock OIDC
    expect(updatedUser!.id).toBe(user.id); // Same user
  });

  it('should reject invalid redirect URI', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/auth/login?redirect_uri=http://malicious.com/steal',
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().code).toBe('INVALID_REDIRECT_URI');
  });

  it('should handle invalid OIDC state', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/auth/callback?code=test-code&state=invalid-state',
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().code).toBe('INVALID_STATE');
  });

  it('should handle OIDC provider errors', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/auth/callback?error=access_denied&error_description=User%20denied%20access',
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().code).toBe('OIDC_ERROR');
  });
});