import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Fastify from 'fastify';
import { loginRoutes } from '../../src/routes/auth/login.js';
import { callbackRoutes } from '../../src/routes/auth/callback.js';
import { logoutRoutes } from '../../src/routes/auth/logout.js';
import { switchOrgRoutes } from '../../src/routes/auth/switch-org.js';

describe('Neon Auth Endpoints Integration Test', () => {
  let app: ReturnType<typeof Fastify>;

  beforeEach(async () => {
    // Create Fastify app
    app = Fastify({ logger: false });
    await app.register(import('@fastify/cookie'));

    // Mock all dependencies for comprehensive testing
    const mockNeonAuthClient = {
      signInWithSocial: async (provider: string, callbackURL: string) => ({
        redirect: true,
        url: 'https://accounts.google.com/oauth/authorize?client_id=test&redirect_uri=' + encodeURIComponent(callbackURL),
      }),
    };

    const mockNeonAuthService = {
      handleCallback: async (params: any) => {
        if (params.sessionVerifier === 'valid-verifier') {
          return {
            userId: 'test-user-456',
            orgId: 'test-org-123',
            role: 'owner',
            version: 1,
          };
        }
        throw new Error('Invalid session verifier');
      },
      terminateSession: async () => ({ success: true }),
    };

    const mockSessionManager = {
      createSession: async (userId: string, orgId: string, role: string) => 'session-123',
      getSession: async (sessionId: string) => 
        sessionId === 'session-123' ? { user_id: 'test-user-456', org_id: 'test-org-123', role: 'owner' } : null,
      deleteSession: async (sessionId: string) => true,
      updateSession: async (sessionId: string, updates: any) => true,
    };

    const mockJWTManager = {
      mintPlatformJWT: (userId: string, orgId: string, role: string, version: number) => 'jwt-token-123',
      verifyPlatformJWT: (token: string) => ({ 
        sub: 'test-user-456', 
        org: 'test-org-123', 
        role: 'owner', 
        ver: 1, 
        exp: Math.floor(Date.now() / 1000) + 600,
        iat: Math.floor(Date.now() / 1000),
      }),
    };

    const mockJWTCache = {
      set: async (sessionId: string, orgId: string, jwt: string, exp: number) => true,
      get: async (sessionId: string, orgId: string) => 'jwt-token-123',
      invalidate: async (sessionId: string) => true,
    };

    const mockOrgRepository = {
      getUserRole: async (userId: string, orgId: string) => 
        orgId === 'test-org-456' ? { role: 'developer', version: 1 } : null,
    };

    // Configuration
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

    // Register all routes
    loginRoutes(app, mockNeonAuthClient as any, mockSessionManager as any, {} as any, {} as any, loginConfig);
    callbackRoutes(app, mockNeonAuthService as any, mockSessionManager as any, mockJWTManager as any, mockJWTCache as any, callbackConfig);
    logoutRoutes(app, mockSessionManager as any, mockJWTCache as any, mockNeonAuthService as any, logoutConfig);
    switchOrgRoutes(app, mockSessionManager as any, mockJWTCache as any, mockOrgRepository as any, switchOrgConfig);

    await app.ready();
  });

  afterEach(async () => {
    if (app) {
      await app.close();
    }
  });

  describe('Login Endpoint Tests', () => {
    it('should serve HTML login page with Continue with Google button', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/auth/login',
      });

      expect(response.statusCode).toBe(200);
      expect(response.headers['content-type']).toContain('text/html');
      expect(response.body).toContain('Continue with Google');
      expect(response.body).toContain('Welcome back');
      expect(response.body).toContain('Sign in to Platform');
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
      expect(response.headers.location).toContain('redirect_uri=');
    });
  });

  describe('Task 22: Callback endpoint with Platform JWT minting', () => {
    it('should handle OAuth callback and create platform session', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/auth/callback?sessionVerifier=valid-verifier',
      });

      expect(response.statusCode).toBe(302);
      expect(response.headers.location).toBe('http://localhost:3000/dashboard');

      // Verify secure cookie is set
      const cookies = response.cookies;
      const sessionCookie = cookies.find(c => c.name === '__Host-platform_session');
      expect(sessionCookie).toBeDefined();
      expect(sessionCookie?.httpOnly).toBe(true);
      expect(sessionCookie?.sameSite).toBe('Lax');
      expect(sessionCookie?.path).toBe('/');
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
  });

  describe('Task 23: Logout endpoint', () => {
    it('should logout and clear session', async () => {
      const logoutResponse = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        cookies: {
          '__Host-platform_session': 'session-123',
        },
      });

      expect(logoutResponse.statusCode).toBe(200);
      const body = JSON.parse(logoutResponse.body);
      expect(body.message).toBe('Logged out successfully');

      // Verify cookie is cleared
      const clearCookies = logoutResponse.cookies;
      const clearedCookie = clearCookies.find(c => c.name === '__Host-platform_session');
      expect(clearedCookie?.value).toBe('');
    });

    it('should handle logout without session', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/auth/logout',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.message).toBe('Logged out successfully');
    });
  });

  describe('Task 24: Organization Switch endpoint', () => {
    it('should switch organization context', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/auth/switch-org',
        cookies: {
          '__Host-platform_session': 'session-123',
        },
        payload: {
          org_id: 'test-org-456',
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.message).toBe('Organization switched successfully');
      expect(body.org_id).toBe('test-org-456');
      expect(body.role).toBe('developer');
    });

    it('should reject organization switch for non-member', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/auth/switch-org',
        cookies: {
          '__Host-platform_session': 'session-123',
        },
        payload: {
          org_id: 'non-member-org',
        },
      });

      expect(response.statusCode).toBe(403);
      const body = JSON.parse(response.body);
      expect(body.error).toBe('forbidden');
    });

    it('should require valid session', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/auth/switch-org',
        payload: {
          org_id: 'test-org-456',
        },
      });

      expect(response.statusCode).toBe(401);
      const body = JSON.parse(response.body);
      expect(body.error).toBe('unauthorized');
    });
  });

  describe('Phase 3 Integration: Complete Flow Validation', () => {
    it('should complete full authentication flow', async () => {
      // Step 1: Get login page
      const loginResponse = await app.inject({
        method: 'GET',
        url: '/auth/login',
      });
      expect(loginResponse.statusCode).toBe(200);
      expect(loginResponse.body).toContain('Continue with Google');

      // Step 2: Initiate OAuth
      const oauthResponse = await app.inject({
        method: 'GET',
        url: '/auth/login/google',
      });
      expect(oauthResponse.statusCode).toBe(302);
      expect(oauthResponse.headers.location).toContain('accounts.google.com');

      // Step 3: Handle callback
      const callbackResponse = await app.inject({
        method: 'GET',
        url: '/auth/callback?sessionVerifier=valid-verifier',
      });
      expect(callbackResponse.statusCode).toBe(302);
      expect(callbackResponse.headers.location).toBe('http://localhost:3000/dashboard');

      // Verify session cookie
      const cookies = callbackResponse.cookies;
      const sessionCookie = cookies.find(c => c.name === '__Host-platform_session');
      expect(sessionCookie).toBeDefined();
      expect(sessionCookie?.value).toBe('session-123');

      // Step 4: Use session for org switch
      const switchResponse = await app.inject({
        method: 'POST',
        url: '/auth/switch-org',
        cookies: {
          '__Host-platform_session': 'session-123',
        },
        payload: {
          org_id: 'test-org-456',
        },
      });
      expect(switchResponse.statusCode).toBe(200);

      // Step 5: Logout
      const logoutResponse = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        cookies: {
          '__Host-platform_session': 'session-123',
        },
      });
      expect(logoutResponse.statusCode).toBe(200);
    });
  });
});