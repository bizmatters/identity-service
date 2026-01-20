import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Fastify from 'fastify';
import { loginRoutes } from '../../src/routes/auth/login.js';

describe('Neon Auth Login Flow - Core Logic Test', () => {
  let app: ReturnType<typeof Fastify>;

  beforeEach(async () => {
    // Create Fastify app
    app = Fastify({ logger: false });
    await app.register(import('@fastify/cookie'));

    // Mock dependencies for core logic testing
    const mockNeonAuthClient = {
      signInWithSocial: async (provider: string, callbackURL: string) => ({
        redirect: true,
        url: 'https://accounts.google.com/oauth/authorize?client_id=test&redirect_uri=' + encodeURIComponent(callbackURL),
      }),
    };

    const mockSessionManager = {};
    const mockUserRepository = {};
    const mockOrgRepository = {};

    const loginConfig = {
      allowedRedirectUris: ['http://localhost:3000/dashboard'],
      defaultRedirectUri: 'http://localhost:3000/dashboard',
    };

    // Register routes with mocks
    loginRoutes(
      app,
      mockNeonAuthClient as any,
      mockSessionManager as any,
      mockUserRepository as any,
      mockOrgRepository as any,
      loginConfig
    );

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

  it('should validate redirect_uri in OAuth flow', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/auth/login/google?redirect_uri=https://malicious.com',
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.error).toBe('invalid_redirect_uri');
  });
});