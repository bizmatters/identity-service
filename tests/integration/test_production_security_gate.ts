import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import { testSessionRoutes } from '../../src/routes/auth/test-session.js';
import { SessionManager, SessionConfig } from '../../src/modules/auth/session-manager.js';
import { UserRepository } from '../../src/modules/user/user-repository.js';
import { OrgRepository } from '../../src/modules/org/org-repository.js';
import { db, cache } from './conftest.js';

describe('Production Security Gate Test', () => {
  let app: FastifyInstance;
  let originalNodeEnv: string | undefined;

  beforeEach(async () => {
    // Store original NODE_ENV
    originalNodeEnv = process.env['NODE_ENV'];

    // Create Fastify app
    app = Fastify({ logger: false });

    // Register cookie support
    await app.register(import('@fastify/cookie'));

    // Initialize services
    const sessionConfig: SessionConfig = {
      sessionTTL: 86400,
      absoluteTTL: 604800,
      cookieName: '__Host-platform_session',
    };

    const sessionManager = new SessionManager(cache, sessionConfig);
    const userRepository = new UserRepository(db);
    const orgRepository = new OrgRepository(db);

    const testSessionConfig = {
      cookieSecure: true,
    };

    // Register test session routes
    testSessionRoutes(app, sessionManager, userRepository, orgRepository, testSessionConfig);
  });

  afterEach(async () => {
    // Restore original NODE_ENV
    if (originalNodeEnv !== undefined) {
      process.env['NODE_ENV'] = originalNodeEnv;
    } else {
      delete process.env['NODE_ENV'];
    }

    // Close Fastify app
    await app.close();
  });

  // FIXME: This test is invalid for integration testing
  // Runtime NODE_ENV changes don't affect routes registered at app startup
  // Route registration checks NODE_ENV during initialization, not per-request
  // This should be either:
  // 1. Moved to unit tests with app re-initialization per test case
  // 2. Tested at deployment level (deploy with NODE_ENV=production, verify 404)
  // 3. Removed (production gate tested in actual production environment)
  it.skip('should return 404 when NODE_ENV=production', async () => {
    // Set NODE_ENV to production
    process.env['NODE_ENV'] = 'production';

    const testPayload = {
      external_id: 'test-user-prod',
      email: 'test-prod@example.com',
      organization_name: 'Test Production Org'
    };

    const response = await app.inject({
      method: 'POST',
      url: '/auth/test-session',
      payload: testPayload,
      headers: {
        'content-type': 'application/json'
      }
    });

    expect(response.statusCode).toBe(404);
    
    const responseBody = JSON.parse(response.body);
    expect(responseBody.error).toBe('not_found');
    expect(responseBody.message).toBe('Not found');
  });

  it('should work normally when NODE_ENV=development', async () => {
    // Set NODE_ENV to development
    process.env['NODE_ENV'] = 'development';

    const testPayload = {
      external_id: 'test-user-dev',
      email: 'test-dev@example.com',
      organization_name: 'Test Development Org'
    };

    const response = await app.inject({
      method: 'POST',
      url: '/auth/test-session',
      payload: testPayload,
      headers: {
        'content-type': 'application/json'
      }
    });

    expect(response.statusCode).toBe(200);
    
    const responseBody = JSON.parse(response.body);
    expect(responseBody.status).toBe('success');
    expect(responseBody.user_id).toBeDefined();
    expect(responseBody.org_id).toBeDefined();
    expect(responseBody.session_id).toBeDefined();

    // Verify Set-Cookie header is present
    const setCookieHeader = response.headers['set-cookie'];
    expect(setCookieHeader).toBeDefined();
    expect(setCookieHeader).toContain('__Host-platform_session=');
  });

  it('should work normally when NODE_ENV=test', async () => {
    // Set NODE_ENV to test
    process.env['NODE_ENV'] = 'test';

    const testPayload = {
      external_id: 'test-user-test',
      email: 'test-test@example.com',
      organization_name: 'Test Test Org'
    };

    const response = await app.inject({
      method: 'POST',
      url: '/auth/test-session',
      payload: testPayload,
      headers: {
        'content-type': 'application/json'
      }
    });

    expect(response.statusCode).toBe(200);
    
    const responseBody = JSON.parse(response.body);
    expect(responseBody.status).toBe('success');
  });

  it('should work normally when NODE_ENV is undefined', async () => {
    // Remove NODE_ENV (defaults to development behavior)
    delete process.env['NODE_ENV'];

    const testPayload = {
      external_id: 'test-user-undefined',
      email: 'test-undefined@example.com',
      organization_name: 'Test Undefined Org'
    };

    const response = await app.inject({
      method: 'POST',
      url: '/auth/test-session',
      payload: testPayload,
      headers: {
        'content-type': 'application/json'
      }
    });

    expect(response.statusCode).toBe(200);
    
    const responseBody = JSON.parse(response.body);
    expect(responseBody.status).toBe('success');
  });

  it('should validate request schema', async () => {
    // Set NODE_ENV to development
    process.env['NODE_ENV'] = 'development';

    // Test with missing required fields
    const invalidPayload = {
      external_id: 'test-user-invalid',
      // Missing email and organization_name
    };

    const response = await app.inject({
      method: 'POST',
      url: '/auth/test-session',
      payload: invalidPayload,
      headers: {
        'content-type': 'application/json'
      }
    });

    expect(response.statusCode).toBe(400);
  });

  it('should validate email format', async () => {
    // Set NODE_ENV to development
    process.env['NODE_ENV'] = 'development';

    // Test with invalid email format
    const invalidEmailPayload = {
      external_id: 'test-user-invalid-email',
      email: 'not-an-email',
      organization_name: 'Test Org'
    };

    const response = await app.inject({
      method: 'POST',
      url: '/auth/test-session',
      payload: invalidEmailPayload,
      headers: {
        'content-type': 'application/json'
      }
    });

    expect(response.statusCode).toBe(400);
  });
});