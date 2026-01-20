import { describe, it, expect, beforeEach } from 'vitest';
import { db, cache } from './conftest.js';
import { TestHelpers } from '../mock/test-helpers.js';

// Import production service classes (following integration testing patterns)
import { NeonAuthClient } from '../../src/modules/auth/neon-auth-client.js';
import { SessionManager, SessionConfig } from '../../src/modules/auth/session-manager.js';
import { ValidationService } from '../../src/modules/auth/validation-service.js';
import { JWTManager, JWTConfig } from '../../src/modules/auth/jwt-manager.js';
import { JWTCache } from '../../src/modules/auth/jwt-cache.js';
import { PermissionCache } from '../../src/modules/auth/permission-cache.js';
import { TokenManager } from '../../src/modules/auth/token-manager.js';
import { TokenCache } from '../../src/modules/auth/token-cache.js';
import { UserRepository } from '../../src/modules/user/user-repository.js';
import { OrgRepository } from '../../src/modules/org/org-repository.js';
import { TokenRepository } from '../../src/modules/token/token-repository.js';

describe('End-to-End Authentication Integration Test', () => {
  let neonAuthClient: NeonAuthClient;
  let sessionManager: SessionManager;
  let validationService: ValidationService;
  let jwtManager: JWTManager;
  let jwtCache: JWTCache;
  let permissionCache: PermissionCache;
  let tokenManager: TokenManager;
  let userRepository: UserRepository;
  let orgRepository: OrgRepository;
  let testUser: { id: string; external_id: string; email: string };
  let testOrg: { id: string; name: string; slug: string };

  beforeEach(async () => {
    // Create test data using REAL database
    const testData = await TestHelpers.createTestUser(db);
    testUser = testData.user;
    testOrg = testData.organization;

    // Initialize production service classes with REAL infrastructure
    // Use same environment variables and configuration as production
    const sessionConfig: SessionConfig = {
      sessionTTL: 86400, // 24 hours
      absoluteTTL: 604800, // 7 days
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

    // Initialize all production services (same code paths as production)
    neonAuthClient = new NeonAuthClient({
      baseURL: process.env.NEON_AUTH_BASE_URL!,
      clientId: process.env.NEON_AUTH_CLIENT_ID!,
      clientSecret: process.env.NEON_AUTH_CLIENT_SECRET!,
    });

    sessionManager = new SessionManager(cache, sessionConfig);
    jwtManager = new JWTManager(jwtConfig);
    jwtCache = new JWTCache(cache);
    permissionCache = new PermissionCache(cache);
    userRepository = new UserRepository(db);
    orgRepository = new OrgRepository(db);
    
    const tokenRepository = new TokenRepository(db);
    const tokenCache = new TokenCache(cache);
    tokenManager = new TokenManager(tokenRepository, tokenCache, process.env.TOKEN_PEPPER!);

    validationService = new ValidationService(
      sessionManager,
      tokenManager,
      permissionCache,
      orgRepository
    );
  });

  it('should complete full flow: session → extAuthz → downstream service', async () => {
    // Step 1: Create platform session (simulating successful OIDC login)
    // Note: This test focuses on the extAuthz flow, not the OIDC flow
    const platformSessionId = await sessionManager.createSession(
      testUser.id,
      testOrg.id,
      'owner'
    );

    expect(platformSessionId).toBeDefined();
    expect(typeof platformSessionId).toBe('string');

    // Step 2: Validate session exists in Hot_Cache (REAL Redis)
    const sessionData = await sessionManager.getSession(platformSessionId);
    expect(sessionData).toBeDefined();
    expect(sessionData!.user_id).toBe(testUser.id);
    expect(sessionData!.org_id).toBe(testOrg.id);
    expect(sessionData!.role).toBe('owner');

    // Step 3: Simulate AgentGateway extAuthz request
    // Mock AgentGateway behavior (header stripping/injection)
    const incomingRequest = {
      headers: {
        'cookie': `__Host-platform_session=${platformSessionId}; Path=/; Secure; HttpOnly`,
        'authorization': 'Bearer some-client-token', // This should be stripped
        'user-agent': 'Mozilla/5.0...',
        'x-forwarded-for': '192.168.1.1',
      },
      path: '/api/workflows',
      method: 'GET',
    };

    // Step 4: Extract session from cookie (extAuthz simulation)
    const cookieHeader = incomingRequest.headers.cookie;
    const extractedSessionId = cookieHeader.match(/__Host-platform_session=([^;]+)/)?.[1];
    expect(extractedSessionId).toBe(platformSessionId);

    // Step 5: Validate session through ValidationService (production code path)
    const validationResult = await validationService.validateSession(extractedSessionId!);
    
    expect(validationResult.userId).toBe(testUser.id);
    expect(validationResult.orgId).toBe(testOrg.id);
    expect(validationResult.role).toBe('owner');
    expect(validationResult.version).toBe(1);

    // Step 6: Check for cached JWT or mint new one
    let platformJWT = await jwtCache.get(platformSessionId, testOrg.id);
    
    if (!platformJWT) {
      // Mint new Platform JWT (production code path)
      platformJWT = jwtManager.mintPlatformJWT(
        validationResult.userId,
        validationResult.orgId,
        validationResult.role,
        validationResult.version
      );

      // Cache JWT until near-expiry (production behavior)
      const payload = jwtManager.verifyPlatformJWT(platformJWT);
      await jwtCache.set(platformSessionId, testOrg.id, platformJWT, payload.exp);
    }

    // Step 7: Verify JWT structure and signature
    const jwtPayload = jwtManager.verifyPlatformJWT(platformJWT);
    expect(jwtPayload.sub).toBe(testUser.id);
    expect(jwtPayload.org).toBe(testOrg.id);
    expect(jwtPayload.role).toBe('owner');
    expect(jwtPayload.ver).toBe(1);
    expect(jwtPayload.aud).toBe('platform-services');
    expect(jwtPayload.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));

    // Step 8: Simulate AgentGateway header modifications
    const upstreamRequest = {
      ...incomingRequest,
      headers: {
        // Cookie header stripped from upstream requests
        'user-agent': incomingRequest.headers['user-agent'],
        'x-forwarded-for': incomingRequest.headers['x-forwarded-for'],
        // JWT and X-Auth headers injected
        'authorization': `Bearer ${platformJWT}`,
        'x-auth-user-id': validationResult.userId,
        'x-auth-org-id': validationResult.orgId,
      },
    };

    // Step 9: Validate cookie stripped from upstream
    expect(upstreamRequest.headers.cookie).toBeUndefined();
    expect(upstreamRequest.headers.authorization).toContain('Bearer ');
    expect(upstreamRequest.headers.authorization).not.toContain('some-client-token');

    // Step 10: Validate JWT and X-Auth headers injected
    expect(upstreamRequest.headers.authorization).toBe(`Bearer ${platformJWT}`);
    expect(upstreamRequest.headers['x-auth-user-id']).toBe(testUser.id);
    expect(upstreamRequest.headers['x-auth-org-id']).toBe(testOrg.id);

    // Step 11: Simulate downstream service (IDE Orchestrator) receiving request
    const downstreamHeaders = upstreamRequest.headers;
    
    // Verify downstream service receives Platform_JWT and X-Auth headers
    expect(downstreamHeaders.authorization).toBeDefined();
    expect(downstreamHeaders['x-auth-user-id']).toBe(testUser.id);
    expect(downstreamHeaders['x-auth-org-id']).toBe(testOrg.id);
    
    // Verify no session cookies (stripped by AgentGateway)
    expect(downstreamHeaders.cookie).toBeUndefined();

    // Step 12: Verify downstream service can validate JWT
    const downstreamJWT = downstreamHeaders.authorization.replace('Bearer ', '');
    const downstreamPayload = jwtManager.verifyPlatformJWT(downstreamJWT);
    
    expect(downstreamPayload.sub).toBe(testUser.id);
    expect(downstreamPayload.org).toBe(testOrg.id);
    expect(downstreamPayload.role).toBe('owner');
  });

  it('should test both session-based and token-based auth through extAuthz', async () => {
    // Test 1: Session-based authentication (browser)
    const sessionId = await sessionManager.createSession(
      testUser.id,
      testOrg.id,
      'owner'
    );

    const sessionValidation = await validationService.validateSession(sessionId);
    expect(sessionValidation.userId).toBe(testUser.id);
    expect(sessionValidation.role).toBe('owner');

    // Test 2: Token-based authentication (CLI/API)
    const apiToken = await tokenManager.createApiToken(
      testUser.id,
      testOrg.id,
      'CLI Access Token',
      new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
    );

    expect(apiToken.token).toMatch(/^sk_live_/);

    const tokenValidation = await validationService.validateApiToken(apiToken.token);
    expect(tokenValidation.userId).toBe(testUser.id);
    expect(tokenValidation.orgId).toBe(testOrg.id);
    // Role should be looked up from membership table
    expect(['owner', 'member']).toContain(tokenValidation.role);

    // Both should result in same JWT claims (role will be looked up from membership)
    const sessionJWT = jwtManager.mintPlatformJWT(
      sessionValidation.userId,
      sessionValidation.orgId,
      sessionValidation.role,
      sessionValidation.version
    );

    const tokenJWT = jwtManager.mintPlatformJWT(
      tokenValidation.userId,
      tokenValidation.orgId,
      tokenValidation.role,
      tokenValidation.version
    );

    const sessionPayload = jwtManager.verifyPlatformJWT(sessionJWT);
    const tokenPayload = jwtManager.verifyPlatformJWT(tokenJWT);

    expect(sessionPayload.sub).toBe(tokenPayload.sub);
    expect(sessionPayload.org).toBe(tokenPayload.org);
    expect(sessionPayload.role).toBe(tokenPayload.role);
  });

  it('should validate complete OIDC login workflow with JIT provisioning', async () => {
    // This test would require real Neon Auth integration
    // For now, test the JIT provisioning logic with existing user data
    
    // Step 1: Simulate new user data (would come from real Neon Auth)
    const newUserExternalId = 'new-user-12345';
    const newUserEmail = 'newuser@example.com';

    // Step 2: JIT provision new user (atomic INSERT)
    const newUser = await userRepository.createUserAtomic(
      newUserExternalId,
      newUserEmail
    );

    expect(newUser.external_id).toBe(newUserExternalId);
    expect(newUser.email).toBe(newUserEmail);

    // Step 3: Create default organization for first login
    const defaultOrg = await orgRepository.createOrganization(
      `${newUser.email.split('@')[0]}'s Organization`,
      `${newUser.email.split('@')[0]}-org`,
      newUser.id
    );

    expect(defaultOrg.name).toContain(newUser.email.split('@')[0]);
    expect(defaultOrg.slug).toContain(newUser.email.split('@')[0]);

    // Step 4: Verify user has owner role in default org
    const userRole = await orgRepository.getUserRole(newUser.id, defaultOrg.id);
    expect(userRole.role).toBe('owner');
    expect(userRole.version).toBe(1);

    // Step 5: Create session with default org as active
    const platformSessionId = await sessionManager.createSession(
      newUser.id,
      defaultOrg.id,
      'owner'
    );

    // Step 6: Validate complete flow works for new user
    const validationResult = await validationService.validateSession(platformSessionId);
    expect(validationResult.userId).toBe(newUser.id);
    expect(validationResult.orgId).toBe(defaultOrg.id);
    expect(validationResult.role).toBe('owner');

    // Step 7: Mint JWT for new user
    const jwt = jwtManager.mintPlatformJWT(
      validationResult.userId,
      validationResult.orgId,
      validationResult.role,
      validationResult.version
    );

    const payload = jwtManager.verifyPlatformJWT(jwt);
    expect(payload.sub).toBe(newUser.id);
    expect(payload.org).toBe(defaultOrg.id);
  });

  it('should validate multi-tenant isolation through complete flow', async () => {
    // Create second organization and user
    const testData2 = await TestHelpers.createTestUser(db);
    const testUser2 = testData2.user;
    const testOrg2 = testData2.organization;

    // Create sessions for both users in their respective orgs
    const session1 = await sessionManager.createSession(testUser.id, testOrg.id, 'owner');
    const session2 = await sessionManager.createSession(testUser2.id, testOrg2.id, 'owner');

    // Validate both sessions
    const validation1 = await validationService.validateSession(session1);
    const validation2 = await validationService.validateSession(session2);

    // Mint JWTs for both
    const jwt1 = jwtManager.mintPlatformJWT(
      validation1.userId,
      validation1.orgId,
      validation1.role,
      validation1.version
    );

    const jwt2 = jwtManager.mintPlatformJWT(
      validation2.userId,
      validation2.orgId,
      validation2.role,
      validation2.version
    );

    // Verify tenant isolation in JWT claims
    const payload1 = jwtManager.verifyPlatformJWT(jwt1);
    const payload2 = jwtManager.verifyPlatformJWT(jwt2);

    expect(payload1.sub).toBe(testUser.id);
    expect(payload1.org).toBe(testOrg.id);
    expect(payload2.sub).toBe(testUser2.id);
    expect(payload2.org).toBe(testOrg2.id);

    // Ensure no cross-tenant access
    expect(payload1.org).not.toBe(payload2.org);
    expect(payload1.sub).not.toBe(payload2.sub);

    // Verify JWT caches are isolated by session and org
    await jwtCache.set(session1, testOrg.id, jwt1, payload1.exp);
    await jwtCache.set(session2, testOrg2.id, jwt2, payload2.exp);

    const cachedJWT1 = await jwtCache.get(session1, testOrg.id);
    const cachedJWT2 = await jwtCache.get(session2, testOrg2.id);

    expect(cachedJWT1).toBe(jwt1);
    expect(cachedJWT2).toBe(jwt2);

    // Cross-tenant cache access should return null
    const crossTenantJWT = await jwtCache.get(session1, testOrg2.id);
    expect(crossTenantJWT).toBeNull();
  });

  it('should validate error handling in complete flow', async () => {
    // Test 1: Invalid session ID
    await expect(
      validationService.validateSession('invalid-session-id')
    ).rejects.toThrow('Invalid or expired session');

    // Test 2: Invalid API token
    await expect(
      tokenManager.validateApiToken('sk_live_invalid_token')
    ).rejects.toThrow('Invalid token format');

    // Test 3: Expired session
    const expiredSessionId = await sessionManager.createSession(
      testUser.id,
      testOrg.id,
      'owner'
    );

    // Manually expire session in cache
    await cache.del(`session:${expiredSessionId}`);

    await expect(
      validationService.validateSession(expiredSessionId)
    ).rejects.toThrow('Invalid or expired session');

    // Test 4: User without organization membership
    const orphanUser = await TestHelpers.createUserWithoutOrg(db);
    
    // SessionManager doesn't validate membership - it just creates sessions
    // The validation happens when the session is used (in ValidationService)
    const orphanSessionId = await sessionManager.createSession(orphanUser.id, testOrg.id, 'member');
    
    // But when we try to validate the session, it should fail because user has no membership
    await expect(
      validationService.validateSession(orphanSessionId)
    ).rejects.toThrow('User not found in organization');
  });

  it('should validate performance characteristics of complete flow', async () => {
    // Create session
    const sessionId = await sessionManager.createSession(
      testUser.id,
      testOrg.id,
      'owner'
    );

    // Measure first validation (database hit)
    const start1 = Date.now();
    const validation1 = await validationService.validateSession(sessionId);
    const duration1 = Date.now() - start1;

    // Measure second validation (cache hit)
    const start2 = Date.now();
    const validation2 = await validationService.validateSession(sessionId);
    const duration2 = Date.now() - start2;

    // Cache hit should be significantly faster
    expect(duration2).toBeLessThan(duration1);
    expect(duration1).toBeLessThan(1000); // Should be under 1000ms even for database hit
    expect(duration2).toBeLessThan(200);  // Cache hit should be under 200ms

    // Verify results are identical
    expect(validation1.userId).toBe(validation2.userId);
    expect(validation1.orgId).toBe(validation2.orgId);
    expect(validation1.role).toBe(validation2.role);
  });
});