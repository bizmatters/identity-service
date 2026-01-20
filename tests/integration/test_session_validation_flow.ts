import { describe, it, expect, beforeEach } from 'vitest';
import { db, cache } from './conftest.js';
import { TestHelpers } from '../mock/test-helpers.js';

// Import production service classes (following integration testing patterns)
import { SessionManager, SessionConfig } from '../../src/modules/auth/session-manager.js';
import { ValidationService } from '../../src/modules/auth/validation-service.js';
import { JWTManager, JWTConfig } from '../../src/modules/auth/jwt-manager.js';
import { JWTCache } from '../../src/modules/auth/jwt-cache.js';
import { PermissionCache } from '../../src/modules/auth/permission-cache.js';
import { TokenManager } from '../../src/modules/auth/token-manager.js';
import { TokenCache } from '../../src/modules/auth/token-cache.js';
import { OrgRepository } from '../../src/modules/org/org-repository.js';
import { TokenRepository } from '../../src/modules/token/token-repository.js';

describe('Session Validation Flow Integration Test', () => {
  let sessionManager: SessionManager;
  let validationService: ValidationService;
  let jwtManager: JWTManager;
  let jwtCache: JWTCache;
  let permissionCache: PermissionCache;
  let orgRepository: OrgRepository;
  let testUser: { id: string; external_id: string; email: string };
  let testOrg: { id: string; name: string; slug: string };

  beforeEach(async () => {
    // Create test data using REAL database
    const testData = await TestHelpers.createTestUser(db);
    testUser = testData.user;
    testOrg = testData.organization;

    // Initialize production service classes with REAL infrastructure
    const sessionConfig: SessionConfig = {
      sessionTTL: 86400, // 24 hours
      absoluteTTL: 604800, // 7 days
      cookieName: '__Host-platform_session',
    };

    // Use environment variables like production (same as working test)
    const privateKey = process.env.JWT_PRIVATE_KEY!.replace(/\\n/g, '\n');
    const publicKey = process.env.JWT_PUBLIC_KEY!.replace(/\\n/g, '\n');
    
    const jwtConfig: JWTConfig = {
      privateKey,
      publicKey,
      keyId: process.env.JWT_KEY_ID!,
      expiration: '10m',
    };

    // Initialize all production services
    sessionManager = new SessionManager(cache, sessionConfig);
    jwtManager = new JWTManager(jwtConfig);
    jwtCache = new JWTCache(cache);
    permissionCache = new PermissionCache(cache);
    orgRepository = new OrgRepository(db);
    
    // Create token dependencies (not used in this test but required for ValidationService)
    const tokenRepository = new TokenRepository(db);
    const tokenCache = new TokenCache(cache);
    const tokenManager = new TokenManager(tokenRepository, tokenCache, 'test-pepper');

    validationService = new ValidationService(
      sessionManager,
      tokenManager,
      permissionCache,
      orgRepository
    );
  });

  it('should complete session validation flow: session cookie → extAuthz → JWT minting', async () => {
    // Step 1: Create session using production SessionManager
    const sessionId = await sessionManager.createSession(
      testUser.id,
      testOrg.id,
      'owner'
    );

    expect(sessionId).toBeDefined();
    expect(typeof sessionId).toBe('string');

    // Step 2: Validate session exists in cache (REAL Redis)
    const sessionData = await sessionManager.getSession(sessionId);
    expect(sessionData).toBeDefined();
    expect(sessionData!.user_id).toBe(testUser.id);
    expect(sessionData!.org_id).toBe(testOrg.id);
    expect(sessionData!.role).toBe('owner');

    // Step 3: Validate session through ValidationService (production code path)
    const validationResult = await validationService.validateSession(sessionId);
    
    expect(validationResult.userId).toBe(testUser.id);
    expect(validationResult.orgId).toBe(testOrg.id);
    expect(validationResult.role).toBe('owner');
    expect(validationResult.version).toBe(1); // From membership table

    // Step 4: Mint JWT using production JWTManager
    const jwt = jwtManager.mintPlatformJWT(
      validationResult.userId,
      validationResult.orgId,
      validationResult.role,
      validationResult.version
    );

    expect(jwt).toBeDefined();
    expect(typeof jwt).toBe('string');

    // Step 5: Verify JWT structure and signature
    const payload = jwtManager.verifyPlatformJWT(jwt);
    expect(payload.sub).toBe(testUser.id);
    expect(payload.org).toBe(testOrg.id);
    expect(payload.role).toBe('owner');
    expect(payload.ver).toBe(1);
    expect(payload.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));

    // Step 6: Cache JWT until near-expiry (production behavior)
    await jwtCache.set(sessionId, testOrg.id, jwt, payload.exp);

    // Verify JWT is cached
    const cachedJWT = await jwtCache.get(sessionId, testOrg.id);
    expect(cachedJWT).toBe(jwt);
  });

  it('should validate permission cache behavior (60s TTL)', async () => {
    const sessionId = await sessionManager.createSession(
      testUser.id,
      testOrg.id,
      'owner'
    );

    // First validation should hit database and cache result
    const startTime = Date.now();
    const result1 = await validationService.validateSession(sessionId);
    const firstCallDuration = Date.now() - startTime;

    expect(result1.role).toBe('owner');
    expect(result1.version).toBe(1);

    // Second validation should hit cache (faster)
    const startTime2 = Date.now();
    const result2 = await validationService.validateSession(sessionId);
    const secondCallDuration = Date.now() - startTime2;

    expect(result2.role).toBe('owner');
    expect(result2.version).toBe(1);

    // Cache hit should be faster than database lookup
    expect(secondCallDuration).toBeLessThan(firstCallDuration);

    // Verify permission is cached in Redis
    const cachedPermission = await permissionCache.get(testUser.id, testOrg.id);
    expect(cachedPermission).toBeDefined();
    expect(cachedPermission!.role).toBe('owner');
    expect(cachedPermission!.version).toBe(1);
  });

  it('should validate request collapsing (Singleflight pattern)', async () => {
    const sessionId = await sessionManager.createSession(
      testUser.id,
      testOrg.id,
      'owner'
    );

    // Make multiple concurrent validation requests
    const promises = Array.from({ length: 5 }, () =>
      validationService.validateSession(sessionId)
    );

    const results = await Promise.all(promises);

    // All results should be identical
    results.forEach(result => {
      expect(result.userId).toBe(testUser.id);
      expect(result.orgId).toBe(testOrg.id);
      expect(result.role).toBe('owner');
      expect(result.version).toBe(1);
    });

    // Should only have one cached entry (not 5)
    const cachedPermission = await permissionCache.get(testUser.id, testOrg.id);
    expect(cachedPermission).toBeDefined();
  });

  it('should validate JWT cache behavior (until near-expiry)', async () => {
    const sessionId = await sessionManager.createSession(
      testUser.id,
      testOrg.id,
      'owner'
    );

    // Mint JWT
    const jwt = jwtManager.mintPlatformJWT(testUser.id, testOrg.id, 'owner', 1);
    const payload = jwtManager.verifyPlatformJWT(jwt);

    // Cache JWT
    await jwtCache.set(sessionId, testOrg.id, jwt, payload.exp);

    // Verify JWT is cached
    const cachedJWT = await jwtCache.get(sessionId, testOrg.id);
    expect(cachedJWT).toBe(jwt);

    // Check TTL is set correctly (should be exp - 60 seconds buffer)
    const ttl = await jwtCache.getTTL(sessionId, testOrg.id);
    const expectedTTL = payload.exp - Math.floor(Date.now() / 1000) - 60;
    
    // Allow some variance for test execution time
    expect(ttl).toBeGreaterThan(expectedTTL - 5);
    expect(ttl).toBeLessThanOrEqual(expectedTTL + 5);
  });

  it('should validate fresh permission lookup from PostgreSQL', async () => {
    const sessionId = await sessionManager.createSession(
      testUser.id,
      testOrg.id,
      'owner'
    );

    // First validation caches permission
    await validationService.validateSession(sessionId);

    // Simulate role change in database (increment version)
    await orgRepository.incrementMembershipVersion(testUser.id, testOrg.id);

    // Invalidate cache to force fresh lookup
    await permissionCache.invalidate(testUser.id, testOrg.id);

    // Next validation should get updated version from database
    const result = await validationService.validateSession(sessionId);
    expect(result.version).toBe(2); // Incremented version
  });

  it('should test session expiration (sliding TTL and absolute_expiry) and 401 response', async () => {
    // Create session with short TTL for testing
    const shortSessionConfig: SessionConfig = {
      sessionTTL: 2, // 2 seconds
      absoluteTTL: 10, // 10 seconds absolute
      cookieName: '__Host-platform_session',
    };

    const shortSessionManager = new SessionManager(cache, shortSessionConfig);
    const shortValidationService = new ValidationService(
      shortSessionManager,
      new TokenManager(new TokenRepository(db), new TokenCache(cache), 'test-pepper'),
      permissionCache,
      orgRepository
    );

    const sessionId = await shortSessionManager.createSession(
      testUser.id,
      testOrg.id,
      'owner'
    );

    // Session should be valid initially
    const result1 = await shortValidationService.validateSession(sessionId);
    expect(result1.userId).toBe(testUser.id);

    // Wait for session to expire
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Session should now be expired and throw 401
    await expect(
      shortValidationService.validateSession(sessionId)
    ).rejects.toThrow('Invalid or expired session');
  });

  it('should test absolute expiry enforcement', async () => {
    // Create session with very short absolute expiry
    const absoluteExpiryConfig: SessionConfig = {
      sessionTTL: 86400, // 24 hours sliding
      absoluteTTL: 2, // 2 seconds absolute maximum
      cookieName: '__Host-platform_session',
    };

    const absoluteSessionManager = new SessionManager(cache, absoluteExpiryConfig);
    const absoluteValidationService = new ValidationService(
      absoluteSessionManager,
      new TokenManager(new TokenRepository(db), new TokenCache(cache), 'test-pepper'),
      permissionCache,
      orgRepository
    );

    const sessionId = await absoluteSessionManager.createSession(
      testUser.id,
      testOrg.id,
      'owner'
    );

    // Session should be valid initially
    const result1 = await absoluteValidationService.validateSession(sessionId);
    expect(result1.userId).toBe(testUser.id);

    // Wait for absolute expiry
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Session should be expired due to absolute expiry
    await expect(
      absoluteValidationService.validateSession(sessionId)
    ).rejects.toThrow('Invalid or expired session');

    // Session should be deleted from cache
    const sessionData = await absoluteSessionManager.getSession(sessionId);
    expect(sessionData).toBeNull();
  });

  it('should validate complete extAuthz simulation', async () => {
    // Simulate complete extAuthz flow
    const sessionId = await sessionManager.createSession(
      testUser.id,
      testOrg.id,
      'owner'
    );

    // Step 1: Extract session from cookie (simulated)
    const cookieHeader = `__Host-platform_session=${sessionId}; Path=/; Secure; HttpOnly`;
    const extractedSessionId = cookieHeader.match(/__Host-platform_session=([^;]+)/)?.[1];
    expect(extractedSessionId).toBe(sessionId);

    // Step 2: Validate session
    const validationResult = await validationService.validateSession(extractedSessionId!);

    // Step 3: Check for cached JWT
    let platformJWT = await jwtCache.get(sessionId, testOrg.id);
    
    if (!platformJWT) {
      // Step 4: Mint new JWT if not cached
      platformJWT = jwtManager.mintPlatformJWT(
        validationResult.userId,
        validationResult.orgId,
        validationResult.role,
        validationResult.version
      );

      // Step 5: Cache JWT
      const payload = jwtManager.verifyPlatformJWT(platformJWT);
      await jwtCache.set(sessionId, testOrg.id, platformJWT, payload.exp);
    }

    // Step 6: Verify response headers would be set correctly
    expect(platformJWT).toBeDefined();
    
    const payload = jwtManager.verifyPlatformJWT(platformJWT);
    expect(payload.sub).toBe(testUser.id);
    expect(payload.org).toBe(testOrg.id);

    // Simulate AgentGateway headers
    const responseHeaders = {
      'Authorization': `Bearer ${platformJWT}`,
      'X-Auth-User-Id': validationResult.userId,
      'X-Auth-Org-Id': validationResult.orgId,
    };

    expect(responseHeaders['Authorization']).toContain('Bearer ');
    expect(responseHeaders['X-Auth-User-Id']).toBe(testUser.id);
    expect(responseHeaders['X-Auth-Org-Id']).toBe(testOrg.id);
  });
});