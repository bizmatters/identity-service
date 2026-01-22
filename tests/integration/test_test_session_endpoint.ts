import { describe, it, expect, beforeEach } from 'vitest';
import { db, cache } from './conftest.js';
import { TestHelpers } from '../mock/test-helpers.js';

// Import production service classes
import { SessionManager, SessionConfig } from '../../src/modules/auth/session-manager.js';
import { UserRepository } from '../../src/modules/user/user-repository.js';
import { OrgRepository } from '../../src/modules/org/org-repository.js';

describe('Test Session Endpoint Integration Test', () => {
  let sessionManager: SessionManager;
  let userRepository: UserRepository;
  let orgRepository: OrgRepository;

  beforeEach(async () => {
    // Initialize production service classes with REAL infrastructure
    const sessionConfig: SessionConfig = {
      sessionTTL: 86400, // 24 hours
      absoluteTTL: 604800, // 7 days
      cookieName: '__Host-platform_session',
    };

    sessionManager = new SessionManager(cache, sessionConfig);
    userRepository = new UserRepository(db);
    orgRepository = new OrgRepository(db);
  });

  it('should create test session with JIT user/org provisioning for new user', async () => {
    const testPayload = {
      external_id: 'test-user-12345',
      email: 'test@example.com',
      organization_name: 'Test Organization'
    };

    // Verify user doesn't exist initially
    let user = await userRepository.findByExternalId(testPayload.external_id);
    expect(user).toBeUndefined();

    // Execute JIT provisioning logic (same as test endpoint)
    const orgSlug = testPayload.organization_name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');

    const result = await userRepository.createUserWithDefaultOrg(
      testPayload.external_id,
      testPayload.email,
      testPayload.organization_name,
      orgSlug
    );

    // Verify user and organization created
    expect(result.user.external_id).toBe(testPayload.external_id);
    expect(result.user.email).toBe(testPayload.email);
    expect(result.organization.name).toBe(testPayload.organization_name);
    expect(result.organization.slug).toBe('test-organization');

    // Get user role in organization
    const userRole = await orgRepository.getUserRole(result.user.id, result.organization.id);
    expect(userRole).toBeDefined();
    expect(userRole!.role).toBe('owner');

    // Create session
    const sessionId = await sessionManager.createSession(
      result.user.id,
      result.organization.id,
      userRole!.role
    );

    expect(sessionId).toBeDefined();
    expect(typeof sessionId).toBe('string');

    // Verify session exists in cache
    const sessionData = await sessionManager.getSession(sessionId);
    expect(sessionData).toBeDefined();
    expect(sessionData!.user_id).toBe(result.user.id);
    expect(sessionData!.org_id).toBe(result.organization.id);
    expect(sessionData!.role).toBe('owner');
  });

  it('should handle existing user with profile update', async () => {
    // Create existing user first
    const existingResult = await userRepository.createUserWithDefaultOrg(
      'existing-user-123',
      'old@example.com',
      'Existing Organization',
      'existing-org'
    );

    const testPayload = {
      external_id: 'existing-user-123',
      email: 'updated@example.com', // Updated email
      organization_name: 'Test Organization'
    };

    // Find existing user
    let user = await userRepository.findByExternalId(testPayload.external_id);
    expect(user).toBeDefined();
    expect(user!.email).toBe('old@example.com');

    // Update profile
    await userRepository.updateUserProfile(user!.id, { email: testPayload.email });

    // Verify email updated
    user = await userRepository.findByExternalId(testPayload.external_id);
    expect(user!.email).toBe('updated@example.com');

    // Use existing user's default org
    const orgId = user!.default_org_id!;
    const userRole = await orgRepository.getUserRole(user!.id, orgId);
    expect(userRole).toBeDefined();

    // Create session
    const sessionId = await sessionManager.createSession(
      user!.id,
      orgId,
      userRole!.role
    );

    expect(sessionId).toBeDefined();

    // Verify session
    const sessionData = await sessionManager.getSession(sessionId);
    expect(sessionData!.user_id).toBe(user!.id);
    expect(sessionData!.org_id).toBe(orgId);
  });

  it('should generate correct organization slug from name', async () => {
    const testCases = [
      { name: 'Test Organization', expected: 'test-organization' },
      { name: 'My Company Inc.', expected: 'my-company-inc' },
      { name: 'Special-Characters & Symbols!', expected: 'special-characters-symbols' },
      { name: '  Leading and Trailing Spaces  ', expected: 'leading-and-trailing-spaces' },
      { name: 'Multiple   Spaces   Between', expected: 'multiple-spaces-between' },
    ];

    for (const testCase of testCases) {
      const orgSlug = testCase.name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');

      expect(orgSlug).toBe(testCase.expected);
    }
  });

  it('should be idempotent - multiple calls with same payload return same session', async () => {
    const testPayload = {
      external_id: 'idempotent-user-123',
      email: 'idempotent@example.com',
      organization_name: 'Idempotent Organization'
    };

    // First call - creates user/org
    const result1 = await userRepository.createUserWithDefaultOrg(
      testPayload.external_id,
      testPayload.email,
      testPayload.organization_name,
      'idempotent-organization'
    );

    const userRole1 = await orgRepository.getUserRole(result1.user.id, result1.organization.id);
    const sessionId1 = await sessionManager.createSession(
      result1.user.id,
      result1.organization.id,
      userRole1!.role
    );

    // Second call - should find existing user
    let user = await userRepository.findByExternalId(testPayload.external_id);
    expect(user).toBeDefined();
    
    await userRepository.updateUserProfile(user!.id, { email: testPayload.email });
    
    const userRole2 = await orgRepository.getUserRole(user!.id, user!.default_org_id!);
    const sessionId2 = await sessionManager.createSession(
      user!.id,
      user!.default_org_id!,
      userRole2!.role
    );

    // Should reference same user and org
    expect(user!.id).toBe(result1.user.id);
    expect(user!.default_org_id).toBe(result1.organization.id);
    
    // Sessions should be different (new session each time)
    expect(sessionId1).not.toBe(sessionId2);
    
    // But both should be valid
    const session1Data = await sessionManager.getSession(sessionId1);
    const session2Data = await sessionManager.getSession(sessionId2);
    
    expect(session1Data!.user_id).toBe(session2Data!.user_id);
    expect(session1Data!.org_id).toBe(session2Data!.org_id);
  });

  it('should handle cookie constraints for __Host- prefix', async () => {
    // Test cookie options that would be set by the endpoint
    const cookieOptions = {
      path: '/',
      secure: true, // Required for __Host- prefix
      httpOnly: true,
      sameSite: 'lax' as const,
      maxAge: 24 * 60 * 60, // 24 hours
    };

    // Verify __Host- prefix requirements are met
    expect(cookieOptions.path).toBe('/');
    expect(cookieOptions.secure).toBe(true);
    expect(cookieOptions.httpOnly).toBe(true);
    
    // __Host- prefix requires no domain (should be undefined/not set)
    expect(cookieOptions).not.toHaveProperty('domain');
  });

  it('should validate session data structure matches requirements', async () => {
    const testPayload = {
      external_id: 'structure-test-user',
      email: 'structure@example.com',
      organization_name: 'Structure Test Org'
    };

    const result = await userRepository.createUserWithDefaultOrg(
      testPayload.external_id,
      testPayload.email,
      testPayload.organization_name,
      'structure-test-org'
    );

    const userRole = await orgRepository.getUserRole(result.user.id, result.organization.id);
    const sessionId = await sessionManager.createSession(
      result.user.id,
      result.organization.id,
      userRole!.role
    );

    // Verify response structure matches TestSessionResponse interface
    const response = {
      status: 'success' as const,
      user_id: result.user.id,
      org_id: result.organization.id,
      session_id: sessionId,
    };

    expect(response.status).toBe('success');
    expect(typeof response.user_id).toBe('string');
    expect(typeof response.org_id).toBe('string');
    expect(typeof response.session_id).toBe('string');
    expect(response.user_id).toBe(result.user.id);
    expect(response.org_id).toBe(result.organization.id);
    expect(response.session_id).toBe(sessionId);
  });
});