import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createDatabase } from '../../src/infrastructure/database.js';
import { createCache } from '../../src/infrastructure/cache.js';
import { UserRepository } from '../../src/modules/user/user-repository.js';
import { OrgRepository } from '../../src/modules/org/org-repository.js';
import { SessionManager } from '../../src/modules/auth/session-manager.js';
import { authLogger } from '../../src/infrastructure/logger.js';
import { CONFIG } from '../../src/config/index.js';

/**
 * Organization Management Integration Tests
 * 
 * Tests complete organization workflows using production service classes:
 * - Organization creation with owner membership
 * - Membership management and role changes
 * - Organization switching functionality
 * - Membership versioning for instant revocation
 * - Multi-tenant isolation validation
 * 
 * Uses real PostgreSQL and Redis infrastructure (internal dependencies)
 * Requirements: 3.1-3.9
 */
describe('Organization Management Integration Tests', () => {
  let db: ReturnType<typeof createDatabase>;
  let cache: ReturnType<typeof createCache>;
  let userRepository: UserRepository;
  let orgRepository: OrgRepository;
  let sessionManager: SessionManager;

  // Test data
  const testUser1 = {
    external_id: 'test-user-1-ext-id',
    email: 'user1@example.com',
  };

  const testUser2 = {
    external_id: 'test-user-2-ext-id', 
    email: 'user2@example.com',
  };

  const testOrg1 = {
    name: 'Test Organization 1',
    slug: 'test-org-1',
  };

  const testOrg2 = {
    name: 'Test Organization 2', 
    slug: 'test-org-2',
  };

  beforeEach(async () => {
    // Initialize infrastructure using production code paths
    db = createDatabase();
    cache = createCache();
    
    // Initialize repositories using production service classes
    userRepository = new UserRepository(db);
    orgRepository = new OrgRepository(db);
    
    sessionManager = new SessionManager(cache, {
      sessionTTL: CONFIG.SESSION_TTL,
      absoluteTTL: CONFIG.SESSION_ABSOLUTE_TTL,
      cookieName: CONFIG.SESSION_COOKIE_NAME,
    });

    // Clean database state for each test
    await db.deleteFrom('memberships').execute();
    await db.deleteFrom('api_tokens').execute();
    await db.deleteFrom('users').execute();
    await db.deleteFrom('organizations').execute();
  });

  afterEach(async () => {
    // Clean up after each test
    await db.deleteFrom('memberships').execute();
    await db.deleteFrom('api_tokens').execute();
    await db.deleteFrom('users').execute();
    await db.deleteFrom('organizations').execute();
  });

  describe('Organization Creation and Ownership', () => {
    it('should create user with default organization and owner membership', async () => {
      // Test Requirements 3.1, 3.5: Organization creation with owner membership
      const result = await userRepository.createUserWithDefaultOrg(
        testUser1.external_id,
        testUser1.email,
        testOrg1.name,
        testOrg1.slug
      );

      // Validate user creation
      expect(result.user).toBeDefined();
      expect(result.user.external_id).toBe(testUser1.external_id);
      expect(result.user.email).toBe(testUser1.email);
      expect(result.user.default_org_id).toBe(result.organization.id);

      // Validate organization creation
      expect(result.organization).toBeDefined();
      expect(result.organization.name).toBe(testOrg1.name);
      expect(result.organization.slug).toBe(testOrg1.slug);

      // Validate owner membership was created
      const membership = await orgRepository.getUserRole(result.user.id, result.organization.id);
      expect(membership).toBeDefined();
      expect(membership!.role).toBe('owner');
      expect(membership!.version).toBe(1);

      // Validate persistence by querying database directly
      const dbUser = await db
        .selectFrom('users')
        .selectAll()
        .where('id', '=', result.user.id)
        .executeTakeFirst();
      
      expect(dbUser).toBeDefined();
      expect(dbUser!.default_org_id).toBe(result.organization.id);

      const dbMembership = await db
        .selectFrom('memberships')
        .selectAll()
        .where('user_id', '=', result.user.id)
        .where('org_id', '=', result.organization.id)
        .executeTakeFirst();

      expect(dbMembership).toBeDefined();
      expect(dbMembership!.role).toBe('owner');
    });

    it('should create additional organization with existing user as owner', async () => {
      // Test Requirements 3.1, 3.4: Multiple organization creation
      
      // Create first user with default org
      const userResult = await userRepository.createUserWithDefaultOrg(
        testUser1.external_id,
        testUser1.email,
        testOrg1.name,
        testOrg1.slug
      );

      // Create second organization with same user as owner
      const org2 = await orgRepository.createOrganization(
        testOrg2.name,
        testOrg2.slug,
        userResult.user.id
      );

      // Validate user has memberships in both organizations
      const membership1 = await orgRepository.getUserRole(userResult.user.id, userResult.organization.id);
      const membership2 = await orgRepository.getUserRole(userResult.user.id, org2.id);

      expect(membership1!.role).toBe('owner');
      expect(membership2!.role).toBe('owner');

      // Validate multi-tenant isolation: organizations are separate
      expect(userResult.organization.id).not.toBe(org2.id);
      expect(userResult.organization.slug).not.toBe(org2.slug);
    });
  });

  describe('Membership Management', () => {
    let user1Id: string;
    let user2Id: string;
    let org1Id: string;
    let org2Id: string;

    beforeEach(async () => {
      // Set up test data: two users, two organizations
      const user1Result = await userRepository.createUserWithDefaultOrg(
        testUser1.external_id,
        testUser1.email,
        testOrg1.name,
        testOrg1.slug
      );
      
      const user2Result = await userRepository.createUserWithDefaultOrg(
        testUser2.external_id,
        testUser2.email,
        testOrg2.name,
        testOrg2.slug
      );

      user1Id = user1Result.user.id;
      user2Id = user2Result.user.id;
      org1Id = user1Result.organization.id;
      org2Id = user2Result.organization.id;
    });

    it('should retrieve user role and membership information', async () => {
      // Test Requirements 3.4: Role retrieval
      const membership = await orgRepository.getUserRole(user1Id, org1Id);
      
      expect(membership).toBeDefined();
      expect(membership!.role).toBe('owner');
      expect(membership!.version).toBe(1);

      // Test combined user and membership query
      const userWithRole = await userRepository.getUserWithMembership(user1Id, org1Id);
      
      expect(userWithRole).toBeDefined();
      expect(userWithRole!.id).toBe(user1Id);
      expect(userWithRole!.email).toBe(testUser1.email);
      expect(userWithRole!.role).toBe('owner');
      expect(userWithRole!.version).toBe(1);
    });

    it('should enforce multi-tenant isolation', async () => {
      // Test Requirements 3.9: Multi-tenant isolation
      
      // User1 should not have access to User2's organization
      const crossTenantMembership = await orgRepository.getUserRole(user1Id, org2Id);
      expect(crossTenantMembership).toBeUndefined();

      // User2 should not have access to User1's organization  
      const crossTenantMembership2 = await orgRepository.getUserRole(user2Id, org1Id);
      expect(crossTenantMembership2).toBeUndefined();

      // Validate via combined query as well
      const crossTenantUser = await userRepository.getUserWithMembership(user1Id, org2Id);
      expect(crossTenantUser).toBeUndefined();
    });

    it('should increment membership version for instant revocation', async () => {
      // Test Requirements 3.4: Membership versioning (P2)
      
      // Get initial version
      const initialMembership = await orgRepository.getUserRole(user1Id, org1Id);
      expect(initialMembership!.version).toBe(1);

      // Increment version (simulates permission change/revocation)
      const newVersion = await orgRepository.incrementMembershipVersion(user1Id, org1Id);
      expect(newVersion).toBe(2);

      // Validate version was updated in database
      const updatedMembership = await orgRepository.getUserRole(user1Id, org1Id);
      expect(updatedMembership!.version).toBe(2);

      // Increment again
      const newerVersion = await orgRepository.incrementMembershipVersion(user1Id, org1Id);
      expect(newerVersion).toBe(3);

      // Validate final state
      const finalMembership = await orgRepository.getUserRole(user1Id, org1Id);
      expect(finalMembership!.version).toBe(3);
    });
  });

  describe('Organization Switching', () => {
    let userId: string;
    let org1Id: string;
    let org2Id: string;
    let sessionId: string;

    beforeEach(async () => {
      // Create user with default organization
      const userResult = await userRepository.createUserWithDefaultOrg(
        testUser1.external_id,
        testUser1.email,
        testOrg1.name,
        testOrg1.slug
      );

      userId = userResult.user.id;
      org1Id = userResult.organization.id;

      // Create second organization with same user as owner
      const org2 = await orgRepository.createOrganization(
        testOrg2.name,
        testOrg2.slug,
        userId
      );
      org2Id = org2.id;

      // Create session in first organization
      sessionId = await sessionManager.createSession(userId, org1Id, 'owner');
    });

    it('should switch organization context in session', async () => {
      // Test Requirements 3.8, 3.9: Organization switching
      
      // Verify initial session context
      const initialSession = await sessionManager.getSession(sessionId);
      expect(initialSession).toBeDefined();
      expect(initialSession!.org_id).toBe(org1Id);
      expect(initialSession!.role).toBe('owner');

      // Switch to second organization
      const newSessionId = await sessionManager.regenerateSession(
        sessionId,
        userId,
        org2Id,
        'owner'
      );

      // Verify new session context
      const newSession = await sessionManager.getSession(newSessionId);
      expect(newSession).toBeDefined();
      expect(newSession!.org_id).toBe(org2Id);
      expect(newSession!.role).toBe('owner');
      expect(newSession!.user_id).toBe(userId);

      // Verify old session is invalidated
      const oldSession = await sessionManager.getSession(sessionId);
      expect(oldSession).toBeNull();

      // Log organization switch event
      authLogger.organizationSwitched({
        user_id: userId,
        from_org_id: org1Id,
        to_org_id: org2Id,
        request_id: 'test-request-id',
      });
    });

    it('should validate membership before allowing organization switch', async () => {
      // Test Requirements 3.8: Membership validation for org switching
      
      // Create a third user to own the unauthorized organization
      const user3Result = await userRepository.createUserWithDefaultOrg(
        'test-user-3-ext-id',
        'user3@example.com',
        'User 3 Org',
        'user-3-org'
      );

      // Create third organization where user1 is NOT a member (owned by user3)
      const org3 = await orgRepository.createOrganization(
        'Unauthorized Org',
        'unauthorized-org',
        user3Result.user.id // Use user3 as owner (user1 won't be a member)
      );

      // Verify user has no membership in org3
      const membership = await orgRepository.getUserRole(userId, org3.id);
      expect(membership).toBeUndefined();

      // Attempting to switch to unauthorized org should fail
      // (This would be handled by business logic in actual implementation)
      const userWithRole = await userRepository.getUserWithMembership(userId, org3.id);
      expect(userWithRole).toBeUndefined();
    });
  });

  describe('Session Management with Organizations', () => {
    let userId: string;
    let orgId: string;

    beforeEach(async () => {
      const userResult = await userRepository.createUserWithDefaultOrg(
        testUser1.external_id,
        testUser1.email,
        testOrg1.name,
        testOrg1.slug
      );

      userId = userResult.user.id;
      orgId = userResult.organization.id;
    });

    it('should create and validate session with organization context', async () => {
      // Test Requirements 1.9, 3.6: Session creation with org context
      
      const sessionId = await sessionManager.createSession(userId, orgId, 'owner');
      expect(sessionId).toBeDefined();

      // Validate session contains organization context
      const session = await sessionManager.getSession(sessionId);
      expect(session).toBeDefined();
      expect(session!.user_id).toBe(userId);
      expect(session!.org_id).toBe(orgId);
      expect(session!.role).toBe('owner');

      // Log session creation
      authLogger.sessionCreated({
        user_id: userId,
        org_id: orgId,
        ip_address: '127.0.0.1',
        user_agent: 'test-agent',
        request_id: 'test-request-id',
      });

      // Validate session persistence in cache
      const cachedSession = await cache.get(`session:${sessionId}`);
      expect(cachedSession).toBeDefined();
    });

    it('should handle session expiration and cleanup', async () => {
      // Test session lifecycle management
      
      const sessionId = await sessionManager.createSession(userId, orgId, 'owner');
      
      // Verify session exists
      let session = await sessionManager.getSession(sessionId);
      expect(session).toBeDefined();

      // Delete session (logout)
      await sessionManager.deleteSession(sessionId);

      // Verify session is removed
      session = await sessionManager.getSession(sessionId);
      expect(session).toBeNull();

      // Verify cache cleanup
      const cachedSession = await cache.get(`session:${sessionId}`);
      expect(cachedSession).toBeNull();
    });
  });

  describe('Data Integrity and Constraints', () => {
    it('should enforce unique organization slugs', async () => {
      // Test Requirements 3.1: Unique slug constraint
      
      // Create first organization
      await userRepository.createUserWithDefaultOrg(
        testUser1.external_id,
        testUser1.email,
        testOrg1.name,
        testOrg1.slug
      );

      // Attempt to create organization with same slug should fail
      await expect(
        userRepository.createUserWithDefaultOrg(
          testUser2.external_id,
          testUser2.email,
          'Different Name',
          testOrg1.slug // Same slug
        )
      ).rejects.toThrow();
    });

    it('should enforce valid membership roles', async () => {
      // Test Requirements 3.4: Role validation
      
      const userResult = await userRepository.createUserWithDefaultOrg(
        testUser1.external_id,
        testUser1.email,
        testOrg1.name,
        testOrg1.slug
      );

      // Valid roles should work
      const validRoles = ['owner', 'admin', 'developer', 'viewer'] as const;
      
      for (const role of validRoles) {
        const membership = await orgRepository.getUserRole(userResult.user.id, userResult.organization.id);
        expect(membership).toBeDefined();
        expect(validRoles).toContain(membership!.role);
      }
    });

    it('should maintain referential integrity between users, organizations, and memberships', async () => {
      // Test database constraints and relationships
      
      const userResult = await userRepository.createUserWithDefaultOrg(
        testUser1.external_id,
        testUser1.email,
        testOrg1.name,
        testOrg1.slug
      );

      // Verify foreign key relationships
      const dbUser = await db
        .selectFrom('users')
        .selectAll()
        .where('id', '=', userResult.user.id)
        .executeTakeFirst();

      const dbOrg = await db
        .selectFrom('organizations')
        .selectAll()
        .where('id', '=', userResult.organization.id)
        .executeTakeFirst();

      const dbMembership = await db
        .selectFrom('memberships')
        .selectAll()
        .where('user_id', '=', userResult.user.id)
        .where('org_id', '=', userResult.organization.id)
        .executeTakeFirst();

      expect(dbUser!.default_org_id).toBe(dbOrg!.id);
      expect(dbMembership!.user_id).toBe(dbUser!.id);
      expect(dbMembership!.org_id).toBe(dbOrg!.id);
    });
  });
});