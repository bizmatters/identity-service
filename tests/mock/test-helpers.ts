import { Kysely } from 'kysely';
import { Database } from '../../src/types/database.js';
import type { Redis } from 'ioredis';

export interface TestUser {
  id: string;
  external_id: string;
  email: string;
  default_org_id: string;
}

export interface TestOrganization {
  id: string;
  name: string;
  slug: string;
}

export interface TestMembership {
  user_id: string;
  org_id: string;
  role: 'owner' | 'admin' | 'developer' | 'viewer';
  version: number;
}

/**
 * Test helpers for integration tests
 */
export class TestHelpers {
  constructor(
    private db: Kysely<Database>,
    private cache: Redis
  ) {}

  /**
   * Clean database tables for test isolation
   */
  async cleanDatabase(): Promise<void> {
    await this.db.deleteFrom('memberships').execute();
    await this.db.deleteFrom('api_tokens').execute();
    await this.db.deleteFrom('users').execute();
    await this.db.deleteFrom('organizations').execute();
  }

  /**
   * Clean cache for test isolation
   */
  async cleanCache(): Promise<void> {
    await this.cache.flushall();
  }

  /**
   * Create test user with organization
   */
  async createTestUser(
    externalId: string = 'test-external-id',
    email: string = 'test@example.com',
    orgName: string = 'Test Organization'
  ): Promise<{ user: TestUser; organization: TestOrganization; membership: TestMembership }> {
    // Create organization
    const organization = await this.db
      .insertInto('organizations')
      .values({
        name: orgName,
        slug: `test-org-${Date.now()}`,
      })
      .returningAll()
      .executeTakeFirstOrThrow();

    // Create user
    const user = await this.db
      .insertInto('users')
      .values({
        external_id: externalId,
        email,
        default_org_id: organization.id,
      })
      .returningAll()
      .executeTakeFirstOrThrow();

    // Create membership
    const membership = await this.db
      .insertInto('memberships')
      .values({
        user_id: user.id,
        org_id: organization.id,
        role: 'owner',
      })
      .returningAll()
      .executeTakeFirstOrThrow();

    return {
      user: user as TestUser,
      organization: organization as TestOrganization,
      membership: membership as TestMembership,
    };
  }

  /**
   * Create test session in cache
   */
  async createTestSession(
    sessionId: string,
    userId: string,
    orgId: string,
    role: string = 'owner'
  ): Promise<void> {
    const sessionData = {
      user_id: userId,
      org_id: orgId,
      role,
      created_at: Date.now(),
      last_accessed: Date.now(),
      absolute_expiry: Date.now() + (7 * 24 * 60 * 60 * 1000), // 7 days
    };

    await this.cache.setex(
      `session:${sessionId}`,
      24 * 60 * 60, // 24 hours
      JSON.stringify(sessionData)
    );
  }

  /**
   * Get session from cache
   */
  async getTestSession(sessionId: string): Promise<any | null> {
    const sessionData = await this.cache.get(`session:${sessionId}`);
    return sessionData ? JSON.parse(sessionData) : null;
  }

  /**
   * Create OIDC state in cache
   */
  async createOIDCState(
    state: string,
    nonce: string,
    codeVerifier: string,
    redirectUri: string
  ): Promise<void> {
    const oidcState = {
      state,
      nonce,
      code_verifier: codeVerifier,
      redirect_uri: redirectUri,
    };

    await this.cache.setex(
      `oidc:state:${state}`,
      600, // 10 minutes
      JSON.stringify(oidcState)
    );
  }

  /**
   * Wait for async operations to complete
   */
  async waitFor(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Generate random test data
   */
  generateTestData() {
    const timestamp = Date.now();
    return {
      externalId: `test-external-${timestamp}`,
      email: `test-${timestamp}@example.com`,
      orgName: `Test Org ${timestamp}`,
      sessionId: `test-session-${timestamp}`,
      state: `test-state-${timestamp}`,
      nonce: `test-nonce-${timestamp}`,
      codeVerifier: `test-code-verifier-${timestamp}`,
    };
  }
}