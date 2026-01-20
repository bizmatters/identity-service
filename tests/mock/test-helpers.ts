import { Kysely } from 'kysely';
import { Redis } from 'ioredis';
import { Database } from '../../types/database.js';

export class TestHelpers {
  /**
   * Clean database state for tests
   */
  static async cleanDatabase(db: Kysely<Database>): Promise<void> {
    // Delete in correct dependency order to avoid foreign key violations
    
    // 1. Delete API tokens first (references users)
    await db.deleteFrom('api_tokens').execute();
    
    // 2. Delete memberships (references both users and organizations)
    await db.deleteFrom('memberships').execute();
    
    // 3. Update users to remove foreign key references to organizations
    await db.updateTable('users').set({ default_org_id: null }).execute();
    
    // 4. Delete users (now safe since default_org_id is null)
    await db.deleteFrom('users').execute();
    
    // 5. Delete organizations last (no more references)
    await db.deleteFrom('organizations').execute();
  }

  /**
   * Clean cache state for tests
   */
  static async cleanCache(cache: Redis): Promise<void> {
    await cache.flushall();
  }

  /**
   * Create test user data with unique identifiers
   */
  static async createTestUser(db: Kysely<Database>): Promise<{
    user: { id: string; external_id: string; email: string };
    organization: { id: string; name: string; slug: string };
  }> {
    // Generate unique identifiers to avoid conflicts
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(7);
    const uniqueId = `${timestamp}-${random}`;

    // Create organization first
    const organization = await db
      .insertInto('organizations')
      .values({
        name: `Test Organization ${uniqueId}`,
        slug: `test-org-${uniqueId}`,
      })
      .returningAll()
      .executeTakeFirstOrThrow();

    // Create user with reference to organization
    const user = await db
      .insertInto('users')
      .values({
        external_id: `test-user-${uniqueId}`,
        email: `test-${uniqueId}@example.com`,
        default_org_id: organization.id,
      })
      .returningAll()
      .executeTakeFirstOrThrow();

    // Create membership
    await db
      .insertInto('memberships')
      .values({
        user_id: user.id,
        org_id: organization.id,
        role: 'owner',
        version: 1,
      })
      .execute();

    return { user, organization };
  }

  /**
   * Create test user without organization membership (for testing edge cases)
   */
  static async createUserWithoutOrg(db: Kysely<Database>): Promise<{
    id: string; 
    external_id: string; 
    email: string;
  }> {
    // Generate unique identifiers to avoid conflicts
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(7);
    const uniqueId = `${timestamp}-${random}`;

    // Create user without organization membership
    const user = await db
      .insertInto('users')
      .values({
        external_id: `orphan-user-${uniqueId}`,
        email: `orphan-${uniqueId}@example.com`,
        default_org_id: null, // No default organization
      })
      .returningAll()
      .executeTakeFirstOrThrow();

    return user;
  }

  /**
   * Wait for a condition to be true
   */
  static async waitFor(
    condition: () => Promise<boolean>,
    timeout = 5000,
    interval = 100
  ): Promise<void> {
    const start = Date.now();

    while (Date.now() - start < timeout) {
      if (await condition()) {
        return;
      }
      await new Promise(resolve => setTimeout(resolve, interval));
    }

    throw new Error(`Condition not met within ${timeout}ms`);
  }
}