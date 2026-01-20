import { Kysely } from 'kysely';
import { Redis } from 'ioredis';
import { Database } from '../../types/database.js';

export class TestHelpers {
  /**
   * Clean database state for tests
   */
  static async cleanDatabase(db: Kysely<Database>): Promise<void> {
    // Delete in reverse dependency order
    await db.deleteFrom('memberships').execute();
    await db.deleteFrom('api_tokens').execute();
    await db.deleteFrom('users').execute();
    await db.deleteFrom('organizations').execute();
  }

  /**
   * Clean cache state for tests
   */
  static async cleanCache(cache: Redis): Promise<void> {
    await cache.flushall();
  }

  /**
   * Create test user data
   */
  static async createTestUser(db: Kysely<Database>): Promise<{
    user: { id: string; external_id: string; email: string };
    organization: { id: string; name: string; slug: string };
  }> {
    // Create organization
    const organization = await db
      .insertInto('organizations')
      .values({
        name: 'Test Organization',
        slug: 'test-org',
      })
      .returningAll()
      .executeTakeFirstOrThrow();

    // Create user
    const user = await db
      .insertInto('users')
      .values({
        external_id: 'test-user-456',
        email: 'test@example.com',
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
   * Generate test JWT keys for testing
   */
  static getTestJWTKeys(): {
    privateKey: string;
    publicKey: string;
    keyId: string;
  } {
    // These are test keys - DO NOT use in production
    const privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEjWT2btf02
uSQkyHpcUiHbp/X5yNicxKtA1uqBdAaUOh9fQbuOphN8AM6o4ePnxj9QFLkn6T95
IRXMn/dF25XylcuUbL1RTQHpaabxrVwjnuTHxS8h5Ke6+jH4dDPVgIN3YlPB6zDT
5j9/dGeTf/pY8CB/xNu/5OiWQdJQdxhcyoOoABNnv4FN+2hqaPdwc0NvQoaq30cI
Nhw2HePiHEHhaLnlteO9Z5djFuLxeQvnm5L2ws/U5YP0jKHCFHyPnVHlmAh6QsFf
xz9fkuXn5fCXBYKg+qK9lycTMJ4qQTMhRa57VQIDAQABAoIBAECvfqMnC1WiiyBb
+H4HpJ2N1B8+zFnuBiHyPPul8OwdOWLjyMJmSJXR0L/T+2xIyU2ZgJRG0oxIU6FV
ufgGiHiSWpY8YufMpw1a1nECMsxTVCLOoalLlBcHVYzieHnBahZAXebECAjHHuCO
TtZFfEApgcq+lxpFkuv7iYKHBtaKlBkTFvgHpgP6aM4fQEKKjJ+oxdqJ4JXxqZxI
/+lM5rzbFb8MvMW/sK4KQYEH/+jsHqBb6T9YQ1hoUleEeL3sEVwrri2pyJ3p0L/+
nFx+4Q3/Sl9jBH6PqHGGux5AAAVH2/mxh2+Qk4ckHGjkDlvVmOmcK9+7O8AC8JLy
vEOKxAECgYEA+8LunaUb4OVZ
-----END RSA PRIVATE KEY-----`;

    const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEjWT2btf02uSQkyHpcUiHbp/X5yNicxKtA1uqBdAaUOh9f
QbuOphN8AM6o4ePnxj9QFLkn6T95IRXMn/dF25XylcuUbL1RTQHpaabxrVwjnuTH
xS8h5Ke6+jH4dDPVgIN3YlPB6zDT5j9/dGeTf/pY8CB/xNu/5OiWQdJQdxhcyoOo
ABNnv4FN+2hqaPdwc0NvQoaq30cINhw2HePiHEHhaLnlteO9Z5djFuLxeQvnm5L2
ws/U5YP0jKHCFHyPnVHlmAh6QsFfxz9fkuXn5fCXBYKg+qK9lycTMJ4qQTMhRa57
VQIDAQAB
-----END PUBLIC KEY-----`;

    return {
      privateKey,
      publicKey,
      keyId: 'test-key-1',
    };
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