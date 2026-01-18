import { beforeAll, afterAll, beforeEach } from 'vitest';
import { Kysely, PostgresDialect } from 'kysely';
import { Pool } from 'pg';
import Redis from 'ioredis';
import { Database } from '../../src/types/database.js';
import { TestHelpers } from '../mock/test-helpers.js';

// Test database and cache instances
let testDb: Kysely<Database>;
let testCache: Redis;
let testHelpers: TestHelpers;

// Test configuration
const TEST_CONFIG = {
  database: {
    connectionString: process.env.TEST_DATABASE_URL || 'postgresql://postgres:password@localhost:5432/identity_test',
  },
  cache: {
    host: process.env.TEST_REDIS_HOST || 'localhost',
    port: parseInt(process.env.TEST_REDIS_PORT || '6379'),
    password: process.env.TEST_REDIS_PASSWORD,
    db: 1, // Use different DB for tests
  },
};

/**
 * Setup test infrastructure
 */
beforeAll(async () => {
  // Setup test database
  const pool = new Pool({
    connectionString: TEST_CONFIG.database.connectionString,
    max: 3,
  });

  testDb = new Kysely<Database>({
    dialect: new PostgresDialect({ pool }),
  });

  // Setup test cache
  testCache = new Redis({
    host: TEST_CONFIG.cache.host,
    port: TEST_CONFIG.cache.port,
    password: TEST_CONFIG.cache.password,
    db: TEST_CONFIG.cache.db,
    retryDelayOnFailover: 100,
    maxRetriesPerRequest: 3,
  });

  // Setup test helpers
  testHelpers = new TestHelpers(testDb, testCache);

  // Verify connections
  try {
    await testDb.selectFrom('users').select('id').limit(1).execute();
    console.log('✓ Test database connection established');
  } catch (error) {
    console.error('✗ Test database connection failed:', error);
    throw error;
  }

  try {
    await testCache.ping();
    console.log('✓ Test cache connection established');
  } catch (error) {
    console.error('✗ Test cache connection failed:', error);
    throw error;
  }
});

/**
 * Clean up before each test
 */
beforeEach(async () => {
  await testHelpers.cleanDatabase();
  await testHelpers.cleanCache();
});

/**
 * Cleanup test infrastructure
 */
afterAll(async () => {
  if (testDb) {
    await testDb.destroy();
  }
  
  if (testCache) {
    await testCache.quit();
  }
});

// Export test instances for use in tests
export { testDb, testCache, testHelpers, TEST_CONFIG };