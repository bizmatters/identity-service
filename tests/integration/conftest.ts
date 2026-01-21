import { beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import { createDatabase } from '../../src/infrastructure/database.js';
import { createCache } from '../../src/infrastructure/cache.js';
import { TestHelpers } from '../mock/test-helpers.js';

// Global test fixtures - using REAL infrastructure as per integration testing patterns
export let db: ReturnType<typeof createDatabase>;
export let cache: ReturnType<typeof createCache>;

beforeAll(async () => {
  // Initialize REAL database connection (internal dependency)
  // This uses the same createDatabase() function as production
  // Database URL comes from .env file - real Neon PostgreSQL
  db = createDatabase();
  
  // Initialize REAL cache connection (internal dependency)  
  // This uses the same createCache() function as production
  // Redis connection comes from .env file - real Redis
  cache = createCache();
});

afterAll(async () => {
  // Clean up connections
  if (cache) {
    await cache.quit();
  }
});

beforeEach(async () => {
  // Clean state before each test using REAL infrastructure
  await TestHelpers.cleanDatabase(db);
  await TestHelpers.cleanCache(cache);
});

afterEach(async () => {
  // Clean state after each test using REAL infrastructure
  await TestHelpers.cleanDatabase(db);
  await TestHelpers.cleanCache(cache);
});