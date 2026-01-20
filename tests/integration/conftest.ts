import { beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import { createDatabase } from '../../src/infrastructure/database.js';
import { createCache } from '../../src/infrastructure/cache.js';
import { MockNeonAuthProvider } from '../mock/mock-neon-auth-provider.js';
import { TestHelpers } from '../mock/test-helpers.js';

// Global test fixtures - using REAL infrastructure as per integration testing patterns
export let db: ReturnType<typeof createDatabase>;
export let cache: ReturnType<typeof createCache>;
export let mockNeonAuth: MockNeonAuthProvider;

beforeAll(async () => {
  // Initialize REAL database connection (internal dependency)
  // This uses the same createDatabase() function as production
  // Database URL comes from .env file - real Neon PostgreSQL
  db = createDatabase();
  
  // Initialize REAL cache connection (internal dependency)  
  // This uses the same createCache() function as production
  // Redis connection comes from .env file - real Redis
  cache = createCache();
  
  // Start mock Neon Auth provider (external dependency - should be mocked)
  // Only mock external Neon Auth API, not the Neon database
  mockNeonAuth = new MockNeonAuthProvider(3001);
  await mockNeonAuth.start();
  
  // Set environment variable to point to mock Neon Auth API (environment variable override pattern)
  process.env['NEON_AUTH_URL'] = mockNeonAuth.getBaseURL();
});

afterAll(async () => {
  // Clean up connections
  if (cache) {
    await cache.quit();
  }
  
  if (mockNeonAuth) {
    await mockNeonAuth.stop();
  }
  
  // Clean up environment
  delete process.env['NEON_AUTH_URL'];
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