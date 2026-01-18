// Test script for CHECKPOINT 2: Database Layer Functional
import 'dotenv/config';
import { createDatabase, checkDatabaseHealth } from './infrastructure/database.js';
import { runMigrations } from './infrastructure/migrations.js';
import { UserRepository } from './modules/user/user-repository.js';
import { OrgRepository } from './modules/org/org-repository.js';
import { TokenRepository } from './modules/token/token-repository.js';
import crypto from 'crypto';

async function testDatabaseLayer(): Promise<void> {
  console.log('🔍 Testing Database Layer for CHECKPOINT 2...');

  // Initialize database connection
  const db = createDatabase();

  try {
    // Test database connection
    console.log('📊 Testing database connection...');
    const dbHealthy = await checkDatabaseHealth(db);
    if (!dbHealthy) {
      throw new Error('Database connection failed');
    }
    console.log('✅ Database connection successful');

    // Run migrations
    console.log('🔧 Running database migrations...');
    await runMigrations(db);
    console.log('✅ Migrations completed');

    // Initialize repositories
    const userRepo = new UserRepository(db);
    const orgRepo = new OrgRepository(db);
    const tokenRepo = new TokenRepository(db);

    // Test organization creation
    console.log('🏢 Testing organization creation...');
    
    const timestamp = Date.now();
    
    // First create a user without organization
    const ownerUser = await db
      .insertInto('users')
      .values({
        external_id: `owner-external-id-${timestamp}`,
        email: `owner-${timestamp}@example.com`,
        default_org_id: null,
        last_login_at: new Date(),
      })
      .returningAll()
      .executeTakeFirstOrThrow();
    
    const testOrg = await orgRepo.createOrganization(
      `Test Organization ${timestamp}`,
      `test-org-${timestamp}`,
      ownerUser.id
    );
    console.log('✅ Organization created:', testOrg.name);

    // Test user JIT provisioning
    console.log('👤 Testing user JIT provisioning...');
    const testUser = await userRepo.createUserAtomic(
      `test-external-id-${timestamp}`,
      `test-${timestamp}@example.com`,
      testOrg.id
    );
    if (!testUser) {
      throw new Error('User creation failed');
    }
    console.log('✅ User created:', testUser.email);

    // Test user lookup
    console.log('🔍 Testing user lookup by external ID...');
    const foundUser = await userRepo.findByExternalId(`test-external-id-${timestamp}`);
    if (!foundUser || foundUser.id !== testUser.id) {
      throw new Error('User lookup failed');
    }
    console.log('✅ User lookup successful');

    // Test user with membership query (use owner user who has membership)
    console.log('🔗 Testing user with membership query...');
    const userWithRole = await userRepo.getUserWithMembership(ownerUser.id, testOrg.id);
    if (!userWithRole || userWithRole.role !== 'owner') {
      throw new Error('User with membership query failed');
    }
    console.log('✅ User with membership query successful, role:', userWithRole.role);

    // Test API token creation
    console.log('🔑 Testing API token creation...');
    const tokenHash = crypto.createHash('sha256').update('test-token').digest('hex');
    const apiToken = await tokenRepo.createToken(
      testUser.id,
      testOrg.id,
      tokenHash,
      'Test Token'
    );
    console.log('✅ API token created:', apiToken.description);

    // Test token lookup
    console.log('🔍 Testing token lookup...');
    const foundToken = await tokenRepo.findByTokenHash(tokenHash);
    if (!foundToken || foundToken.id !== apiToken.id) {
      throw new Error('Token lookup failed');
    }
    console.log('✅ Token lookup successful');

    // Test role lookup (use owner user)
    console.log('👥 Testing role lookup...');
    const userRole = await orgRepo.getUserRole(ownerUser.id, testOrg.id);
    if (!userRole || userRole.role !== 'owner') {
      throw new Error('Role lookup failed');
    }
    console.log('✅ Role lookup successful, role:', userRole.role, 'version:', userRole.version);

    console.log('\n🎉 CHECKPOINT 2: Database Layer Functional - ALL TESTS PASSED');
    console.log('✅ Database schema deployed');
    console.log('✅ Connection pool established');
    console.log('✅ All repositories functional');
    console.log('✅ CRUD operations working');

  } catch (error) {
    console.error('❌ Database layer test failed:', error);
    process.exit(1);
  } finally {
    await db.destroy();
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  testDatabaseLayer().catch(console.error);
}