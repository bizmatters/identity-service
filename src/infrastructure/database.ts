import { Kysely, PostgresDialect } from 'kysely';
import { Pool } from 'pg';
import { Database } from '../types/database.js';
import { CONFIG } from '../config/index.js';

export function createDatabase(): Kysely<Database> {
  // Use DATABASE_URL (external Neon) only
  const connectionString = process.env['DATABASE_URL'];
  
  if (!connectionString) {
    throw new Error('DATABASE_URL environment variable is required');
  }

  console.log(`Using DATABASE_URL: ${connectionString.replace(/:[^:@]*@/, ':***@')}`);

  const poolConfig = {
    connectionString,
    max: CONFIG.DB_POOL_MAX,
    idleTimeoutMillis: CONFIG.DB_POOL_IDLE_TIMEOUT,
    connectionTimeoutMillis: CONFIG.DB_POOL_CONNECTION_TIMEOUT,
  };

  const pool = new Pool(poolConfig);

  return new Kysely<Database>({
    dialect: new PostgresDialect({ pool }),
  });
}

// Health check
export async function checkDatabaseHealth(db: Kysely<Database>): Promise<boolean> {
  try {
    console.log('Attempting database health check...');
    // Use a simple query that works with our schema
    const result = await db.selectFrom('users').select('id').limit(1).execute();
    console.log('Health check result:', result);
    return true;
  } catch (error) {
    console.error('Database health check failed:', error);
    return false;
  }
}