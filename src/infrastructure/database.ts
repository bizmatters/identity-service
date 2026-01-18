import { Kysely, PostgresDialect } from 'kysely';
import { Pool } from 'pg';
import { Database } from '../types/database.js';

export function createDatabase(): Kysely<Database> {
  const pool = new Pool({
    connectionString: process.env['DATABASE_URL'],
    // Fixed minimal pool for HPA safety (prevents connection exhaustion)
    max: parseInt(process.env['DB_POOL_MAX'] || '3', 10),
    idleTimeoutMillis: parseInt(process.env['DB_POOL_IDLE_TIMEOUT'] || '10000', 10),
    connectionTimeoutMillis: parseInt(process.env['DB_POOL_CONNECTION_TIMEOUT'] || '5000', 10),
    ssl: process.env['NODE_ENV'] === 'production' ? { rejectUnauthorized: false } : false,
  });

  return new Kysely<Database>({
    dialect: new PostgresDialect({ pool }),
  });
}

// Health check
export async function checkDatabaseHealth(db: Kysely<Database>): Promise<boolean> {
  try {
    console.log('Attempting database health check...');
    const result = await db.selectFrom('pg_stat_database').select('datname').limit(1).execute();
    console.log('Health check result:', result);
    return true;
  } catch (error) {
    console.error('Database health check failed:', error);
    return false;
  }
}