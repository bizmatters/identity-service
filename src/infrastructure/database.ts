import { Kysely, PostgresDialect } from 'kysely';
import { Pool } from 'pg';
import { Database } from '../types/database.js';
import { CONFIG } from '../config/index.js';
import { infraLogger } from './logger.js';
import { resilientOperations } from './resilience.js';

export function createDatabase(): Kysely<Database> {
  // Use DATABASE_URL (external Neon) only
  const connectionString = process.env['DATABASE_URL'];
  
  if (!connectionString) {
    throw new Error('DATABASE_URL environment variable is required');
  }

  // Log connection attempt (without sensitive data)
  infraLogger.databaseConnected();

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
    // Use resilient database operation for health check
    await resilientOperations.databaseCall(async () => {
      return db.selectFrom('users').select('id').limit(1).execute();
    }, 'health_check');
    return true;
  } catch (error) {
    infraLogger.databaseError(error instanceof Error ? error : new Error(String(error)), 'health_check');
    return false;
  }
}