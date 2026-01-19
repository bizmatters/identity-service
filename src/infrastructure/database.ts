import { Kysely, PostgresDialect } from 'kysely';
import { Pool } from 'pg';
import { Database } from '../types/database.js';

export function createDatabase(): Kysely<Database> {
  // Use individual connection parameters from cluster secrets
  const host = process.env['POSTGRES_HOST'] || 'localhost';
  const port = parseInt(process.env['POSTGRES_PORT'] || '5432', 10);
  const user = process.env['POSTGRES_USER'] || 'postgres';
  const password = process.env['POSTGRES_PASSWORD'] || '';
  const database = process.env['POSTGRES_DB'] || 'postgres';
  
  // Fallback to DATABASE_URL if individual parameters not available
  const connectionString = process.env['DATABASE_URL'];
  
  let poolConfig;
  
  if (host && host !== 'localhost') {
    // Use individual parameters (cluster deployment)
    poolConfig = {
      host,
      port,
      user,
      password,
      database,
      // Fixed minimal pool for HPA safety (prevents connection exhaustion)
      max: parseInt(process.env['DB_POOL_MAX'] || '3', 10),
      idleTimeoutMillis: parseInt(process.env['DB_POOL_IDLE_TIMEOUT'] || '10000', 10),
      connectionTimeoutMillis: parseInt(process.env['DB_POOL_CONNECTION_TIMEOUT'] || '5000', 10),
      ssl: false, // No SSL for cluster-internal connections
    };
  } else if (connectionString) {
    // Use connection string (external database)
    poolConfig = {
      connectionString,
      max: parseInt(process.env['DB_POOL_MAX'] || '3', 10),
      idleTimeoutMillis: parseInt(process.env['DB_POOL_IDLE_TIMEOUT'] || '10000', 10),
      connectionTimeoutMillis: parseInt(process.env['DB_POOL_CONNECTION_TIMEOUT'] || '5000', 10),
      ssl: process.env['NODE_ENV'] === 'production' ? { rejectUnauthorized: false } : false,
    };
  } else {
    throw new Error('No database connection configuration found');
  }

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