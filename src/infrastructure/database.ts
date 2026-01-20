import { Kysely, PostgresDialect } from 'kysely';
import { Pool } from 'pg';
import { Database } from '../types/database.js';

export function createDatabase(): Kysely<Database> {
  // Check for explicit DATABASE_URL first
  let connectionString = process.env['DATABASE_URL'];
  
  // Build from individual environment variables if DATABASE_URL not provided
  if (!connectionString) {
    const host = process.env['POSTGRES_HOST'];
    const port = process.env['POSTGRES_PORT'] || '5432';
    const user = process.env['POSTGRES_USER'];
    const password = process.env['POSTGRES_PASSWORD'];
    const dbname = process.env['POSTGRES_DB'];
    
    if (host && user && password && dbname) {
      connectionString = `postgresql://${user}:${password}@${host}:${port}/${dbname}`;
    }
  }
  
  if (!connectionString) {
    throw new Error('DATABASE_URL environment variable or POSTGRES_* variables are required');
  }

  const poolConfig = {
    connectionString,
    max: parseInt(process.env['DB_POOL_MAX'] || '3', 10),
    idleTimeoutMillis: parseInt(process.env['DB_POOL_IDLE_TIMEOUT'] || '10000', 10),
    connectionTimeoutMillis: parseInt(process.env['DB_POOL_CONNECTION_TIMEOUT'] || '5000', 10),
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