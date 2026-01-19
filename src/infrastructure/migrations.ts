import { readdir, readFile } from 'fs/promises';
import { join } from 'path';
import { Kysely, sql } from 'kysely';
import { createDatabase } from './database.js';
import { Database } from '../types/database.js';

export async function runMigrations(db: Kysely<Database>): Promise<void> {
  // Create migrations table if it doesn't exist
  await db.schema
    .createTable('migrations')
    .ifNotExists()
    .addColumn('id', 'serial', (col) => col.primaryKey())
    .addColumn('name', 'varchar(255)', (col) => col.notNull().unique())
    .addColumn('executed_at', 'timestamp', (col) => col.defaultTo(sql`now()`).notNull())
    .execute();

  // Get executed migrations
  const executedMigrations = await db
    .selectFrom('migrations')
    .select('name')
    .execute();

  const executedNames = new Set(executedMigrations.map((m) => m.name));

  // Read migration files
  const migrationsDir = join(process.cwd(), 'migrations');
  const files = await readdir(migrationsDir);
  const migrationFiles = files
    .filter((f) => f.endsWith('.sql'))
    .sort();

  // Execute pending migrations
  for (const file of migrationFiles) {
    if (!executedNames.has(file)) {
      console.log(`Running migration: ${file}`);
      
      const sqlContent = await readFile(join(migrationsDir, file), 'utf-8');
      
      // Execute migration in transaction
      await db.transaction().execute(async (trx) => {
        // Execute the SQL using raw query
        await sql`${sql.raw(sqlContent)}`.execute(trx);
        
        // Record migration
        await trx
          .insertInto('migrations')
          .values({ name: file })
          .execute();
      });
      
      console.log(`Completed migration: ${file}`);
    }
  }
}

// CLI runner
async function main() {
  try {
    console.log('Starting database migrations...');
    
    const db = createDatabase();
    await runMigrations(db);
    
    console.log('All migrations completed successfully');
    process.exit(0);
  } catch (error) {
    console.error('Migration failed:', error);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}