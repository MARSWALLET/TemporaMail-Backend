import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { loadEnv } from '../config/env.js';
import { createDbConnection } from '../storage/db.js';

async function main(): Promise<void> {
  const config = loadEnv();
  if (!config.databaseUrl) {
    console.error('DATABASE_URL is not set');
    process.exit(1);
  }

  const drizzleDir = path.resolve(process.cwd(), 'drizzle');
  const sqlFiles = readdirSync(drizzleDir)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  const conn = createDbConnection(config.databaseUrl);
  try {
    for (const file of sqlFiles) {
      const fullPath = path.join(drizzleDir, file);
      const sql = readFileSync(fullPath, 'utf8');
      console.log(`Applying migration: ${file}`);
      await conn.pool.query(sql);
      console.log(`Applied ${file}`);
    }
    console.log('All migrations applied successfully.');
  } finally {
    await conn.close();
  }
}

void main().catch((err) => {
  console.error('Migration failed:', err);
  process.exit(1);
});
