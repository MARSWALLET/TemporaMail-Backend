import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import pg from 'pg';
import * as schema from './schema.js';

export type Database = NodePgDatabase<typeof schema>;

export interface DbConnection {
  readonly pool: pg.Pool;
  readonly db: Database;
  close(): Promise<void>;
}

export function createDbConnection(databaseUrl: string): DbConnection {
  const pool = new pg.Pool({
    connectionString: databaseUrl,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
  });

  const db = drizzle(pool, { schema });

  return {
    pool,
    db,
    async close(): Promise<void> {
      await pool.end();
    },
  };
}
