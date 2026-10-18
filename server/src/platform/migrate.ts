import { migrate } from "drizzle-orm/node-postgres/migrator";
import { join } from "node:path";
import { Pool } from "pg";
import { createDb } from "./db/client";

/** Serialises concurrent migration runs (e.g. several app instances starting together). */
const MIGRATION_LOCK_ID = 7731001;
const MIGRATIONS_FOLDER = join(import.meta.dir, "..", "..", "drizzle");

/**
 * Applies the SQL migrations in server/drizzle, which drizzle-kit generates from
 * server/src/platform/db/schema.ts (itself including the schema the Better Auth CLI generates).
 * Safe to run repeatedly.
 */
export async function runMigrations(pool: Pool) {
  const lock = await pool.connect();
  try {
    await lock.query(`select pg_advisory_lock(${MIGRATION_LOCK_ID})`);
    await migrate(createDb(pool), { migrationsFolder: MIGRATIONS_FOLDER });
  } finally {
    await lock.query(`select pg_advisory_unlock(${MIGRATION_LOCK_ID})`).catch(() => {});
    lock.release();
  }
}

if (import.meta.main) {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  await runMigrations(pool);
  await pool.end();
  console.log("migrations applied");
}
