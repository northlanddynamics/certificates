import { getMigrations } from "better-auth/db/migration";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { Pool } from "pg";
import { createAuth } from "./auth";

const MIGRATIONS_DIR = join(import.meta.dir, "..", "migrations");

/**
 * Applies Better Auth's schema (identity, organizations, invitations), then the
 * platform's own numbered SQL migrations. Safe to run repeatedly.
 */
export async function runMigrations(pool: Pool, authOptions: Parameters<typeof getMigrations>[0]) {
  const { runMigrations: runAuthMigrations } = await getMigrations(authOptions);
  await runAuthMigrations();

  await pool.query(
    `create table if not exists schema_migration (name text primary key, applied_at timestamptz not null default now())`,
  );
  const files = (await readdir(MIGRATIONS_DIR)).filter((f) => f.endsWith(".sql")).sort();
  for (const file of files) {
    const client = await pool.connect();
    try {
      await client.query("select pg_advisory_lock(7731001)");
      const done = await client.query(`select 1 from schema_migration where name = $1`, [file]);
      if (done.rowCount) continue;
      await client.query("begin");
      await client.query(await readFile(join(MIGRATIONS_DIR, file), "utf8"));
      await client.query(`insert into schema_migration (name) values ($1)`, [file]);
      await client.query("commit");
    } catch (err) {
      await client.query("rollback").catch(() => {});
      throw err;
    } finally {
      await client.query("select pg_advisory_unlock(7731001)").catch(() => {});
      client.release();
    }
  }
}

if (import.meta.main) {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const auth = createAuth({
    pool,
    baseURL: process.env.BASE_URL ?? "http://localhost:3000",
    secret: process.env.AUTH_SECRET ?? "migrate-only",
  });
  await runMigrations(pool, auth.options);
  await pool.end();
  console.log("migrations applied");
}
