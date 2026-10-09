// Config for the Better Auth CLI only: `bun run auth:generate` reads the plugins from here and
// writes server/src/db/auth-schema.ts. It never connects to a database.
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import { createAuth } from "./auth";

export const auth = createAuth({
  db: drizzle(new Pool({ connectionString: "postgres://unused" })),
  baseURL: "http://localhost:3000",
  secret: "cli-only-secret-cli-only-secret-cli-only",
});
