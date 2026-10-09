import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import type { Pool } from "pg";
import * as schema from "./schema";

export type Db = NodePgDatabase<typeof schema>;
/** A transaction handle: same query API as `Db`, scoped to one transaction. */
export type Tx = Parameters<Parameters<Db["transaction"]>[0]>[0];

export function createDb(pool: Pool): Db {
  return drizzle(pool, { schema });
}
