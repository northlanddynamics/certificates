import type { Pool } from "pg";
import { PLATFORM_OPERATOR_ROLE, type Auth } from "./auth";

/** Creates (or promotes) a Platform Operator. Run at install time; also used by tests. */
export async function bootstrapPlatformOperator(
  auth: Auth,
  pool: Pool,
  input: { email: string; password: string; name: string },
) {
  const existing = await pool.query(`select id from "user" where email = $1`, [input.email.toLowerCase()]);
  if (!existing.rowCount) {
    await auth.api.signUpEmail({ body: input });
  }
  await pool.query(`update "user" set role = $2 where email = $1`, [input.email.toLowerCase(), PLATFORM_OPERATOR_ROLE]);
}
