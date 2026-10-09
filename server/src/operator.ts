import { eq } from "drizzle-orm";
import { PLATFORM_OPERATOR_ROLE, type Auth } from "./auth";
import type { Db } from "./db/client";
import { user } from "./db/schema";

/** Creates (or promotes) a Platform Operator. Run at install time; also used by tests. */
export async function bootstrapPlatformOperator(
  auth: Auth,
  db: Db,
  input: { email: string; password: string; name: string },
) {
  const email = input.email.toLowerCase();
  const [existing] = await db.select({ id: user.id }).from(user).where(eq(user.email, email));
  if (!existing) await auth.api.signUpEmail({ body: input });
  await db.update(user).set({ role: PLATFORM_OPERATOR_ROLE }).where(eq(user.email, email));
}
