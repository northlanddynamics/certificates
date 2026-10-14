// Better Auth's client, for what is Better Auth's alone: signing in with a second factor or a passkey, and a user's own
// TOTP and passkeys (served on the platform API under /api/auth; see server/src/account-security.ts).
import { passkeyClient } from "@better-auth/passkey/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { createAuthClient } from "better-auth/react";
import { ApiError } from "@/lib/api";

export const authClient = createAuthClient({ basePath: "/api/auth", plugins: [twoFactorClient(), passkeyClient()] });

type Result<T> = { data: T; error: null } | { data: null; error: { message?: string; status: number; statusText: string } };

/** A Better Auth call's data, or its error thrown as the API's errors are, for react-query. */
export async function unwrap<T>(call: Promise<Result<T>>): Promise<NonNullable<T>> {
  const { data, error } = await call;
  if (error) throw new ApiError(error.status, error.message || error.statusText);
  return data as NonNullable<T>;
}
