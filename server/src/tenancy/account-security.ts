// Better Auth's two-factor and passkey endpoints, served as they are, but each change to a signed-in user's sign-in methods
// on a transaction of the unit of work, which records it as Audit Events on that same transaction. Like the organization
// endpoints (organization-changes.ts), these open no transaction of their own, and the plugins have no hooks to audit
// from, so the change is found by comparing the user's sign-in methods before and after the endpoint ran.
//
// A sign-in method belongs to a user, not to an Organization, while an Audit Event belongs to one Organization: it is
// recorded in each Organization the user is a member of when it happens (a user in none leaves none).
//
// This module is the only one that knows which of those endpoints exist. Anything not listed here is not served; in
// particular the email OTP method, which is not configured.
import { asc, eq } from "drizzle-orm";
import { createAuth, type Auth, type AuthConfig } from "./auth";
import type { Tx } from "../platform/db/client";
import { member, passkey, user } from "../platform/db/schema";
import type { AuditAction } from "../audit/audit";
import type { Actor, Change, UnitOfWork } from "../platform/unit-of-work";

/**
 * Served straight from Better Auth, outside the unit of work: reads, and the sign-in ceremonies. The sign-in ones count
 * failed attempts toward Better Auth's lockout, which a rolled-back transaction would forget. `verify-totp` with a session
 * is a change (its first right code enables TOTP), without one a sign-in.
 */
const PASS_THROUGH = new Set([
  "two-factor/get-totp-uri",
  "two-factor/verify-backup-code",
  "passkey/generate-register-options",
  "passkey/generate-authenticate-options",
  "passkey/verify-authentication",
  "passkey/list-user-passkeys",
]);

/** The endpoints that change a signed-in user's sign-in methods. */
const CHANGES = new Set([
  "two-factor/enable",
  "two-factor/verify-totp",
  "two-factor/disable",
  "two-factor/generate-backup-codes",
  "passkey/verify-registration",
  "passkey/update-passkey",
  "passkey/delete-passkey",
]);

/** The paths this module answers, for mounting. */
export const ACCOUNT_SECURITY_PATHS = ["/api/auth/two-factor/*", "/api/auth/passkey/*"];

export interface AccountSecurityDeps {
  unitOfWork: UnitOfWork;
  /** Better Auth as configured, for the endpoints served outside the unit of work and for looking up who is asking. */
  auth: Auth;
  authConfig: Omit<AuthConfig, "db" | "organization">;
}

export interface AccountSecurity {
  /** Answers a request under /api/auth/two-factor/ or /api/auth/passkey/. A refused change leaves no trace. */
  serve(request: Request): Promise<Response>;
}

/** Thrown to roll back and still answer with Better Auth's own error response. */
class Refused extends Error {
  constructor(readonly response: Response) {
    super("refused");
  }
}

export function createAccountSecurity({ unitOfWork, auth, authConfig }: AccountSecurityDeps): AccountSecurity {
  return {
    async serve(request) {
      const endpoint = new URL(request.url).pathname.replace(/^\/api\/auth\//, "");
      if (PASS_THROUGH.has(endpoint)) return auth.handler(request);
      if (!CHANGES.has(endpoint)) return Response.json({ error: "not found" }, { status: 404 });
      const session = await auth.api.getSession({ headers: request.headers });
      if (!session) return auth.handler(request); // a sign-in's second factor, or Better Auth's own 401
      const actor = { id: session.user.id, email: session.user.email };
      try {
        return await unitOfWork.run(actor, async (tx, change) => {
          // Serialises the user's own concurrent changes, so each sees the sign-in methods the one before left.
          await tx.select({ id: user.id }).from(user).where(eq(user.id, actor.id)).for("update");
          const before = await signInMethodsOf(tx, actor.id);
          const res = await createAuth({ ...authConfig, db: tx }).handler(request);
          if (res.status >= 400) throw new Refused(res);
          const after = await signInMethodsOf(tx, actor.id);
          await audit(tx, change, actor.id, changes(actor, before, after, endpoint));
          return res;
        });
      } catch (err) {
        if (err instanceof Refused) return err.response;
        throw err;
      }
    },
  };
}

interface SignInMethods {
  twoFactorEnabled: boolean;
  /** The user's passkeys' names, by id. */
  passkeys: Map<string, string | null>;
}

async function signInMethodsOf(tx: Tx, userId: string): Promise<SignInMethods> {
  const [u] = await tx.select({ twoFactorEnabled: user.twoFactorEnabled }).from(user).where(eq(user.id, userId));
  const keys = await tx.select({ id: passkey.id, name: passkey.name }).from(passkey).where(eq(passkey.userId, userId)).orderBy(asc(passkey.id));
  return { twoFactorEnabled: Boolean(u?.twoFactorEnabled), passkeys: new Map(keys.map((k) => [k.id, k.name])) };
}

/** One change to a user's sign-in methods, as the Audit Event that records it. */
interface SignInMethodChange {
  action: AuditAction;
  target: { type: "user" | "passkey"; id: string };
  detail: Record<string, unknown>;
}

function changes(actor: Actor, before: SignInMethods, after: SignInMethods, endpoint: string): SignInMethodChange[] {
  const found: SignInMethodChange[] = [];
  const ofUser = (action: AuditAction) => found.push({ action, target: { type: "user", id: actor.id }, detail: { email: actor.email } });
  const ofPasskey = (action: AuditAction, id: string, detail: Record<string, unknown>) =>
    found.push({ action, target: { type: "passkey", id }, detail: { userId: actor.id, email: actor.email, ...detail } });
  if (!before.twoFactorEnabled && after.twoFactorEnabled) ofUser("two_factor.enabled");
  if (before.twoFactorEnabled && !after.twoFactorEnabled) ofUser("two_factor.disabled");
  // The codes are stored encrypted, so a new set is told by the endpoint that makes one rather than by comparing.
  if (endpoint === "two-factor/generate-backup-codes") ofUser("two_factor.backup_codes_regenerated");
  for (const [id, name] of after.passkeys) {
    if (!before.passkeys.has(id)) ofPasskey("passkey.registered", id, { name });
    else if (before.passkeys.get(id) !== name) ofPasskey("passkey.renamed", id, { from: before.passkeys.get(id), to: name });
  }
  for (const [id, name] of before.passkeys) if (!after.passkeys.has(id)) ofPasskey("passkey.deleted", id, { name });
  return found;
}

/** Records each change in every Organization the user belongs to now. */
async function audit(tx: Tx, change: Change, userId: string, found: SignInMethodChange[]) {
  if (found.length === 0) return;
  const memberships = await tx.select({ organizationId: member.organizationId }).from(member).where(eq(member.userId, userId)).orderBy(asc(member.organizationId));
  for (const { organizationId } of memberships) for (const c of found) await change.audit({ organizationId, ...c });
}
