// An Organization's login policy, and its enforcement. It can require SSO, which sso-sign-in.ts enforces where Better Auth
// makes a session; and it can require MFA. Requiring MFA means no member relies on a password alone: a
// member who has a password and has not set up TOTP may sign in, but may use nothing on the platform until they set it up.
// A passkey does not count, because the password still signs in by itself; a user without a password (who signs in by
// passkey only) is not a password user and is not held up.
//
// It is enforced where a signed-in user is looked up for the platform's routes (`requireUser` in app.ts), for Better
// Auth's organization endpoints (organization-changes.ts) and for a user's API keys (api-keys.ts), for the user as a
// whole rather than one Organization: a member of any Organization that requires MFA sets up TOTP before doing anything
// anywhere. What stays open is what setting it up needs: `/api/me`, Better Auth's own endpoints (two-factor among them), and the login policy itself,
// so that an Organization Administrator who required MFA can still undo it.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, eq, inArray, isNotNull } from "drizzle-orm";
import type { Authorizer } from "./authorization";
import type { Db } from "./db/client";
import { account, loginPolicy, member, ssoProvider, user } from "./db/schema";
import { HttpError, OrgParam, errors, json } from "./http";
import type { Actor, UnitOfWork } from "./unit-of-work";

export interface MfaStatus {
  /** Whether the user has set up TOTP. */
  enabled: boolean;
  /** Whether an Organization of theirs requires MFA of a password user like them, who has not set up TOTP. */
  setupRequired: boolean;
}

export interface LoginPolicies {
  /** Where the user stands with MFA. */
  mfaOf(actor: { id: string }): Promise<MfaStatus>;
  /** Refuses (403) a user who must set up MFA before going on. */
  admit(actor: { id: string }): Promise<void>;
}

export function createLoginPolicies(db: Db): LoginPolicies {
  async function mfaOf(actor: { id: string }): Promise<MfaStatus> {
    const [[u], [password], [requiring]] = await Promise.all([
      db.select({ enabled: user.twoFactorEnabled }).from(user).where(eq(user.id, actor.id)),
      db
        .select({ id: account.id })
        .from(account)
        .where(and(eq(account.userId, actor.id), eq(account.providerId, "credential"), isNotNull(account.password)))
        .limit(1),
      db
        .select({ id: loginPolicy.organizationId })
        .from(member)
        .innerJoin(loginPolicy, eq(loginPolicy.organizationId, member.organizationId))
        .where(and(eq(member.userId, actor.id), eq(loginPolicy.requireMfa, true)))
        .limit(1),
    ]);
    const enabled = Boolean(u?.enabled);
    return { enabled, setupRequired: !enabled && Boolean(password) && Boolean(requiring) };
  }
  return {
    mfaOf,
    async admit(actor) {
      if ((await mfaOf(actor)).setupRequired) {
        throw new HttpError(403, "MFA required: an Organization of yours requires it; set up an authenticator app to continue");
      }
    },
  };
}

const Policy = z.object({
  requireMfa: z.boolean().openapi({ description: "Whether members who sign in with a password must set up TOTP before using the platform." }),
  requireSso: z.boolean().openapi({
    description: "Whether members must sign in through one of the Organization's SSO connections, and in no other way (Platform Operators excepted).",
  }),
});
const PolicyChange = Policy.partial().openapi({ description: "What to change; what is left out stays as it is." });

export function registerLoginPolicy(ctx: {
  app: OpenAPIHono;
  db: Db;
  /** The signed-in user, whether or not they must set up MFA first: the policy stays open to them (see above). */
  requireSession(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
}) {
  const { app, db, requireSession, authorize, unitOfWork } = ctx;
  const current = async (tx: Pick<Db, "select">, organizationId: string, lock = false) => {
    const query = tx
      .select({ requireMfa: loginPolicy.requireMfa, requireSso: loginPolicy.requireSso })
      .from(loginPolicy)
      .where(eq(loginPolicy.organizationId, organizationId));
    const [row] = await (lock ? query.for("update") : query);
    return { requireMfa: row?.requireMfa ?? false, requireSso: row?.requireSso ?? false };
  };

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/login-policy",
      tags: ["Identity"],
      summary: "The Organization's login policy",
      request: { params: OrgParam },
      responses: { 200: json(Policy), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireSession(c), orgId, { loginPolicy: ["read"] });
      return c.json(await current(db, orgId), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/api/organizations/{orgId}/login-policy",
      tags: ["Identity"],
      summary: "Change the Organization's login policy",
      description:
        "Requiring MFA holds up every member who signs in with a password and has not set up TOTP, the caller included, until they set it up. Requiring SSO refuses every other way of signing in to the members; the caller must have signed in through one of the Organization's SSO connections themselves, so that they know it lets them back in. A change is an Audit Event.",
      request: { params: OrgParam, body: { content: { "application/json": { schema: PolicyChange } } } },
      responses: { 200: json(Policy), ...errors(400, 401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const asked = c.req.valid("json");
      const actor = await requireSession(c);
      await authorize(actor, orgId, { loginPolicy: ["update"] });
      const changed = await unitOfWork.run(actor, async (tx, change) => {
        // Serialises concurrent changes, so each records the value the one before left.
        await tx.insert(loginPolicy).values({ organizationId: orgId, updatedAt: change.occurredAt }).onConflictDoNothing();
        const before = await current(tx, orgId, true);
        const after = { ...before, ...asked };
        const detail: Record<string, { from: boolean; to: boolean }> = {};
        for (const key of ["requireMfa", "requireSso"] as const) if (before[key] !== after[key]) detail[key] = { from: before[key], to: after[key] };
        if (Object.keys(detail).length === 0) return before;
        if (detail.requireSso?.to) await refuseLockout(tx, orgId, actor);
        await tx.update(loginPolicy).set({ ...after, updatedAt: change.occurredAt }).where(eq(loginPolicy.organizationId, orgId));
        await change.audit({ organizationId: orgId, action: "login_policy.changed", target: { type: "organization", id: orgId }, detail });
        return after;
      });
      return c.json(changed, 200);
    },
  );
}

/**
 * Refuses to require SSO of an Organization whose administrator could not get back in: one without an SSO connection,
 * or whose administrator making the change has not signed in through one of its connections. Deleting the last
 * connection while SSO is required is refused where connections are deleted (sso-connections.ts).
 */
async function refuseLockout(tx: Pick<Db, "select">, organizationId: string, actor: Actor) {
  const connections = await tx.select({ providerId: ssoProvider.providerId }).from(ssoProvider).where(eq(ssoProvider.organizationId, organizationId));
  if (connections.length === 0) throw new HttpError(409, "the Organization has no SSO connection to require");
  const [signedIn] = await tx
    .select({ id: account.id })
    .from(account)
    .where(and(eq(account.userId, actor.id), inArray(account.providerId, connections.map((c) => c.providerId))))
    .limit(1);
  if (!signedIn) throw new HttpError(409, "sign in through one of the Organization's SSO connections first, so that you know it lets you back in");
}
