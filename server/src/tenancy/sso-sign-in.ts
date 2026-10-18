// Sign-in through an Organization's SSO connections (Better Auth's SSO plugin), and the login policy that requires it.
//
// A connection speaks for the email addresses in its domain and for nobody else: an identity provider that asserts an
// address outside it is refused, so that an Organization Administrator's IdP cannot claim an address another company
// owns (and the domain itself is proven by DNS, sso-connections.ts). It links to a user who already exists only when that
// user is a member of the connection's Organization, and never to a Platform Operator; anyone else with that address keeps
// their account to themselves. A user it signs in who is not yet a member is made a Member of its Organization
// (`SsoSignedIn`, which the app runs on the unit of work with its Audit Event).
//
// An Organization that requires SSO (login-policy.ts) has its members sign in through an SSO connection of an
// Organization of theirs that requires it, and in no other way: not by password, nor by passkey. A Platform Operator
// is not held to it, so that someone can still get in when an identity provider fails, nor is a Platform Operator
// impersonating a member.
import { APIError } from "better-auth/api";
import { and, eq, gt, sql } from "drizzle-orm";
import type { NodePgDatabase } from "drizzle-orm/node-postgres";
import { auditEvent, invitation, loginPolicy, member, ssoProvider, user } from "../platform/db/schema";
import { MEMBER_ROLE, PLATFORM_OPERATOR_ROLE } from "./permissions";
import type { UnitOfWork } from "../platform/unit-of-work";

/** Runs after each sign-in through a connection, once Better Auth has the user and their session. */
export type SsoSignedIn = (user: { id: string; email: string }, connection: { providerId: string; organizationId?: string | null }) => Promise<void>;

/** Whether `email` is an address in `domain` or one of its subdomains. */
export function inDomain(email: string, domain: string) {
  const host = email.toLowerCase().split("@").pop() ?? "";
  const d = domain.toLowerCase();
  return host === d || host.endsWith(`.${d}`);
}

export function createSsoSignIn(db: NodePgDatabase<any>) {
  const connection = async (providerId: string) => {
    const [row] = await db
      .select({ organizationId: ssoProvider.organizationId, domain: ssoProvider.domain })
      .from(ssoProvider)
      .where(eq(ssoProvider.providerId, providerId));
    return row;
  };

  return {
    /** Better Auth's `user.validateUserInfo`: only the SSO methods are looked at. */
    async validateUserInfo(data: { user: { id?: unknown; email?: unknown }; source: { method: string; action: string; sso?: { providerId: string } } }) {
      const { source } = data;
      if (source.method !== "sso-oidc" && source.method !== "sso-saml") return;
      const found = source.sso && (await connection(source.sso.providerId));
      if (!found?.organizationId) return { error: "unknown_connection", errorDescription: "This SSO connection does not exist." };
      const email = typeof data.user.email === "string" ? data.user.email : "";
      if (!inDomain(email, found.domain)) {
        return { error: "email_outside_domain", errorDescription: `This SSO connection signs in addresses in ${found.domain} only.` };
      }
      if (source.action === "link-account") {
        const [existing] = await db.select({ role: user.role }).from(user).where(eq(user.id, String(data.user.id)));
        if (existing?.role === PLATFORM_OPERATOR_ROLE) return { error: "account_exists", errorDescription: "A Platform Operator signs in with their own credentials." };
        const [isMember] = await db
          .select({ id: member.id })
          .from(member)
          .where(and(eq(member.userId, String(data.user.id)), eq(member.organizationId, found.organizationId)));
        if (!isMember) return { error: "account_exists", errorDescription: "An account with this email already exists; ask to be invited to the Organization." };
      }
    },

    /** Better Auth's `databaseHooks.session.create.before`: refuses a session the user's login policy does not allow. */
    async admitSession(session: { userId: string; impersonatedBy?: string | null }, ctx?: { path?: string; params?: Record<string, string | undefined> } | null) {
      const requiring = await db
        .select({ organizationId: member.organizationId })
        .from(member)
        .innerJoin(loginPolicy, eq(loginPolicy.organizationId, member.organizationId))
        .where(and(eq(member.userId, session.userId), eq(loginPolicy.requireSso, true)));
      if (requiring.length === 0) return;
      // Only a Platform Operator can impersonate (the admin plugin).
      if (session.impersonatedBy) return;
      const [signingIn] = await db.select({ role: user.role }).from(user).where(eq(user.id, session.userId));
      if (signingIn?.role === PLATFORM_OPERATOR_ROLE) return;
      const providerId = ctx?.path?.startsWith("/sso/") ? ctx.params?.providerId : undefined;
      const through = providerId ? await connection(providerId) : undefined;
      if (through && requiring.some((r) => r.organizationId === through.organizationId)) return;
      throw new APIError("FORBIDDEN", { code: "SSO_REQUIRED", message: "An Organization of yours requires SSO: sign in through its identity provider." });
    },
  };
}

/**
 * Makes a user who signs in through a connection a Member of its Organization when they are not one, with the Audit
 * Event that records it. It is looked at on every sign-in, so that one that failed, or was put off, happens at the next.
 * Put off: one with a pending invitation there is left to accept it, so that they get the role they were invited to.
 * Never: a member who was removed from the Organization is not made one again by signing in.
 */
export function provisionOnSsoSignIn(unitOfWork: UnitOfWork): SsoSignedIn {
  return async (signedIn, connection) => {
    const organizationId = connection.organizationId;
    if (!organizationId) return;
    await unitOfWork.run({ id: signedIn.id, email: signedIn.email }, async (tx, change) => {
      // Serialises the user's own concurrent sign-ins, so that only one makes them a Member.
      await tx.select({ id: user.id }).from(user).where(eq(user.id, signedIn.id)).for("update");
      const [already] = await tx.select({ id: member.id }).from(member).where(and(eq(member.organizationId, organizationId), eq(member.userId, signedIn.id)));
      if (already) return;
      const [invited] = await tx
        .select({ id: invitation.id })
        .from(invitation)
        .where(and(eq(invitation.organizationId, organizationId), eq(invitation.email, signedIn.email.toLowerCase()), eq(invitation.status, "pending"), gt(invitation.expiresAt, change.occurredAt)));
      if (invited) return;
      const [removed] = await tx
        .select({ id: auditEvent.id })
        .from(auditEvent)
        .where(and(eq(auditEvent.organizationId, organizationId), eq(auditEvent.action, "member.removed"), sql`${auditEvent.detail}->>'userId' = ${signedIn.id}`))
        .limit(1);
      if (removed) return;
      const id = crypto.randomUUID();
      await tx.insert(member).values({ id, organizationId, userId: signedIn.id, role: MEMBER_ROLE, createdAt: change.occurredAt });
      await change.audit({
        organizationId,
        action: "member.provisioned",
        target: { type: "member", id },
        detail: { userId: signedIn.id, email: signedIn.email, role: MEMBER_ROLE, connectionId: connection.providerId },
      });
    });
  };
}
