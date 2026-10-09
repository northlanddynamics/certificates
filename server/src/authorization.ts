import { and, eq } from "drizzle-orm";
import { orgRoles, type Permissions } from "./auth";
import type { Db, Tx } from "./db/client";
import { member } from "./db/schema";
import { HttpError } from "./http";

/** Whether `role` holds every permission asked for. Roles and their permissions are defined in auth.ts. */
export function roleCan(role: string, permissions: Permissions): boolean {
  const r = (orgRoles as Record<string, (typeof orgRoles)[keyof typeof orgRoles] | undefined>)[role];
  return r ? r.authorize(permissions).success : false;
}

export interface AuthorizeOptions {
  /** Run on this transaction instead of the pool. */
  tx?: Tx;
  /**
   * Lock the actor's membership row until the transaction ends, so that a concurrent demotion or removal of the
   * actor waits for this change to finish instead of racing it. Use it on every change made inside a transaction.
   */
  lockActor?: boolean;
}

export interface Authorizer {
  /**
   * "Can this actor do this in this Organization?": the only way other modules ask about permissions.
   * With no `permissions`, membership is enough. Throws 404 for a non-member (so an Organization's existence is
   * not revealed, and a Platform Operator who was not invited in sees nothing) and 403 for a member whose role
   * lacks a permission.
   */
  authorize(
    actor: { id: string },
    organizationId: string,
    permissions?: Permissions,
    options?: AuthorizeOptions,
  ): Promise<{ role: string }>;
}

export function createAuthorizer(db: Db): Authorizer {
  return {
    async authorize(actor, organizationId, permissions, { tx, lockActor } = {}) {
      const query = (tx ?? db)
        .select({ role: member.role })
        .from(member)
        .where(and(eq(member.organizationId, organizationId), eq(member.userId, actor.id)));
      const [row] = await (lockActor ? query.for("share") : query);
      if (!row) throw new HttpError(404, "organization not found");
      if (permissions && !roleCan(row.role, permissions)) throw new HttpError(403, "not permitted");
      return { role: row.role };
    },
  };
}
