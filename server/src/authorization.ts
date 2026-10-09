import { and, eq } from "drizzle-orm";
import { APPROVER_ROLE, MEMBER_ROLE, ORG_ADMIN_ROLE } from "./auth";
import type { Db } from "./db/client";
import { member } from "./db/schema";
import { HttpError } from "./http";

/**
 * Everything an Organization member can be permitted to do. Add an action here, and to a role below,
 * rather than testing a role name anywhere else: this is the one place permissions are decided.
 */
export type Action =
  | "organization.read"
  | "member.read"
  | "member.invite"
  | "member.changeRole"
  | "member.remove"
  | "invitation.read"
  | "invitation.cancel"
  | "team.read"
  | "team.create"
  | "team.update"
  | "team.delete"
  | "team.manageMembers"
  | "managedCertificate.list"
  | "audit.read";

const EVERYONE: readonly Action[] = ["organization.read", "member.read", "team.read", "managedCertificate.list"];

const ROLE_PERMISSIONS: Record<string, ReadonlySet<Action>> = {
  [MEMBER_ROLE]: new Set(EVERYONE),
  [APPROVER_ROLE]: new Set(EVERYONE),
  [ORG_ADMIN_ROLE]: new Set<Action>([
    ...EVERYONE,
    "member.invite",
    "member.changeRole",
    "member.remove",
    "invitation.read",
    "invitation.cancel",
    "team.create",
    "team.update",
    "team.delete",
    "team.manageMembers",
    "audit.read",
  ]),
};

export const roleCan = (role: string, action: Action) => ROLE_PERMISSIONS[role]?.has(action) ?? false;

export interface Authorizer {
  /**
   * "Can this actor do this action in this Organization?" The only way other modules ask about permissions.
   * Throws 404 for a non-member (so an Organization's existence is not revealed, and a Platform Operator
   * who was not invited in sees nothing) and 403 for a member whose role does not permit the action.
   */
  authorize(actor: { id: string }, organizationId: string, action: Action): Promise<{ role: string }>;
}

export function createAuthorizer(db: Db): Authorizer {
  return {
    async authorize(actor, organizationId, action) {
      const [row] = await db
        .select({ role: member.role })
        .from(member)
        .where(and(eq(member.organizationId, organizationId), eq(member.userId, actor.id)));
      if (!row) throw new HttpError(404, "organization not found");
      if (!roleCan(row.role, action)) throw new HttpError(403, "not permitted");
      return { role: row.role };
    },
  };
}
