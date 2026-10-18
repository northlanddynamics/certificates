import { and, eq } from "drizzle-orm";
import type { Db } from "../platform/db/client";
import { member } from "../platform/db/schema";
import { HttpError } from "../platform/http";
import { roleCan, type Permissions } from "./permissions";

export interface Authorizer {
  /**
   * "Can this actor do this in this Organization?": the way the platform's own routes ask about permissions.
   * (Better Auth's organization endpoints check the same roles themselves.)
   * With no `permissions`, membership is enough. Throws 404 for a non-member (so an Organization's existence is
   * not revealed, and a Platform Operator who was not invited in sees nothing) and 403 for a member whose role
   * lacks a permission.
   */
  authorize(actor: { id: string }, organizationId: string, permissions?: Permissions): Promise<{ role: string }>;
}

export function createAuthorizer(db: Db): Authorizer {
  return {
    async authorize(actor, organizationId, permissions) {
      const [row] = await db
        .select({ role: member.role })
        .from(member)
        .where(and(eq(member.organizationId, organizationId), eq(member.userId, actor.id)));
      if (!row) throw new HttpError(404, "organization not found");
      if (permissions && !roleCan(row.role, permissions)) throw new HttpError(403, "not permitted");
      return { role: row.role };
    },
  };
}
