// The one organization read Better Auth cannot serve: Better Auth lists a Team's members only to members of
// that Team, and without their emails, while an administrator needs the whole picture.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, eq, exists, inArray, not } from "drizzle-orm";
import type { Authorizer } from "./authorization";
import type { Db } from "../platform/db/client";
import { team, teamMember, user } from "../platform/db/schema";
import { OrgParam, PageQuery, errors, json, pageOf } from "../platform/http";
import type { Actor } from "../platform/unit-of-work";

export function registerTeamsOverview(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
}) {
  const { app, db, requireUser, authorize } = ctx;
  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/teams",
      tags: ["Teams"],
      summary: "The Organization's Teams with their members, oldest first, a page at a time",
      request: {
        params: OrgParam,
        query: PageQuery.extend({ membership: z.enum(["empty", "populated"]).optional().meta({ description: "Only Teams with no members, or only those with some." }) }),
      },
      responses: {
        200: json(
          pageOf(
            z.object({
              id: z.string(),
              name: z.string(),
              members: z.array(z.object({ userId: z.string(), email: z.string() })),
            }),
          ),
        ),
        ...errors(400, 401, 404),
      },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId);
      const { page, pageSize, membership } = c.req.valid("query");
      const hasMembers = exists(db.select({ one: teamMember.teamId }).from(teamMember).where(eq(teamMember.teamId, team.id)));
      const where = and(eq(team.organizationId, orgId), membership && (membership === "empty" ? not(hasMembers) : hasMembers));
      const [total, teams] = await Promise.all([
        db.$count(team, where),
        db.select().from(team).where(where).orderBy(asc(team.createdAt), asc(team.id)).limit(pageSize).offset((page - 1) * pageSize),
      ]);
      const memberships = teams.length
        ? await db
            .select({ teamId: teamMember.teamId, userId: user.id, email: user.email })
            .from(teamMember)
            .innerJoin(user, eq(user.id, teamMember.userId))
            .where(inArray(teamMember.teamId, teams.map((t) => t.id)))
            .orderBy(asc(user.email))
        : [];
      return c.json(
        {
          items: teams.map((t) => ({
            id: t.id,
            name: t.name,
            members: memberships.filter((m) => m.teamId === t.id).map(({ userId, email }) => ({ userId, email })),
          })),
          total,
          page,
          pageSize,
        },
        200,
      );
    },
  );
}
