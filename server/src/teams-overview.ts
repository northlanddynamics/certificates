// The one organization read Better Auth cannot serve: Better Auth lists a Team's members only to members of
// that Team, and without their emails, while an administrator needs the whole picture.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { asc, eq, inArray } from "drizzle-orm";
import type { Authorizer } from "./authorization";
import type { Db } from "./db/client";
import { team, teamMember, user } from "./db/schema";
import { OrgParam, errors, json } from "./http";
import type { Actor } from "./unit-of-work";

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
      request: { params: OrgParam },
      responses: {
        200: json(
          z.object({
            items: z.array(
              z.object({
                id: z.string(),
                name: z.string(),
                members: z.array(z.object({ userId: z.string(), email: z.string() })),
              }),
            ),
          }),
        ),
        ...errors(401, 404),
      },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId);
      const teams = await db.select().from(team).where(eq(team.organizationId, orgId)).orderBy(asc(team.createdAt), asc(team.id));
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
        },
        200,
      );
    },
  );
}
