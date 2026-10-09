// The platform API for who is in an Organization: invitations, members, roles and Teams. Better Auth's
// organization plugin does the work (validation, last-administrator protection, Team clean-up on removal);
// this file adds what it does not: the Organization-scoping 404, one place for permissions (`authorize`),
// a transaction around each change so its audit entry commits with it (see unit-of-work.ts), and the
// OpenAPI contract the web UI uses.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, eq, inArray } from "drizzle-orm";
import { APPROVER_ROLE, MEMBER_ROLE, ORG_ADMIN_ROLE, type Auth, type Permissions } from "./auth";
import type { Authorizer } from "./authorization";
import type { Db, Tx } from "./db/client";
import { invitation, member, team, teamMember, user } from "./db/schema";
import { HttpError, OrgParam, errors, json, pathParam } from "./http";
import type { Actor, UnitOfWork } from "./unit-of-work";

interface Context {
  app: OpenAPIHono;
  db: Db;
  /** Better Auth, for reads. Changes go through `unitOfWork`. */
  auth: Auth;
  unitOfWork: UnitOfWork;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
}

const Role = z.enum([MEMBER_ROLE, APPROVER_ROLE, ORG_ADMIN_ROLE]);
const noContent = { 204: { description: "Done" } } as const;

export function registerOrganizationRoutes({ app, db, auth, unitOfWork, requireUser, authorize }: Context) {
  /**
   * Authorizes the signed-in user, then runs `fn` as one audited unit of work. Changes to the Organization's
   * administrators lock them first, so two concurrent changes cannot together leave it with none.
   */
  async function mutate<T>(
    c: any,
    orgId: string,
    permissions: Permissions,
    fn: (auth: Auth, tx: Tx, headers: Headers) => Promise<T>,
    { lockAdministrators = false } = {},
  ): Promise<T> {
    const actor = await requireUser(c);
    return unitOfWork.run(actor, async (txAuth, tx) => {
      if (lockAdministrators) await lockOrganizationAdministrators(tx, orgId);
      await authorize(actor, orgId, permissions, { tx, lockActor: !lockAdministrators });
      return fn(txAuth, tx, c.req.raw.headers);
    });
  }

  /** Authorizes the signed-in user and returns what Better Auth needs to answer a read. */
  async function read(c: any, orgId: string, permissions?: Permissions) {
    await authorize(await requireUser(c), orgId, permissions);
    return c.req.raw.headers as Headers;
  }

  // ---------- invitations ----------

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/invitations",
      tags: ["Members"],
      request: {
        params: OrgParam,
        body: { content: { "application/json": { schema: z.object({ email: z.email(), role: Role }) } } },
      },
      responses: { 201: json(z.object({ id: z.string() }), "Created"), ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const { email, role } = c.req.valid("json");
      const created = await mutate(c, orgId, { invitation: ["create"] }, (a, _tx, headers) =>
        a.api.createInvitation({ body: { email, role, organizationId: orgId }, headers }),
      );
      return c.json({ id: created.id }, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/invitations",
      tags: ["Members"],
      request: { params: OrgParam },
      responses: {
        200: json(
          z.object({
            items: z.array(z.object({ id: z.string(), email: z.string(), role: z.string(), expiresAt: z.string() })),
          }),
        ),
        ...errors(401, 403, 404),
      },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      // Whoever may invite may see who is still pending.
      const headers = await read(c, orgId, { invitation: ["create"] });
      const all = await auth.api.listInvitations({ query: { organizationId: orgId }, headers });
      const now = new Date(); // Better Auth judges expiry against the real time
      const items = all
        .filter((i) => i.status === "pending" && i.expiresAt > now)
        .sort((x, y) => x.createdAt.getTime() - y.createdAt.getTime())
        .map((i) => ({ id: i.id, email: i.email, role: i.role ?? MEMBER_ROLE, expiresAt: i.expiresAt.toISOString() }));
      return c.json({ items }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/api/organizations/{orgId}/invitations/{invitationId}",
      tags: ["Members"],
      request: { params: OrgParam.extend({ invitationId: pathParam("invitationId") }) },
      responses: { ...noContent, ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, invitationId } = c.req.valid("param");
      await mutate(c, orgId, { invitation: ["cancel"] }, async (a, tx, headers) => {
        // Better Auth looks the invitation up by id alone; make sure it is a pending one of this Organization.
        const [pending] = await tx
          .select({ id: invitation.id })
          .from(invitation)
          .where(
            and(eq(invitation.id, invitationId), eq(invitation.organizationId, orgId), eq(invitation.status, "pending")),
          );
        if (!pending) throw new HttpError(404, "invitation not found");
        await a.api.cancelInvitation({ body: { invitationId }, headers });
      });
      return c.body(null, 204);
    },
  );

  // ---------- members ----------

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/members",
      tags: ["Members"],
      request: { params: OrgParam },
      responses: {
        200: json(
          z.object({
            items: z.array(z.object({ id: z.string(), userId: z.string(), email: z.string(), name: z.string(), role: z.string() })),
          }),
        ),
        ...errors(401, 404),
      },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const headers = await read(c, orgId);
      const { members } = await auth.api.listMembers({ query: { organizationId: orgId, sortBy: "createdAt" }, headers });
      return c.json(
        { items: members.map((m) => ({ id: m.id, userId: m.userId, email: m.user.email, name: m.user.name, role: m.role })) },
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/api/organizations/{orgId}/members/{memberId}",
      tags: ["Members"],
      request: {
        params: OrgParam.extend({ memberId: pathParam("memberId") }),
        body: { content: { "application/json": { schema: z.object({ role: Role }) } } },
      },
      responses: { 200: json(z.object({ id: z.string(), role: z.string() })), ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, memberId } = c.req.valid("param");
      const { role } = c.req.valid("json");
      await mutate(
        c,
        orgId,
        { member: ["update"] },
        async (a, tx, headers) => {
          await requireMemberOf(tx, orgId, memberId);
          await a.api.updateMemberRole({ body: { memberId, role, organizationId: orgId }, headers });
        },
        { lockAdministrators: true },
      );
      return c.json({ id: memberId, role }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/api/organizations/{orgId}/members/{memberId}",
      tags: ["Members"],
      request: { params: OrgParam.extend({ memberId: pathParam("memberId") }) },
      responses: { ...noContent, ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, memberId } = c.req.valid("param");
      await mutate(
        c,
        orgId,
        { member: ["delete"] },
        async (a, tx, headers) => {
          await requireMemberOf(tx, orgId, memberId);
          await a.api.removeMember({ body: { memberIdOrEmail: memberId, organizationId: orgId }, headers });
        },
        { lockAdministrators: true },
      );
      return c.body(null, 204);
    },
  );

  // ---------- Teams ----------

  const TeamName = z.object({ name: z.string().trim().min(1).max(100) });
  const TeamParam = OrgParam.extend({ teamId: pathParam("teamId") });

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
      await read(c, orgId);
      // Better Auth lists a Team's members only to members of that Team, and without their emails, so the
      // administrator's overview of Teams and their members is one query of ours.
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

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/teams",
      tags: ["Teams"],
      request: { params: OrgParam, body: { content: { "application/json": { schema: TeamName } } } },
      responses: { 201: json(z.object({ id: z.string(), name: z.string() }), "Created"), ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const { name } = c.req.valid("json");
      const created = await mutate(c, orgId, { team: ["create"] }, (a, _tx, headers) =>
        a.api.createTeam({ body: { name, organizationId: orgId }, headers }),
      );
      return c.json({ id: created.id, name: created.name }, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/api/organizations/{orgId}/teams/{teamId}",
      tags: ["Teams"],
      request: { params: TeamParam, body: { content: { "application/json": { schema: TeamName } } } },
      responses: { 200: json(z.object({ id: z.string(), name: z.string() })), ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, teamId } = c.req.valid("param");
      const { name } = c.req.valid("json");
      await mutate(c, orgId, { team: ["update"] }, (a, _tx, headers) =>
        a.api.updateTeam({ body: { teamId, data: { name, organizationId: orgId } }, headers }),
      );
      return c.json({ id: teamId, name }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/api/organizations/{orgId}/teams/{teamId}",
      tags: ["Teams"],
      request: { params: TeamParam },
      responses: { ...noContent, ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, teamId } = c.req.valid("param");
      await mutate(c, orgId, { team: ["delete"] }, (a, _tx, headers) =>
        a.api.removeTeam({ body: { teamId, organizationId: orgId }, headers }),
      );
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/teams/{teamId}/members",
      tags: ["Teams"],
      request: { params: TeamParam, body: { content: { "application/json": { schema: z.object({ userId: z.string() }) } } } },
      responses: { ...noContent, ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, teamId } = c.req.valid("param");
      const { userId } = c.req.valid("json");
      // Better Auth's permission for changing who is in a Team is `member: update`.
      await mutate(c, orgId, { member: ["update"] }, async (a, tx, headers) => {
        // Adding someone already in the Team changes nothing, so it must not be audited as a change.
        const [existing] = await tx
          .select({ id: teamMember.id })
          .from(teamMember)
          .innerJoin(team, eq(team.id, teamMember.teamId))
          .where(and(eq(teamMember.teamId, teamId), eq(teamMember.userId, userId), eq(team.organizationId, orgId)));
        if (existing) return;
        await a.api.addTeamMember({ body: { teamId, userId, organizationId: orgId }, headers });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/api/organizations/{orgId}/teams/{teamId}/members/{userId}",
      tags: ["Teams"],
      request: { params: TeamParam.extend({ userId: pathParam("userId") }) },
      responses: { ...noContent, ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, teamId, userId } = c.req.valid("param");
      await mutate(c, orgId, { member: ["delete"] }, (a, _tx, headers) =>
        a.api.removeTeamMember({ body: { teamId, userId, organizationId: orgId }, headers }),
      );
      return c.body(null, 204);
    },
  );
}

/**
 * Better Auth refuses to demote or remove the last Organization Administrator, but checks by reading, so two
 * concurrent changes could both pass. Locking the administrators' rows makes each wait for the other.
 */
async function lockOrganizationAdministrators(tx: Tx, orgId: string) {
  await tx
    .select({ id: member.id })
    .from(member)
    .where(and(eq(member.organizationId, orgId), eq(member.role, ORG_ADMIN_ROLE)))
    .orderBy(asc(member.id))
    .for("update");
}

/**
 * Better Auth looks a member up by id alone and answers differently depending on which of its checks a member of
 * another Organization trips first, so confirm the member is in this Organization: otherwise it is just not found.
 */
async function requireMemberOf(tx: Tx, orgId: string, memberId: string) {
  const [row] = await tx
    .select({ id: member.id })
    .from(member)
    .where(and(eq(member.id, memberId), eq(member.organizationId, orgId)));
  if (!row) throw new HttpError(404, "member not found");
}
