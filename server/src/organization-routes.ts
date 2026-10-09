// Members, roles, invitations and Teams: the Organization Administrator's controls over who is in the
// Organization. Every route authorizes through `authorize` and writes its audit entry in the same
// transaction as the change.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, eq, gt, inArray, sql } from "drizzle-orm";
import { APPROVER_ROLE, MEMBER_ROLE, ORG_ADMIN_ROLE } from "./auth";
import { recordAudit } from "./audit";
import type { Authorizer } from "./authorization";
import type { Db, Tx } from "./db/client";
import { invitation, member, session, team, teamMember, user } from "./db/schema";
import { HttpError, OrgParam, errors, isUniqueViolation, json, pathParam } from "./http";
import { INVITATION_TTL_MS } from "./invitations";
import { memberRemovalHooks } from "./member-removal";
import type { AppDeps } from "./app";

type Actor = { id: string; email: string };

interface Context {
  app: OpenAPIHono;
  db: Db;
  deps: AppDeps;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
}

const Role = z.enum([MEMBER_ROLE, APPROVER_ROLE, ORG_ADMIN_ROLE]);
const noContent = { 204: { description: "Done" } } as const;

export function registerOrganizationRoutes({ app, db, deps, requireUser, authorize }: Context) {
  const { clock, mailer } = deps;

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
      const { role } = c.req.valid("json");
      const email = c.req.valid("json").email.toLowerCase();
      const actor = await requireUser(c);
      await authorize(actor, orgId, "member.invite");
      const now = clock();
      const id = crypto.randomUUID();
      const orgName = await db.transaction(async (tx) => {
        const [existing] = await tx
          .select({ id: member.id })
          .from(member)
          .innerJoin(user, eq(user.id, member.userId))
          .where(and(eq(member.organizationId, orgId), sql`lower(${user.email}) = ${email}`));
        if (existing) throw new HttpError(409, "already a member of this organization");
        // Serialise invitations to one Organization so two concurrent requests cannot both pass the check below.
        const [org] = await tx.execute<{ name: string }>(sql`select name from organization where id = ${orgId} for update`).then((r) => r.rows);
        const [pending] = await tx
          .select({ id: invitation.id })
          .from(invitation)
          .where(pendingFor(orgId, now, sql`lower(${invitation.email}) = ${email}`));
        if (pending) throw new HttpError(409, "an invitation for this email is already pending");
        await tx.insert(invitation).values({
          id,
          organizationId: orgId,
          email,
          role,
          status: "pending",
          expiresAt: new Date(now.getTime() + INVITATION_TTL_MS),
          createdAt: now,
          inviterId: actor.id,
        });
        await recordAudit(tx, {
          organizationId: orgId,
          occurredAt: now,
          actor,
          action: "invitation.created",
          target: { type: "invitation", id },
          detail: { email, role },
        });
        return org!.name;
      });
      await mailer
        .send({
          to: email,
          subject: `You are invited to join ${orgName}`,
          text: `Accept your invitation: ${deps.webURL ?? deps.baseURL}/accept-invitation/${id}`,
        })
        .catch((err) => console.error("invitation email failed", err));
      return c.json({ id }, 201);
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
      await authorize(await requireUser(c), orgId, "invitation.read");
      const rows = await db
        .select()
        .from(invitation)
        .where(pendingFor(orgId, clock()))
        .orderBy(asc(invitation.createdAt), asc(invitation.id));
      return c.json(
        {
          items: rows.map((r) => ({ id: r.id, email: r.email, role: r.role ?? MEMBER_ROLE, expiresAt: r.expiresAt.toISOString() })),
        },
        200,
      );
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
      const actor = await requireUser(c);
      await authorize(actor, orgId, "invitation.cancel");
      const now = clock();
      await db.transaction(async (tx) => {
        const [inv] = await tx
          .update(invitation)
          .set({ status: "cancelled" })
          .where(and(eq(invitation.id, invitationId), pendingFor(orgId, now)))
          .returning();
        if (!inv) throw new HttpError(404, "invitation not found");
        await recordAudit(tx, {
          organizationId: orgId,
          occurredAt: now,
          actor,
          action: "invitation.cancelled",
          target: { type: "invitation", id: invitationId },
          detail: { email: inv.email, role: inv.role },
        });
      });
      return c.body(null, 204);
    },
  );

  // ---------- members ----------

  const MemberBody = z.object({ id: z.string(), userId: z.string(), email: z.string(), name: z.string(), role: z.string() });

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/members",
      tags: ["Members"],
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(MemberBody) })), ...errors(401, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, "member.read");
      const items = await db
        .select({ id: member.id, userId: member.userId, email: user.email, name: user.name, role: member.role })
        .from(member)
        .innerJoin(user, eq(user.id, member.userId))
        .where(eq(member.organizationId, orgId))
        .orderBy(asc(member.createdAt), asc(member.id));
      return c.json({ items }, 200);
    },
  );

  /** Locks the Organization's administrators so concurrent demotions and removals cannot leave it with none. */
  async function lockAdministrators(tx: Tx, orgId: string) {
    const rows = await tx
      .select({ id: member.id })
      .from(member)
      .where(and(eq(member.organizationId, orgId), eq(member.role, ORG_ADMIN_ROLE)))
      .for("update");
    return rows.map((r) => r.id);
  }

  async function findMember(tx: Tx, orgId: string, memberId: string) {
    const [row] = await tx
      .select({ id: member.id, userId: member.userId, role: member.role, email: user.email })
      .from(member)
      .innerJoin(user, eq(user.id, member.userId))
      .where(and(eq(member.id, memberId), eq(member.organizationId, orgId)));
    if (!row) throw new HttpError(404, "member not found");
    return row;
  }

  app.openapi(
    createRoute({
      method: "patch",
      path: "/api/organizations/{orgId}/members/{memberId}",
      tags: ["Members"],
      request: {
        params: OrgParam.extend({ memberId: pathParam("memberId") }),
        body: { content: { "application/json": { schema: z.object({ role: Role }) } } },
      },
      responses: { 200: json(MemberBody.pick({ id: true, role: true })), ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, memberId } = c.req.valid("param");
      const { role } = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, "member.changeRole");
      const now = clock();
      await db.transaction(async (tx) => {
        const admins = await lockAdministrators(tx, orgId);
        const target = await findMember(tx, orgId, memberId);
        if (target.role === role) return;
        if (target.role === ORG_ADMIN_ROLE && admins.length <= 1) {
          throw new HttpError(409, "an Organization needs at least one Organization Administrator");
        }
        await tx.update(member).set({ role }).where(eq(member.id, memberId));
        await recordAudit(tx, {
          organizationId: orgId,
          occurredAt: now,
          actor,
          action: "member.role_changed",
          target: { type: "member", id: memberId },
          detail: { userId: target.userId, email: target.email, from: target.role, to: role },
        });
      });
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
      const actor = await requireUser(c);
      await authorize(actor, orgId, "member.remove");
      const now = clock();
      await db.transaction(async (tx) => {
        const admins = await lockAdministrators(tx, orgId);
        const target = await findMember(tx, orgId, memberId);
        if (target.role === ORG_ADMIN_ROLE && admins.length <= 1) {
          throw new HttpError(409, "an Organization needs at least one Organization Administrator");
        }
        await tx.delete(member).where(eq(member.id, memberId));
        const orgTeams = tx.select({ id: team.id }).from(team).where(eq(team.organizationId, orgId));
        const left = await tx
          .delete(teamMember)
          .where(and(eq(teamMember.userId, target.userId), inArray(teamMember.teamId, orgTeams)))
          .returning({ teamId: teamMember.teamId });
        const leftTeamIds = left.map((r) => r.teamId);
        await refreshMemberCounts(tx, leftTeamIds);
        // Sessions that had this Organization (or one of its Teams) active no longer do.
        await tx
          .update(session)
          .set({ activeOrganizationId: null, activeTeamId: null })
          .where(and(eq(session.userId, target.userId), eq(session.activeOrganizationId, orgId)));
        for (const hook of memberRemovalHooks) await hook(tx, { organizationId: orgId, userId: target.userId });
        await recordAudit(tx, {
          organizationId: orgId,
          occurredAt: now,
          actor,
          action: "member.removed",
          target: { type: "member", id: memberId },
          detail: { userId: target.userId, email: target.email, role: target.role, teamIds: leftTeamIds },
        });
      });
      return c.body(null, 204);
    },
  );

  // ---------- Teams ----------

  const TeamBody = z.object({
    id: z.string(),
    name: z.string(),
    members: z.array(z.object({ userId: z.string(), email: z.string() })),
  });
  const TeamParam = OrgParam.extend({ teamId: pathParam("teamId") });
  const TeamName = z.object({ name: z.string().trim().min(1).max(100) });

  /** Locks the Team row, so it cannot be deleted while a change to its membership is in flight. */
  async function findTeam(tx: Tx, orgId: string, teamId: string) {
    const [row] = await tx
      .select()
      .from(team)
      .where(and(eq(team.id, teamId), eq(team.organizationId, orgId)))
      .for("update");
    if (!row) throw new HttpError(404, "team not found");
    return row;
  }

  async function refreshMemberCounts(tx: Tx, teamIds: string[]) {
    if (teamIds.length === 0) return;
    await tx
      .update(team)
      .set({ memberCount: sql`(select count(*)::int from ${teamMember} where ${teamMember.teamId} = ${team.id})` })
      .where(inArray(team.id, teamIds));
  }

  const duplicateName = (err: unknown) => {
    if (isUniqueViolation(err)) throw new HttpError(409, "a Team with this name already exists");
    throw err;
  };

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/teams",
      tags: ["Teams"],
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(TeamBody) })), ...errors(401, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, "team.read");
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
      const actor = await requireUser(c);
      await authorize(actor, orgId, "team.create");
      const now = clock();
      const id = crypto.randomUUID();
      await db
        .transaction(async (tx) => {
          await tx.insert(team).values({ id, name, organizationId: orgId, createdAt: now, updatedAt: now });
          await recordAudit(tx, {
            organizationId: orgId,
            occurredAt: now,
            actor,
            action: "team.created",
            target: { type: "team", id },
            detail: { name },
          });
        })
        .catch(duplicateName);
      return c.json({ id, name }, 201);
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
      const actor = await requireUser(c);
      await authorize(actor, orgId, "team.update");
      const now = clock();
      await db
        .transaction(async (tx) => {
          const existing = await findTeam(tx, orgId, teamId);
          if (existing.name === name) return;
          await tx.update(team).set({ name, updatedAt: now }).where(eq(team.id, teamId));
          await recordAudit(tx, {
            organizationId: orgId,
            occurredAt: now,
            actor,
            action: "team.renamed",
            target: { type: "team", id: teamId },
            detail: { from: existing.name, to: name },
          });
        })
        .catch(duplicateName);
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
      const actor = await requireUser(c);
      await authorize(actor, orgId, "team.delete");
      const now = clock();
      await db.transaction(async (tx) => {
        const existing = await findTeam(tx, orgId, teamId);
        await tx.delete(team).where(eq(team.id, teamId)); // its memberships cascade
        await recordAudit(tx, {
          organizationId: orgId,
          occurredAt: now,
          actor,
          action: "team.deleted",
          target: { type: "team", id: teamId },
          detail: { name: existing.name },
        });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/teams/{teamId}/members",
      tags: ["Teams"],
      request: { params: TeamParam, body: { content: { "application/json": { schema: z.object({ userId: z.string() }) } } } },
      responses: { ...noContent, ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, teamId } = c.req.valid("param");
      const { userId } = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, "team.manageMembers");
      const now = clock();
      await db
        .transaction(async (tx) => {
          const existing = await findTeam(tx, orgId, teamId);
          const [target] = await tx
            .select({ email: user.email })
            .from(member)
            .innerJoin(user, eq(user.id, member.userId))
            .where(and(eq(member.organizationId, orgId), eq(member.userId, userId)))
            .for("update", { of: member }); // so a concurrent removal from the Organization cannot be missed
          if (!target) throw new HttpError(404, "user is not a member of this organization");
          await tx.insert(teamMember).values({
            id: crypto.randomUUID(),
            teamId,
            userId,
            membershipKey: `${teamId}:${userId}`,
            createdAt: now,
          });
          await refreshMemberCounts(tx, [teamId]);
          await recordAudit(tx, {
            organizationId: orgId,
            occurredAt: now,
            actor,
            action: "team.member_added",
            target: { type: "team", id: teamId },
            detail: { name: existing.name, userId, email: target.email },
          });
        })
        .catch((err) => {
          if (isUniqueViolation(err)) throw new HttpError(409, "already in this Team");
          throw err;
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
      const actor = await requireUser(c);
      await authorize(actor, orgId, "team.manageMembers");
      const now = clock();
      await db.transaction(async (tx) => {
        const existing = await findTeam(tx, orgId, teamId);
        const [removed] = await tx
          .delete(teamMember)
          .where(and(eq(teamMember.teamId, teamId), eq(teamMember.userId, userId)))
          .returning({ id: teamMember.id });
        if (!removed) throw new HttpError(404, "user is not in this Team");
        await refreshMemberCounts(tx, [teamId]);
        const [target] = await tx.select({ email: user.email }).from(user).where(eq(user.id, userId));
        await recordAudit(tx, {
          organizationId: orgId,
          occurredAt: now,
          actor,
          action: "team.member_removed",
          target: { type: "team", id: teamId },
          detail: { name: existing.name, userId, email: target?.email ?? null },
        });
      });
      return c.body(null, 204);
    },
  );
}

/** Invitations to this Organization that can still be accepted. */
const pendingFor = (orgId: string, now: Date, ...extra: ReturnType<typeof sql>[]) =>
  and(eq(invitation.organizationId, orgId), eq(invitation.status, "pending"), gt(invitation.expiresAt, now), ...extra);
