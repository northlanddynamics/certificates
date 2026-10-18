// An Organization's Agents, for the people who run them: an Organization Administrator makes the single-use token by
// which an Agent registers, sees every Agent with its host, operating system, version, last contact and whether it is
// online, and revokes one. What an Agent itself calls is in agent-gateway.ts.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, eq, gte, inArray, isNotNull, isNull, lt, or, sql, type SQL } from "drizzle-orm";
import type { Context } from "hono";
import { AGENT_ARCHES, AGENT_OSES, isOutdated } from "./agent-kinds";
import { newRegistrationToken, hashToken, type AgentGatewayConfig } from "./agent-gateway";
import type { Authorizer } from "../tenancy/authorization";
import type { Db } from "../platform/db/client";
import { agent, agentRegistrationToken, deployment, issuance } from "../platform/db/schema";
import { HttpError, OrgParam, PageQuery, anyOf, errors, json, pageOf } from "../platform/http";
import type { Issuances } from "../issuance/issuance";
import type { Actor, UnitOfWork } from "../platform/unit-of-work";

type Row = typeof agent.$inferSelect;
const DAY_MS = 24 * 3600_000;
export const AGENT_STATUSES = ["online", "offline", "revoked"] as const;

/** The last contact before which an Agent that is not revoked is offline at `now`: it has been silent longer than `offlineAfterSeconds`. */
export const silentSince = (now: Date, offlineAfterSeconds: number) => new Date(now.getTime() - offlineAfterSeconds * 1000);

/** Whether the Agent is online at `now`: `revoked` once its credential was ended, `offline` once it has been silent too long. */
export const agentStatus = (row: { revokedAt: Date | null; lastContactAt: Date }, now: Date, offlineAfterSeconds: number): (typeof AGENT_STATUSES)[number] =>
  row.revokedAt ? "revoked" : row.lastContactAt < silentSince(now, offlineAfterSeconds) ? "offline" : "online";

/** The condition that an Agent is offline, as `agentStatus` says, for Agents silent since `since` (from `silentSince`). */
export const agentOffline = (since: Date) => and(isNull(agent.revokedAt), lt(agent.lastContactAt, since))!;

const AgentView = z.object({
  id: z.string(),
  hostName: z.string(),
  os: z.enum(AGENT_OSES),
  arch: z.enum(AGENT_ARCHES),
  version: z.string(),
  outdated: z.boolean().openapi({ description: "Whether it runs a version older than the newest the platform knows of." }),
  status: z.enum(AGENT_STATUSES).openapi({ description: "`offline` once it has been silent for longer than a missed poll or two; `revoked` once an Organization Administrator ended its credential." }),
  registeredAt: z.string(),
  lastContactAt: z.string(),
  revokedAt: z.string().nullable(),
});
const AgentsQuery = PageQuery.extend({
  status: anyOf(AGENT_STATUSES).optional().meta({ description: "Those that are any of these, comma-separated." }),
  os: anyOf(AGENT_OSES).optional().meta({ description: "Those running any of these operating systems, comma-separated." }),
  outdated: z.literal("true").optional().meta({ description: "Only those running an outdated version." }),
});
const AgentParams = OrgParam.extend({ agentId: z.string().openapi({ param: { name: "agentId", in: "path" } }) });

export function registerAgents(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: Context): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  clock: () => Date;
  config: AgentGatewayConfig;
  issuances: Issuances;
}) {
  const { app, db, requireUser, authorize, unitOfWork, clock, config, issuances } = ctx;

  const toView = (row: Row, now: Date) => ({
    id: row.id,
    hostName: row.hostName,
    os: row.os,
    arch: row.arch,
    version: row.version,
    outdated: isOutdated(row.version, config.latestVersion),
    status: agentStatus(row, now, config.offlineAfterSeconds),
    registeredAt: row.registeredAt.toISOString(),
    lastContactAt: row.lastContactAt.toISOString(),
    revokedAt: row.revokedAt?.toISOString() ?? null,
  });

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/agent-registration-tokens",
      tags: ["Agents"],
      summary: "Make a single-use token for an Agent to register into the Organization",
      description:
        "Organization Administrators only. The token is in this response and nowhere else. It registers one Agent, once, into this Organization, and expires if it is not used in time; " +
        "the Agent presents it to `POST /api/agent/registration`.",
      request: { params: OrgParam },
      responses: { 201: json(z.object({ token: z.string(), expiresAt: z.string() }), "Created"), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { agent: ["register"] });
      const token = newRegistrationToken();
      const made = await unitOfWork.run(actor, async (tx, change) => {
        const expiresAt = new Date(change.occurredAt.getTime() + config.registrationTokenDays * DAY_MS);
        const [row] = await tx
          .insert(agentRegistrationToken)
          .values({ organizationId: orgId, tokenHash: hashToken(token), createdById: actor.id, createdByEmail: actor.email, createdAt: change.occurredAt, expiresAt })
          .returning({ id: agentRegistrationToken.id });
        await change.audit({ organizationId: orgId, action: "agent_registration_token.created", target: { type: "agent_registration_token", id: row!.id }, detail: { expiresAt: expiresAt.toISOString() } });
        return { token, expiresAt: expiresAt.toISOString() };
      });
      return c.json(made, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/agents",
      tags: ["Agents"],
      summary: "The Organization's Agents, oldest first, a page at a time",
      description: "Organization Administrators only. Revoked Agents are listed too, as such. The filters combine; `total` is how many match them, whatever the page.",
      request: { params: OrgParam, query: AgentsQuery },
      responses: {
        200: json(pageOf(AgentView).extend({ latestVersion: z.string().openapi({ description: "The version an Agent is outdated against." }) })),
        ...errors(400, 401, 403, 404),
      },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { agent: ["read"] });
      const { page, pageSize, status, os, outdated } = c.req.valid("query");
      const now = clock();
      const since = silentSince(now, config.offlineAfterSeconds);
      const conditions: (SQL | undefined)[] = [eq(agent.organizationId, orgId)];
      if (status) {
        const wanted = status.split(",");
        // `status` is worked out as `toView` does: revoked first, then by how long it has been silent.
        conditions.push(
          or(
            wanted.includes("revoked") ? isNotNull(agent.revokedAt) : undefined,
            wanted.includes("offline") ? agentOffline(since) : undefined,
            wanted.includes("online") ? and(isNull(agent.revokedAt), gte(agent.lastContactAt, since)) : undefined,
          ),
        );
      }
      if (os) conditions.push(inArray(agent.os, os.split(",") as Row["os"][]));
      if (outdated) {
        // Whether a version is outdated is not for the database to say; the Organization has few distinct versions to ask about.
        const versions = await db.selectDistinct({ version: agent.version }).from(agent).where(eq(agent.organizationId, orgId));
        const old = versions.map((v) => v.version).filter((v) => isOutdated(v, config.latestVersion));
        conditions.push(old.length > 0 ? inArray(agent.version, old) : sql`false`);
      }
      const where = and(...conditions);
      const [total, rows] = await Promise.all([
        db.$count(agent, where),
        db.select().from(agent).where(where).orderBy(asc(agent.registeredAt), asc(agent.id)).limit(pageSize).offset((page - 1) * pageSize),
      ]);
      return c.json({ items: rows.map((row) => toView(row, now)), total, page, pageSize, latestVersion: config.latestVersion }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/agents/{agentId}/revoke",
      tags: ["Agents"],
      summary: "Revoke an Agent: its credential is accepted no more",
      description:
        "Organization Administrators only. For a decommissioned or compromised host. It cannot be undone: a new Agent registers with a new token. " +
        "A Renewal waiting for it to make a new key fails, as no key will come; the Managed Certificates whose key it holds cannot be renewed from then on.",
      request: { params: AgentParams },
      responses: { 200: json(AgentView, "Revoked"), ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, agentId } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { agent: ["revoke"] });
      const revoked = await unitOfWork.run(actor, async (tx, change) => {
        const [row] = await tx.select().from(agent).where(and(eq(agent.organizationId, orgId), eq(agent.id, agentId))).for("update");
        if (!row) throw new HttpError(404, "Agent not found");
        if (row.revokedAt) throw new HttpError(409, "the Agent is already revoked");
        const [updated] = await tx
          .update(agent)
          .set({ revokedAt: change.occurredAt, revokedById: actor.id, revokedByEmail: actor.email })
          .where(and(eq(agent.id, agentId), isNull(agent.revokedAt)))
          .returning();
        await change.audit({ organizationId: orgId, action: "agent.revoked", target: { type: "agent", id: agentId }, detail: { hostName: row.hostName } });
        const waiting = await tx
          .select({ id: issuance.id })
          .from(issuance)
          .innerJoin(deployment, eq(deployment.managedCertificateId, issuance.managedCertificateId))
          .where(and(eq(deployment.agentId, agentId), eq(issuance.status, "running"), eq(issuance.awaitingKey, true)));
        for (const { id } of waiting) await issuances.abandon(tx, change, id, { code: "agent_key_failed", message: `the Agent ${row.hostName} was revoked before it made the new key` });
        return updated!;
      });
      return c.json(toView(revoked, clock()), 200);
    },
  );
}
