// An Organization's Agents, for the people who run them: an Organization Administrator makes the single-use token by
// which an Agent registers, sees every Agent with its host, operating system, version, last contact and whether it is
// online, and revokes one. What an Agent itself calls is in agent-gateway.ts.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, eq, isNull } from "drizzle-orm";
import type { Context } from "hono";
import { AGENT_ARCHES, AGENT_OSES, isOutdated } from "./agent-kinds";
import { newRegistrationToken, hashToken, type AgentGatewayConfig } from "./agent-gateway";
import type { Authorizer } from "./authorization";
import type { Db } from "./db/client";
import { agent, agentRegistrationToken } from "./db/schema";
import { HttpError, OrgParam, errors, json } from "./http";
import type { Actor, UnitOfWork } from "./unit-of-work";

type Row = typeof agent.$inferSelect;
const STATUSES = ["online", "offline", "revoked"] as const;

const AgentView = z.object({
  id: z.string(),
  hostName: z.string(),
  os: z.enum(AGENT_OSES),
  arch: z.enum(AGENT_ARCHES),
  version: z.string(),
  outdated: z.boolean().openapi({ description: "Whether it runs a version older than the newest the platform knows of." }),
  status: z.enum(STATUSES).openapi({ description: "`offline` once it has been silent for longer than a missed poll or two; `revoked` once an Organization Administrator ended its identity." }),
  registeredAt: z.string(),
  lastContactAt: z.string(),
  revokedAt: z.string().nullable(),
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
}) {
  const { app, db, requireUser, authorize, unitOfWork, clock, config } = ctx;

  const toView = (row: Row, now: Date) => ({
    id: row.id,
    hostName: row.hostName,
    os: row.os,
    arch: row.arch,
    version: row.version,
    outdated: isOutdated(row.version, config.latestVersion),
    status: row.revokedAt ? ("revoked" as const) : now.getTime() - row.lastContactAt.getTime() > config.offlineAfterSeconds * 1000 ? ("offline" as const) : ("online" as const),
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
        const expiresAt = new Date(change.occurredAt.getTime() + config.registrationTokenDays * 24 * 3600_000);
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
      summary: "The Organization's Agents",
      description: "Organization Administrators only. Revoked Agents are listed too, as such.",
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(AgentView), latestVersion: z.string().openapi({ description: "The version an Agent is outdated against." }) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { agent: ["read"] });
      const now = clock();
      const rows = await db.select().from(agent).where(eq(agent.organizationId, orgId)).orderBy(asc(agent.registeredAt), asc(agent.id));
      return c.json({ items: rows.map((row) => toView(row, now)), latestVersion: config.latestVersion }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/agents/{agentId}/revoke",
      tags: ["Agents"],
      summary: "Revoke an Agent: its identity is accepted no more",
      description: "Organization Administrators only. For a decommissioned or compromised host. It cannot be undone: a new Agent registers with a new token.",
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
        return updated!;
      });
      return c.json(toView(revoked, clock()), 200);
    },
  );
}
