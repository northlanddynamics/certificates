// The platform's side of the Agent protocol, which an Agent speaks only outbound, over HTTPS:
//  - Agent Registration: an Agent with a single-use token sends a CSR for a key it generated, and is given an identity
//    certificate from the Agent identity CA (agent-identity-ca.ts). The only call that needs no certificate.
//  - everything after authenticates with that certificate (mTLS): polling, which is also the heartbeat and carries the
//    version and brings the Agent its work items, and rotating the identity before it expires.
// The TLS terminator in front of the platform requires and verifies the client certificate against the identity CA
// (`GET /api/agent/identity-ca`) and passes the verified one on in a header (ADR 0005); the platform checks it again and
// whether it is the one the Agent is meant to be using.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { and, eq, gt, isNull } from "drizzle-orm";
import type { Context } from "hono";
import { AGENT_ARCHES, AGENT_OSES, LATEST_AGENT_VERSION } from "./agent-kinds";
import { AgentCsrError, type AgentIdentityCa } from "./agent-identity-ca";
import type { Db } from "./db/client";
import { agent, agentRegistrationToken } from "./db/schema";
import { HttpError, errors, json } from "./http";
import type { UnitOfWork } from "./unit-of-work";
import type { WorkItems } from "./work-items";

export interface AgentGatewayConfig {
  /** The newest Agent version the platform knows of; older ones are flagged. */
  latestVersion: string;
  /** How long an identity certificate lasts. An Agent replaces it well before: it rotates once a third of its life is left. */
  identityValidityDays: number;
  /** How long a Registration token may wait to be used. */
  registrationTokenDays: number;
  /** How often an Agent is told to poll, and how long it may be silent before it counts as offline. */
  pollAfterSeconds: number;
  offlineAfterSeconds: number;
  /**
   * How long a poll with nothing to bring waits for something to come, so that work reaches an Agent within moments of
   * being asked for rather than a poll later. Zero answers at once. An Agent polls again straight after a long poll.
   */
  longPollSeconds: number;
  /** The request header in which the TLS terminator passes the client certificate it verified: PEM, URL-encoded (nginx's `$ssl_client_escaped_cert`). */
  clientCertificateHeader: string;
  /**
   * When set, every call that carries an identity must also send it in `x-agent-gateway-secret`: the TLS terminator adds it, so a
   * client certificate in the header is trusted only from the terminator, even if the platform's port can be reached some other way.
   */
  terminatorSecret?: string;
}

export const DEFAULT_AGENT_GATEWAY: AgentGatewayConfig = {
  latestVersion: LATEST_AGENT_VERSION,
  identityValidityDays: 30,
  registrationTokenDays: 7,
  pollAfterSeconds: 30,
  offlineAfterSeconds: 120,
  longPollSeconds: 0,
  clientCertificateHeader: "x-client-cert",
};

/** How often a long poll looks for work. */
const LONG_POLL_CHECK_MS = 250;
export const TERMINATOR_SECRET_HEADER = "x-agent-gateway-secret";
export const REGISTRATION_TOKEN_PREFIX = "agt_";
export const hashToken = (token: string) => createHash("sha256").update(token).digest("hex");
export const newRegistrationToken = () => REGISTRATION_TOKEN_PREFIX + randomBytes(32).toString("base64url");

const SECURITY = [{ agentIdentity: [] }];
const IDENTITY_NOT_ACCEPTED = "the Agent's identity is not accepted";
const Certificate = z.object({
  certificate: z.string().openapi({ description: "The Agent's identity certificate, PEM." }),
  notAfter: z.string().openapi({ description: "When it ends. The Agent rotates it once a third of its life is left." }),
});
const WorkItem = z.object({
  id: z.string(),
  type: z.string().openapi({
    description:
      "What the Agent is asked to do; an Agent ignores a type it does not know. `dns.present`, `dns.cleanup` and `dns.test` are DNS Provider operations the Agent relays: " +
      "the payload has `provider` (`type`, its `settings` and its `secret`, the credentials, which the Agent uses for this operation only) and, but for `dns.test`, the TXT `record` (`name`, `value`). " +
      "The Agent reports how it went to `POST /api/agent/work-items/{id}/result`.",
  }),
  payload: z.record(z.string(), z.unknown()),
});
const WorkItemParams = z.object({ id: z.string().openapi({ param: { name: "id", in: "path" } }) });
const WorkResult = z.object({
  ok: z.boolean(),
  kind: z.enum(["rejected", "unreachable"]).optional().openapi({ description: "When a DNS Provider operation failed: `rejected` if the DNS service answered and said no, `unreachable` if it did not answer." }),
  error: z.string().max(1000).optional().openapi({ description: "What went wrong, for a person to read. It must not contain the credentials." }),
});

export function registerAgentGateway(ctx: { app: OpenAPIHono; db: Db; unitOfWork: UnitOfWork; identityCa: AgentIdentityCa; workItems: WorkItems; clock: () => Date; config: AgentGatewayConfig }) {
  const { app, db, unitOfWork, identityCa, workItems, clock, config } = ctx;

  app.openAPIRegistry.registerComponent("securitySchemes", "agentIdentity", {
    type: "mutualTLS",
    description: "The Agent's identity certificate, from Agent Registration or its latest rotation.",
  } as never);

  /** An identity certificate for the CSR, or the 400 that says what is wrong with it. */
  async function issueIdentity(csr: string, agentId: string, now: Date) {
    try {
      return await identityCa.issue({ csr, agentId, now, validityDays: config.identityValidityDays });
    } catch (err) {
      if (err instanceof AgentCsrError) throw new HttpError(400, err.message);
      throw err;
    }
  }

  /** The Agent whose identity certificate the request carries, or a 401: no certificate, one that is not the identity CA's or is not valid now, one that is no longer the Agent's, or an Agent that is revoked. */
  async function authenticate(c: Context) {
    const refused = new HttpError(401, IDENTITY_NOT_ACCEPTED);
    if (config.terminatorSecret !== undefined) {
      const sent = Buffer.from(c.req.header(TERMINATOR_SECRET_HEADER) ?? "");
      const expected = Buffer.from(config.terminatorSecret);
      if (sent.length !== expected.length || !timingSafeEqual(sent, expected)) throw refused;
    }
    const header = c.req.header(config.clientCertificateHeader);
    if (!header) throw new HttpError(401, "an Agent identity certificate is required");
    let pem: string;
    try {
      pem = decodeURIComponent(header);
    } catch {
      throw refused;
    }
    const now = clock();
    const identity = await identityCa.verify(pem, now);
    if (!identity) throw refused;
    const [row] = await db.select().from(agent).where(eq(agent.id, identity.agentId));
    if (!row || row.revokedAt) throw refused;
    if (identity.serial !== row.identitySerial && identity.serial !== row.previousIdentitySerial) throw refused;
    return { row, serial: identity.serial, now };
  }

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/agent/identity-ca",
      tags: ["Agent protocol"],
      summary: "The Agent identity CA's certificate",
      description: "What a TLS terminator in front of the platform verifies Agents' client certificates against. Public.",
      responses: { 200: json(z.object({ certificate: z.string().openapi({ description: "PEM." }) })) },
    }),
    async (c) => c.json({ certificate: await identityCa.certificate() }, 200),
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/agent/registration",
      tags: ["Agent protocol"],
      summary: "Agent Registration: bind a newly installed Agent to an Organization with a single-use token",
      description:
        "The token is the one an Organization Administrator made for the Organization; it is used up by this call, and used or expired ones are refused. " +
        "The Agent generates an ECDSA P-256 key, keeps it, and sends only a CSR for it (ADR 0002); the response is its identity certificate, which it presents from then on.",
      request: {
        body: {
          content: {
            "application/json": {
              schema: z.object({
                token: z.string().min(1).max(200),
                csr: z.string().min(1).openapi({ description: "PEM, for the Agent's new identity key." }),
                hostName: z.string().trim().min(1).max(255),
                os: z.enum(AGENT_OSES),
                arch: z.enum(AGENT_ARCHES),
                version: z.string().trim().min(1).max(64),
              }),
            },
          },
        },
      },
      responses: { 201: json(Certificate.extend({ agentId: z.string(), pollAfterSeconds: z.number().int() }), "Registered"), ...errors(400, 401) },
    }),
    async (c) => {
      const body = c.req.valid("json");
      const registered = await unitOfWork.run(null, async (tx, change) => {
        // Used up first, atomically: of two registrations with one token, the second waits for the first and finds it used.
        const [token] = await tx
          .update(agentRegistrationToken)
          .set({ usedAt: change.occurredAt })
          .where(and(eq(agentRegistrationToken.tokenHash, hashToken(body.token)), isNull(agentRegistrationToken.usedAt), gt(agentRegistrationToken.expiresAt, change.occurredAt)))
          .returning();
        if (!token) throw new HttpError(401, "the registration token is not valid: it is unknown, used or expired");
        const agentId = crypto.randomUUID();
        // A CSR that is refused rolls the transaction back, so the token is not spent on a request that could not be served.
        const issued = await issueIdentity(body.csr, agentId, change.occurredAt);
        await tx.insert(agent).values({
          id: agentId,
          organizationId: token.organizationId,
          hostName: body.hostName,
          os: body.os,
          arch: body.arch,
          version: body.version,
          identitySerial: issued.serial,
          registeredAt: change.occurredAt,
          lastContactAt: change.occurredAt,
        });
        await tx.update(agentRegistrationToken).set({ agentId }).where(eq(agentRegistrationToken.id, token.id));
        await change.audit({
          organizationId: token.organizationId,
          action: "agent.registered",
          target: { type: "agent", id: agentId },
          detail: { hostName: body.hostName, os: body.os, arch: body.arch, version: body.version, registrationTokenId: token.id },
        });
        return { agentId, certificate: issued.certificate, notAfter: issued.notAfter.toISOString(), pollAfterSeconds: config.pollAfterSeconds };
      });
      return c.json(registered, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/agent/poll",
      tags: ["Agent protocol"],
      summary: "Heartbeat: report the version and receive work items",
      description: "An Agent calls this every `pollAfterSeconds`. Each call is its contact with the platform: it is how its last contact, its version and so its online status are known.",
      security: SECURITY,
      request: { body: { content: { "application/json": { schema: z.object({ version: z.string().trim().min(1).max(64) }) } } } },
      responses: { 200: json(z.object({ items: z.array(WorkItem), pollAfterSeconds: z.number().int() })), ...errors(400, 401) },
    }),
    async (c) => {
      const { version } = c.req.valid("json");
      const { row, serial, now } = await authenticate(c);
      // A heartbeat records no Audit Event, but it is a change like any other and goes through the unit of work.
      await unitOfWork.run(null, (tx) =>
        tx
          .update(agent)
          .set({ version, lastContactAt: now, ...(serial === row.identitySerial && row.previousIdentitySerial ? { previousIdentitySerial: null } : {}) })
          .where(eq(agent.id, row.id)),
      );
      // Each item is given once. When there is none the call may wait for one: it ends with the first, or after `longPollSeconds`.
      const deadline = Date.now() + config.longPollSeconds * 1000;
      let items = await workItems.deliver(row);
      while (items.length === 0 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, Math.min(LONG_POLL_CHECK_MS, Math.max(deadline - Date.now(), 1))));
        items = await workItems.deliver(row);
      }
      // After a long poll the Agent asks again at once; the next one is its next heartbeat.
      return c.json({ items, pollAfterSeconds: config.longPollSeconds > 0 ? 1 : config.pollAfterSeconds }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/agent/work-items/{id}/result",
      tags: ["Agent protocol"],
      summary: "Report how a work item went",
      description:
        "Once, by the Agent the item was given to. An item whose requester stopped waiting for the Agent (it was too slow, so another was asked) is refused with a 409, as is one already reported on.",
      security: SECURITY,
      request: { params: WorkItemParams, body: { content: { "application/json": { schema: WorkResult } } } },
      responses: { 200: json(z.object({ received: z.boolean() })), ...errors(400, 401, 404, 409) },
    }),
    async (c) => {
      const { id } = c.req.valid("param");
      const result = c.req.valid("json");
      const { row } = await authenticate(c);
      await workItems.report(row, id, result);
      return c.json({ received: true }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/agent/identity",
      tags: ["Agent protocol"],
      summary: "Rotate the Agent's identity certificate",
      description:
        "The Agent sends a CSR for a new key it generated and receives a new certificate, which replaces the one it presented. " +
        "That one stays accepted until the new one is first used, so an Agent that never received the response can try again.",
      security: SECURITY,
      request: { body: { content: { "application/json": { schema: z.object({ csr: z.string().min(1) }) } } } },
      responses: { 200: json(Certificate), ...errors(400, 401) },
    }),
    async (c) => {
      const { csr } = c.req.valid("json");
      const { row, serial } = await authenticate(c);
      const rotated = await unitOfWork.run(null, async (tx, change) => {
        // Under the Agent's row, so a revocation or another rotation in flight has finished.
        const [current] = await tx.select().from(agent).where(eq(agent.id, row.id)).for("update");
        // The certificate presented must still be one of the Agent's now, not one that another rotation has just replaced.
        if (!current || current.revokedAt || (serial !== current.identitySerial && serial !== current.previousIdentitySerial)) throw new HttpError(401, IDENTITY_NOT_ACCEPTED);
        const issued = await issueIdentity(csr, row.id, change.occurredAt);
        await tx.update(agent).set({ identitySerial: issued.serial, previousIdentitySerial: current.identitySerial, lastContactAt: change.occurredAt }).where(eq(agent.id, row.id));
        await change.audit({
          organizationId: row.organizationId,
          action: "agent.identity_rotated",
          target: { type: "agent", id: row.id },
          detail: { hostName: row.hostName, notAfter: issued.notAfter.toISOString() },
        });
        return { certificate: issued.certificate, notAfter: issued.notAfter.toISOString() };
      });
      return c.json(rotated, 200);
    },
  );
}
