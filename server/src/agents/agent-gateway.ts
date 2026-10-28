// The platform's side of the Agent protocol, which an Agent speaks only outbound, over HTTPS:
//  - Agent Registration: an Agent with a single-use token is given a credential for itself. The only call that needs no credential.
//  - everything after authenticates with that credential, as a bearer token (ADR 0006): polling, which is also the
//    heartbeat and carries the version and brings the Agent its work items, and rotating the credential before it ends.
// Only the credential's SHA-256 is kept, so the platform cannot be made to reveal one.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { randomBytes } from "node:crypto";
import { and, eq, gt, isNull, or } from "drizzle-orm";
import type { Context } from "hono";
import { AGENT_ARCHES, AGENT_OSES, LATEST_AGENT_VERSION } from "./agent-kinds";
import type { Db } from "../platform/db/client";
import { agent, agentRegistrationToken } from "../platform/db/schema";
import { MAX_CSR_LENGTH } from "../pki/csr";
import { OUTPUT_LIMIT_BYTES } from "../deployment/deployments";
import { HttpError, errors, json } from "../platform/http";
import type { UnitOfWork } from "../platform/unit-of-work";
import type { WorkItems } from "./work-items";
import { sha256Hex } from "../platform/crypto/sha256";
import { DiscoveryResult, SubmissionResult } from "../adcs/adcs-work";

export interface AgentGatewayConfig {
  /** The newest Agent version the platform knows of; older ones are flagged. */
  latestVersion: string;
  /** How long a credential lasts. An Agent replaces it well before: it rotates once a third of its life is left. */
  credentialValidityDays: number;
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
}

export const DEFAULT_AGENT_GATEWAY: AgentGatewayConfig = {
  latestVersion: LATEST_AGENT_VERSION,
  credentialValidityDays: 30,
  registrationTokenDays: 7,
  pollAfterSeconds: 30,
  offlineAfterSeconds: 120,
  longPollSeconds: 0,
};

/** How often a long poll looks for work. */
const LONG_POLL_CHECK_MS = 250;
export const REGISTRATION_TOKEN_PREFIX = "agt_";
export const AGENT_CREDENTIAL_PREFIX = "agk_";
export const hashToken = (token: string) => sha256Hex(token);
export const newRegistrationToken = () => REGISTRATION_TOKEN_PREFIX + randomBytes(32).toString("base64url");
const newCredential = () => AGENT_CREDENTIAL_PREFIX + randomBytes(32).toString("base64url");

const SECURITY = [{ agentCredential: [] }];
const CREDENTIAL_NOT_ACCEPTED = "the Agent's credential is not accepted";
const Credential = z.object({
  credential: z.string().openapi({ description: "The Agent's credential, sent as `Authorization: Bearer <credential>`. It is shown only in this response: the platform keeps only its hash." }),
  expiresAt: z.string().openapi({ description: "When it ends. The Agent rotates it once a third of its life is left." }),
});
const WorkItem = z.object({
  id: z.string(),
  type: z.string().openapi({
    description:
      "What the Agent is asked to do; an Agent ignores a type it does not know. `dns.present`, `dns.cleanup` and `dns.test` are DNS Provider operations the Agent relays: " +
      "the payload has `provider` (`type`, its `settings` and its `secret`, the credentials, which the Agent uses for this operation only) and, but for `dns.test`, the TXT `record` (`name`, `value`). " +
      "`deployment.generate_key` asks the Agent to make a private key for a Managed Certificate in a store only its service account can read, and to report a CSR for it (never the key): the payload has `deploymentId`, `managedCertificateId`, `names` and `keyAlgorithm`: `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-3072`, `rsa-4096`, or `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` (pure ML-DSA with an empty context, as RFC 9881 has it in X.509). An Agent that does not make the algorithm fails the item with a reason. " +
      "`deployment.run` gives the Agent a Certificate and a Deployment Script to run for it: the payload has `deploymentId`, `managedCertificateId`, `trigger`, `names`, the `certificate` (`id`, `fingerprint`, `notAfter`, `chainPem`: the leaf then the intermediates), the `script` (`name`, `interpreter`, `version`, `hash`, `content`) " +
      "and `parameters`, the Deployment's parameter values by name (an object of strings, empty when it has none), which the Agent gives the script as environment variables named `DEPLOY_PARAM_` and the name. " +
      "The Agent runs the script only if the SHA-256 of its content is the hash, and reports how it went. " +
      "`adcs.discover` asks the Agent to reach an ADCS CA with MS-WCCE, as its own account, and to report the CA's certificate chain and its Certificate Templates with their facts, as `discovery`: the payload has `configString`, the CA's `host\\CA Name`. " +
      "`adcs.submit` asks the Agent to submit a CSR to an ADCS CA with MS-WCCE, as its own account, under a Certificate Template, and to report what ADCS answered as `submission`: the payload has `configString`, `template` (the template's ADCS name) and `csr` (PEM). " +
      "ADCS may issue it (`issued`), hold it for a CA manager's approval (`pending`) or deny it (`denied`). " +
      "`adcs.check` asks the Agent to ask an ADCS CA again where a request it held pending stands, and to report it as `submission`, in the same shape: the payload has `configString` and `requestId`, ADCS's ID of the request. " +
      "An Agent that cannot reach ADCS (one not on Windows) fails an ADCS item as `rejected`, saying so; one whose CA does not answer fails it as `unreachable`, and the platform asks another; ADCS refusing the request is `rejected`, with its reason. " +
      "The Agent reports how it went to `POST /api/agent/work-items/{id}/result`.",
  }),
  payload: z.record(z.string(), z.unknown()),
});
const WorkItemParams = z.object({ id: z.string().openapi({ param: { name: "id", in: "path" } }) });
const WorkResult = z.object({
  ok: z.boolean(),
  kind: z
    .enum(["rejected", "unreachable"])
    .optional()
    .openapi({ description: "When a DNS Provider or ADCS operation failed: `rejected` if the DNS service or ADCS answered and said no, `unreachable` if it did not answer." }),
  error: z.string().max(1000).optional().openapi({ description: "What went wrong, for a person to read. It must not contain the credentials." }),
  csr: z.string().max(MAX_CSR_LENGTH).optional().openapi({ description: "For `deployment.generate_key`: a PEM CSR for the key the Agent made, for the names and key algorithm it was given. The key is never sent." }),
  run: z
    .object({
      startedAt: z.string(),
      finishedAt: z.string(),
      exitCode: z.number().int().nullable().openapi({ description: "The script's exit code; none when it was not started, which it is not when its content does not match its hash." }),
      output: z.string().max(OUTPUT_LIMIT_BYTES * 2).openapi({ description: `What the script wrote to its standard output and error, cut to ${OUTPUT_LIMIT_BYTES / 1024} KiB; when it was not started, why.` }),
      outputTruncated: z.boolean(),
    })
    .optional()
    .openapi({ description: "For `deployment.run`: how the script went. `ok` is whether it succeeded (exit code 0)." }),
  discovery: DiscoveryResult.optional(),
  submission: SubmissionResult.optional(),
});

export function registerAgentGateway(ctx: { app: OpenAPIHono; db: Db; unitOfWork: UnitOfWork; workItems: WorkItems; clock: () => Date; config: AgentGatewayConfig }) {
  const { app, db, unitOfWork, workItems, clock, config } = ctx;

  app.openAPIRegistry.registerComponent("securitySchemes", "agentCredential", {
    type: "http",
    scheme: "bearer",
    description: "The Agent's credential, from Agent Registration or its latest rotation.",
  });

  /** A new credential and when it ends, for a change that happened at `now`. */
  function issueCredential(now: Date) {
    const credential = newCredential();
    return { credential, hash: hashToken(credential), expiresAt: new Date(now.getTime() + config.credentialValidityDays * 24 * 3600_000) };
  }

  /**
   * The Agent whose credential the request carries, or a 401: no credential, one that is not an Agent's, one that has
   * ended (the one an Agent replaced is accepted until its replacement is first used, but not past its own end), or an
   * Agent that is revoked. `hash` is the one presented, which says whether it was the current one.
   */
  async function authenticate(c: Context) {
    const refused = new HttpError(401, CREDENTIAL_NOT_ACCEPTED);
    const presented = /^Bearer\s+(\S+)$/i.exec(c.req.header("authorization") ?? "")?.[1];
    if (!presented) throw new HttpError(401, "an Agent credential is required");
    const hash = hashToken(presented);
    const now = clock();
    const [row] = await db.select().from(agent).where(or(eq(agent.credentialHash, hash), eq(agent.previousCredentialHash, hash)));
    if (!row || row.revokedAt) throw refused;
    const endsAt = hash === row.credentialHash ? row.credentialExpiresAt : row.previousCredentialExpiresAt;
    if (!endsAt || endsAt <= now) throw refused;
    return { row, hash, now };
  }

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/agent/registration",
      tags: ["Agent protocol"],
      summary: "Agent Registration: bind a newly installed Agent to an Organization with a single-use token",
      description:
        "The token is the one an Organization Administrator made for the Organization; it is used up by this call, and used or expired ones are refused. " +
        "The response holds the Agent's credential, which it keeps and presents from then on (ADR 0006); the platform keeps only its hash, so it is not shown again.",
      request: {
        body: {
          content: {
            "application/json": {
              schema: z.object({
                token: z.string().min(1).max(200),
                hostName: z.string().trim().min(1).max(255),
                os: z.enum(AGENT_OSES),
                arch: z.enum(AGENT_ARCHES),
                version: z.string().trim().min(1).max(64),
              }),
            },
          },
        },
      },
      responses: { 201: json(Credential.extend({ agentId: z.string(), pollAfterSeconds: z.number().int() }), "Registered"), ...errors(400, 401) },
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
        const issued = issueCredential(change.occurredAt);
        await tx.insert(agent).values({
          id: agentId,
          organizationId: token.organizationId,
          hostName: body.hostName,
          os: body.os,
          arch: body.arch,
          version: body.version,
          credentialHash: issued.hash,
          credentialExpiresAt: issued.expiresAt,
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
        return { agentId, credential: issued.credential, expiresAt: issued.expiresAt.toISOString(), pollAfterSeconds: config.pollAfterSeconds };
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
      const { row, hash, now } = await authenticate(c);
      // A heartbeat records no Audit Event, but it is a change like any other and goes through the unit of work.
      await unitOfWork.run(null, (tx) =>
        tx
          .update(agent)
          .set({ version, lastContactAt: now, ...(hash === row.credentialHash && row.previousCredentialHash ? { previousCredentialHash: null, previousCredentialExpiresAt: null } : {}) })
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
      path: "/api/agent/credential",
      tags: ["Agent protocol"],
      summary: "Rotate the Agent's credential",
      description:
        "The Agent receives a new credential, which replaces the one it presented. " +
        "That one stays accepted until the new one is first used, so an Agent that never received the response can try again.",
      security: SECURITY,
      responses: { 200: json(Credential), ...errors(401) },
    }),
    async (c) => {
      const { row, hash } = await authenticate(c);
      const rotated = await unitOfWork.run(null, async (tx, change) => {
        // Under the Agent's row, so a revocation or another rotation in flight has finished.
        const [current] = await tx.select().from(agent).where(eq(agent.id, row.id)).for("update");
        // The credential presented must still be one of the Agent's now, not one that another rotation has just replaced.
        if (!current || current.revokedAt || (hash !== current.credentialHash && hash !== current.previousCredentialHash)) throw new HttpError(401, CREDENTIAL_NOT_ACCEPTED);
        const issued = issueCredential(change.occurredAt);
        await tx
          .update(agent)
          .set({
            credentialHash: issued.hash,
            credentialExpiresAt: issued.expiresAt,
            previousCredentialHash: current.credentialHash,
            previousCredentialExpiresAt: current.credentialExpiresAt,
            lastContactAt: change.occurredAt,
          })
          .where(eq(agent.id, row.id));
        await change.audit({
          organizationId: row.organizationId,
          action: "agent.credential_rotated",
          target: { type: "agent", id: row.id },
          detail: { hostName: row.hostName, expiresAt: issued.expiresAt.toISOString() },
        });
        return { credential: issued.credential, expiresAt: issued.expiresAt.toISOString() };
      });
      return c.json(rotated, 200);
    },
  );
}
