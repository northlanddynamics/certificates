// Audit forwarding: an Organization's Audit Events sent to its SIEM (such as CrowdStrike NG-SIEM) by webhook or syslog, in
// the stable JSON schema `certificate-platform.audit/1` (docs/audit-events.md).
//
// Each Audit Event is queued for every forwarder the Organization has, in the transaction that records it (audit.ts), so
// that no event is missed however transactions interleave. A delivery pass (a job queue in Postgres) sends each forwarder
// its queue in the order of the events' ids, and drops what it delivered. Ids are taken as events are recorded, not as they
// commit, so of two changes committing at about the same time the later id may be sent first. A forwarder that cannot be reached is tried
// again with growing waits and never given up: every event reaches it at least once, and some may reach it twice.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, count, eq, exists, inArray, lte, notExists, notInArray, sql } from "drizzle-orm";
import { isIP } from "node:net";
import { toItem, type AuditItem } from "./audit";
import { AUDIT_FORWARDER_KINDS } from "./audit-forwarder-kinds";
import type { AuditDestination, AuditTransport } from "./audit-transport";
import type { Authorizer } from "../tenancy/authorization";
import type { Db } from "../platform/db/client";
import { auditDelivery, auditEvent, auditForwarder, secret } from "../platform/db/schema";
import { HttpError, OrgParam, errors, isUniqueViolation, json } from "../platform/http";
import { isInternalHost } from "../notifications/notification-channels";
import type { Secrets } from "../platform/crypto/secrets";
import type { Actor, UnitOfWork } from "../platform/unit-of-work";

/** The version of the JSON a forwarded Audit Event is; a change that is not only an addition makes a new one. */
export const AUDIT_SCHEMA = "certificate-platform.audit/1";

/** An Audit Event as it is forwarded: what the API shows, with the schema and the Organization it belongs to. */
export const forwarded = (organizationId: string, item: AuditItem) => ({ schema: AUDIT_SCHEMA, ...item, organization: { id: organizationId } });

/** A forwarder that could not be reached is tried again after these waits, the last of them for as long as it takes. */
const RETRY_DELAYS_MS = [60_000, 5 * 60_000, 30 * 60_000, 60 * 60_000];
/** How long a forwarder being sent to is left alone by other passes; a pass that stopped meanwhile has it tried again after this. */
const LEASE_MS = 30 * 60_000;
/** How many events are taken from a forwarder's queue at a time. */
const BATCH = 100;

export interface AuditForwarding {
  /** One pass at the clock's time: sends every forwarder that is due what it has queued. Returns how many events were delivered. */
  tick(): Promise<number>;
}

export function createAuditForwarding({ db, unitOfWork, secrets, transport, clock }: { db: Db; unitOfWork: UnitOfWork; secrets: Secrets; transport: AuditTransport; clock: () => Date }): AuditForwarding {
  const hasQueue = exists(db.select({ one: sql`1` }).from(auditDelivery).where(eq(auditDelivery.forwarderId, auditForwarder.id)));
  /** The forwarder's lease, from now: no other pass sends to it until this ends, unless it is renewed or let go first. */
  const lease = (id: string) => db.update(auditForwarder).set({ nextAttemptAt: new Date(clock().getTime() + LEASE_MS) }).where(eq(auditForwarder.id, id));

  /** Takes the next forwarder that is due, has something queued and was not seen yet in this pass, and leases it. */
  function claimNext(now: Date, seen: string[]) {
    return unitOfWork.run(null, async (tx) => {
      const [row] = await tx
        .select()
        .from(auditForwarder)
        .where(and(lte(auditForwarder.nextAttemptAt, now), hasQueue, seen.length > 0 ? notInArray(auditForwarder.id, seen) : undefined))
        .orderBy(asc(auditForwarder.nextAttemptAt), asc(auditForwarder.id))
        .limit(1)
        .for("update", { skipLocked: true });
      if (!row) return null;
      await tx.update(auditForwarder).set({ nextAttemptAt: new Date(clock().getTime() + LEASE_MS) }).where(eq(auditForwarder.id, row.id));
      return row;
    });
  }

  async function destinationOf(row: typeof auditForwarder.$inferSelect): Promise<AuditDestination> {
    if (row.kind === "syslog") return { kind: "syslog", host: row.host, port: row.port! };
    const { url, authorization } = JSON.parse(await secrets.open(db, row.organizationId, row.secretId!)) as { url: string; authorization?: string };
    return { kind: "webhook", url, ...(authorization && { authorization }) };
  }

  /**
   * Sends the forwarder its queue, a batch at a time, renewing its lease before each, until the queue is empty or a send
   * fails; returns how many it delivered.
   */
  async function drain(row: typeof auditForwarder.$inferSelect) {
    let total = 0;
    let error: string | undefined;
    try {
      const destination = await destinationOf(row);
      for (;;) {
        const batch = await db
          .select({ event: auditEvent })
          .from(auditDelivery)
          .innerJoin(auditEvent, eq(auditEvent.id, auditDelivery.auditEventId))
          .where(eq(auditDelivery.forwarderId, row.id))
          .orderBy(asc(auditDelivery.auditEventId))
          .limit(BATCH);
        if (batch.length === 0) break;
        await lease(row.id);
        const outcome = await transport.deliver(destination, batch.map(({ event: e }) => forwarded(row.organizationId, toItem(e))));
        const done = batch.slice(0, outcome.delivered).map(({ event: e }) => e.id);
        if (done.length > 0) await db.delete(auditDelivery).where(and(eq(auditDelivery.forwarderId, row.id), inArray(auditDelivery.auditEventId, done)));
        total += done.length;
        if (outcome.error !== undefined) {
          error = outcome.error;
          break;
        }
      }
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    }
    // A receiver that took some of the queue before failing is reachable: its wait starts again from the shortest.
    const failures = error === undefined ? 0 : total > 0 ? 1 : row.failures + 1;
    const wait = error === undefined ? 0 : RETRY_DELAYS_MS[Math.min(failures, RETRY_DELAYS_MS.length) - 1]!;
    const now = clock();
    await db
      .update(auditForwarder)
      .set({
        failures,
        nextAttemptAt: new Date(now.getTime() + wait),
        lastError: error === undefined ? null : error.replace(/\u0000/g, "").slice(0, 1000),
        ...(total > 0 && { lastDeliveredAt: now }),
      })
      .where(eq(auditForwarder.id, row.id));
    return total;
  }

  return {
    async tick() {
      const now = clock();
      // What a removed forwarder had queued, or was queued for it while it was being removed, goes nowhere.
      await db.delete(auditDelivery).where(notExists(db.select({ one: sql`1` }).from(auditForwarder).where(eq(auditForwarder.id, auditDelivery.forwarderId))));
      let delivered = 0;
      const seen: string[] = [];
      for (let row = await claimNext(now, seen); row; row = await claimNext(now, seen)) {
        seen.push(row.id);
        delivered += await drain(row);
      }
      return delivered;
    },
  };
}

const Forwarder = z
  .object({
    id: z.string(),
    name: z.string(),
    kind: z.enum(AUDIT_FORWARDER_KINDS),
    host: z.string().openapi({ description: "Where it sends: a webhook's host (its URL is a Secret and never shown), or the syslog receiver." }),
    port: z.number().int().nullable().openapi({ description: "The syslog receiver's port; none for a webhook." }),
    createdAt: z.string(),
    backlog: z.number().int().openapi({ description: "How many Audit Events are waiting to be delivered to it." }),
    lastDeliveredAt: z.string().nullable(),
    lastError: z.string().nullable().openapi({ description: "Why the last try failed; none once it delivers again." }),
    nextAttemptAt: z.string().nullable().openapi({ description: "When it is tried again after failing; none while it is not failing." }),
  });

/** A host name or IP literal that is not the platform's own or internal. */
const syslogHost = z
  .string()
  .trim()
  .min(1)
  .max(253)
  .refine((h) => isIP(h) !== 0 || /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(h), "a host name or IP address")
  .refine((h) => !isInternalHost(h), "a forwarder cannot send to the platform's own host or an internal address");

const webhookUrl = z
  .url({ protocol: /^https$/ })
  .max(2048)
  .refine((url) => !URL.canParse(url) || !isInternalHost(new URL(url).hostname), "a forwarder cannot send to the platform's own host or an internal address");

const NewForwarder = z.discriminatedUnion("kind", [
  z.object({
    name: z.string().trim().min(1).max(100),
    kind: z.literal("webhook"),
    url: webhookUrl.openapi({ description: "Where each event is posted as JSON, over HTTPS. Write-only: only its host is shown again." }),
    authorization: z
      .string()
      .min(1)
      .max(4096)
      .regex(/^[^\r\n]*$/, "one line")
      .optional()
      .openapi({ description: "The Authorization header each post carries, such as `Bearer <token>` for an HTTP event collector. Write-only." }),
  }),
  z.object({
    name: z.string().trim().min(1).max(100),
    kind: z.literal("syslog"),
    host: syslogHost.openapi({ description: "The syslog receiver, which must speak TLS (RFC 5425) with a certificate valid for this name." }),
    port: z.number().int().min(1).max(65535).default(6514),
  }),
]);

const ForwarderParams = OrgParam.extend({ forwarderId: z.string().openapi({ param: { name: "forwarderId", in: "path" } }) });

export function registerAuditForwarders(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  secrets: Secrets;
}) {
  const { app, db, requireUser, authorize, unitOfWork, secrets } = ctx;

  async function list(orgId: string) {
    const rows = await db
      .select({ forwarder: auditForwarder, backlog: count(auditDelivery.auditEventId) })
      .from(auditForwarder)
      .leftJoin(auditDelivery, eq(auditDelivery.forwarderId, auditForwarder.id))
      .where(eq(auditForwarder.organizationId, orgId))
      .groupBy(auditForwarder.id)
      .orderBy(sql`lower(${auditForwarder.name})`);
    return rows.map(({ forwarder: f, backlog }) => ({
      id: f.id,
      name: f.name,
      kind: f.kind,
      host: f.host,
      port: f.port,
      createdAt: f.createdAt.toISOString(),
      backlog,
      lastDeliveredAt: f.lastDeliveredAt?.toISOString() ?? null,
      lastError: f.lastError,
      nextAttemptAt: f.failures > 0 ? f.nextAttemptAt.toISOString() : null,
    }));
  }

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/audit-forwarders",
      tags: ["Audit"],
      summary: "Where the Organization's Audit Events are forwarded, and how delivery is going",
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(Forwarder) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { auditForwarder: ["read"] });
      return c.json({ items: await list(orgId) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/audit-forwarders",
      tags: ["Audit"],
      summary: "Forward Audit Events to a SIEM by webhook or syslog",
      description:
        "Only Organization Administrators may. Every Audit Event recorded from now on, this change's own included, is delivered at least once, in the schema `certificate-platform.audit/1`. Names are unique in the Organization, whatever their case.",
      request: { params: OrgParam, body: { content: { "application/json": { schema: NewForwarder } } } },
      responses: { 201: json(Forwarder, "Created"), ...errors(400, 401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { auditForwarder: ["create"] });
      try {
        const id = await unitOfWork.run(actor, async (tx, change) => {
          const target =
            body.kind === "webhook"
              ? { secretId: await secrets.create(tx, orgId, JSON.stringify({ url: body.url, authorization: body.authorization })), host: new URL(body.url).host, port: null }
              : { secretId: null, host: body.host.toLowerCase(), port: body.port };
          const [created] = await tx
            .insert(auditForwarder)
            .values({ organizationId: orgId, name: body.name, kind: body.kind, ...target, createdAt: change.occurredAt, nextAttemptAt: change.occurredAt })
            .returning();
          await change.audit({
            organizationId: orgId,
            action: "audit_forwarder.created",
            target: { type: "audit_forwarder", id: created!.id },
            detail: { name: created!.name, kind: created!.kind, host: created!.host, ...(created!.port !== null && { port: created!.port }) },
          });
          return created!.id;
        });
        return c.json((await list(orgId)).find((f) => f.id === id)!, 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw new HttpError(409, `the Organization already has a forwarder named ${body.name}`);
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/api/organizations/{orgId}/audit-forwarders/{forwarderId}",
      tags: ["Audit"],
      summary: "Stop forwarding to a SIEM",
      description: "Only Organization Administrators may. Audit Events not yet delivered to it are not sent; the audit log itself is kept.",
      request: { params: ForwarderParams },
      responses: { 200: json(z.object({ deleted: z.literal(true) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, forwarderId } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { auditForwarder: ["delete"] });
      if (!z.uuid().safeParse(forwarderId).success) throw new HttpError(404, "audit forwarder not found");
      await unitOfWork.run(actor, async (tx, change) => {
        const [row] = await tx
          .select()
          .from(auditForwarder)
          .where(and(eq(auditForwarder.organizationId, orgId), eq(auditForwarder.id, forwarderId)))
          .for("update");
        if (!row) throw new HttpError(404, "audit forwarder not found");
        await tx.delete(auditForwarder).where(eq(auditForwarder.id, row.id));
        await tx.delete(auditDelivery).where(eq(auditDelivery.forwarderId, row.id));
        // The webhook's URL and credential go with it: nothing else could ever use them.
        if (row.secretId) await tx.delete(secret).where(and(eq(secret.organizationId, orgId), eq(secret.id, row.secretId)));
        await change.audit({ organizationId: orgId, action: "audit_forwarder.deleted", target: { type: "audit_forwarder", id: row.id }, detail: { name: row.name, kind: row.kind, host: row.host } });
      });
      return c.json({ deleted: true as const }, 200);
    },
  );
}
