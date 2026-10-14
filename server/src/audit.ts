import { and, asc, desc, eq, gt, gte, like, lt, or, sql, type SQL } from "drizzle-orm";
import type { Db, Tx } from "./db/client";
import { auditDelivery, auditEvent, auditForwarder } from "./db/schema";

/** Every action an Audit Event can record, each documented in docs/audit-events.md. A new kind of change adds its name here. */
export const AUDIT_ACTIONS = [
  "organization.created",
  "invitation.created",
  "invitation.accepted",
  "invitation.rejected",
  "invitation.canceled",
  "member.role_changed",
  "member.removed",
  "team.created",
  "team.renamed",
  "team.deleted",
  "team.member_added",
  "team.member_removed",
  "acme_account.created",
  "acme_account.key_replaced",
  "dns_provider.created",
  "dns_provider.changed",
  "dns_provider.secret_replaced",
  "dns_provider.tested",
  "dns_provider.relay_changed",
  "validation_zone.created",
  "validation_zone.deleted",
  "dcv_rule.created",
  "dcv_rule.changed",
  "dcv_rule.deleted",
  "managed_certificate.created",
  "managed_certificate.proposed",
  "managed_certificate.approved",
  "managed_certificate.rejected",
  "managed_certificate.owner_added",
  "managed_certificate.owner_removed",
  "managed_certificate.subscriber_added",
  "managed_certificate.subscriber_removed",
  "managed_certificate.renewal_policy_changed",
  "managed_certificate.csr_uploaded",
  "managed_certificate.names_changed",
  "managed_certificate.archived",
  "certificate.revoked",
  "name_change.proposed",
  "name_change.approved",
  "name_change.rejected",
  "name_change.withdrawn",
  "name_change.discarded",
  "api_key.created",
  "api_key.revoked",
  "api_key.used",
  "agent_registration_token.created",
  "agent.registered",
  "agent.credential_rotated",
  "agent.revoked",
  "deployment_script.uploaded",
  "deployment.created",
  "deployment.key_generated",
  "deployment.key_failed",
  "deployment.key_requested",
  "deployment.run_requested",
  "deployment_run.succeeded",
  "deployment_run.failed",
  "notification_channel.created",
  "notification_channel.deleted",
  "audit_forwarder.created",
  "audit_forwarder.deleted",
  "issuance.started",
  "issuance.succeeded",
  "issuance.failed",
] as const;
export type AuditAction = (typeof AUDIT_ACTIONS)[number];

export interface AuditInput {
  organizationId: string;
  occurredAt: Date;
  /** Whoever made the change; none when an Organization's API key or the platform itself (the Renewal scheduler) did. */
  actor: { id: string; email: string } | null;
  action: AuditAction;
  target: { type: string; id?: string };
  detail?: Record<string, unknown>;
}

/**
 * Call with the transaction handle so the entry commits or rolls back with the change it records. It is queued for every
 * forwarder the Organization has (audit-forwarding.ts) on the same transaction, so that none misses it.
 */
export async function recordAudit(db: Db | Tx, e: AuditInput) {
  const [recorded] = await db.insert(auditEvent).values({
    organizationId: e.organizationId,
    occurredAt: e.occurredAt,
    actorId: e.actor?.id ?? null,
    actorEmail: e.actor?.email ?? null,
    action: e.action,
    targetType: e.target.type,
    targetId: e.target.id ?? null,
    detail: e.detail ?? {},
  }).returning({ id: auditEvent.id });
  await db
    .insert(auditDelivery)
    .select(
      db
        .select({ forwarderId: auditForwarder.id, organizationId: auditForwarder.organizationId, auditEventId: sql<number>`${recorded!.id}::bigint`.as("audit_event_id") })
        .from(auditForwarder)
        .where(eq(auditForwarder.organizationId, e.organizationId)),
    );
}

/** How an Audit Event is searched: every filter given must match. */
export interface AuditQuery {
  /** Who made the change: a user's id, or their email in any case. */
  actor?: string;
  /** An action (`team.created`), or every action under a prefix (`team.*`). */
  action?: string;
  targetType?: string;
  targetId?: string;
  /** From this time, inclusive. */
  from?: Date;
  /** Until this time, exclusive. */
  to?: Date;
  /** Oldest first (the default) or newest first. */
  order?: "asc" | "desc";
  /** Where the page before ended: its `nextCursor`. */
  cursor?: string;
  limit: number;
}

/** One Audit Event as the API shows it, which is also the body of `certificate-platform.audit/1` (audit-forwarding.ts). */
export type AuditItem = ReturnType<typeof toItem>;

export const toItem = (r: typeof auditEvent.$inferSelect) => ({
  id: String(r.id),
  occurredAt: r.occurredAt.toISOString(),
  actor: { id: r.actorId, email: r.actorEmail },
  action: r.action,
  target: { type: r.targetType, id: r.targetId },
  detail: r.detail,
});

/** The Organization's Audit Events that match `q`, a page at a time; `nextCursor` is none on the last page. */
export async function searchAudit(db: Db, organizationId: string, q: AuditQuery) {
  const newestFirst = q.order === "desc";
  const where: (SQL | undefined)[] = [eq(auditEvent.organizationId, organizationId)];
  if (q.actor) where.push(or(eq(auditEvent.actorId, q.actor), sql`lower(${auditEvent.actorEmail}) = lower(${q.actor})`));
  if (q.action) where.push(q.action.endsWith(".*") ? like(auditEvent.action, `${q.action.slice(0, -1).replace(/[\\%_]/g, "\\$&")}%`) : eq(auditEvent.action, q.action));
  if (q.targetType) where.push(eq(auditEvent.targetType, q.targetType));
  if (q.targetId) where.push(eq(auditEvent.targetId, q.targetId));
  if (q.from) where.push(gte(auditEvent.occurredAt, q.from));
  if (q.to) where.push(lt(auditEvent.occurredAt, q.to));
  if (q.cursor) where.push(newestFirst ? lt(auditEvent.id, Number(q.cursor)) : gt(auditEvent.id, Number(q.cursor)));
  const rows = await db
    .select()
    .from(auditEvent)
    .where(and(...where))
    .orderBy(newestFirst ? desc(auditEvent.id) : asc(auditEvent.id))
    .limit(q.limit + 1);
  const page = rows.slice(0, q.limit);
  return { items: page.map(toItem), nextCursor: rows.length > q.limit ? String(page.at(-1)!.id) : null };
}

/** Every one of the Organization's Audit Events, oldest first. */
export async function listAudit(db: Db, organizationId: string) {
  const rows = await db.select().from(auditEvent).where(eq(auditEvent.organizationId, organizationId)).orderBy(asc(auditEvent.id));
  return rows.map(toItem);
}
