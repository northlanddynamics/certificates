import { asc, eq } from "drizzle-orm";
import type { Db, Tx } from "./db/client";
import { auditEvent } from "./db/schema";

/** Every action an Audit Event can record. A new kind of change adds its name here. */
export type AuditAction =
  | "organization.created"
  | "invitation.created"
  | "invitation.accepted"
  | "invitation.rejected"
  | "invitation.canceled"
  | "member.role_changed"
  | "member.removed"
  | "team.created"
  | "team.renamed"
  | "team.deleted"
  | "team.member_added"
  | "team.member_removed"
  | "acme_account.created"
  | "acme_account.key_replaced"
  | "dns_provider.created"
  | "dns_provider.changed"
  | "dns_provider.secret_replaced"
  | "dns_provider.tested"
  | "managed_certificate.created"
  | "managed_certificate.proposed"
  | "managed_certificate.approved"
  | "managed_certificate.rejected"
  | "managed_certificate.owner_added"
  | "managed_certificate.owner_removed"
  | "issuance.started"
  | "issuance.succeeded"
  | "issuance.failed";

export interface AuditInput {
  organizationId: string;
  occurredAt: Date;
  actor: { id: string; email: string };
  action: AuditAction;
  target: { type: string; id?: string };
  detail?: Record<string, unknown>;
}

/** Call with the transaction handle so the entry commits or rolls back with the change it records. */
export async function recordAudit(db: Db | Tx, e: AuditInput) {
  await db.insert(auditEvent).values({
    organizationId: e.organizationId,
    occurredAt: e.occurredAt,
    actorId: e.actor.id,
    actorEmail: e.actor.email,
    action: e.action,
    targetType: e.target.type,
    targetId: e.target.id ?? null,
    detail: e.detail ?? {},
  });
}

export async function listAudit(db: Db, organizationId: string) {
  const rows = await db
    .select()
    .from(auditEvent)
    .where(eq(auditEvent.organizationId, organizationId))
    .orderBy(asc(auditEvent.id));
  return rows.map((r) => ({
    id: String(r.id),
    occurredAt: r.occurredAt.toISOString(),
    actor: { id: r.actorId, email: r.actorEmail },
    action: r.action,
    target: { type: r.targetType, id: r.targetId },
    detail: r.detail,
  }));
}
