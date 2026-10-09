import { asc, eq } from "drizzle-orm";
import type { Db, Tx } from "./db/client";
import { auditEvent } from "./db/schema";

export interface AuditInput {
  organizationId: string;
  occurredAt: Date;
  actor: { id: string; email: string };
  action: string;
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
