import type { Pool, PoolClient } from "pg";

type Queryable = Pool | PoolClient;

export interface AuditInput {
  organizationId: string;
  occurredAt: Date;
  actor: { id: string; email: string };
  action: string;
  target: { type: string; id?: string };
  detail?: Record<string, unknown>;
}

/** Call with the transaction's client so the entry commits or rolls back with the change it records. */
export async function recordAudit(db: Queryable, e: AuditInput) {
  await db.query(
    `insert into audit_event (organization_id, occurred_at, actor_id, actor_email, action, target_type, target_id, detail)
     values ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [e.organizationId, e.occurredAt, e.actor.id, e.actor.email, e.action, e.target.type, e.target.id ?? null, e.detail ?? {}],
  );
}

export async function listAudit(db: Queryable, organizationId: string) {
  const { rows } = await db.query(
    `select id, occurred_at, actor_id, actor_email, action, target_type, target_id, detail
       from audit_event where organization_id = $1 order by id`,
    [organizationId],
  );
  return rows.map((r) => ({
    id: String(r.id),
    occurredAt: (r.occurred_at as Date).toISOString(),
    actor: { id: r.actor_id as string | null, email: r.actor_email as string | null },
    action: r.action as string,
    target: { type: r.target_type as string, id: r.target_id as string | null },
    detail: r.detail as Record<string, unknown>,
  }));
}
