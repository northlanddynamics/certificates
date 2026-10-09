// A Managed Certificate's history: how it got to its current state, oldest first. It is read from the audit log and
// from its Certificates, so it can only say what really happened, and a later kind of change (a name change, a
// Deployment Run) adds its Audit Event action to HISTORY_KINDS.
import { and, asc, eq, inArray } from "drizzle-orm";
import type { Db } from "./db/client";
import { auditEvent, certificate } from "./db/schema";

/** The Audit Event actions that are part of a Managed Certificate's history, and what each is called there. */
export const HISTORY_KINDS = {
  "managed_certificate.created": "created",
  "managed_certificate.proposed": "proposed",
  "managed_certificate.approved": "approved",
  "managed_certificate.rejected": "rejected",
} as const;
type HistoryKind = (typeof HISTORY_KINDS)[keyof typeof HISTORY_KINDS];

type HistoryEvent = {
  kind: HistoryKind;
  at: string;
  actor: { id: string; email: string } | null;
  /** What the Approver said, for a decision. */
  reason: string | null;
};
type HistoryCertificate = { kind: "certificate_issued"; at: string; certificate: typeof certificate.$inferSelect };

export async function historyOf(db: Db, organizationId: string, managedCertificateId: string): Promise<(HistoryEvent | HistoryCertificate)[]> {
  const events = await db
    .select()
    .from(auditEvent)
    .where(
      and(
        eq(auditEvent.organizationId, organizationId),
        eq(auditEvent.targetType, "managed_certificate"),
        eq(auditEvent.targetId, managedCertificateId),
        inArray(auditEvent.action, Object.keys(HISTORY_KINDS)),
      ),
    )
    .orderBy(asc(auditEvent.id));
  const certificates = await db
    .select()
    .from(certificate)
    .where(and(eq(certificate.organizationId, organizationId), eq(certificate.managedCertificateId, managedCertificateId)))
    .orderBy(asc(certificate.createdAt), asc(certificate.id));
  const entries = [
    ...events.map(
      (e): HistoryEvent => ({
        kind: HISTORY_KINDS[e.action as keyof typeof HISTORY_KINDS],
        at: e.occurredAt.toISOString(),
        actor: e.actorId && e.actorEmail ? { id: e.actorId, email: e.actorEmail } : null,
        reason: typeof e.detail.reason === "string" ? e.detail.reason : null,
      }),
    ),
    ...certificates.map((c): HistoryCertificate => ({ kind: "certificate_issued", at: c.issuedAt.toISOString(), certificate: c })),
  ];
  // Stable, so of two things at the same moment an Audit Event stays before the Certificate it led to.
  return entries.sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
}
