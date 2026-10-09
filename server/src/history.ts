// A Managed Certificate's history: how it got to its current state, oldest first. It is read from the audit log and
// from its Certificates, so it can only say what really happened, and a later kind of change (a Deployment Run)
// adds its Audit Event action to HISTORY_KINDS.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, eq, inArray } from "drizzle-orm";
import type { Db } from "./db/client";
import { auditEvent, certificate } from "./db/schema";
import { errors, json } from "./http";
import { Certificate, ManagedCertificateParams, Person, toCertificate, type ManagedCertificateReader } from "./managed-certificate-reader";
import type { Actor } from "./unit-of-work";

/** The Audit Event actions that are part of a Managed Certificate's history, and what each is called there. */
export const HISTORY_KINDS = {
  "managed_certificate.created": "created",
  "managed_certificate.proposed": "proposed",
  "managed_certificate.approved": "approved",
  "managed_certificate.rejected": "rejected",
  "name_change.proposed": "names_change_proposed",
  "name_change.approved": "names_change_approved",
  "name_change.rejected": "names_change_rejected",
  "name_change.withdrawn": "names_change_withdrawn",
  "name_change.discarded": "names_change_discarded",
  "managed_certificate.names_changed": "names_changed",
} as const;
type HistoryKind = (typeof HISTORY_KINDS)[keyof typeof HISTORY_KINDS];

type HistoryEvent = {
  kind: HistoryKind;
  at: string;
  actor: { id: string; email: string } | null;
  /** What the Approver said, for a decision. */
  reason: string | null;
  /** The names before and after, for a name change. */
  names: { from: string[]; to: string[] } | null;
};
type HistoryCertificate = { kind: "certificate_issued"; at: string; certificate: typeof certificate.$inferSelect };

const isNames = (value: unknown): value is string[] => Array.isArray(value) && value.every((name) => typeof name === "string");

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
        names: isNames(e.detail.from) && isNames(e.detail.to) ? { from: e.detail.from, to: e.detail.to } : null,
      }),
    ),
    ...certificates.map((c): HistoryCertificate => ({ kind: "certificate_issued", at: c.issuedAt.toISOString(), certificate: c })),
  ];
  // Stable, so of two things at the same moment an Audit Event stays before the Certificate it led to.
  return entries.sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
}

const HistoryEntry = z.discriminatedUnion("kind", [
  z.object({
    kind: z.enum(Object.values(HISTORY_KINDS) as [string, ...string[]]),
    at: z.string(),
    actor: Person.nullable(),
    reason: z.string().nullable().openapi({ description: "What the Approver said, for a decision." }),
    names: z.object({ from: z.array(z.string()), to: z.array(z.string()) }).nullable().openapi({ description: "The names before and after, for a name change." }),
  }),
  z.object({ kind: z.literal("certificate_issued"), at: z.string(), certificate: Certificate }),
]);

export function registerHistory(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  reader: ManagedCertificateReader;
}) {
  const { app, db, requireUser, reader } = ctx;
  const { findReadable } = reader;

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/history",
      tags: ["Managed Certificates"],
      summary: "How the Managed Certificate got to its current state, oldest first",
      description: "Its creation or proposal, its Approvals, its name changes and the Certificates issued for it.",
      request: { params: ManagedCertificateParams },
      responses: { 200: json(z.object({ items: z.array(HistoryEntry) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const mc = await findReadable(await requireUser(c), orgId, id);
      const entries = await historyOf(db, orgId, mc.id);
      return c.json({ items: entries.map((e) => (e.kind === "certificate_issued" ? { ...e, certificate: toCertificate(e.certificate) } : e)) }, 200);
    },
  );
}
