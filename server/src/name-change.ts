// Name changes: replacing the names a Managed Certificate is issued for, together with the CSR for the new names.
// Approval is needed when someone other than an Organization Administrator makes one (approval.ts), and until it is
// given Renewal carries on with the last approved names and CSR, which are the Managed Certificate's own. A change that
// is approved, or made by an Organization Administrator, replaces them and an Issuance of the new names begins. The
// routes are in name-change-routes.ts; the decisions on them are made in the Approval queue (approvals.ts).
import { z } from "@hono/zod-openapi";
import { and, asc, eq, inArray, isNull } from "drizzle-orm";
import type { ApprovalStatus } from "./approval";
import type { KeyCustody } from "./csr";
import type { Tx, Db } from "./db/client";
import { managedCertificate, nameChange } from "./db/schema";
import { HttpError } from "./http";
import type { Issuances } from "./issuance";
import type { MemberRemovalHook } from "./member-removal";
import type { Actor, Change } from "./unit-of-work";

/** What became of a name change: pending, decided by an Approver, or ended without a decision (withdrawn by its proposer, discarded by the platform). */
export type NameChangeStatus = "pending" | "approved" | "rejected" | "withdrawn" | "discarded";

/** A name change waiting for Approval. */
export const PendingNameChange = z.object({
  names: z.array(z.string()).openapi({ description: "The names asked for; the Managed Certificate keeps its own until this is approved." }),
  validityDays: z.number().nullable().openapi({ description: "The validity the Managed Certificate is to have, as its `validityDays`: none for its Issuing CA's default." }),
  proposedBy: z.object({ id: z.string(), email: z.string() }),
  proposedAt: z.string(),
});

type NameChangeRow = typeof nameChange.$inferSelect;

export const toPendingNameChange = (row: NameChangeRow) => ({
  names: row.names,
  validityDays: row.validityDays,
  proposedBy: { id: row.proposedById, email: row.proposedByEmail },
  proposedAt: row.createdAt.toISOString(),
});

/** The name change each of the Managed Certificates is waiting on, for those with one. */
export async function pendingNameChanges(db: Db | Tx, managedCertificateIds: string[]): Promise<Map<string, NameChangeRow>> {
  if (managedCertificateIds.length === 0) return new Map();
  const rows = await db
    .select()
    .from(nameChange)
    .where(and(inArray(nameChange.managedCertificateId, managedCertificateIds), eq(nameChange.status, "pending")));
  return new Map(rows.map((row) => [row.managedCertificateId, row]));
}

/** Every name change in the Organization waiting for Approval, the oldest first; an archived Managed Certificate's cannot be approved, so is left out. */
export const pendingNameChangesOf = (db: Db, organizationId: string) =>
  db
    .select({ change: nameChange, currentNames: managedCertificate.names, currentValidityDays: managedCertificate.validityDays })
    .from(nameChange)
    .innerJoin(managedCertificate, and(eq(managedCertificate.id, nameChange.managedCertificateId), eq(managedCertificate.organizationId, nameChange.organizationId)))
    .where(and(eq(nameChange.organizationId, organizationId), eq(nameChange.status, "pending"), isNull(managedCertificate.archivedAt)))
    .orderBy(asc(nameChange.createdAt), asc(nameChange.id));

/** Locks the Managed Certificate for the rest of the transaction, so changes to its names, its archiving and its Issuances take turns. */
export async function lockManagedCertificate(tx: Tx, organizationId: string, id: string) {
  const [mc] = await tx
    .select()
    .from(managedCertificate)
    .where(and(eq(managedCertificate.id, id), eq(managedCertificate.organizationId, organizationId)))
    .for("update");
  if (!mc) throw new HttpError(404, "Managed Certificate not found");
  return mc;
}

/** Why the Managed Certificate's names may not be changed now, if they may not. */
export function refusalToChangeNames(mc: { approvalStatus: ApprovalStatus; archivedAt: Date | null; keyCustody: KeyCustody }): string | null {
  // A new CSR for new names would need the Agent to make a new key, which a Deployment does not yet do.
  if (mc.keyCustody === "agent") return "the key of this Managed Certificate is held by an Agent, so its names cannot be changed";
  if (mc.archivedAt) return "the Managed Certificate is archived, so its names cannot be changed";
  if (mc.approvalStatus === "pending") return "the Managed Certificate is awaiting Approval, which decides its names, so they cannot be changed";
  if (mc.approvalStatus === "rejected") return "the Managed Certificate is rejected, so its names cannot be changed";
  return null;
}

/** What an Audit Event of a change says of the validity: `{ from, to }` when the change gives the Managed Certificate another, nothing when it keeps its own. */
export const validityChangeDetail = (from: number | null, to: number | null) => (from === to ? {} : { validityDays: { from, to } });

/**
 * Gives the locked Managed Certificate its new names, CSR and validity, as a change that is approved or needs no Approval, and
 * has an Issuance for them begin. Refused (409) while an Issuance runs, which keeps what it started with: the new names
 * would get no Certificate until the next Renewal, so the change is made once that has ended.
 */
export async function applyNames(tx: Tx, change: Change, actor: Actor, issuances: Issuances, mc: { id: string; organizationId: string }, to: { names: string[]; csr: string; validityDays: number | null }) {
  await tx.update(managedCertificate).set({ names: to.names, csr: to.csr, validityDays: to.validityDays }).where(and(eq(managedCertificate.id, mc.id), eq(managedCertificate.organizationId, mc.organizationId)));
  const begun = await issuances.begin(tx, change, actor, mc, "issue");
  if ("refused" in begun) {
    if (begun.refused === "already_running") throw new HttpError(409, "an Issuance of this Managed Certificate is running; its names can be changed once it has ended");
    throw new Error(`the Issuance of a Managed Certificate whose names were just changed was refused: ${begun.refused}`);
  }
}

/**
 * Ends the pending change without a decision on it, audited: withdrawn by whoever proposed it (`actor`), or discarded by
 * the platform because what it was proposed for is gone (`reason` says what). Whoever decides it, or ends it, does so on
 * a change that is still pending, so of two at once one wins; false for the one that finds it already ended.
 */
export async function endPendingNameChange(
  tx: Tx,
  change: Change,
  pending: NameChangeRow,
  currentNames: string[],
  ending: { status: "withdrawn"; actor: Actor } | { status: "discarded"; reason: string },
): Promise<boolean> {
  const ended = await tx
    .update(nameChange)
    .set({
      status: ending.status,
      decidedById: "actor" in ending ? ending.actor.id : null,
      decidedByEmail: "actor" in ending ? ending.actor.email : null,
      decidedAt: change.occurredAt,
      decisionReason: "reason" in ending ? ending.reason : null,
    })
    .where(and(eq(nameChange.id, pending.id), eq(nameChange.status, "pending")))
    .returning({ id: nameChange.id });
  if (ended.length === 0) return false;
  await change.audit({
    organizationId: pending.organizationId,
    action: ending.status === "withdrawn" ? "name_change.withdrawn" : "name_change.discarded",
    target: { type: "managed_certificate", id: pending.managedCertificateId },
    detail: { from: currentNames, to: pending.names, proposedBy: pending.proposedByEmail, ...("reason" in ending && { reason: ending.reason }) },
  });
  return true;
}

/**
 * For the Archive of a Managed Certificate, which calls it on its own transaction: a change that waits for Approval of
 * names that will not be issued is discarded, with the reason given. Nothing pending is not an error.
 */
export async function discardPendingNameChange(tx: Tx, change: Change, mc: { id: string; organizationId: string }, reason: string) {
  const pending = (await pendingNameChanges(tx, [mc.id])).get(mc.id);
  if (!pending) return;
  const [row] = await tx
    .select({ names: managedCertificate.names })
    .from(managedCertificate)
    .where(and(eq(managedCertificate.id, mc.id), eq(managedCertificate.organizationId, mc.organizationId)));
  await endPendingNameChange(tx, change, pending, row!.names, { status: "discarded", reason });
}

/** Runs when a user is removed from an Organization: what they proposed and is still waiting for Approval is discarded, as nobody is left to answer for it. */
export const discardNameChangesOfRemoved: MemberRemovalHook = async (tx, { organizationId, userId }, change) => {
  const rows = await tx
    .select({ pending: nameChange, currentNames: managedCertificate.names })
    .from(nameChange)
    .innerJoin(managedCertificate, and(eq(managedCertificate.id, nameChange.managedCertificateId), eq(managedCertificate.organizationId, nameChange.organizationId)))
    .where(and(eq(nameChange.organizationId, organizationId), eq(nameChange.proposedById, userId), eq(nameChange.status, "pending")))
    .orderBy(asc(nameChange.createdAt), asc(nameChange.id));
  for (const { pending, currentNames } of rows) await endPendingNameChange(tx, change, pending, currentNames, { status: "discarded", reason: "its proposer left the Organization" });
};
