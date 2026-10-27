// Revocations: the one place a Certificate's or a Device Certificate's CA is asked to revoke it, and the Revocation
// recorded. An ACME CA and a Private CA revoke at once: the Revocation and its Audit Event are recorded on the caller's
// change. A kind whose CA confirms later (one reached through an Agent) answers pending instead: a Revocation Request is
// kept, nothing is revoked meanwhile, and the same Certificate cannot be revoked again until the kind reports. Confirmed
// (`report`), the Revocation is recorded then, attributed to whoever asked, as it would have been at once; refused or
// unreachable, or not answered by the deadline (`timeOut`), the request is kept as failed with its cause, and the
// Certificate stays unrevoked until it is asked again. Callers lock what they revoke first, so that two who ask at once
// take turns.
import { and, eq, inArray, lte } from "drizzle-orm";
import { CertificateAuthorityError } from "./acme/certificate-authority";
import type { Db, Tx } from "../platform/db/client";
import { certificate, certificateRevocation, deviceCertificate, enrollmentProfile, revocationRequest } from "../platform/db/schema";
import { certificateIssuerOf, issuerDetail, type CertificateIssuer, type Issuers } from "./issuer";
import { lockManagedCertificate } from "../certificates/name-change";
import type { RevocationReason } from "../pki/revocation-reasons";
import type { Actor, Change, UnitOfWork } from "../platform/unit-of-work";

/**
 * Who asked for a Device Certificate's Revocation that no person did, as its Audit Event's `detail.by` records it: the
 * Enrollment Validator's feed, or the RenewalReq whose replacement (by its serial) supersedes it. None when an
 * Organization Administrator did, who is the change's actor.
 */
export type RevokedBy = { enrollmentValidator: { kind: string } } | { renewal: { serial: string } };

export const REVOCATION_REQUEST_STATUSES = ["pending", "failed"] as const;
export type RevocationRequestStatus = (typeof REVOCATION_REQUEST_STATUSES)[number];

/** Why a Revocation Request failed: the CA said no, could not be reached, or did not answer by the deadline; or the platform failed. */
export const REVOCATION_FAILURE_CODES = ["rejected", "unreachable", "timed_out", "internal"] as const;
export type RevocationFailureCode = (typeof REVOCATION_FAILURE_CODES)[number];

export type RevocationRequestRow = typeof revocationRequest.$inferSelect;

/** What is revoked: a Managed Certificate's Certificate, which a person asked for, or a Device Certificate. */
export type RevocationTarget =
  | { kind: "certificate"; certificate: typeof certificate.$inferSelect; requestedBy: Actor }
  | {
      kind: "device_certificate";
      deviceCertificate: { id: string; serial: string; subject: string; certificatePem: string; enrollmentProfile: { id: string; name: string } };
      requestedBy: Actor | null;
      by?: RevokedBy;
    };

/** What the kind of a pending Revocation Request reports: that its CA revoked the Certificate, or the error it failed with (as `Issuers.revoke` throws it). */
export type RevocationReport = "revoked" | { failed: unknown };

export interface Revocations {
  /**
   * Asks the CA the targets came from (all from `issuedBy`) to revoke each for its reason, on the change, and answers
   * for each in turn: "revoked" when the Revocation is recorded, or "requested" when the CA confirms later. The caller
   * has locked the targets and found none revoked nor `awaiting`. Throws a CertificateAuthorityError as Issuers.revoke
   * does; the change then rolls back.
   */
  revoke(tx: Tx, change: Change, organizationId: string, issuedBy: CertificateIssuer, targets: { target: RevocationTarget; reason: RevocationReason }[]): Promise<("revoked" | "requested")[]>;
  /**
   * What the CA answered, later, for a pending Revocation Request: the Revocation is recorded (and the request gone), or
   * the request fails with the cause. A confirmation after it timed out is still recorded, since the CA has revoked it.
   * False when it no longer waits for that answer: it was answered, refused, or asked again since.
   */
  report(requestId: string, result: RevocationReport): Promise<boolean>;
  /** One pass at the clock's time: fails the pending Revocation Requests whose deadline has passed. Returns how many. */
  timeOut(): Promise<number>;
}

/** The Revocation Requests of the Certificates, by Certificate, for those that have one. */
export async function revocationRequestsOf(db: Db | Tx, certificateIds: string[]): Promise<Map<string, RevocationRequestRow>> {
  if (certificateIds.length === 0) return new Map();
  const rows = await db.select().from(revocationRequest).where(inArray(revocationRequest.certificateId, certificateIds));
  return new Map(rows.map((row) => [row.certificateId!, row]));
}

/**
 * Whether the CA's confirmation of a Revocation Request is still recorded: while it is pending, and once it timed out,
 * since the CA has then revoked the Certificate however late. Not once the CA refused, or it was asked again since.
 */
const confirmable = (row: RevocationRequestRow) => row.status === "pending" || row.failureCode === "timed_out";

/** Whether a Revocation Request waits for its CA, so that what it is of cannot be revoked again meanwhile. */
export const awaiting = (row: RevocationRequestRow | null | undefined) => row?.status === "pending";

/** The Revocation Request as the API shows it, on what it is of. */
export const toRevocationRequest = (row: RevocationRequestRow) => ({
  reason: row.reason,
  status: row.status,
  requestedAt: row.requestedAt.toISOString(),
  requestedBy: row.requestedById && row.requestedByEmail ? { id: row.requestedById, email: row.requestedByEmail } : null,
  deadline: row.deadline.toISOString(),
  failure: row.failureCode && row.failureMessage ? { code: row.failureCode, message: row.failureMessage } : null,
});

function failureOf(err: unknown): { code: RevocationFailureCode; message: string } {
  if (err instanceof CertificateAuthorityError) return { code: err.kind, message: err.message };
  console.error("a revocation failed", err);
  return { code: "internal", message: "the platform failed while revoking; see its log" };
}

export function createRevocations({ db, unitOfWork, issuers, clock }: { db: Db; unitOfWork: UnitOfWork; issuers: Issuers; clock: () => Date }): Revocations {
  /** The Revocation Request of what the target is, whatever its state. */
  const requestOf = (target: RevocationTarget) =>
    target.kind === "certificate" ? eq(revocationRequest.certificateId, target.certificate.id) : eq(revocationRequest.deviceCertificateId, target.deviceCertificate.id);

  /** Records the target's Revocation and its Audit Event on the change; a Revocation Request it had, which failed or is now confirmed, is gone. */
  async function record(tx: Tx, change: Change, organizationId: string, target: RevocationTarget, reason: RevocationReason) {
    await tx.delete(revocationRequest).where(requestOf(target));
    if (target.kind === "certificate") {
      const { certificate: issued, requestedBy } = target;
      await tx
        .insert(certificateRevocation)
        .values({ certificateId: issued.id, organizationId, reason, revokedById: requestedBy.id, revokedByEmail: requestedBy.email, revokedAt: change.occurredAt });
      await change.audit({
        organizationId,
        action: "certificate.revoked",
        target: { type: "managed_certificate", id: issued.managedCertificateId },
        detail: { certificateId: issued.id, fingerprint: issued.fingerprint, serial: issued.serial, reason, ...issuerDetail(certificateIssuerOf(issued)) },
      });
      return;
    }
    const { deviceCertificate: device, by } = target;
    await tx.update(deviceCertificate).set({ revokedAt: change.occurredAt, revocationReason: reason }).where(eq(deviceCertificate.id, device.id));
    await change.audit({
      organizationId,
      action: "device_certificate.revoked",
      target: { type: "device_certificate", id: device.id },
      detail: { enrollmentProfile: device.enrollmentProfile, serial: device.serial, subject: device.subject, reason, ...(by && { by }) },
    });
  }

  /** What an Audit Event of a Revocation Request is about: its target and what identifies the Certificate. */
  function aboutOf(target: RevocationTarget) {
    if (target.kind === "certificate") {
      const issued = target.certificate;
      return { target: { type: "managed_certificate", id: issued.managedCertificateId }, detail: { certificateId: issued.id, fingerprint: issued.fingerprint, serial: issued.serial } };
    }
    const device = target.deviceCertificate;
    return { target: { type: "device_certificate", id: device.id }, detail: { enrollmentProfile: device.enrollmentProfile, serial: device.serial, subject: device.subject, ...(target.by && { by: target.by }) } };
  }

  const actionOf = (target: RevocationTarget, what: "requested" | "failed") =>
    target.kind === "certificate" ? (`certificate.revocation_${what}` as const) : (`device_certificate.revocation_${what}` as const);

  const actorOf = (row: RevocationRequestRow): Actor | null => (row.requestedById && row.requestedByEmail ? { id: row.requestedById, email: row.requestedByEmail } : null);

  /** The target a Revocation Request is of, read again; none when it is gone (a pruned Device Certificate). */
  async function targetOf(tx: Tx, row: RevocationRequestRow): Promise<RevocationTarget | undefined> {
    if (row.certificateId) {
      const [issued] = await tx.select().from(certificate).where(eq(certificate.id, row.certificateId));
      if (!issued || !row.requestedById || !row.requestedByEmail) return undefined;
      return { kind: "certificate", certificate: issued, requestedBy: { id: row.requestedById, email: row.requestedByEmail } };
    }
    const [device] = await tx
      .select({
        id: deviceCertificate.id,
        serial: deviceCertificate.serial,
        subject: deviceCertificate.subject,
        certificatePem: deviceCertificate.certificatePem,
        enrollmentProfile: { id: enrollmentProfile.id, name: enrollmentProfile.name },
      })
      .from(deviceCertificate)
      .innerJoin(enrollmentProfile, eq(enrollmentProfile.id, deviceCertificate.enrollmentProfileId))
      .where(eq(deviceCertificate.id, row.deviceCertificateId!));
    if (!device) return undefined;
    return { kind: "device_certificate", deviceCertificate: device, requestedBy: actorOf(row), ...(row.requestedBy && { by: row.requestedBy }) };
  }

  /**
   * Locks what a Revocation Request is of as every revocation of it does (its Managed Certificate, or the Device
   * Certificate), then the request itself, so that it takes turns with them; the request as it is now, if it still is.
   */
  async function lockRequest(tx: Tx, seen: RevocationRequestRow) {
    if (seen.certificateId) {
      const [issued] = await tx.select({ managedCertificateId: certificate.managedCertificateId }).from(certificate).where(eq(certificate.id, seen.certificateId));
      if (issued) await lockManagedCertificate(tx, seen.organizationId, issued.managedCertificateId);
    } else {
      await tx.select({ id: deviceCertificate.id }).from(deviceCertificate).where(eq(deviceCertificate.id, seen.deviceCertificateId!)).for("update");
    }
    const [row] = await tx.select().from(revocationRequest).where(eq(revocationRequest.id, seen.id)).for("update");
    return row;
  }

  /** Fails the Revocation Request if it is still pending, on a change attributed to whoever asked. Whether it did. */
  async function fail(requestId: string, failure: { code: RevocationFailureCode; message: string }) {
    const [seen] = await db.select().from(revocationRequest).where(eq(revocationRequest.id, requestId));
    if (!seen || seen.status !== "pending") return false;
    return unitOfWork.run(actorOf(seen), async (tx, change) => {
      // Locked, so that a result reported twice at once, or with a timeout, is applied once.
      const row = await lockRequest(tx, seen);
      if (!row || row.status !== "pending") return false;
      await tx
        .update(revocationRequest)
        .set({ status: "failed", failureCode: failure.code, failureMessage: failure.message, finishedAt: change.occurredAt })
        .where(eq(revocationRequest.id, requestId));
      const target = await targetOf(tx, row);
      if (target) {
        const about = aboutOf(target);
        await change.audit({ organizationId: row.organizationId, action: actionOf(target, "failed"), target: about.target, detail: { ...about.detail, reason: row.reason, failure } });
      }
      return true;
    });
  }

  return {
    async revoke(tx, change, organizationId, issuedBy, targets) {
      const asked = targets.map(({ target, reason }) => ({ target, reason, requestId: crypto.randomUUID(), recorded: false }));
      const answers = await issuers.revoke(
        tx,
        change,
        organizationId,
        issuedBy,
        asked.map((one) => ({
          requestId: one.requestId,
          certificate: one.target.kind === "certificate" ? one.target.certificate.chainPem : one.target.deviceCertificate.certificatePem,
          reason: one.reason,
          record: async () => {
            if (one.recorded) return;
            one.recorded = true;
            await record(tx, change, organizationId, one.target, one.reason);
          },
        })),
      );
      const outcomes: ("revoked" | "requested")[] = [];
      for (const [i, one] of asked.entries()) {
        const answer = answers[i];
        if (answer === "revoked") {
          if (!one.recorded) throw new Error("the issuer's kind answered revoked without recording the Revocation");
          outcomes.push("revoked");
          continue;
        }
        if (!answer || one.recorded) throw new Error("the issuer's kind answered pending for a Revocation it recorded");
        const of = one.target.kind === "certificate" ? { certificateId: one.target.certificate.id } : { deviceCertificateId: one.target.deviceCertificate.id };
        // A failed request before it is replaced: one per Certificate.
        await tx.delete(revocationRequest).where(requestOf(one.target));
        await tx.insert(revocationRequest).values({
          id: one.requestId,
          organizationId,
          ...of,
          reason: one.reason,
          requestedById: one.target.requestedBy?.id ?? null,
          requestedByEmail: one.target.requestedBy?.email ?? null,
          requestedBy: one.target.kind === "device_certificate" ? (one.target.by ?? null) : null,
          status: "pending",
          handle: answer.pending.handle,
          deadline: answer.pending.deadline,
          requestedAt: change.occurredAt,
        });
        const about = aboutOf(one.target);
        await change.audit({ organizationId, action: actionOf(one.target, "requested"), target: about.target, detail: { ...about.detail, reason: one.reason } });
        outcomes.push("requested");
      }
      return outcomes;
    },

    async report(requestId, result) {
      if (result !== "revoked") return fail(requestId, failureOf(result.failed));
      const [seen] = await db.select().from(revocationRequest).where(eq(revocationRequest.id, requestId));
      if (!seen || !confirmable(seen)) return false;
      return unitOfWork.run(actorOf(seen), async (tx, change) => {
        const row = await lockRequest(tx, seen);
        if (!row || !confirmable(row)) return false;
        const target = await targetOf(tx, row);
        if (!target) return false;
        await record(tx, change, row.organizationId, target, row.reason);
        return true;
      });
    },

    async timeOut() {
      const now = clock();
      const rows = await db
        .select({ id: revocationRequest.id, deadline: revocationRequest.deadline })
        .from(revocationRequest)
        .where(and(eq(revocationRequest.status, "pending"), lte(revocationRequest.deadline, now)));
      let ended = 0;
      for (const row of rows) {
        const failure = { code: "timed_out" as const, message: `the CA did not confirm the revocation by ${row.deadline.toISOString()}; it may not be revoked, so ask again` };
        if (await fail(row.id, failure)) ended++;
      }
      return ended;
    },
  };
}
