// Device Certificate Revocation: the one place a Device Certificate is revoked, whoever asks for it. An Organization
// Administrator does (device-certificates.ts), its Enrollment Validator's revocation feed does (enrollment-validators.ts),
// and a RenewalReq signed with it does once its replacement is issued, as `superseded` (scep.ts). Each is recorded,
// audited as `device_certificate.revoked` and put on its Issuing CA's CRL on the caller's change, so all of it commits or
// none does. The rows are locked first, so that two asking at once take turns and the second finds it revoked: a
// Revocation is never recorded twice, nor undone.
import { and, asc, eq, inArray } from "drizzle-orm";
import type { Tx } from "./db/client";
import { deviceCertificate, enrollmentProfile } from "./db/schema";
import type { PrivateCas } from "./private-ca";
import type { RevocationReason } from "./revocation-reasons";
import type { Change } from "./unit-of-work";

/**
 * Who asked for a Revocation that no person did, as its Audit Event's `detail.by` records it: the Enrollment Validator's
 * feed, or the RenewalReq whose replacement (by its serial) supersedes it. None when an Organization Administrator did,
 * who is the change's actor.
 */
export type RevokedBy = { enrollmentValidator: { kind: string } } | { renewal: { serial: string } };

/** A Device Certificate to revoke, by id, with its RFC 5280 reason. */
export interface DeviceCertificateRevocation {
  id: string;
  reason: RevocationReason;
  by?: RevokedBy;
}

export interface DeviceCertificateRevocations {
  /**
   * Revokes the Organization's Device Certificates on the change, in the order given, and reissues once the CRL of each
   * Issuing CA that revoked one. Answers, for each in turn, whether this revoked it: not when it is already revoked (or
   * was earlier in the same call), nor when the Organization has no such Device Certificate. Throws a
   * CertificateAuthorityError when the KMS does not sign a CRL; the change then rolls back, Revocations and all.
   */
  revoke(tx: Tx, change: Change, organizationId: string, revocations: DeviceCertificateRevocation[]): Promise<boolean[]>;
}

export function createDeviceCertificateRevocations({ privateCas }: { privateCas: Pick<PrivateCas, "publishRevocation"> }): DeviceCertificateRevocations {
  return {
    async revoke(tx, change, organizationId, revocations) {
      if (revocations.length === 0) return [];
      // Locked in order of id, so that changes revoking several at once never wait on each other in a cycle.
      const rows = await tx
        .select({
          id: deviceCertificate.id,
          serial: deviceCertificate.serial,
          subject: deviceCertificate.subject,
          issuingCaId: deviceCertificate.issuingCaId,
          revokedAt: deviceCertificate.revokedAt,
          enrollmentProfile: { id: enrollmentProfile.id, name: enrollmentProfile.name },
        })
        .from(deviceCertificate)
        .innerJoin(enrollmentProfile, eq(enrollmentProfile.id, deviceCertificate.enrollmentProfileId))
        .where(and(eq(deviceCertificate.organizationId, organizationId), inArray(deviceCertificate.id, [...new Set(revocations.map((r) => r.id))])))
        .orderBy(asc(deviceCertificate.id))
        .for("update", { of: deviceCertificate });
      const unrevoked = new Map(rows.filter((row) => row.revokedAt === null).map((row) => [row.id, row]));
      const published = new Set<string>();
      const outcomes: boolean[] = [];
      for (const { id, reason, by } of revocations) {
        const row = unrevoked.get(id);
        outcomes.push(row !== undefined);
        if (!row) continue;
        unrevoked.delete(id);
        await tx.update(deviceCertificate).set({ revokedAt: change.occurredAt, revocationReason: reason }).where(eq(deviceCertificate.id, id));
        await change.audit({
          organizationId,
          action: "device_certificate.revoked",
          target: { type: "device_certificate", id },
          detail: { enrollmentProfile: row.enrollmentProfile, serial: row.serial, subject: row.subject, reason, ...(by && { by }) },
        });
        published.add(row.issuingCaId);
      }
      for (const issuingCaId of published) await privateCas.publishRevocation(tx, change, organizationId, issuingCaId);
      return outcomes;
    },
  };
}
