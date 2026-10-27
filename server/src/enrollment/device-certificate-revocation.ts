// Device Certificate Revocation: the one place a Device Certificate is revoked, whoever asks for it. An Organization
// Administrator does (device-certificates.ts), its Enrollment Validator's revocation feed does (enrollment-validators.ts),
// and a RenewalReq signed with it does once its replacement is issued, as `superseded` (device-enrollment.ts). Each goes
// to its CA as any Certificate's Revocation does (revocations.ts): an Issuing CA records it, audited as
// `device_certificate.revoked`, and puts it on its CRL on the caller's change, so all of it commits or none does; a CA
// that confirms later has it requested, and recorded once it confirms. The rows are locked first, so that two asking at
// once take turns and the second finds it revoked, or requested: a Revocation is never recorded twice, nor undone.
import { and, asc, eq, inArray } from "drizzle-orm";
import type { Tx } from "../platform/db/client";
import { deviceCertificate, enrollmentProfile, revocationRequest } from "../platform/db/schema";
import type { RevocationReason } from "../pki/revocation-reasons";
import type { Change } from "../platform/unit-of-work";
import type { Revocations, RevokedBy } from "../issuance/revocations";

export type { RevokedBy } from "../issuance/revocations";

/** A Device Certificate to revoke, by id, with its RFC 5280 reason. */
export interface DeviceCertificateRevocation {
  id: string;
  reason: RevocationReason;
  by?: RevokedBy;
}

/** Whether a Device Certificate was revoked: true when it is, "requested" when its CA confirms later, false when nothing was done. */
export type DeviceCertificateRevocationOutcome = boolean | "requested";

export interface DeviceCertificateRevocations {
  /**
   * Revokes the Organization's Device Certificates on the change, in the order given, asking each CA once for those it
   * signed (an Issuing CA reissues its CRL once). Answers, for each in turn, whether this revoked it, or had it requested
   * from a CA that confirms later: not when it is already revoked or requested (or was earlier in the same call), nor
   * when the Organization has no such Device Certificate. Throws a CertificateAuthorityError when the CA says no or the
   * KMS does not sign a CRL; the change then rolls back, Revocations and all. The change's actor, if any, is who asked.
   */
  revoke(tx: Tx, change: Change, organizationId: string, revocations: DeviceCertificateRevocation[], actor?: { id: string; email: string } | null): Promise<DeviceCertificateRevocationOutcome[]>;
}

export function createDeviceCertificateRevocations({ revocations: asked }: { revocations: Pick<Revocations, "revoke"> }): DeviceCertificateRevocations {
  return {
    async revoke(tx, change, organizationId, revocations, actor = null) {
      if (revocations.length === 0) return [];
      // Locked in order of id, so that changes revoking several at once never wait on each other in a cycle.
      const rows = await tx
        .select({
          id: deviceCertificate.id,
          serial: deviceCertificate.serial,
          subject: deviceCertificate.subject,
          certificatePem: deviceCertificate.certificatePem,
          issuingCaId: deviceCertificate.issuingCaId,
          revokedAt: deviceCertificate.revokedAt,
          requestStatus: revocationRequest.status,
          enrollmentProfile: { id: enrollmentProfile.id, name: enrollmentProfile.name },
        })
        .from(deviceCertificate)
        .innerJoin(enrollmentProfile, eq(enrollmentProfile.id, deviceCertificate.enrollmentProfileId))
        .leftJoin(revocationRequest, eq(revocationRequest.deviceCertificateId, deviceCertificate.id))
        .where(and(eq(deviceCertificate.organizationId, organizationId), inArray(deviceCertificate.id, [...new Set(revocations.map((r) => r.id))])))
        .orderBy(asc(deviceCertificate.id))
        .for("update", { of: deviceCertificate });
      const unrevoked = new Map(rows.filter((row) => row.revokedAt === null && row.requestStatus !== "pending").map((row) => [row.id, row]));
      // What each Issuing CA is asked to revoke, in the order given; and which of those each asked-for one is.
      const byCa = new Map<string, { row: (typeof rows)[number]; reason: RevocationReason; by?: RevokedBy }[]>();
      const asking: ({ issuingCaId: string; index: number } | undefined)[] = [];
      for (const { id, reason, by } of revocations) {
        const row = unrevoked.get(id);
        if (!row) {
          asking.push(undefined);
          continue;
        }
        unrevoked.delete(id);
        const ofCa = byCa.get(row.issuingCaId) ?? [];
        byCa.set(row.issuingCaId, ofCa);
        asking.push({ issuingCaId: row.issuingCaId, index: ofCa.push({ row, reason, by }) - 1 });
      }
      const answers = new Map<string, ("revoked" | "requested")[]>();
      for (const [issuingCaId, ofCa] of byCa) {
        const targets = ofCa.map(({ row, reason, by }) => ({
          target: { kind: "device_certificate" as const, deviceCertificate: row, requestedBy: actor, ...(by && { by }) },
          reason,
        }));
        answers.set(issuingCaId, await asked.revoke(tx, change, organizationId, { kind: "private_ca", issuingCaId }, targets));
      }
      return asking.map((one) => {
        if (!one) return false;
        return answers.get(one.issuingCaId)![one.index] === "revoked" ? true : "requested";
      });
    },
  };
}
