// Pruning: a Device Certificate that ended more than its Enrollment Profile's retention period ago is deleted, so that
// the inventory reflects the devices still enrolled and the table stays bounded however large the fleet. Its CRL entry
// went when it ended (crl.ts lists only what has not), and its Audit Events stay. Each pass writes one
// `device_certificate.pruned` Audit Event per Organization it pruned anything of, with the count, in the same change.
import { and, asc, eq, inArray, sql } from "drizzle-orm";
import type { Db } from "./db/client";
import { deviceCertificate, enrollmentProfile } from "./db/schema";
import type { UnitOfWork } from "./unit-of-work";

export interface DeviceCertificatePruning {
  /** One pass at the clock: prunes what is due in every Organization and returns how many Device Certificates it deleted. */
  prune(): Promise<number>;
}

export function createDeviceCertificatePruning({ db, unitOfWork, clock }: { db: Db; unitOfWork: UnitOfWork; clock: () => Date }): DeviceCertificatePruning {
  return {
    async prune() {
      const now = clock();
      // Due: it ended more than its profile's retention period (whole days of 24 hours) before now.
      const due = sql`${deviceCertificate.notAfter} < ${now.toISOString()}::timestamptz - ${enrollmentProfile.retentionDays} * interval '24 hours'`;
      const organizations = await db
        .selectDistinct({ id: enrollmentProfile.organizationId })
        .from(deviceCertificate)
        .innerJoin(enrollmentProfile, eq(enrollmentProfile.id, deviceCertificate.enrollmentProfileId))
        .where(due);

      let total = 0;
      for (const { id: organizationId } of organizations) {
        try {
          total += await unitOfWork.run(null, async (tx, change) => {
            const deleted = await tx
              .delete(deviceCertificate)
              .where(
                and(
                  eq(deviceCertificate.organizationId, organizationId),
                  sql`exists (select 1 from ${enrollmentProfile} where ${enrollmentProfile.id} = ${deviceCertificate.enrollmentProfileId} and ${due})`,
                ),
              )
              .returning({ profileId: deviceCertificate.enrollmentProfileId });
            if (deleted.length === 0) return 0;
            const counts = new Map<string, number>();
            for (const { profileId } of deleted) counts.set(profileId, (counts.get(profileId) ?? 0) + 1);
            const names = await tx
              .select({ id: enrollmentProfile.id, name: enrollmentProfile.name })
              .from(enrollmentProfile)
              .where(inArray(enrollmentProfile.id, [...counts.keys()]))
              .orderBy(asc(enrollmentProfile.createdAt), asc(enrollmentProfile.id));
            await change.audit({
              organizationId,
              action: "device_certificate.pruned",
              target: { type: "organization", id: organizationId },
              detail: { count: deleted.length, enrollmentProfiles: names.map(({ id, name }) => ({ id, name, count: counts.get(id)! })) },
            });
            return deleted.length;
          });
        } catch (err) {
          // One Organization's failure does not keep the others' from being pruned; the next pass tries it again.
          console.error("could not prune an Organization's Device Certificates", err);
        }
      }
      return total;
    },
  };
}
