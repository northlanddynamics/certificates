// The Renewal scheduler: on each pass it finds the automatic Managed Certificates that are due for Renewal (renewal.ts)
// and starts an Issuance for each, which reuses the CSR the Managed Certificate holds. It keeps no state of its own: what
// is due, and what to wait for after a failure, are read from the Managed Certificates and their Issuances, so a pass
// that is repeated, or run by two platform instances at once, starts a Renewal once (a Managed Certificate has at most
// one Issuance running). Its time is the clock it is given, so tests control it.
import { and, desc, eq, inArray, isNull, sql } from "drizzle-orm";
import type { Db } from "./db/client";
import { certificate, issuance, managedCertificate } from "./db/schema";
import { isUniqueViolation } from "./http";
import type { Issuances } from "./issuance";
import { failuresOf, nextAttemptAt } from "./renewal";
import type { UnitOfWork } from "./unit-of-work";

export interface RenewalScheduler {
  /** One pass at the clock's time: starts the Renewals that are due and returns how many it started. It never throws for one Managed Certificate's trouble. */
  tick(): Promise<number>;
}

export function createRenewalScheduler({ db, unitOfWork, issuances, clock }: { db: Db; unitOfWork: UnitOfWork; issuances: Issuances; clock: () => Date }): RenewalScheduler {
  /** Each Managed Certificate's most recent Certificate. */
  const current = db
    .selectDistinctOn([certificate.managedCertificateId], {
      managedCertificateId: certificate.managedCertificateId,
      notBefore: certificate.notBefore,
      notAfter: certificate.notAfter,
    })
    .from(certificate)
    .orderBy(certificate.managedCertificateId, desc(certificate.createdAt), desc(certificate.id))
    .as("current");

  return {
    async tick() {
      const now = clock();
      // Automatic, live, approved, with a Certificate to renew and none being issued. The days rule is checked in
      // the database (in seconds, as a day interval would follow the session's time zone through a clock change) to leave out most of them; the rest of what makes one due (nextAttemptAt) is checked here.
      const candidates = await db
        .select({ managedCertificate, notBefore: current.notBefore, notAfter: current.notAfter })
        .from(managedCertificate)
        .innerJoin(current, eq(current.managedCertificateId, managedCertificate.id))
        .where(
          and(
            eq(managedCertificate.renewalMode, "automatic"),
            isNull(managedCertificate.archivedAt),
            inArray(managedCertificate.approvalStatus, ["not_required", "approved"]),
            sql`${current.notAfter} - make_interval(secs => ${managedCertificate.renewalDaysBeforeExpiry} * 86400) <= ${now}`,
            sql`not exists (select 1 from ${issuance} where ${issuance.managedCertificateId} = ${managedCertificate.id} and ${issuance.status} = 'running')`,
          ),
        );
      const failures = await failuresOf(db, candidates.map((c) => c.managedCertificate.id));

      let started = 0;
      for (const { managedCertificate: mc, notBefore, notAfter } of candidates) {
        const policy = { mode: mc.renewalMode, daysBeforeExpiry: mc.renewalDaysBeforeExpiry };
        const at = nextAttemptAt(policy, { notBefore, notAfter }, failures.get(mc.id));
        if (!at || at > now) continue;
        try {
          const issuanceId = await unitOfWork.run(null, async (tx, change) => {
            // Looked at again under a lock: a change made since the pass began (a switch to manual, an archive) wins.
            const [row] = await tx.select().from(managedCertificate).where(eq(managedCertificate.id, mc.id)).for("update");
            if (!row || row.renewalMode !== "automatic" || row.archivedAt || !["not_required", "approved"].includes(row.approvalStatus)) return null;
            return issuances.begin(tx, change, null, mc, "scheduled");
          });
          if (!issuanceId) continue;
          issuances.start(issuanceId);
          started++;
        } catch (err) {
          // Another pass, or a person, started one first.
          if (!isUniqueViolation(err)) console.error("could not start the Renewal of", mc.id, err);
        }
      }
      return started;
    },
  };
}
