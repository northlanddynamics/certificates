// The Renewal scheduler: on each pass it finds the automatic Managed Certificates that are due for Renewal (renewal.ts)
// and starts an Issuance for each, which reuses the CSR the Managed Certificate holds. It keeps no state of its own: what
// is due, and what to wait for after a failure, are read from the Managed Certificates and their Issuances, so a pass
// that is repeated, or run by two platform instances at once, starts a Renewal once (a Managed Certificate has at most
// one Issuance running). One whose Certificate Profile is disabled is not renewed (issuance.ts refuses to begin): the
// first pass that finds it due marks it renewal-blocked and tells its Subscribers, and later passes leave it alone while
// the profile stays disabled. The next Issuance that begins clears the mark, so one blocked again is told of again. Its
// time is the clock it is given, so tests control it.
import { and, eq, isNull, or, sql } from "drizzle-orm";
import type { Db } from "../platform/db/client";
import { certificateProfile, issuance, managedCertificate, renewalInfo } from "../platform/db/schema";
import { renewsAutomatically, type Issuances } from "./issuance";
import type { Issuers } from "./issuer";
import { currentCertificates, failuresOf, nextAttemptAt } from "./renewal";
import { refreshRenewalInfo, informationOf } from "./renewal-information";
import type { Notifications } from "../notifications/notifications";
import type { UnitOfWork } from "../platform/unit-of-work";

export interface RenewalScheduler {
  /** One pass at the clock's time: starts the Renewals that are due and returns how many it started. It never throws for one Managed Certificate's trouble. */
  tick(): Promise<number>;
}

export function createRenewalScheduler({
  db,
  unitOfWork,
  issuances,
  issuers,
  notifications,
  clock,
}: {
  db: Db;
  unitOfWork: UnitOfWork;
  issuances: Issuances;
  issuers: Issuers;
  notifications: Pick<Notifications, "notify">;
  clock: () => Date;
}): RenewalScheduler {
  const current = currentCertificates(db);

  return {
    async tick() {
      const now = clock();
      // The CA's windows first, so that a Renewal it has just asked for is seen by this pass.
      await refreshRenewalInfo({ db, issuers, now });
      // Automatic, live, approved, with a Certificate to renew and none being issued. The days rule, or the start of the
      // CA's window, is checked in the database (the days in seconds, as a day interval would follow the session's time
      // zone through a clock change) to leave out most of them; the rest of what makes one due (nextAttemptAt) is checked here.
      const candidates = await db
        .select({ managedCertificate, certificate: { id: current.id, fingerprint: current.fingerprint, notBefore: current.notBefore, notAfter: current.notAfter } })
        .from(managedCertificate)
        .innerJoin(current, eq(current.managedCertificateId, managedCertificate.id))
        .leftJoin(renewalInfo, eq(renewalInfo.certificateId, current.id))
        .where(
          and(
            renewsAutomatically,
            or(
              sql`${current.notAfter} - make_interval(secs => ${managedCertificate.renewalDaysBeforeExpiry} * 86400) <= ${now}`,
              sql`${renewalInfo.windowStart} <= ${now}`,
            ),
            sql`not exists (select 1 from ${issuance} where ${issuance.managedCertificateId} = ${managedCertificate.id} and ${issuance.status} = 'running')`,
            // Marked blocked, and its profile still disabled: nothing to do until it is enabled.
            sql`not (${managedCertificate.renewalBlockedAt} is not null and exists (select 1 from ${certificateProfile} where ${certificateProfile.id} = ${managedCertificate.certificateProfileId} and not ${certificateProfile.enabled}))`,
          ),
        );
      const failures = await failuresOf(db, candidates.map((c) => c.managedCertificate.id));
      const information = await informationOf(db, candidates.map((c) => c.certificate.id));

      let started = 0;
      for (const { managedCertificate: mc, certificate } of candidates) {
        const policy = { mode: mc.renewalMode, daysBeforeExpiry: mc.renewalDaysBeforeExpiry };
        const at = nextAttemptAt(policy, certificate, failures.get(mc.id), information.get(certificate.id)?.window ?? null);
        if (!at || at > now) continue;
        try {
          // Decided again under a lock: a change made since the pass began (a switch to manual, an archive, another Issuance) wins.
          const begun = await unitOfWork.run(null, async (tx, change) => {
            const outcome = await issuances.begin(tx, change, null, mc, "scheduled");
            if ("refused" in outcome && outcome.refused === "profile_disabled") {
              // Marked once: a pass that finds it marked already has told its Subscribers.
              const marked = await tx
                .update(managedCertificate)
                .set({ renewalBlockedAt: change.occurredAt })
                .where(and(eq(managedCertificate.id, mc.id), isNull(managedCertificate.renewalBlockedAt)))
                .returning({ id: managedCertificate.id });
              if (marked.length > 0) {
                await notifications.notify(tx, change, mc, {
                  event: "renewal.blocked",
                  detail: { certificateProfile: { id: mc.certificateProfileId!, name: outcome.profile! }, dueAt: at.toISOString() },
                });
              }
            }
            return outcome;
          });
          if ("issuanceId" in begun) started++;
        } catch (err) {
          console.error("could not start the Renewal of", mc.id, err);
        }
      }
      return started;
    },
  };
}
