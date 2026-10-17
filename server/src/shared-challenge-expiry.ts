// Expiry of previous Shared Challenges: once the expiry an administrator set when rotating has passed, a profile's
// previous Shared Challenge (shared-challenge.ts) is cleared, with an `enrollment_profile.shared_challenge_retired`
// Audit Event that has no actor, as if it had been retired. A device presenting it is refused from its expiry on whether
// or not this has run (scep.ts reads the expiry itself); this is what records that it ended.
import { and, eq, isNotNull, lte } from "drizzle-orm";
import type { Db } from "./db/client";
import { enrollmentProfile } from "./db/schema";
import { NO_PREVIOUS_SHARED_CHALLENGE } from "./shared-challenge";
import type { UnitOfWork } from "./unit-of-work";

export interface SharedChallengeExpiry {
  /** One pass at the clock: clears every previous Shared Challenge that has expired, or only the profile's when given, and returns how many. */
  expire(profileId?: string): Promise<number>;
}

export function createSharedChallengeExpiry({ db, unitOfWork, clock }: { db: Db; unitOfWork: UnitOfWork; clock: () => Date }): SharedChallengeExpiry {
  return {
    async expire(profileId) {
      // Expired: it has a previous Shared Challenge whose expiry is not after `now`; only the profile's when one was given.
      const expired = (now: Date) =>
        and(isNotNull(enrollmentProfile.previousSharedChallengeId), lte(enrollmentProfile.previousSharedChallengeExpiresAt, now), profileId === undefined ? undefined : eq(enrollmentProfile.id, profileId));
      const due = await db.select({ id: enrollmentProfile.id }).from(enrollmentProfile).where(expired(clock()));
      let total = 0;
      for (const { id } of due) {
        try {
          total += await unitOfWork.run(null, async (tx, change) => {
            // Locked, and asked again: retired or rotated since, it has nothing left to expire.
            const [row] = await tx.select().from(enrollmentProfile).where(and(eq(enrollmentProfile.id, id), expired(change.occurredAt))).for("update");
            if (!row) return 0;
            await tx.update(enrollmentProfile).set(NO_PREVIOUS_SHARED_CHALLENGE).where(eq(enrollmentProfile.id, id));
            await change.audit({
              organizationId: row.organizationId,
              action: "enrollment_profile.shared_challenge_retired",
              target: { type: "enrollment_profile", id },
              detail: { name: row.name, sharedChallenge: { id: row.previousSharedChallengeId }, expired: true },
            });
            return 1;
          });
        } catch (err) {
          // One profile's failure does not keep the others' from expiring; the next pass tries it again.
          console.error("could not expire a previous Shared Challenge", err);
        }
      }
      return total;
    },
  };
}
