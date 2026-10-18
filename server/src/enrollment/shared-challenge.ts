// The Shared Challenge: the one secret every device enrolling under an Enrollment Profile presents, for the Shared
// Challenge kind of Enrollment Validator, where the device's manager (such as Iru, formerly Kandji, or network gear) can
// give no per-device challenge (ADR 0008). It belongs to the profile, not to a validator, and this module holds it
// through its life: it is issued when the profile is created and shown once, the platform keeping only its hash (as it
// does an Agent's credential); a PKCSReq's challengePassword is checked against it, in constant time, before the
// validator is asked (device-enrollment.ts); a rotation issues a new one, shown once, and keeps the old one as the previous, which
// devices may still present until it expires or is retired, so a profile holds at most two. Once its expiry has passed,
// the expiry pass clears the previous one, with an `enrollment_profile.shared_challenge_retired` Audit Event that has no
// actor, as if it had been retired; a device presenting it is refused from its expiry on whether or not the pass has run.
// A RenewalReq is not checked: its signature by the device's current Device Certificate is the proof. Nor is the
// validator told of outcomes (enrollment-validators.ts), which would keep the CSR, and so the challenge, in the
// platform's database.
//
// The kind itself checks nothing more: it does not vouch for names, allows renewal, and has no settings, secret,
// revocation feed or device ID, so what a holder of the challenge gets is bounded by the profile's Name Rules, if any,
// and its Issuing CA's Permitted Name Rules.
import { z } from "@hono/zod-openapi";
import { and, eq, isNotNull, lte } from "drizzle-orm";
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { Db, Tx } from "../platform/db/client";
import { enrollmentProfile } from "../platform/db/schema";
import type { EnrollmentValidatorKind } from "./enrollment-validator";
import { HttpError } from "../platform/http";
import { sha256Hex } from "../platform/crypto/sha256";
import type { Actor, UnitOfWork } from "../platform/unit-of-work";

type ProfileRow = typeof enrollmentProfile.$inferSelect;

/** A profile's Shared Challenges, as the platform keeps them. */
export interface HeldSharedChallenges {
  sharedChallengeId: string | null;
  sharedChallengeHash: string | null;
  previousSharedChallengeId: string | null;
  previousSharedChallengeHash: string | null;
  previousSharedChallengeExpiresAt: Date | null;
}

/** A Shared Challenge as it is shown, once, when it is issued. */
export interface ShownSharedChallenge {
  id: string;
  challenge: string;
}

/**
 * A new Shared Challenge, with its id and the hash that is kept of it: 192 bits of randomness as lower-case hex, which
 * a CSR's challengePassword (a PrintableString) and Iru's form both take.
 */
function newSharedChallenge() {
  const challenge = randomBytes(24).toString("hex");
  return { id: randomUUID(), challenge, hash: sha256Hex(challenge) };
}

/** Compared against when there is no hash, so that having none takes no less time. */
const NO_HASH = "0".repeat(64);

/** Whether the challenge a device presented is the one `hash` was kept of, compared in constant time; never when there is no hash. */
function isSharedChallenge(presented: string, hash: string | null): boolean {
  const matches = timingSafeEqual(Buffer.from(sha256Hex(presented), "hex"), Buffer.from(hash ?? NO_HASH, "hex"));
  return matches && hash !== null;
}

/** What clears a profile's previous Shared Challenge, when it is retired or expires. */
const NO_PREVIOUS_SHARED_CHALLENGE = { previousSharedChallengeId: null, previousSharedChallengeHash: null, previousSharedChallengeExpiresAt: null };

/** Whether the profile's previous Shared Challenge may still be presented at `now`: it has one, and it has not expired. */
const holdsValidPrevious = (held: HeldSharedChallenges, now: Date) => held.previousSharedChallengeExpiresAt !== null && held.previousSharedChallengeExpiresAt > now;

/** The profile's Shared Challenges as the API shows them at `now`, by id: its current one, and its previous one while that may still be presented. */
export function sharedChallengesOf(held: HeldSharedChallenges, now: Date) {
  return {
    sharedChallenge: held.sharedChallengeId === null ? null : { id: held.sharedChallengeId },
    previousSharedChallenge: holdsValidPrevious(held, now) ? { id: held.previousSharedChallengeId!, expiresAt: held.previousSharedChallengeExpiresAt!.toISOString() } : null,
  };
}

export interface SharedChallenges {
  /** A new profile's Shared Challenge: what the profile keeps of it, and the challenge, to be shown this once. */
  issue(): { held: Pick<HeldSharedChallenges, "sharedChallengeId" | "sharedChallengeHash">; shown: ShownSharedChallenge };
  /**
   * Checks the challengePassword a PKCSReq presented against the profile's Shared Challenges at the clock: the id of the
   * one it presented, its current one or its previous one while that has not expired, or why it is refused. Both are
   * compared, whichever matches, so that the time taken says nothing of which.
   */
  check(held: HeldSharedChallenges, presented: string | undefined): { id: string } | { refusal: string };
  /**
   * Issues the profile a new Shared Challenge, keeping its current one as the previous until `previousExpiresAt`. A 422
   * when the profile has none, or `previousExpiresAt` is not in the future; a 409 while its previous one has not
   * expired, or when it was rotated meanwhile. A previous one that has expired is first recorded as such, with no actor.
   */
  rotate(actor: Actor, profile: ProfileRow, previousExpiresAt: Date): Promise<{ row: ProfileRow; shown: ShownSharedChallenge }>;
  /** Retires the profile's previous Shared Challenge at once. A 409 when it holds none that has not expired. */
  retire(actor: Actor, profile: ProfileRow): Promise<ProfileRow>;
  /** One pass at the clock: clears every previous Shared Challenge that has expired, or only the profile's when given, and returns how many. */
  expire(profileId?: string): Promise<number>;
}

export function createSharedChallenges({ db, unitOfWork, clock }: { db: Db; unitOfWork: UnitOfWork; clock: () => Date }): SharedChallenges {
  /** The profile, locked for the change. */
  const locked = async (tx: Tx, id: string) => (await tx.select().from(enrollmentProfile).where(eq(enrollmentProfile.id, id)).for("update"))[0]!;

  async function expire(profileId?: string) {
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
  }

  return {
    issue() {
      const { id, challenge, hash } = newSharedChallenge();
      return { held: { sharedChallengeId: id, sharedChallengeHash: hash }, shown: { id, challenge } };
    },

    check(held, presented) {
      if (presented === undefined) return { refusal: "the request has no challengePassword: present the Enrollment Profile's Shared Challenge" };
      const current = isSharedChallenge(presented, held.sharedChallengeHash);
      const previous = isSharedChallenge(presented, held.previousSharedChallengeHash) && holdsValidPrevious(held, clock());
      if (current) return { id: held.sharedChallengeId! };
      if (previous) return { id: held.previousSharedChallengeId! };
      return { refusal: "the request's challengePassword is not the Enrollment Profile's Shared Challenge" };
    },

    async rotate(actor, profile, previousExpiresAt) {
      if (profile.sharedChallengeId === null) throw new HttpError(422, `an Enrollment Validator of the kind ${profile.validatorKind} uses no Shared Challenge`);
      if (previousExpiresAt <= clock()) throw new HttpError(422, "previousExpiresAt must be in the future");
      const stillValid = () => new HttpError(409, "the Enrollment Profile still holds a previous Shared Challenge that has not expired: retire it first");
      if (holdsValidPrevious(profile, clock())) throw stillValid();
      // One that has expired is recorded as such, with no actor, before it is replaced.
      if (profile.previousSharedChallengeId !== null) await expire(profile.id);
      const shared = newSharedChallenge();
      const row = await unitOfWork.run(actor, async (tx, change) => {
        const current = await locked(tx, profile.id);
        if (holdsValidPrevious(current, change.occurredAt)) throw stillValid();
        if (current.previousSharedChallengeId !== null || current.sharedChallengeId !== profile.sharedChallengeId) throw new HttpError(409, "the Enrollment Profile was changed meanwhile; ask again");
        const [row] = await tx
          .update(enrollmentProfile)
          .set({ sharedChallengeId: shared.id, sharedChallengeHash: shared.hash, previousSharedChallengeId: current.sharedChallengeId, previousSharedChallengeHash: current.sharedChallengeHash, previousSharedChallengeExpiresAt: previousExpiresAt })
          .where(eq(enrollmentProfile.id, profile.id))
          .returning();
        await change.audit({
          organizationId: current.organizationId,
          action: "enrollment_profile.shared_challenge_rotated",
          target: { type: "enrollment_profile", id: profile.id },
          detail: { name: current.name, sharedChallenge: { id: shared.id }, previous: { id: current.sharedChallengeId, expiresAt: previousExpiresAt.toISOString() } },
        });
        return row!;
      });
      return { row, shown: { id: shared.id, challenge: shared.challenge } };
    },

    async retire(actor, profile) {
      const none = () => new HttpError(409, "the Enrollment Profile holds no previous Shared Challenge that has not expired");
      if (!holdsValidPrevious(profile, clock())) throw none();
      return unitOfWork.run(actor, async (tx, change) => {
        const current = await locked(tx, profile.id);
        if (!holdsValidPrevious(current, change.occurredAt)) throw none();
        const [row] = await tx.update(enrollmentProfile).set(NO_PREVIOUS_SHARED_CHALLENGE).where(eq(enrollmentProfile.id, profile.id)).returning();
        await change.audit({
          organizationId: current.organizationId,
          action: "enrollment_profile.shared_challenge_retired",
          target: { type: "enrollment_profile", id: profile.id },
          detail: { name: current.name, sharedChallenge: { id: current.previousSharedChallengeId }, expired: false },
        });
        return row!;
      });
    },

    expire,
  };
}

export const sharedChallenge: EnrollmentValidatorKind<Record<string, never>> = {
  settings: z.object({}).strict(),
  vouchesForNames: false,
  allowsRenewal: true,
  usesSharedChallenge: true,
  create: () => ({
    // Only what the platform let through reaches it: a PKCSReq with the Shared Challenge, or a RenewalReq.
    async validate() {
      return { allowed: true };
    },
    async issued() {},
    async failed() {},
    async test() {
      return { note: "The Shared Challenge kind has no external service to reach: the platform checks the Shared Challenge itself." };
    },
  }),
};
