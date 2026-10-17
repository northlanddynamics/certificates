// The Shared Challenge: the one secret every device enrolling under an Enrollment Profile presents, for the Shared
// Challenge kind of Enrollment Validator, where the device's manager (such as Iru, formerly Kandji, or network gear) can
// give no per-device challenge (ADR 0008). It belongs to the profile, not to a validator: the platform makes it when the
// profile is created, shows it once, keeps only its hash (as it does an Agent's credential), and checks a PKCSReq's
// challengePassword against it, in constant time, before the validator is asked (scep.ts). A rotation makes a new one,
// shown once, and keeps the old one as the previous, which devices may still present until it expires or is retired
// (enrollment-profiles.ts, shared-challenge-expiry.ts), so a profile holds at most two. A RenewalReq is not checked:
// its signature by the device's current Device Certificate is the proof. Nor is the validator told of outcomes, which
// would keep the CSR, and so the challenge, in the platform's database.
//
// The kind itself checks nothing more: it does not vouch for names, allows renewal, and has no settings, secret,
// revocation feed or device ID, so what a holder of the challenge gets is bounded by the profile's Name Rules, if any,
// and its Issuing CA's Permitted Name Rules.
import { z } from "@hono/zod-openapi";
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { EnrollmentValidatorKind } from "./enrollment-validator";
import { sha256Hex } from "./sha256";

/**
 * A new Shared Challenge, with its id and the hash that is kept of it: 192 bits of randomness as lower-case hex, which
 * a CSR's challengePassword (a PrintableString) and Iru's form both take.
 */
export function newSharedChallenge() {
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

/** A profile's Shared Challenges, as the platform keeps them. */
export interface HeldSharedChallenges {
  sharedChallengeId: string | null;
  sharedChallengeHash: string | null;
  previousSharedChallengeId: string | null;
  previousSharedChallengeHash: string | null;
  previousSharedChallengeExpiresAt: Date | null;
}

/** What clears a profile's previous Shared Challenge, when it is retired or expires. */
export const NO_PREVIOUS_SHARED_CHALLENGE = { previousSharedChallengeId: null, previousSharedChallengeHash: null, previousSharedChallengeExpiresAt: null };

/** Whether the profile's previous Shared Challenge may still be presented at `now`: it has one, and it has not expired. */
export const holdsValidPrevious = (held: HeldSharedChallenges, now: Date) => held.previousSharedChallengeExpiresAt !== null && held.previousSharedChallengeExpiresAt > now;

/**
 * The id of the profile's Shared Challenge a device presented at `now`: its current one, or its previous one while that
 * has not expired. None when it presented neither. Both are compared, whichever matches, so that the time taken says
 * nothing of which.
 */
export function presentedSharedChallenge(presented: string | undefined, held: HeldSharedChallenges, now: Date): string | undefined {
  if (presented === undefined) return undefined;
  const current = isSharedChallenge(presented, held.sharedChallengeHash);
  const previous = isSharedChallenge(presented, held.previousSharedChallengeHash) && holdsValidPrevious(held, now);
  return current ? held.sharedChallengeId! : previous ? held.previousSharedChallengeId! : undefined;
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
