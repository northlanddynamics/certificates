// The Shared Challenge: the one secret every device enrolling under an Enrollment Profile presents, for the Shared
// Challenge kind of Enrollment Validator, where the device's manager (such as Iru, formerly Kandji, or network gear) can
// give no per-device challenge (ADR 0008). It belongs to the profile, not to a validator: the platform makes it when the
// profile is created, shows it once, keeps only its hash (as it does an Agent's credential), and checks a PKCSReq's
// challengePassword against it, in constant time, before the validator is asked (scep.ts). A RenewalReq is not checked:
// its signature by the device's current Device Certificate is the proof. Nor is the validator told of outcomes, which
// would keep the CSR, and so the challenge, in the platform's database.
//
// The kind itself checks nothing more: it does not vouch for names, allows renewal, and has no settings, secret,
// revocation feed or device ID, so what a holder of the challenge gets is bounded by the profile's Name Rules, if any,
// and its Issuing CA's Permitted Name Rules.
import { z } from "@hono/zod-openapi";
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { EnrollmentValidatorKind } from "./enrollment-validator";

/**
 * A new Shared Challenge, with its id and the hash that is kept of it: 192 bits of randomness as lower-case hex, which
 * a CSR's challengePassword (a PrintableString) and Iru's form both take.
 */
export function newSharedChallenge() {
  const challenge = randomBytes(24).toString("hex");
  return { id: randomUUID(), challenge, hash: hashOf(challenge) };
}

const hashOf = (challenge: string) => createHash("sha256").update(challenge).digest("hex");

/** Whether the challenge a device presented is the one `hash` was kept of, compared in constant time; never when there is no hash. */
export function isSharedChallenge(presented: string | undefined, hash: string | null): boolean {
  if (presented === undefined || hash === null) return false;
  return timingSafeEqual(Buffer.from(hashOf(presented), "hex"), Buffer.from(hash, "hex"));
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
