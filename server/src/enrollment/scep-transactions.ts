// SCEP transactions (RFC 8894, 3.2.1.1): a device that sends a request again, because it never got the answer, or asks
// after it with GetCertInitial, is answered with what its transaction was first answered, and nothing is issued twice.
// Each transaction ID is an Enrollment Profile's own. The request that decides a transaction claims it first, so that
// another request for it, even on another server, waits for that answer rather than deciding it too; a claim left
// undecided for long (its server stopped) is taken over. A refusal that may not hold next time is released, not kept.
// A transaction of a profile on an ADCS CA is decided, then pending while an Agent asks ADCS for its Device Certificate
// (`pending`): it is answered PENDING until that request ends, when it is answered as it ended (`answer`).
import { and, eq, isNull, lt } from "drizzle-orm";
import type { Db, Tx } from "../platform/db/client";
import { deviceCertificate, scepTransaction } from "../platform/db/schema";

/** What a transaction was answered: the PEM of the Device Certificate it was issued, or why it was refused; or that it waits for ADCS. */
export type ScepAnswer = { issuedPem: string } | { refusal: string } | { pending: true };

/** What a transaction that waits for ADCS was decided with, which its Device Certificate records once it is issued. */
export type ScepDecided = NonNullable<typeof scepTransaction.$inferSelect.decided>;

/**
 * A transaction this request claimed and decides; record its answer in the change that issues or refuses it. A claim
 * another request took over once it was abandoned is no longer this request's: its answer is not recorded.
 */
export interface ScepClaim {
  id: string;
  claimedAt: Date;
}

/** What `issued` throws when the claim was taken over, so that the change issuing the Device Certificate rolls back. */
export class ScepClaimLost extends Error {}

/** How long a claim may stay undecided before another request takes it over; longer than any request is decided in. */
const ABANDONED_MS = 5 * 60_000;
/** How long a request waits for another's answer to the same transaction, and how often it looks. */
const WAIT_MS = 60_000;
const LOOK_EVERY_MS = 100;

export function createScepTransactions({ db, clock }: { db: Db; clock: () => Date }) {
  type Row = typeof scepTransaction.$inferSelect;
  const of = (profile: { id: string }, transactionId: string) => and(eq(scepTransaction.enrollmentProfileId, profile.id), eq(scepTransaction.transactionId, transactionId));
  /** The claim's row while it is still this request's and undecided. */
  const held = (claim: ScepClaim) => and(eq(scepTransaction.id, claim.id), eq(scepTransaction.claimedAt, claim.claimedAt), isNull(scepTransaction.deviceCertificateId), isNull(scepTransaction.refusal));

  async function answerOf(row: Row): Promise<ScepAnswer | undefined> {
    if (row.refusal !== null) return { refusal: row.refusal };
    if (row.deviceCertificateId === null) return row.adcsRequestId === null ? undefined : { pending: true };
    const [issued] = await db.select({ pem: deviceCertificate.certificatePem }).from(deviceCertificate).where(eq(deviceCertificate.id, row.deviceCertificateId));
    return { issuedPem: issued!.pem };
  }

  return {
    /**
     * Claims the profile's transaction for this request to decide; or, when another request claimed it, its answer once
     * there is one. When none comes in time the request is answered that it is still being decided.
     */
    async claim(profile: { id: string; organizationId: string }, transactionId: string): Promise<{ claim: ScepClaim } | { answer: ScepAnswer } | { deciding: true }> {
      const deadline = Date.now() + WAIT_MS;
      for (;;) {
        const now = clock();
        const [claimed] = await db
          .insert(scepTransaction)
          .values({ organizationId: profile.organizationId, enrollmentProfileId: profile.id, transactionId, claimedAt: now })
          .onConflictDoNothing()
          .returning({ id: scepTransaction.id, claimedAt: scepTransaction.claimedAt });
        if (claimed) return { claim: claimed };
        // Taken over only while undecided and abandoned; of two requests doing so at once, the update lets one through.
        const [takenOver] = await db
          .update(scepTransaction)
          .set({ claimedAt: now })
          .where(
            and(
              of(profile, transactionId),
              isNull(scepTransaction.deviceCertificateId),
              isNull(scepTransaction.refusal),
              isNull(scepTransaction.adcsRequestId),
              lt(scepTransaction.claimedAt, new Date(now.getTime() - ABANDONED_MS)),
            ),
          )
          .returning({ id: scepTransaction.id, claimedAt: scepTransaction.claimedAt });
        if (takenOver) return { claim: takenOver };
        const [row] = await db.select().from(scepTransaction).where(of(profile, transactionId));
        const answer = row && (await answerOf(row));
        if (answer) return { answer };
        if (Date.now() >= deadline) return { deciding: true };
        await new Promise((resolve) => setTimeout(resolve, LOOK_EVERY_MS));
      }
    },

    /** The profile's transaction's answer, for GetCertInitial: none when it never had it, `deciding` while it is decided. */
    async find(profile: { id: string }, transactionId: string): Promise<ScepAnswer | { deciding: true } | undefined> {
      const [row] = await db.select().from(scepTransaction).where(of(profile, transactionId));
      if (!row) return undefined;
      return (await answerOf(row)) ?? { deciding: true };
    },

    /** Records, in the change that stores it, that the claimed transaction was issued the Device Certificate; throws ScepClaimLost when the claim was taken over. */
    async issued(tx: Tx, claim: ScepClaim, deviceCertificateId: string) {
      const recorded = await tx.update(scepTransaction).set({ deviceCertificateId }).where(held(claim)).returning({ id: scepTransaction.id });
      if (recorded.length === 0) throw new ScepClaimLost(`the SCEP transaction claim ${claim.id} was taken over`);
    },

    /** Records, in the change that refuses it, why the claimed transaction was refused; nothing when the claim was taken over. */
    async refused(tx: Tx, claim: ScepClaim, refusal: string) {
      await tx.update(scepTransaction).set({ refusal }).where(held(claim));
    },

    /**
     * Records, in the change that submits it, that the claimed transaction waits for the ADCS request (by its id), and
     * what it was decided with; throws ScepClaimLost when the claim was taken over.
     */
    async pending(tx: Tx, claim: ScepClaim, adcsRequestId: string, decided: ScepDecided) {
      const recorded = await tx.update(scepTransaction).set({ adcsRequestId, decided }).where(held(claim)).returning({ id: scepTransaction.id });
      if (recorded.length === 0) throw new ScepClaimLost(`the SCEP transaction claim ${claim.id} was taken over`);
    },

    /** The transaction that waits for the ADCS request (by its id), locked, while it still waits; none once it is answered. */
    async waiting(tx: Tx, adcsRequestId: string) {
      const [row] = await tx.select().from(scepTransaction).where(eq(scepTransaction.adcsRequestId, adcsRequestId)).for("update");
      return row && row.deviceCertificateId === null && row.refusal === null ? row : undefined;
    },

    /** Records, in the change that learned it, what the transaction that waited for ADCS (`waiting`) is answered. */
    async answer(tx: Tx, waiting: Row, answer: { deviceCertificateId: string } | { refusal: string }) {
      await tx.update(scepTransaction).set(answer).where(eq(scepTransaction.id, waiting.id));
    },

    /** Gives the claimed transaction up undecided, so that the device's next request for it is decided afresh. */
    async release(tx: Db | Tx, claim: ScepClaim) {
      await tx.delete(scepTransaction).where(held(claim));
    },
  };
}

export type ScepTransactions = ReturnType<typeof createScepTransactions>;
