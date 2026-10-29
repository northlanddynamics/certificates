// Running Enrollment Validators (enrollment-validator.ts) for Enrollment Profiles: opening a profile's validator with its
// settings and secret, telling validators what became of requests, and pulling their revocation feeds.
//
// What a validator is told is queued on the transaction of what it tells of (the issued Device Certificate, the refusal,
// the Revocations) and told afterwards by the delivery pass: a job queue in Postgres, like notices (notifications.ts), so
// that a device is never kept waiting for it, a validator that cannot be reached is told again later, and nothing is told
// of a change that rolled back. A revocation feed is pulled by its own pass, at most as often as its kind allows, and what
// it hands over is stored at once, since it is not handed over again; each stored Revocation is then matched by serial
// and issuer among the Device Certificates of the profiles that share the feed, revoked with its Issuing CA's CRL
// published in the same change (device-certificate-revocation.ts), and its outcome told back the same way. One from an
// ADCS CA is revoked only once an Agent reports that ADCS did, so it is kept until then and told on the pass after; a
// refusal is tried again as a change that rolls back is, up to the same count. Profiles that share a feed may hold
// different secrets (one rotated, one not yet), so the feed is pulled and told with the first whose validator works.
//
// Of an error a validator throws, only what describeValidatorError allows is shown, kept or logged.
import * as x509 from "@peculiar/x509";
import { and, asc, eq, inArray, isNotNull, isNull, lte, sql } from "drizzle-orm";
import type { Db, Tx } from "../platform/db/client";
import { deviceCertificate, enrollmentProfile, enrollmentValidatorFeed, enrollmentValidatorMessage, enrollmentValidatorRevocationRequest, issuingCa, revocationRequest } from "../platform/db/schema";
import type { DeviceCertificateRevocations } from "./device-certificate-revocation";
import {
  EnrollmentValidatorError,
  describeValidatorError,
  type DecidedRequest,
  type EnrollmentValidator,
  type EnrollmentValidators,
  type IssuedDeviceCertificate,
  kindOf,
  kindsOf,
  type RevocationOutcome,
  type RevocationRequest,
} from "./enrollment-validator";
import type { Secrets } from "../platform/crypto/secrets";
import type { Change, UnitOfWork } from "../platform/unit-of-work";
import { CertificateAuthorityError } from "../issuance/acme/certificate-authority";

type ProfileRow = typeof enrollmentProfile.$inferSelect;
type MessageRow = typeof enrollmentValidatorMessage.$inferSelect;

/** A message that could not be told is tried again after each of these waits in turn, then given up (`failed`). */
const RETRY_DELAYS_MS = [60_000, 5 * 60_000, 30 * 60_000, 2 * 3_600_000, 6 * 3_600_000, 24 * 3_600_000];
/** How long a message being told is left alone by other passes; a pass that stopped while telling it has it told again after this. */
const LEASE_MS = 5 * 60_000;
/** How many changes may try to act on a pulled Revocation and roll back before it is answered as failed. */
const REVOCATION_ATTEMPTS = 5;

export interface EnrollmentValidatorRuns {
  /** The profile's validator, running with its settings and secret. Throws when the platform does not run its kind, or its configuration can no longer be used. */
  open(db: Db | Tx, profile: ProfileRow): Promise<EnrollmentValidator>;
  /**
   * Queues telling the profile's validator that the request was issued the certificate, on the transaction that stores
   * it. Nothing is queued for a kind that uses a Shared Challenge (shared-challenge.ts): the request's CSR holds it as its
   * challengePassword, and the platform never keeps it.
   */
  tellIssued(tx: Tx, change: Change, profile: ProfileRow, request: DecidedRequest, certificate: IssuedDeviceCertificate): Promise<void>;
  /** Queues telling the profile's validator that a request it was asked about was refused, on the transaction that records the refusal; as `tellIssued`, never for a kind that uses a Shared Challenge. */
  tellFailed(tx: Tx, change: Change, profile: ProfileRow, request: DecidedRequest, reason: string): Promise<void>;
  /** One pass at the clock's time: tells validators what is due. Returns how many messages were told. */
  deliver(): Promise<number>;
  /** One pass at the clock's time: pulls each revocation feed that is due and revokes what it asks for. Returns how many feeds were pulled. */
  pollFeeds(): Promise<number>;
}

const requestOf = (payload: Record<string, unknown>): DecidedRequest => {
  const request = payload.request as { csr: string; transactionId: string };
  return { csr: new Uint8Array(Buffer.from(request.csr, "base64")), transactionId: request.transactionId };
};
const requestPayload = (request: DecidedRequest) => ({ csr: Buffer.from(request.csr).toString("base64"), transactionId: request.transactionId });

/** Whether two distinguished names (RFC 4514) are the same name, however each is spaced. */
function sameName(a: string, b: string) {
  const canonical = (name: string) => {
    try {
      return JSON.stringify(new x509.Name(name).toJSON()).toLowerCase();
    } catch {
      return name.toLowerCase();
    }
  };
  return canonical(a) === canonical(b);
}

/** A serial as hex in upper case, without separators or leading zeros, so that the forms validators send compare. */
const canonicalSerial = (serial: string) => serial.toUpperCase().replace(/[^0-9A-F]/g, "").replace(/^0+(?=.)/, "");

export function createEnrollmentValidatorRuns(deps: { db: Db; unitOfWork: UnitOfWork; secrets: Secrets; revocations: DeviceCertificateRevocations; kinds: EnrollmentValidators; clock: () => Date }): EnrollmentValidatorRuns {
  const { db, unitOfWork, secrets, revocations, kinds, clock } = deps;

  async function open(db: Db | Tx, profile: ProfileRow) {
    const kind = kindOf(kinds, profile.validatorKind);
    if (!kind) throw new EnrollmentValidatorError(`the platform does not run the Enrollment Validator ${profile.validatorKind}`);
    const settings = kind.settings.safeParse(profile.validatorSettings);
    if (!settings.success) throw new EnrollmentValidatorError(`the Enrollment Validator's stored settings can no longer be used`);
    const secret = profile.validatorSecretId ? await secrets.open(db, profile.organizationId, profile.validatorSecretId) : "";
    return kind.create(settings.data, secret);
  }

  /** The profiles of the Organization whose validators share the feed of this kind from this source, oldest first. */
  async function sharing(organizationId: string, kindName: string, source: string) {
    const kind = kindOf(kinds, kindName);
    if (!kind?.revocationFeed) return [];
    const rows = await db
      .select()
      .from(enrollmentProfile)
      .where(and(eq(enrollmentProfile.organizationId, organizationId), eq(enrollmentProfile.validatorKind, kindName)))
      .orderBy(asc(enrollmentProfile.createdAt), asc(enrollmentProfile.id));
    return rows.filter((row) => {
      const settings = kind.settings.safeParse(row.validatorSettings);
      return settings.success && kind.revocationFeed!.sourceOf(settings.data) === source;
    });
  }

  /** Does `work` with the feed of the first of the profiles whose validator works; throws the last validator's error when none does. */
  async function withFeed<T>(profiles: ProfileRow[], work: (feed: NonNullable<EnrollmentValidator["revocations"]>) => Promise<T>): Promise<T> {
    let last: unknown = new EnrollmentValidatorError("no Enrollment Profile shares the feed any more");
    for (const profile of profiles) {
      try {
        const validator = await open(db, profile);
        if (!validator.revocations) throw new EnrollmentValidatorError(`the Enrollment Validator ${profile.validatorKind} has no revocation feed`);
        return await work(validator.revocations);
      } catch (err) {
        last = err;
      }
    }
    throw last;
  }

  const usesSharedChallenge = (profile: ProfileRow) => kindOf(kinds, profile.validatorKind)?.usesSharedChallenge === true;

  const queue = async (tx: Tx, change: Change, profile: ProfileRow, type: MessageRow["type"], payload: Record<string, unknown>) => {
    await tx.insert(enrollmentValidatorMessage).values({ organizationId: profile.organizationId, enrollmentProfileId: profile.id, type, payload, nextAttemptAt: change.occurredAt, createdAt: change.occurredAt });
  };

  /** Takes the next message that is due, if there is one, and leases it, as notices are (notifications.ts). Nothing is told while a transaction is open. */
  function claimNext(now: Date) {
    return unitOfWork.run(null, async (tx) => {
      const [row] = await tx
        .select()
        .from(enrollmentValidatorMessage)
        .where(and(eq(enrollmentValidatorMessage.status, "queued"), lte(enrollmentValidatorMessage.nextAttemptAt, now)))
        .orderBy(asc(enrollmentValidatorMessage.nextAttemptAt), asc(enrollmentValidatorMessage.createdAt), asc(enrollmentValidatorMessage.id))
        .limit(1)
        .for("update", { skipLocked: true });
      if (!row) return null;
      const attempts = row.attempts + 1;
      await tx.update(enrollmentValidatorMessage).set({ attempts, nextAttemptAt: new Date(now.getTime() + LEASE_MS) }).where(eq(enrollmentValidatorMessage.id, row.id));
      return { ...row, attempts };
    });
  }

  async function tell(row: MessageRow) {
    const [profile] = await db.select().from(enrollmentProfile).where(and(eq(enrollmentProfile.id, row.enrollmentProfileId), eq(enrollmentProfile.organizationId, row.organizationId)));
    const payload = row.payload;
    if (row.type === "revocations") {
      const others = await sharing(row.organizationId, profile!.validatorKind, payload.source as string);
      await withFeed([profile!, ...others.filter((p) => p.id !== profile!.id)], (feed) => feed.report(payload.outcomes as RevocationOutcome[]));
      return;
    }
    const validator = await open(db, profile!);
    if (row.type === "issued") {
      const certificate = payload.certificate as Omit<IssuedDeviceCertificate, "notAfter"> & { notAfter: string };
      await validator.issued(requestOf(payload), { ...certificate, notAfter: new Date(certificate.notAfter) });
    } else await validator.failed(requestOf(payload), payload.reason as string);
  }

  /** Tells a claimed message and records how that went; returns whether it was told. One that could not be waits to be tried again, or is given up. */
  async function send(row: MessageRow, now: Date) {
    let error: string | null = null;
    try {
      await tell(row);
    } catch (err) {
      error = describeValidatorError(err);
    }
    const wait = RETRY_DELAYS_MS[row.attempts - 1];
    await unitOfWork.run(null, (tx) =>
      tx
        .update(enrollmentValidatorMessage)
        .set(
          error === null
            ? { status: "sent", sentAt: now, lastError: null }
            : { lastError: error, ...(wait === undefined ? { status: "failed" as const } : { nextAttemptAt: new Date(now.getTime() + wait) }) },
        )
        .where(eq(enrollmentValidatorMessage.id, row.id)),
    );
    return error === null;
  }

  type Feed = { organizationId: string; kindName: string; source: string; intervalMs: number; profiles: ProfileRow[] };
  const ofFeed = <T extends { organizationId: any; validatorKind: any; source: any }>(table: T, feed: Feed) =>
    and(eq(table.organizationId, feed.organizationId), eq(table.validatorKind, feed.kindName), eq(table.source, feed.source));
  type StoredRequest = typeof enrollmentValidatorRevocationRequest.$inferSelect;
  /** A stored request with what the feed is told of it. */
  type Answered = { request: StoredRequest; outcome: RevocationOutcome };

  /** The Device Certificates of the feed's profiles the request asks for, by serial and issuer, oldest first, with where their Revocation stands. */
  async function matching(tx: Tx, feed: Feed, request: StoredRequest) {
    const serial = canonicalSerial(request.serial);
    const rows = await tx
      .select({
        id: deviceCertificate.id,
        issuer: issuingCa.subject,
        certificatePem: deviceCertificate.certificatePem,
        revokedAt: deviceCertificate.revokedAt,
        requestStatus: revocationRequest.status,
        failureMessage: revocationRequest.failureMessage,
      })
      .from(deviceCertificate)
      .leftJoin(issuingCa, eq(issuingCa.id, deviceCertificate.issuingCaId))
      .leftJoin(revocationRequest, eq(revocationRequest.deviceCertificateId, deviceCertificate.id))
      .where(
        and(
          eq(deviceCertificate.organizationId, feed.organizationId),
          inArray(deviceCertificate.enrollmentProfileId, feed.profiles.map((p) => p.id)),
          sql`ltrim(${deviceCertificate.serial}, '0') = ${serial.replace(/^0+/, "")}`,
        ),
      )
      .orderBy(asc(deviceCertificate.createdAt));
    // One from an ADCS CA names its issuer itself.
    const issuerOf = (r: (typeof rows)[number]) => r.issuer ?? new x509.X509Certificate(r.certificatePem).issuer;
    return rows.filter((r) => request.issuer === null || sameName(issuerOf(r), request.issuer));
  }

  /** Queues telling the feed the outcomes, and forgets the requests they answer: on the change's transaction. */
  async function answer(tx: Tx, change: Change, feed: Feed, answered: Answered[]) {
    if (answered.length === 0) return;
    await tx.delete(enrollmentValidatorRevocationRequest).where(inArray(enrollmentValidatorRevocationRequest.id, answered.map((a) => a.request.id)));
    await queue(tx, change, feed.profiles[0]!, "revocations", { source: feed.source, outcomes: answered.map((a) => a.outcome) });
  }

  /**
   * Revokes what the feed asked for among the Device Certificates of its profiles, with the CRL of each Issuing CA that
   * revoked one, and queues telling the feed each outcome: all on the change's transaction. One whose CA confirms later
   * (or was already asked to by someone else) is kept, marked asked, and answered once that CA has (`settle`).
   */
  async function revoke(tx: Tx, change: Change, feed: Feed, requests: StoredRequest[]) {
    const asked: { request: StoredRequest; matched: Awaited<ReturnType<typeof matching>> }[] = [];
    for (const request of requests) asked.push({ request, matched: await matching(tx, feed, request) });
    const by = { enrollmentValidator: { kind: feed.kindName } };
    const revoked = await revocations.revoke(
      tx,
      change,
      feed.organizationId,
      asked.flatMap(({ request, matched }) => matched.map(({ id }) => ({ id, reason: request.reason, by }))),
    );
    // `revoked` answers for the requests' Device Certificates in turn.
    let next = 0;
    const answered: Answered[] = [];
    for (const { request, matched } of asked) {
      const ofRequest = revoked.slice(next, next + matched.length);
      next += matched.length;
      const { ref } = request;
      if (matched.length === 0) answered.push({ request, outcome: { ref, outcome: "not_found" } });
      else if (ofRequest.includes("requested") || matched.some((m) => m.requestStatus === "pending")) {
        await tx.update(enrollmentValidatorRevocationRequest).set({ askedAt: change.occurredAt }).where(eq(enrollmentValidatorRevocationRequest.id, request.id));
      } else answered.push({ request, outcome: { ref, outcome: ofRequest.includes(true) ? "revoked" : "already_revoked" } });
    }
    await answer(tx, change, feed, answered);
  }

  /**
   * Answers what the feed asked for of a CA that confirms later, once that CA has: revoked, or failed, which counts as a
   * try and is asked again by the next `revoke` until it was tried too often, when it is answered as failed. One whose
   * CA has yet to answer is left waiting. All on the change's transaction.
   */
  async function settle(tx: Tx, change: Change, feed: Feed, requests: StoredRequest[]) {
    const answered: Answered[] = [];
    for (const request of requests) {
      const matched = await matching(tx, feed, request);
      if (matched.some((m) => m.requestStatus === "pending")) continue;
      const { ref } = request;
      const failed = matched.find((m) => m.revokedAt === null && m.requestStatus === "failed");
      if (failed || matched.some((m) => m.revokedAt === null)) {
        // Not revoked: a try, which is asked again unless it was tried too often.
        if (request.attempts + 1 >= REVOCATION_ATTEMPTS) {
          answered.push({ request, outcome: { ref, outcome: "failed", message: `its CA did not revoke it: ${failed?.failureMessage ?? "it gave no answer"}` } });
        } else {
          await tx
            .update(enrollmentValidatorRevocationRequest)
            .set({ askedAt: null, attempts: sql`${enrollmentValidatorRevocationRequest.attempts} + 1` })
            .where(eq(enrollmentValidatorRevocationRequest.id, request.id));
        }
      } else answered.push({ request, outcome: { ref, outcome: matched.length > 0 ? "revoked" : "not_found" } });
    }
    await answer(tx, change, feed, answered);
  }

  /** Pulls the feed when it is due and stores what it hands over. Whether it was pulled. */
  async function pullFeed(feed: Feed, now: Date) {
    const due = await unitOfWork.run(null, async (tx) => {
      await tx.insert(enrollmentValidatorFeed).values({ organizationId: feed.organizationId, validatorKind: feed.kindName, source: feed.source, nextPullAt: now }).onConflictDoNothing();
      const [state] = await tx.select().from(enrollmentValidatorFeed).where(ofFeed(enrollmentValidatorFeed, feed)).for("update");
      if (state!.nextPullAt > now) return false;
      // Counted from the pull being asked for, whether or not it succeeds: a kind's interval is how often its service may be asked.
      await tx.update(enrollmentValidatorFeed).set({ lastPulledAt: now, nextPullAt: new Date(now.getTime() + feed.intervalMs) }).where(ofFeed(enrollmentValidatorFeed, feed));
      return true;
    });
    if (!due) return false;
    const requests = await withFeed(feed.profiles, (revocations) => revocations.pull());
    if (requests.length === 0) return true;
    await unitOfWork.run(null, (tx) =>
      tx.insert(enrollmentValidatorRevocationRequest).values(
        requests.map((r: RevocationRequest, position) => ({
          organizationId: feed.organizationId,
          validatorKind: feed.kindName,
          source: feed.source,
          ref: r.ref,
          serial: r.serial,
          issuer: r.issuer ?? null,
          reason: r.reason,
          pulledAt: now,
          position,
        })),
      ),
    );
    return true;
  }

  /**
   * Acts on the Revocations the feed handed over that are still stored: settles those asked of a CA that confirms later,
   * then revokes the rest, or, when that change rolls back, counts the try, answering as failed those tried too often.
   * Each is answered once, on the change that removes it.
   */
  async function actOnPulled(feed: Feed) {
    /** The stored requests, locked: those asked of a CA that confirms later (`awaitingCa`), or the rest. */
    const stored = (tx: Tx, which: "awaitingCa" | "toAsk") =>
      tx
        .select()
        .from(enrollmentValidatorRevocationRequest)
        .where(and(ofFeed(enrollmentValidatorRevocationRequest, feed), which === "awaitingCa" ? isNotNull(enrollmentValidatorRevocationRequest.askedAt) : isNull(enrollmentValidatorRevocationRequest.askedAt)))
        .orderBy(asc(enrollmentValidatorRevocationRequest.pulledAt), asc(enrollmentValidatorRevocationRequest.position))
        .for("update", { skipLocked: true });
    await unitOfWork
      .run(null, async (tx, change) => {
        const rows = await stored(tx, "awaitingCa");
        if (rows.length > 0) await settle(tx, change, feed, rows);
      })
      .catch((err) => console.error(`could not settle what an Enrollment Validator ${feed.kindName}'s feed asked of a CA that confirms later`, err instanceof Error ? err.message : err));
    try {
      await unitOfWork.run(null, async (tx, change) => {
        const rows = await stored(tx, "toAsk");
        if (rows.length > 0) await revoke(tx, change, feed, rows);
      });
    } catch (err) {
      console.error(`could not revoke what an Enrollment Validator ${feed.kindName}'s feed asked for`, err instanceof Error ? err.message : err);
      await unitOfWork.run(null, async (tx, change) => {
        const rows = await stored(tx, "toAsk");
        const givenUp = rows.filter((r) => r.attempts + 1 >= REVOCATION_ATTEMPTS);
        const kept = rows.filter((r) => r.attempts + 1 < REVOCATION_ATTEMPTS);
        if (kept.length > 0) {
          await tx
            .update(enrollmentValidatorRevocationRequest)
            .set({ attempts: sql`${enrollmentValidatorRevocationRequest.attempts} + 1` })
            .where(inArray(enrollmentValidatorRevocationRequest.id, kept.map((r) => r.id)));
        }
        // A CA's own refusal (such as no Agent online to ask ADCS) says why; anything else is the platform's.
        const message = err instanceof CertificateAuthorityError ? `its CA did not revoke it: ${err.message}` : "the platform could not revoke it; ask again";
        await answer(tx, change, feed, givenUp.map((request) => ({ request, outcome: { ref: request.ref, outcome: "failed", message } })));
      });
    }
  }

  return {
    open,
    async tellIssued(tx, change, profile, request, certificate) {
      if (usesSharedChallenge(profile)) return;
      await queue(tx, change, profile, "issued", { request: requestPayload(request), certificate: { ...certificate, notAfter: certificate.notAfter.toISOString() } });
    },
    async tellFailed(tx, change, profile, request, reason) {
      if (usesSharedChallenge(profile)) return;
      await queue(tx, change, profile, "failed", { request: requestPayload(request), reason });
    },

    async deliver() {
      const now = clock();
      let told = 0;
      for (let row = await claimNext(now); row; row = await claimNext(now)) {
        if (await send(row, now)) told++;
      }
      return told;
    },

    async pollFeeds() {
      const now = clock();
      const fed = kindsOf(kinds).filter((kind) => kind.revocationFeed);
      if (fed.length === 0) return 0;
      // Every Organization's: the pass is the platform's own, and each feed is pulled for its own Organization's profiles only.
      const rows = await db
        .select()
        .from(enrollmentProfile)
        .where(inArray(enrollmentProfile.validatorKind, fed.map((kind) => kind.name)))
        .orderBy(asc(enrollmentProfile.createdAt), asc(enrollmentProfile.id));
      const feeds = new Map<string, Feed>();
      for (const row of rows) {
        const kind = kindOf(kinds, row.validatorKind)!;
        // A profile whose stored settings can no longer be read feeds nothing.
        const settings = kind.settings.safeParse(row.validatorSettings);
        if (!settings.success) continue;
        const source = kind.revocationFeed!.sourceOf(settings.data);
        const key = JSON.stringify([row.organizationId, row.validatorKind, source]);
        const feed = feeds.get(key) ?? { organizationId: row.organizationId, kindName: row.validatorKind, source, intervalMs: kind.revocationFeed!.intervalMs, profiles: [] };
        feed.profiles.push(row);
        feeds.set(key, feed);
      }
      let pulled = 0;
      for (const feed of feeds.values()) {
        try {
          if (await pullFeed(feed, now)) pulled++;
        } catch (err) {
          console.error(`could not pull the revocation feed of an Enrollment Validator ${feed.kindName}:`, describeValidatorError(err));
        }
        // Whether or not it was pulled now: what an earlier pass pulled and could not revoke is tried again.
        await actOnPulled(feed).catch((err) => console.error("could not act on a revocation feed", err instanceof Error ? err.message : err));
      }
      return pulled;
    },
  };
}
