// Running Enrollment Validators (enrollment-validator.ts) for Enrollment Profiles: opening a profile's validator with its
// settings and secret, telling validators what became of requests, and pulling their revocation feeds.
//
// What a validator is told is queued on the transaction of what it tells of (the issued Device Certificate, the refusal,
// the Revocations) and told afterwards by the delivery pass: a job queue in Postgres, like notices (notifications.ts), so
// that a device is never kept waiting for it, a validator that cannot be reached is told again later, and nothing is told
// of a change that rolled back. A revocation feed is pulled by its own pass, at most as often as its kind allows; each
// Revocation it asks for is matched by serial and issuer among the Device Certificates of the profiles that share the
// feed, revoked with its Issuing CA's CRL published in the same change, and its outcome told back the same way.
import * as x509 from "@peculiar/x509";
import { and, asc, eq, inArray, lte, sql } from "drizzle-orm";
import type { Db, Tx } from "./db/client";
import { deviceCertificate, enrollmentProfile, enrollmentValidatorFeed, enrollmentValidatorMessage, issuingCa } from "./db/schema";
import type { DecidedRequest, EnrollmentValidator, EnrollmentValidators, IssuedDeviceCertificate, RevocationOutcome, RevocationRequest } from "./enrollment-validator";
import type { PrivateCas } from "./private-ca";
import type { Secrets } from "./secrets";
import type { Change, UnitOfWork } from "./unit-of-work";

type ProfileRow = typeof enrollmentProfile.$inferSelect;
type MessageRow = typeof enrollmentValidatorMessage.$inferSelect;

/** A message that could not be told is tried again after these waits, then given up. */
const RETRY_DELAYS_MS = [60_000, 5 * 60_000, 30 * 60_000, 2 * 3_600_000, 6 * 3_600_000, 24 * 3_600_000];
/** How long a message being told is left alone by other passes; a pass that stopped while telling it has it told again after this. */
const LEASE_MS = 5 * 60_000;

export interface EnrollmentValidatorRuns {
  /** The profile's validator, running with its settings and secret. Throws when the platform does not run its kind, or its configuration can no longer be used. */
  open(db: Db | Tx, profile: ProfileRow): Promise<EnrollmentValidator>;
  /** Queues telling the profile's validator that the request was issued the certificate, on the transaction that stores it. */
  tellIssued(tx: Tx, change: Change, profile: ProfileRow, request: DecidedRequest, certificate: IssuedDeviceCertificate): Promise<void>;
  /** Queues telling the profile's validator that a request it was asked about was refused, on the transaction that records the refusal. */
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

export function createEnrollmentValidatorRuns(deps: { db: Db; unitOfWork: UnitOfWork; secrets: Secrets; privateCas: PrivateCas; kinds: EnrollmentValidators; clock: () => Date }): EnrollmentValidatorRuns {
  const { db, unitOfWork, secrets, privateCas, kinds, clock } = deps;

  async function open(db: Db | Tx, profile: ProfileRow) {
    const kind = Object.hasOwn(kinds, profile.validatorKind) ? kinds[profile.validatorKind]! : undefined;
    if (!kind) throw new Error(`the platform does not run the Enrollment Validator ${profile.validatorKind}`);
    const settings = kind.settings.parse(profile.validatorSettings);
    const secret = profile.validatorSecretId ? await secrets.open(db, profile.organizationId, profile.validatorSecretId) : "";
    return kind.create(settings, secret);
  }

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
    const validator = await open(db, profile!);
    const payload = row.payload;
    if (row.type === "issued") {
      const certificate = payload.certificate as Omit<IssuedDeviceCertificate, "notAfter"> & { notAfter: string };
      await validator.issued(requestOf(payload), { ...certificate, notAfter: new Date(certificate.notAfter) });
    } else if (row.type === "failed") await validator.failed(requestOf(payload), payload.reason as string);
    else {
      if (!validator.revocations) throw new Error(`the Enrollment Validator ${profile!.validatorKind} has no revocation feed`);
      await validator.revocations.report(payload.outcomes as RevocationOutcome[]);
    }
  }

  /** Tells a claimed message and records how that went; returns whether it was told. One that could not be waits to be tried again, or is given up. */
  async function send(row: MessageRow, now: Date) {
    let error: string | null = null;
    try {
      await tell(row);
    } catch (err) {
      error = (err instanceof Error ? err.message : String(err)).replace(/\u0000/g, "").slice(0, 1000);
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

  /**
   * Revokes what the feed asked for among the Device Certificates of `profiles`, publishes the CRL of each Issuing CA
   * that revoked one, and queues telling the feed's validator each outcome: all on the change's transaction.
   */
  async function revoke(tx: Tx, change: Change, profiles: ProfileRow[], requests: RevocationRequest[]) {
    const [first] = profiles;
    const organizationId = first!.organizationId;
    const outcomes: RevocationOutcome[] = [];
    const published = new Set<string>();
    for (const request of requests) {
      const serial = canonicalSerial(request.serial);
      const rows = await tx
        .select({ certificate: deviceCertificate, issuer: issuingCa.subject })
        .from(deviceCertificate)
        .innerJoin(issuingCa, eq(issuingCa.id, deviceCertificate.issuingCaId))
        .where(
          and(
            eq(deviceCertificate.organizationId, organizationId),
            inArray(deviceCertificate.enrollmentProfileId, profiles.map((p) => p.id)),
            sql`ltrim(${deviceCertificate.serial}, '0') = ${serial.replace(/^0+/, "")}`,
          ),
        )
        .orderBy(asc(deviceCertificate.createdAt))
        .for("update", { of: deviceCertificate });
      const matching = rows.filter((r) => request.issuer === undefined || sameName(r.issuer, request.issuer));
      if (matching.length === 0) {
        outcomes.push({ ref: request.ref, outcome: "not_found" });
        continue;
      }
      let revoked = false;
      for (const { certificate } of matching.filter((r) => r.certificate.revokedAt === null)) {
        await tx.update(deviceCertificate).set({ revokedAt: change.occurredAt, revocationReason: request.reason }).where(eq(deviceCertificate.id, certificate.id));
        const profile = profiles.find((p) => p.id === certificate.enrollmentProfileId)!;
        await change.audit({
          organizationId,
          action: "device_certificate.revoked",
          target: { type: "device_certificate", id: certificate.id },
          detail: {
            enrollmentProfile: { id: profile.id, name: profile.name },
            serial: certificate.serial,
            subject: certificate.subject,
            reason: request.reason,
            by: { enrollmentValidator: { kind: profile.validatorKind } },
          },
        });
        published.add(certificate.issuingCaId);
        revoked = true;
      }
      outcomes.push({ ref: request.ref, outcome: revoked ? "revoked" : "already_revoked" });
    }
    for (const issuingCaId of published) await privateCas.publishRevocation(tx, change, organizationId, issuingCaId);
    await queue(tx, change, first!, "revocations", { outcomes });
  }

  /** Pulls the feed the profiles share, when it is due, and acts on what it asks for. Whether it was pulled. */
  async function pullFeed(kindName: string, source: string, profiles: ProfileRow[], intervalMs: number, now: Date) {
    const organizationId = profiles[0]!.organizationId;
    const due = await unitOfWork.run(null, async (tx) => {
      await tx.insert(enrollmentValidatorFeed).values({ organizationId, validatorKind: kindName, source, nextPullAt: now }).onConflictDoNothing();
      const [feed] = await tx
        .select()
        .from(enrollmentValidatorFeed)
        .where(and(eq(enrollmentValidatorFeed.organizationId, organizationId), eq(enrollmentValidatorFeed.validatorKind, kindName), eq(enrollmentValidatorFeed.source, source)))
        .for("update");
      if (feed!.nextPullAt > now) return false;
      // Counted from the pull being asked for, whether or not it succeeds: a kind's interval is how often its service may be asked.
      await tx
        .update(enrollmentValidatorFeed)
        .set({ lastPulledAt: now, nextPullAt: new Date(now.getTime() + intervalMs) })
        .where(and(eq(enrollmentValidatorFeed.organizationId, organizationId), eq(enrollmentValidatorFeed.validatorKind, kindName), eq(enrollmentValidatorFeed.source, source)));
      return true;
    });
    if (!due) return false;
    const validator = await open(db, profiles[0]!);
    if (!validator.revocations) throw new Error(`the Enrollment Validator ${kindName} has no revocation feed`);
    const requests = await validator.revocations.pull();
    if (requests.length === 0) return true;
    try {
      await unitOfWork.run(null, (tx, change) => revoke(tx, change, profiles, requests));
    } catch (err) {
      // What was pulled is not asked for again, so it is answered either way: as failed, which the validator may ask again.
      console.error("could not revoke what an Enrollment Validator's feed asked for", err);
      const message = "the platform could not revoke it; ask again";
      await unitOfWork.run(null, (tx, change) => queue(tx, change, profiles[0]!, "revocations", { outcomes: requests.map((r) => ({ ref: r.ref, outcome: "failed", message })) }));
    }
    return true;
  }

  return {
    open,
    tellIssued: (tx, change, profile, request, certificate) => queue(tx, change, profile, "issued", { request: requestPayload(request), certificate: { ...certificate, notAfter: certificate.notAfter.toISOString() } }),
    tellFailed: (tx, change, profile, request, reason) => queue(tx, change, profile, "failed", { request: requestPayload(request), reason }),

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
      const fed = Object.entries(kinds).filter(([, kind]) => kind.revocationFeed);
      if (fed.length === 0) return 0;
      // Every Organization's: the pass is the platform's own, and each feed is pulled for its own Organization's profiles only.
      const rows = await db
        .select()
        .from(enrollmentProfile)
        .where(inArray(enrollmentProfile.validatorKind, fed.map(([name]) => name)))
        .orderBy(asc(enrollmentProfile.createdAt), asc(enrollmentProfile.id));
      const feeds = new Map<string, { kindName: string; source: string; intervalMs: number; profiles: ProfileRow[] }>();
      for (const row of rows) {
        const kind = kinds[row.validatorKind]!;
        // A profile whose stored settings can no longer be read feeds nothing.
        const settings = kind.settings.safeParse(row.validatorSettings);
        if (!settings.success) continue;
        const source = kind.revocationFeed!.sourceOf(settings.data);
        const key = JSON.stringify([row.organizationId, row.validatorKind, source]);
        const feed = feeds.get(key) ?? { kindName: row.validatorKind, source, intervalMs: kind.revocationFeed!.intervalMs, profiles: [] };
        feed.profiles.push(row);
        feeds.set(key, feed);
      }
      let pulled = 0;
      for (const { kindName, source, intervalMs, profiles } of feeds.values()) {
        try {
          if (await pullFeed(kindName, source, profiles, intervalMs, now)) pulled++;
        } catch (err) {
          console.error(`could not pull the revocation feed of an Enrollment Validator ${kindName}`, err);
        }
      }
      return pulled;
    },
  };
}
