// The SCEP server (RFC 8894): public, unauthenticated routes at each Enrollment Profile's opaque public id, where devices
// enroll. ts-scep handles the protocol, running as the profile's RA: it opens each request's envelope with the RA key and
// verifies its signer, and signs the CertRep with the RA key, encrypted to the device. What is issued is decided here,
// per request: a PKCSReq must present the profile's Shared Challenge when it has one (shared-challenge.ts), the
// device's key must be one the profile allows, its names must keep the profile's name rules when it has them, the
// Enrollment Validator must allow the request, and then the Issuing CA signs a
// Device Certificate through the Private CA module, which is stored with its Audit Event in one Unit of Work; for a
// RenewalReq, that Unit of Work also revokes the Device Certificate it was signed with as superseded. A device is
// always answered SUCCESS with its certificate or FAILURE with a failInfo, never PENDING; a refusal is an Audit Event.
// The validator is told the outcome afterwards, in the background (enrollment-validators.ts).
import type { OpenAPIHono } from "@hono/zod-openapi";
import { and, eq } from "drizzle-orm";
import type { Context } from "hono";
import { getConnInfo } from "hono/bun";
import { createHash } from "node:crypto";
import { FailInfo, ScepServer, type EnrollmentRequest as ScepEnrollmentRequest, type ScepResult } from "ts-scep";
import { subjectAltNamesOf } from "./ca-certificates";
import type { Db, Tx } from "./db/client";
import { deviceCertificate, enrollmentProfile } from "./db/schema";
import { DEVICE_EXTENDED_KEY_USAGES, DEVICE_KEY_TYPES, type DeviceKeyType } from "./enrollment-profile-kinds";
import { describeValidatorError, type EnrollmentValidator, type EnrollmentValidators } from "./enrollment-validator";
import type { EnrollmentValidatorRuns } from "./enrollment-validators";
import { IssuanceFailure } from "./issuance-failure";
import { findIssuingCa, type PrivateCas } from "./private-ca";
import { nameRulesRefusal } from "./name-rules";
import type { ScepAnswer, ScepClaim, ScepTransactions } from "./scep-transactions";
import type { Secrets } from "./secrets";
import { isSharedChallenge } from "./shared-challenge";
import type { Change, UnitOfWork } from "./unit-of-work";

type ProfileRow = typeof enrollmentProfile.$inferSelect;
/** The Device Certificate a RenewalReq was signed with, which its replacement supersedes. */
type Renewed = Pick<typeof deviceCertificate.$inferSelect, "id" | "serial" | "subject" | "issuingCaId">;

/** The Device Certificate a RenewalReq was signed with was revoked after the request was checked, so it renews nothing. */
class RevokedMeanwhile extends Error {}

/**
 * How the SCEP routes are rate limited, so that a flood of requests cannot exhaust the platform or a validator's service:
 * at most `perAddress` requests from one source address and `perProfile` to one Enrollment Profile in each window of
 * `windowMs`, every SCEP operation counting. Beyond that a request is answered 429 before it is looked at. The counts are
 * the process's own: each server behind a load balancer counts what reaches it.
 */
export interface ScepConfig {
  windowMs: number;
  perAddress: number;
  perProfile: number;
  /**
   * Whether the source address is the last in X-Forwarded-For, as the TLS terminator in front of the platform adds it,
   * rather than the connection's; set only when there is one, or devices could choose the address they are counted by.
   */
  trustForwardedFor: boolean;
}

/** A device enrolls with three requests or so (GetCACaps, GetCACert, PKIOperation), and many may share a NAT address. */
export const SCEP_DEFAULTS: ScepConfig = { windowMs: 60_000, perAddress: 120, perProfile: 3000, trustForwardedFor: false };

/** Counts requests per key in fixed windows of the clock; `take` answers how many seconds until the key may go on, when it may not now. */
function createRateLimiter(clock: () => Date) {
  let windowStart = 0;
  let counts = new Map<string, number>();
  return {
    take(key: string, limit: number, windowMs: number): number | undefined {
      const now = clock().getTime();
      if (now >= windowStart + windowMs || now < windowStart) {
        windowStart = now - (now % windowMs);
        counts = new Map();
      }
      const count = (counts.get(key) ?? 0) + 1;
      counts.set(key, count);
      return count > limit ? Math.ceil((windowStart + windowMs - now) / 1000) : undefined;
    },
    reset() {
      counts = new Map();
    },
  };
}

/**
 * What GetCACaps advertises (RFC 8894, 3.5.2), with Renewal where the profile's validator allows it. What is accepted is
 * wider, for the clients in the field: SHA-1 signatures and 3DES or single DES content encryption (micromdm's scepclient
 * uses DES whatever it is offered), and RSA-OAEP key transport besides PKCS#1 v1.5 (Windows), which RFC 8894 has no
 * keyword for. CertRep answers with the key transport the request used.
 */
const CAPABILITIES = ["POSTPKIOperation", "SHA-256", "SHA-512", "AES", "SCEPStandard"];

/** The device key's type as a profile names it, such as "rsa-2048"; none for a key no profile can allow. */
function keyTypeOf(request: ScepEnrollmentRequest): DeviceKeyType | undefined {
  const key = request.csr.publicKey;
  const type = `rsa-${key.asymmetricKeyDetails?.modulusLength}`;
  return key.asymmetricKeyType === "rsa" && (DEVICE_KEY_TYPES as readonly string[]).includes(type) ? (type as DeviceKeyType) : undefined;
}

/** The device's key as a refusal names it: its algorithm and size, and its type (`keyTypeOf`) where a profile could allow it. */
function describeKey(request: ScepEnrollmentRequest, type: DeviceKeyType | undefined): string {
  const key = request.csr.publicKey;
  if (key.asymmetricKeyType !== "rsa") return `an ${key.asymmetricKeyType?.toUpperCase() ?? "unknown"} key${key.asymmetricKeyDetails?.namedCurve ? ` (${key.asymmetricKeyDetails.namedCurve})` : ""}`;
  return `a ${key.asymmetricKeyDetails?.modulusLength}-bit RSA key${type ? ` (${type})` : ""}`;
}

export function registerScep(ctx: {
  app: OpenAPIHono;
  db: Db;
  unitOfWork: UnitOfWork;
  secrets: Secrets;
  privateCas: PrivateCas;
  kinds: EnrollmentValidators;
  validators: EnrollmentValidatorRuns;
  transactions: ScepTransactions;
  clock: () => Date;
  /** Read on each request, so that it may be changed while the app runs. */
  config?: Partial<ScepConfig>;
}) {
  const { app, db, unitOfWork, secrets, privateCas, kinds, validators, transactions, clock } = ctx;
  const config = () => ({ ...SCEP_DEFAULTS, ...ctx.config });
  const limiter = createRateLimiter(clock);
  const allowsRenewal = (profile: ProfileRow) => Object.hasOwn(kinds, profile.validatorKind) && kinds[profile.validatorKind]!.allowsRenewal === true;

  /**
   * Why the profile does not take this RenewalReq, if it does not; otherwise the Device Certificate it renews, which
   * issuing its replacement supersedes. ts-scep has already checked that its signer was issued by the profile's Issuing CA.
   */
  async function renewalRefusal(profile: ProfileRow, request: ScepEnrollmentRequest): Promise<{ refusal: string } | { renewalOf: Renewed }> {
    if (!allowsRenewal(profile)) return { refusal: "RenewalReq is not supported: enroll again with PKCSReq" };
    const fingerprint = createHash("sha256").update(new Uint8Array(request.signerCertificate.raw)).digest("hex");
    const [current] = await db
      .select({ id: deviceCertificate.id, serial: deviceCertificate.serial, subject: deviceCertificate.subject, issuingCaId: deviceCertificate.issuingCaId, revokedAt: deviceCertificate.revokedAt, notAfter: deviceCertificate.notAfter })
      .from(deviceCertificate)
      .where(and(eq(deviceCertificate.enrollmentProfileId, profile.id), eq(deviceCertificate.fingerprint, fingerprint)));
    if (!current) return { refusal: "the RenewalReq is not signed with a Device Certificate of this Enrollment Profile" };
    if (current.revokedAt) return { refusal: `the Device Certificate the RenewalReq is signed with (${current.serial}) is revoked` };
    if (current.notAfter <= clock()) return { refusal: `the Device Certificate the RenewalReq is signed with (${current.serial}) has expired` };
    return { renewalOf: current };
  }

  /**
   * Revokes the Device Certificate a RenewalReq replaced as `superseded`, on the change that stores its replacement, and
   * reissues its Issuing CA's CRL there: a renewed device holds one valid certificate.
   */
  async function supersede(tx: Tx, change: Change, profile: ProfileRow, renewed: Renewed, replacementSerial: string) {
    // Locked as an administrator and the feed lock it: revoked since it was checked (by them, or by another RenewalReq
    // signed with it), it is not renewed, so that no revocation is undone by a replacement.
    const [row] = await tx.select({ revokedAt: deviceCertificate.revokedAt }).from(deviceCertificate).where(eq(deviceCertificate.id, renewed.id)).for("update");
    if (row!.revokedAt) throw new RevokedMeanwhile();
    await tx.update(deviceCertificate).set({ revokedAt: change.occurredAt, revocationReason: "superseded" }).where(eq(deviceCertificate.id, renewed.id));
    await change.audit({
      organizationId: profile.organizationId,
      action: "device_certificate.revoked",
      target: { type: "device_certificate", id: renewed.id },
      detail: { enrollmentProfile: { id: profile.id, name: profile.name }, serial: renewed.serial, subject: renewed.subject, reason: "superseded", by: { renewal: { serial: replacementSerial } } },
    });
    await privateCas.publishRevocation(tx, change, profile.organizationId, renewed.issuingCaId);
  }

  /** A transaction's answer, as the device is sent it: its Device Certificate with `chain` (the Issuing CA's and those above it), or FAILURE. */
  const resultOf = (answer: ScepAnswer, chain: string[]): ScepResult =>
    "issuedPem" in answer ? { status: "success", certificates: [answer.issuedPem, ...chain] } : { status: "failure", failInfo: FailInfo.badRequest, failInfoText: answer.refusal };
  const decidedOf = (request: ScepEnrollmentRequest) => ({ csr: request.csr.der, transactionId: request.transactionId });
  const STILL_DECIDING: ScepResult = { status: "failure", failInfo: FailInfo.badRequest, failInfoText: "the transaction is still being decided; send it again later" };

  /**
   * Answers a PKCSReq or RenewalReq under the profile: its Device Certificate, or FAILURE with an `enrollment.refused`
   * Audit Event. A validator that was asked about the request is told a refusal in the background, as it is told an issue.
   * A transaction the profile has answered before is answered the same again (scep-transactions.ts).
   */
  async function enroll(profile: ProfileRow, chain: string[], request: ScepEnrollmentRequest): Promise<ScepResult> {
    const claimed = await transactions.claim(profile, request.transactionId);
    if ("answer" in claimed) return resultOf(claimed.answer, chain);
    if ("deciding" in claimed) return STILL_DECIDING;
    const { claim } = claimed;
    try {
      const outcome = await decide(profile, request, claim);
      if ("certificate" in outcome) return { status: "success", certificates: outcome.certificates };
      const { reason, validatorAsked, retryable } = outcome;
      await unitOfWork.run(null, async (tx, change) => {
        await change.audit({
          organizationId: profile.organizationId,
          action: "enrollment.refused",
          target: { type: "enrollment_profile", id: profile.id },
          detail: { enrollmentProfile: { id: profile.id, name: profile.name }, reason, validator: { kind: profile.validatorKind }, transactionId: request.transactionId },
        });
        if (validatorAsked) await validators.tellFailed(tx, change, profile, decidedOf(request), reason);
        if (retryable) await transactions.release(tx, claim);
        else await transactions.refused(tx, claim, reason);
      });
      return { status: "failure", failInfo: FailInfo.badRequest, failInfoText: reason };
    } catch (err) {
      // Undecided: the device's next request for it decides it afresh. Released only while no answer was recorded.
      await transactions.release(db, claim).catch(() => {});
      throw err;
    }
  }

  /**
   * Decides a request under the profile and, when it is allowed, issues and stores its Device Certificate, recording it
   * as the claimed transaction's answer and queueing its validator to be told. Otherwise why not, whether its validator
   * was asked about it, and whether the refusal may not hold next time (`retryable`), so that it is not kept as the answer.
   */
  async function decide(
    profile: ProfileRow,
    request: ScepEnrollmentRequest,
    claim: ScepClaim,
  ): Promise<{ certificate: string; certificates: string[] } | { reason: string; validatorAsked: boolean; retryable: boolean }> {
    const refused = (reason: string, validatorAsked = false, retryable = false) => ({ reason, validatorAsked, retryable });
    if (!profile.enabled) return refused("the Enrollment Profile is disabled, so it issues nothing");
    let renewalOf: Renewed | undefined;
    if (request.renewal) {
      const renewal = await renewalRefusal(profile, request);
      if ("refusal" in renewal) return refused(renewal.refusal);
      renewalOf = renewal.renewalOf;
    } else if (profile.sharedChallengeHash !== null) {
      // First of all, so that a device without it learns nothing of the profile. Released rather than kept as the
      // transaction's answer, so that whoever does not hold the challenge cannot settle a device's transaction for it.
      const presented = request.csr.challengePassword;
      if (!isSharedChallenge(presented, profile.sharedChallengeHash)) {
        return refused(presented === undefined ? "the request has no challengePassword: present the Enrollment Profile's Shared Challenge" : "the request's challengePassword is not the Enrollment Profile's Shared Challenge", false, true);
      }
    }
    const keyType = keyTypeOf(request);
    if (!keyType || !profile.allowedKeyTypes.includes(keyType)) {
      return refused(`the Enrollment Profile does not allow ${describeKey(request, keyType)}; it allows ${profile.allowedKeyTypes.join(", ")}`);
    }
    // These before the validator is asked, so that a request that would be refused anyway does not use up a one-time challenge.
    if (profile.nameRules) {
      const broken = nameRulesRefusal(profile.nameRules, request.csr.der);
      if (broken) return refused(broken);
    }
    const caRefusal = await privateCas.deviceRefusal(db, profile.organizationId, profile.issuingCaId, request.csr.der);
    if (caRefusal) return refused(caRefusal);
    let validator: EnrollmentValidator;
    try {
      validator = await validators.open(db, profile);
    } catch (err) {
      console.error("the Enrollment Validator could not be opened:", describeValidatorError(err));
      return refused(`the Enrollment Validator ${profile.validatorKind} is not available`, false, true);
    }
    let retryable = false;
    const decision = await validator.validate({ csr: request.csr.der, challengePassword: request.csr.challengePassword, transactionId: request.transactionId, ...(renewalOf && { renewalOf: renewalOf.serial }) }).then(
      (decision) => (decision.allowed ? decision : { allowed: false as const, reason: `the Enrollment Validator refused the request: ${decision.reason}` }),
      (err: unknown) => {
        console.error("the Enrollment Validator could not be asked:", describeValidatorError(err));
        retryable = true;
        return { allowed: false as const, reason: "the Enrollment Validator could not be asked" };
      },
    );
    if (!decision.allowed) return refused(decision.reason, true, retryable);

    let issued: Awaited<ReturnType<PrivateCas["issueDevice"]>>;
    try {
      issued = await privateCas.issueDevice(db, profile.organizationId, profile.issuingCaId, {
        csr: request.csr.der,
        validityDays: profile.validityDays,
        keyUsage: profile.keyUsage,
        extendedKeyUsages: profile.extendedKeyUsage.map((name) => DEVICE_EXTENDED_KEY_USAGES[name]),
      });
    } catch (err) {
      if (err instanceof IssuanceFailure) return refused(err.message, true);
      // Anything else (the KMS not signing, say) is still this request's answer, and its validator, which allowed it, is told.
      console.error("could not issue a Device Certificate", err);
      return refused("the platform could not issue the Device Certificate; enroll again", true, true);
    }
    const { certificate } = issued;
    const serial = certificate.serialNumber.toUpperCase();
    const subjectAltNames = subjectAltNamesOf(certificate);
    const deviceId = (Object.hasOwn(kinds, profile.validatorKind) ? kinds[profile.validatorKind]!.deviceIdOf?.(subjectAltNames) : undefined) ?? null;
    try {
      await unitOfWork.run(null, async (tx, change) => {
        const [row] = await tx
          .insert(deviceCertificate)
          .values({
            organizationId: profile.organizationId,
            enrollmentProfileId: profile.id,
            issuingCaId: profile.issuingCaId,
            serial,
            fingerprint: createHash("sha256").update(new Uint8Array(certificate.rawData)).digest("hex"),
            subject: certificate.subject,
            subjectAltNames,
            notBefore: certificate.notBefore,
            notAfter: certificate.notAfter,
            certificatePem: certificate.toString("pem"),
            deviceId,
            keyType,
            transactionId: request.transactionId,
            createdAt: change.occurredAt,
          })
          .returning({ id: deviceCertificate.id });
        await change.audit({
          organizationId: profile.organizationId,
          action: "device_certificate.issued",
          target: { type: "device_certificate", id: row!.id },
          detail: {
            enrollmentProfile: { id: profile.id, name: profile.name },
            serial,
            subject: certificate.subject,
            subjectAltNames,
            deviceId,
            keyType,
            notAfter: certificate.notAfter.toISOString(),
            transactionId: request.transactionId,
          },
        });
        if (renewalOf) await supersede(tx, change, profile, renewalOf, serial);
        await transactions.issued(tx, claim, row!.id);
        await validators.tellIssued(tx, change, profile, decidedOf(request), { pem: certificate.toString("pem"), serial, notAfter: certificate.notAfter, issuer: certificate.issuer });
      });
    } catch (err) {
      // Signed but not stored: it is answered as refused, so no device holds a Device Certificate the platform does not know of.
      if (err instanceof RevokedMeanwhile) return refused(`the Device Certificate the RenewalReq is signed with (${renewalOf!.serial}) is revoked`, true);
      console.error("could not store a Device Certificate", err);
      return refused("the platform could not issue the Device Certificate; enroll again", true, true);
    }
    return { certificate: certificate.toString("pem"), certificates: [certificate.toString("pem"), ...issued.chainPem] };
  }

  /** The SCEP server of the profile with this public id, whatever its Organization: the id, unguessable, is all a device has. None when there is no such profile. */
  async function serverOf(publicId: string) {
    const [profile] = await db.select().from(enrollmentProfile).where(eq(enrollmentProfile.publicId, publicId));
    if (!profile) return undefined;
    const of = (await findIssuingCa(db, profile.organizationId, profile.issuingCaId))!;
    const above = [of.ca.chainPem, of.ca.rootCertificatePem].filter((pem): pem is string => pem !== null).flatMap((pem) => pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []);
    const chain = [of.issuing.certificatePem!, ...above];
    return new ScepServer({
      // A profile is made only on an Issuing CA that has its certificate, which it then keeps.
      ca: { certificate: of.issuing.certificatePem!, chain: above },
      ra: { certificate: profile.raCertificatePem, privateKey: await secrets.open(db, profile.organizationId, profile.raKeySecretId) },
      capabilities: allowsRenewal(profile) ? [...CAPABILITIES, "Renewal"] : CAPABILITIES,
      handler: {
        enroll: (request) => enroll(profile, chain, request),
        // GetCertInitial: the platform never answers PENDING, but a client may still ask after a request it sent.
        async poll(request) {
          const answer = await transactions.find(profile, request.transactionId);
          if (!answer) return { status: "failure", failInfo: FailInfo.badCertId, failInfoText: "no such transaction" };
          return "deciding" in answer ? STILL_DECIDING : resultOf(answer, chain);
        },
      },
    });
  }

  /** Where the request came from, as the rate limit counts it. */
  function sourceAddressOf(c: Context): string {
    if (config().trustForwardedFor) {
      const hops = c.req.header("x-forwarded-for")?.split(",") ?? [];
      const last = hops.at(-1)?.trim();
      if (last) return last;
    }
    try {
      return getConnInfo(c).remote.address ?? "unknown";
    } catch {
      return "unknown";
    }
  }

  // Windows' SCEP client appends /pkiclient.exe to the URL it is given; others use it as it is.
  app.on(["GET", "POST"], ["/scep/:publicId", "/scep/:publicId/pkiclient.exe"], async (c) => {
    const { windowMs, perAddress, perProfile } = config();
    const limited = (retryAfter: number) => c.text("too many requests", 429, { "retry-after": String(retryAfter) });
    const addressWait = limiter.take(`address:${sourceAddressOf(c)}`, perAddress, windowMs);
    if (addressWait !== undefined) return limited(addressWait);
    // Counted before the profile is looked up and its RA key opened, which a flood would otherwise cost each time.
    const publicId = c.req.param("publicId");
    const profileWait = limiter.take(`profile:${publicId}`, perProfile, windowMs);
    if (profileWait !== undefined) return limited(profileWait);
    const server = await serverOf(publicId);
    if (!server) return c.text("not found", 404);
    return server.fetchHandler(c.req.raw);
  });

  return {
    /** Forgets every count, as if a new window began. */
    resetRateLimits: () => limiter.reset(),
  };
}
