// Device enrollment: what an Enrollment Profile issues a device that asks, whatever protocol it asks in (SCEP is the
// one there is, scep.ts). Each request is decided here: a first enrollment must present the profile's Shared Challenge
// when its validator's kind uses one (shared-challenge.ts), a renewal must be signed with a Device Certificate of the
// profile that is neither revoked nor expired, the device's key must be one the profile allows, its names must keep the
// profile's name rules when it has them and its Issuing CA's Permitted Name Rules, and the Enrollment Validator must
// allow it; then the profile's issuer issues a Device Certificate (enrollment-issuer.ts), which is stored with its Audit
// Event in one Unit of Work, and for a renewal that Unit of Work also revokes the Device Certificate it was signed with
// as superseded (device-certificate-revocation.ts). A request is answered with its Device Certificate or refused, never
// left pending; a refusal is an Audit Event. Each request belongs to a transaction, which is answered the same each
// time it is asked again (scep-transactions.ts). The validator is told the outcome afterwards, in the background
// (enrollment-validators.ts).
//
// A profile on an ADCS CA cannot issue at once: once a request is decided, an Agent submits its CSR to ADCS under the
// profile's template (adcs-issuance.ts) and the device is answered PENDING, as it is each time it asks again, until ADCS
// issues it, denies it or holds it too long. What ADCS answered is recorded then, on the change that learned it: the
// Device Certificate stored and the transaction answered with it, or the transaction refused, as above.
import { createPublicKey } from "node:crypto";
import * as x509 from "@peculiar/x509";
import { and, eq } from "drizzle-orm";
import { subjectAltNamesOf } from "../pki/ca-certificates";
import type { Db, Tx } from "../platform/db/client";
import { deviceCertificate, enrollmentProfile } from "../platform/db/schema";
import type { DeviceCertificateRevocations } from "./device-certificate-revocation";
import { DEVICE_EXTENDED_KEY_USAGES, DEVICE_KEY_TYPES, type DeviceKeyType } from "./enrollment-profile-kinds";
import { describeValidatorError, kindOf, type EnrollmentValidator, type EnrollmentValidators } from "./enrollment-validator";
import type { EnrollmentValidatorRuns } from "./enrollment-validators";
import { IssuanceFailure } from "../issuance/issuance-failure";
import { deviceIssuerColumns, enrollmentIssuerOf, type DeviceCertificateIssuer, type EnrollmentIssuers } from "./enrollment-issuer";
import { nameRulesRefusal } from "./name-rules";
import type { ScepAnswer, ScepClaim, ScepDecided, ScepTransactions } from "./scep-transactions";
import type { AdcsIssuance, AdcsRequestRow } from "../adcs/adcs-issuance";
import { CertificateAuthorityError } from "../issuance/acme/certificate-authority";
import type { SharedChallenges } from "./shared-challenge";
import type { Change, UnitOfWork } from "../platform/unit-of-work";
import { fingerprintOf } from "../pki/fingerprint";

type ProfileRow = typeof enrollmentProfile.$inferSelect;
/** The Device Certificate a renewal was signed with, which its replacement supersedes. */
type Renewed = Pick<typeof deviceCertificate.$inferSelect, "id" | "serial">;

/** The Device Certificate a renewal was signed with was revoked after the request was checked, so it renews nothing. */
class RevokedMeanwhile extends Error {}

/** One request a device makes under an Enrollment Profile, once its protocol has verified who signed it. */
export interface DeviceEnrollmentRequest {
  /** The PKCS #10 request, DER. */
  csr: Uint8Array;
  /** The CSR's PKCS #9 challengePassword, if it has one. */
  challengePassword?: string;
  /** The request's transaction, which a device that asks again names again. */
  transactionId: string;
  /**
   * For a renewal, the certificate (DER) the request is signed with, which the protocol has checked was issued by the
   * profile's Issuing CA; none for a first enrollment.
   */
  renewalSignedWith?: Uint8Array;
}

/**
 * What a device is answered: its Device Certificate, with the certificates above it up to the root (PEM, the Issuing
 * CA's first), or why it is refused, or that the transaction is still being decided by another request for it, or that
 * it waits for ADCS (PENDING).
 */
export type DeviceEnrollmentAnswer = { issued: { certificatePem: string; chainPem: string[] } } | { refused: string } | { deciding: true } | { pending: true };

export interface DeviceEnrollment {
  /**
   * Answers the request under the profile: its Device Certificate, or why not, with an `enrollment.refused` Audit Event;
   * on an ADCS CA, once it is allowed, that it is pending.
   * A transaction the profile has answered before is answered the same again; one another request is deciding is
   * answered `deciding`. Throws only when the request could not be decided at all, which the next request for its
   * transaction decides afresh.
   */
  enroll(profile: ProfileRow, request: DeviceEnrollmentRequest): Promise<DeviceEnrollmentAnswer>;
  /** What the profile answered the transaction, when it has: as `enroll` would answer it again. None when it has no such transaction. */
  answerOf(profile: ProfileRow, transactionId: string): Promise<DeviceEnrollmentAnswer | undefined>;
}

/** The device key's type as a profile names it, such as "rsa-2048"; none for a key no profile can allow. */
function keyTypeOf(key: ReturnType<typeof createPublicKey>): DeviceKeyType | undefined {
  const type = `rsa-${key.asymmetricKeyDetails?.modulusLength}`;
  return key.asymmetricKeyType === "rsa" && (DEVICE_KEY_TYPES as readonly string[]).includes(type) ? (type as DeviceKeyType) : undefined;
}

/** The device's key as a refusal names it: its algorithm and size, and its type (`keyTypeOf`) where a profile could allow it. */
function describeKey(key: ReturnType<typeof createPublicKey>, type: DeviceKeyType | undefined): string {
  if (key.asymmetricKeyType !== "rsa") return `an ${key.asymmetricKeyType?.toUpperCase() ?? "unknown"} key${key.asymmetricKeyDetails?.namedCurve ? ` (${key.asymmetricKeyDetails.namedCurve})` : ""}`;
  return `a ${key.asymmetricKeyDetails?.modulusLength}-bit RSA key${type ? ` (${type})` : ""}`;
}

/** The CSR (DER) as PEM, as an Agent submits it to ADCS. */
const csrPemOf = (csr: Uint8Array) => new x509.Pkcs10CertificateRequest(new Uint8Array(csr)).toString("pem");

/** The public key of the CSR (DER). */
const publicKeyOf = (csr: Uint8Array) => createPublicKey({ key: Buffer.from(new x509.Pkcs10CertificateRequest(new Uint8Array(csr)).publicKey.rawData), format: "der", type: "spki" });

export function createDeviceEnrollment(deps: {
  db: Db;
  unitOfWork: UnitOfWork;
  issuers: EnrollmentIssuers;
  revocations: DeviceCertificateRevocations;
  sharedChallenges: SharedChallenges;
  kinds: EnrollmentValidators;
  validators: EnrollmentValidatorRuns;
  transactions: ScepTransactions;
  /** Where an Agent's answer from ADCS to a device's request comes back. */
  adcs: Pick<AdcsIssuance, "handle">;
  clock: () => Date;
}): DeviceEnrollment {
  const { db, unitOfWork, issuers, revocations, sharedChallenges, kinds, validators, transactions, adcs, clock } = deps;

  /**
   * Why the profile does not take this renewal, if it does not; otherwise the Device Certificate it renews, which
   * issuing its replacement supersedes.
   */
  async function renewalRefusal(profile: ProfileRow, signedWith: Uint8Array): Promise<{ refusal: string } | { renewalOf: Renewed }> {
    if (!kindOf(kinds, profile.validatorKind)?.allowsRenewal) return { refusal: "RenewalReq is not supported: enroll again with PKCSReq" };
    const fingerprint = fingerprintOf(signedWith);
    const [current] = await db
      .select({ id: deviceCertificate.id, serial: deviceCertificate.serial, revokedAt: deviceCertificate.revokedAt, notAfter: deviceCertificate.notAfter })
      .from(deviceCertificate)
      .where(and(eq(deviceCertificate.enrollmentProfileId, profile.id), eq(deviceCertificate.fingerprint, fingerprint)));
    if (!current) return { refusal: "the RenewalReq is not signed with a Device Certificate of this Enrollment Profile" };
    if (current.revokedAt) return { refusal: `the Device Certificate the RenewalReq is signed with (${current.serial}) is revoked` };
    if (current.notAfter <= clock()) return { refusal: `the Device Certificate the RenewalReq is signed with (${current.serial}) has expired` };
    return { renewalOf: current };
  }

  /**
   * Revokes the Device Certificate a renewal replaced as `superseded`, on the change that stores its replacement, with
   * its Issuing CA's CRL: a renewed device holds one valid certificate. Revoked since it was checked (by an administrator,
   * the feed, or another renewal signed with it), it is not renewed, so that no Revocation is undone by a replacement.
   */
  async function supersede(tx: Tx, change: Change, profile: ProfileRow, renewed: Renewed, replacementSerial: string) {
    const [superseded] = await revocations.revoke(tx, change, profile.organizationId, [{ id: renewed.id, reason: "superseded", by: { renewal: { serial: replacementSerial } } }]);
    if (!superseded) throw new RevokedMeanwhile();
  }

  /** A recorded answer, as the device is sent it: its Device Certificate with the chain the profile's issuer has now, or the refusal, or that it is pending. */
  async function answered(profile: ProfileRow, answer: ScepAnswer): Promise<DeviceEnrollmentAnswer> {
    if ("pending" in answer) return { pending: true };
    if ("refusal" in answer) return { refused: answer.refusal };
    return { issued: { certificatePem: answer.issuedPem, chainPem: await issuers.chainOf(db, profile.organizationId, enrollmentIssuerOf(profile)) } };
  }
  const decidedOf = (request: Pick<DeviceEnrollmentRequest, "csr" | "transactionId">) => ({ csr: request.csr, transactionId: request.transactionId });

  /**
   * Stores the Device Certificate the issuer issued for a decided request, with its Audit Event, and has its validator
   * told, on the change; for a renewal, the Device Certificate it renews is revoked as superseded first (RevokedMeanwhile
   * when it was revoked since). Returns its id.
   */
  async function store(
    tx: Tx,
    change: Change,
    profile: ProfileRow,
    issued: { certificate: x509.X509Certificate; issuer: DeviceCertificateIssuer },
    decided: ScepDecided & { csr: Uint8Array; transactionId: string },
  ) {
    const { certificate, issuer } = issued;
    const kind = kindOf(kinds, profile.validatorKind);
    const serial = certificate.serialNumber.toUpperCase();
    const subjectAltNames = subjectAltNamesOf(certificate);
    const deviceId = kind?.deviceIdOf(subjectAltNames) ?? null;
    const [row] = await tx
      .insert(deviceCertificate)
      .values({
        organizationId: profile.organizationId,
        enrollmentProfileId: profile.id,
        ...deviceIssuerColumns(issuer),
        serial,
        fingerprint: fingerprintOf(certificate.rawData),
        subject: certificate.subject,
        subjectAltNames,
        notBefore: certificate.notBefore,
        notAfter: certificate.notAfter,
        certificatePem: certificate.toString("pem"),
        deviceId,
        keyType: decided.keyType,
        sharedChallengeId: decided.sharedChallengeId,
        transactionId: decided.transactionId,
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
        keyType: decided.keyType,
        sharedChallenge: decided.sharedChallengeId === null ? null : { id: decided.sharedChallengeId },
        notAfter: certificate.notAfter.toISOString(),
        transactionId: decided.transactionId,
        ...(issuer.kind === "adcs" && { adcsCa: { id: issuer.adcsCaId }, template: { id: issuer.templateId }, adcsRequestId: issuer.requestId }),
      },
    });
    if (decided.renewalOf) {
      await supersede(tx, change, profile, decided.renewalOf, serial).catch((err: unknown) => {
        // ADCS revokes through an Agent: when none can be asked now, the replacement is kept, and the one it renews is not yet revoked.
        if (issuer.kind === "adcs" && err instanceof CertificateAuthorityError) return console.error("could not have ADCS revoke a renewed Device Certificate:", err.message);
        throw err;
      });
    }
    await validators.tellIssued(tx, change, profile, decidedOf(decided), { pem: certificate.toString("pem"), serial, notAfter: certificate.notAfter, issuer: certificate.issuer });
    return row!.id;
  }

  /** Refuses a decided request on the change: its Audit Event, its validator told when it was asked, and its transaction's answer. */
  async function refuse(tx: Tx, change: Change, profile: ProfileRow, request: Pick<DeviceEnrollmentRequest, "csr" | "transactionId">, reason: string, extra: Record<string, unknown> = {}) {
    await change.audit({
      organizationId: profile.organizationId,
      action: "enrollment.refused",
      target: { type: "enrollment_profile", id: profile.id },
      detail: { enrollmentProfile: { id: profile.id, name: profile.name }, reason, validator: { kind: profile.validatorKind }, transactionId: request.transactionId, ...extra },
    });
    await validators.tellFailed(tx, change, profile, decidedOf(request), reason);
  }

  /** What a device's request to ADCS left waiting: its transaction and profile, locked, while the transaction still waits. */
  async function waitingFor(tx: Tx, request: AdcsRequestRow) {
    const waiting = await transactions.waiting(tx, request.id);
    if (!waiting) return undefined;
    const [profile] = await tx.select().from(enrollmentProfile).where(eq(enrollmentProfile.id, request.enrollmentProfileId!));
    const asked = { csr: new Uint8Array(new x509.Pkcs10CertificateRequest(request.csr).rawData), transactionId: waiting.transactionId };
    return { waiting, profile: profile!, asked, decided: waiting.decided! };
  }

  adcs.handle("device", {
    async issued(tx, change, request, certificatePem) {
      const found = await waitingFor(tx, request);
      if (!found) return;
      const { waiting, profile, asked, decided } = found;
      const certificate = new x509.X509Certificate(certificatePem);
      const issuer: DeviceCertificateIssuer = { kind: "adcs", adcsCaId: request.adcsCaId, templateId: request.templateId, requestId: request.adcsRequestId! };
      // Within a savepoint, so that a renewal whose Device Certificate was revoked meanwhile stores nothing and is refused.
      const stored = await tx
        .transaction(async (inner) => store(inner, change, profile, { certificate, issuer }, { ...decided, ...asked }))
        .catch((err: unknown) => {
          if (err instanceof RevokedMeanwhile) return undefined;
          throw err;
        });
      if (stored) return transactions.answer(tx, waiting, { deviceCertificateId: stored });
      const reason = `the Device Certificate the RenewalReq is signed with (${decided.renewalOf!.serial}) is revoked`;
      await refuse(tx, change, profile, asked, reason, { adcsRequestId: request.adcsRequestId });
      await transactions.answer(tx, waiting, { refusal: reason });
    },
    async failed(tx, change, request, failure) {
      const found = await waitingFor(tx, request);
      if (!found) return;
      const { waiting, profile, asked } = found;
      await refuse(tx, change, profile, asked, failure.message, { adcsRequestId: request.adcsRequestId });
      await transactions.answer(tx, waiting, { refusal: failure.message });
    },
  });

  /**
   * Decides a request under the profile and, when it is allowed, issues and stores its Device Certificate, recording it
   * as the claimed transaction's answer and queueing its validator to be told. Otherwise why not, whether its validator
   * was asked about it, and whether the refusal may not hold next time (`retryable`), so that it is not kept as the answer.
   */
  async function decide(
    profile: ProfileRow,
    request: DeviceEnrollmentRequest,
    claim: ScepClaim,
  ): Promise<{ issued: { certificatePem: string; chainPem: string[] } } | { pending: true } | { reason: string; validatorAsked: boolean; retryable: boolean }> {
    const refused = (reason: string, validatorAsked = false, retryable = false) => ({ reason, validatorAsked, retryable });
    if (!profile.enabled) return refused("the Enrollment Profile is disabled, so it issues nothing");
    const kind = kindOf(kinds, profile.validatorKind);
    let renewalOf: Renewed | undefined;
    // The id of the Shared Challenge a first enrollment presented, which its Device Certificate records.
    let sharedChallengeId: string | null = null;
    if (request.renewalSignedWith) {
      const renewal = await renewalRefusal(profile, request.renewalSignedWith);
      if ("refusal" in renewal) return refused(renewal.refusal);
      renewalOf = renewal.renewalOf;
    } else if (kind?.usesSharedChallenge) {
      // First of all, so that a device without it learns nothing of the profile. Released rather than kept as the
      // transaction's answer, so that whoever does not hold the challenge cannot settle a device's transaction for it.
      const checked = sharedChallenges.check(profile, request.challengePassword);
      if ("refusal" in checked) return refused(checked.refusal, false, true);
      sharedChallengeId = checked.id;
    }
    const publicKey = publicKeyOf(request.csr);
    const keyType = keyTypeOf(publicKey);
    if (!keyType || !profile.allowedKeyTypes.includes(keyType)) {
      return refused(`the Enrollment Profile does not allow ${describeKey(publicKey, keyType)}; it allows ${profile.allowedKeyTypes.join(", ")}`);
    }
    // These before the validator is asked, so that a request that would be refused anyway does not use up a one-time challenge.
    if (profile.nameRules) {
      const broken = nameRulesRefusal(profile.nameRules, request.csr);
      if (broken) return refused(broken);
    }
    const issuer = enrollmentIssuerOf(profile);
    const caRefusal = await issuers.deviceRefusal(db, profile.organizationId, issuer, request.csr, keyType);
    if (caRefusal) return refused(caRefusal);
    let validator: EnrollmentValidator;
    try {
      validator = await validators.open(db, profile);
    } catch (err) {
      console.error("the Enrollment Validator could not be opened:", describeValidatorError(err));
      return refused(`the Enrollment Validator ${profile.validatorKind} is not available`, false, true);
    }
    let retryable = false;
    const decision = await validator.validate({ csr: request.csr, challengePassword: request.challengePassword, transactionId: request.transactionId, ...(renewalOf && { renewalOf: renewalOf.serial }) }).then(
      (decision) => (decision.allowed ? decision : { allowed: false as const, reason: `the Enrollment Validator refused the request: ${decision.reason}` }),
      (err: unknown) => {
        console.error("the Enrollment Validator could not be asked:", describeValidatorError(err));
        retryable = true;
        return { allowed: false as const, reason: "the Enrollment Validator could not be asked" };
      },
    );
    if (!decision.allowed) return refused(decision.reason, true, retryable);
    const decided: ScepDecided = { keyType, sharedChallengeId, renewalOf: renewalOf ?? null };

    if (issuer.kind === "adcs") {
      // Submitted through an Agent, and answered once ADCS has: the transaction waits for it.
      try {
        await unitOfWork.run(null, async (tx, change) => {
          const requestId = await issuers.requestFromAdcs(tx, change, profile.organizationId, issuer, { purpose: "device", csrPem: csrPemOf(request.csr), enrollmentProfileId: profile.id });
          await transactions.pending(tx, claim, requestId, decided);
        });
      } catch (err) {
        console.error("could not submit a device's request to ADCS", err);
        return refused("the platform could not submit the request to ADCS; enroll again", true, true);
      }
      return { pending: true };
    }

    let issued: Awaited<ReturnType<EnrollmentIssuers["issueDevice"]>>;
    try {
      issued = await issuers.issueDevice(db, profile.organizationId, issuer, {
        csr: request.csr,
        validityDays: profile.validityDays!,
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
    try {
      await unitOfWork.run(null, async (tx, change) => {
        const id = await store(tx, change, profile, { certificate, issuer }, { ...decided, ...decidedOf(request) });
        await transactions.issued(tx, claim, id);
      });
    } catch (err) {
      // Signed but not stored: it is answered as refused, so no device holds a Device Certificate the platform does not know of.
      if (err instanceof RevokedMeanwhile) return refused(`the Device Certificate the RenewalReq is signed with (${renewalOf!.serial}) is revoked`, true);
      console.error("could not store a Device Certificate", err);
      return refused("the platform could not issue the Device Certificate; enroll again", true, true);
    }
    return { issued: { certificatePem: certificate.toString("pem"), chainPem: issued.chainPem } };
  }

  return {
    async enroll(profile, request) {
      const claimed = await transactions.claim(profile, request.transactionId);
      if ("answer" in claimed) return answered(profile, claimed.answer);
      if ("deciding" in claimed) return { deciding: true };
      const { claim } = claimed;
      try {
        const outcome = await decide(profile, request, claim);
        if ("issued" in outcome || "pending" in outcome) return outcome;
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
        return { refused: reason };
      } catch (err) {
        // Undecided: the device's next request for it decides it afresh. Released only while no answer was recorded.
        await transactions.release(db, claim).catch(() => {});
        throw err;
      }
    },

    async answerOf(profile, transactionId) {
      const answer = await transactions.find(profile, transactionId);
      if (!answer) return undefined;
      return "deciding" in answer ? { deciding: true } : answered(profile, answer);
    },
  };
}
