// The SCEP server (RFC 8894): public, unauthenticated routes at each Enrollment Profile's opaque public id, where devices
// enroll. ts-scep handles the protocol, running as the profile's RA: it opens each request's envelope with the RA key and
// verifies its signer, and signs the CertRep with the RA key, encrypted to the device. What is issued is decided here,
// per request: the device's key must be one the profile allows, its names must keep the profile's name rules when its
// Enrollment Validator does not vouch for names, the validator must allow the request, and then the Issuing CA signs a
// Device Certificate through the Private CA module, which is stored with its Audit Event in one Unit of Work. A device is
// always answered SUCCESS with its certificate or FAILURE with a failInfo, never PENDING; a refusal is an Audit Event.
// The validator is told the outcome afterwards, in the background (enrollment-validators.ts).
import type { OpenAPIHono } from "@hono/zod-openapi";
import { eq } from "drizzle-orm";
import { createHash } from "node:crypto";
import { FailInfo, ScepServer, type EnrollmentRequest as ScepEnrollmentRequest, type ScepResult } from "ts-scep";
import { subjectAltNamesOf } from "./ca-certificates";
import type { Db } from "./db/client";
import { deviceCertificate, enrollmentProfile } from "./db/schema";
import { DEVICE_EXTENDED_KEY_USAGES, DEVICE_KEY_TYPES, type DeviceKeyType } from "./enrollment-profile-kinds";
import { describeValidatorError, type EnrollmentValidator } from "./enrollment-validator";
import type { EnrollmentValidatorRuns } from "./enrollment-validators";
import { IssuanceFailure } from "./issuance-failure";
import { findIssuingCa, type PrivateCas } from "./private-ca";
import { nameRulesRefusal } from "./name-rules";
import type { Secrets } from "./secrets";
import type { UnitOfWork } from "./unit-of-work";

type ProfileRow = typeof enrollmentProfile.$inferSelect;

/** What GetCACaps advertises (RFC 8894, 3.5.2). Renewal is not: a device re-enrolls with PKCSReq. */
const CAPABILITIES = ["POSTPKIOperation", "SHA-256", "SHA-512", "AES", "SCEPStandard"];

/** The device key's type as a profile names it, such as "rsa-2048"; none for a key no profile can allow. */
function keyTypeOf(request: ScepEnrollmentRequest): DeviceKeyType | undefined {
  const key = request.csr.publicKey;
  const type = `rsa-${key.asymmetricKeyDetails?.modulusLength}`;
  return key.asymmetricKeyType === "rsa" && (DEVICE_KEY_TYPES as readonly string[]).includes(type) ? (type as DeviceKeyType) : undefined;
}

export function registerScep(ctx: { app: OpenAPIHono; db: Db; unitOfWork: UnitOfWork; secrets: Secrets; privateCas: PrivateCas; validators: EnrollmentValidatorRuns }) {
  const { app, db, unitOfWork, secrets, privateCas, validators } = ctx;

  /**
   * Answers a PKCSReq under the profile: its Device Certificate, or FAILURE with an `enrollment.refused` Audit Event. A
   * validator that was asked about the request is told a refusal in the background, as it is told an issue.
   */
  async function enroll(profile: ProfileRow, request: ScepEnrollmentRequest): Promise<ScepResult> {
    const decided = { csr: request.csr.der, transactionId: request.transactionId };
    const outcome = await decide(profile, request);
    if ("certificate" in outcome) return { status: "success", certificates: outcome.certificates };
    const { reason, validatorAsked } = outcome;
    await unitOfWork.run(null, async (tx, change) => {
      await change.audit({
        organizationId: profile.organizationId,
        action: "enrollment.refused",
        target: { type: "enrollment_profile", id: profile.id },
        detail: { enrollmentProfile: { id: profile.id, name: profile.name }, reason, validator: { kind: profile.validatorKind }, transactionId: request.transactionId },
      });
      if (validatorAsked) await validators.tellFailed(tx, change, profile, decided, reason);
    });
    return { status: "failure", failInfo: FailInfo.badRequest, failInfoText: reason };
  }

  /**
   * Decides a PKCSReq under the profile and, when it is allowed, issues and stores its Device Certificate, queueing its
   * validator to be told. Otherwise why not, and whether its validator was asked about it.
   */
  async function decide(profile: ProfileRow, request: ScepEnrollmentRequest): Promise<{ certificate: string; certificates: string[] } | { reason: string; validatorAsked: boolean }> {
    const refused = (reason: string, validatorAsked = false) => ({ reason, validatorAsked });
    if (request.renewal) return refused("RenewalReq is not supported: enroll again with PKCSReq");
    const keyType = keyTypeOf(request);
    if (!keyType || !profile.allowedKeyTypes.includes(keyType)) {
      const asked = request.csr.publicKey.asymmetricKeyType === "rsa" ? `rsa-${request.csr.publicKey.asymmetricKeyDetails?.modulusLength}` : request.csr.publicKey.asymmetricKeyType;
      return refused(`the Enrollment Profile does not allow a ${asked} key; it allows ${profile.allowedKeyTypes.join(", ")}`);
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
      return refused(`the Enrollment Validator ${profile.validatorKind} is not available`);
    }
    const decision = await validator.validate({ csr: request.csr.der, challengePassword: request.csr.challengePassword, transactionId: request.transactionId }).then(
      (decision) => (decision.allowed ? decision : { allowed: false as const, reason: `the Enrollment Validator refused the request: ${decision.reason}` }),
      (err: unknown) => {
        console.error("the Enrollment Validator could not be asked:", describeValidatorError(err));
        return { allowed: false as const, reason: "the Enrollment Validator could not be asked" };
      },
    );
    if (!decision.allowed) return refused(decision.reason, true);

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
      return refused("the platform could not issue the Device Certificate; enroll again", true);
    }
    const { certificate } = issued;
    const serial = certificate.serialNumber.toUpperCase();
    const subjectAltNames = subjectAltNamesOf(certificate);
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
            transactionId: request.transactionId,
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
            notAfter: certificate.notAfter.toISOString(),
            transactionId: request.transactionId,
          },
        });
        await validators.tellIssued(tx, change, profile, { csr: request.csr.der, transactionId: request.transactionId }, { pem: certificate.toString("pem"), serial, notAfter: certificate.notAfter, issuer: certificate.issuer });
      });
    } catch (err) {
      // Signed but not stored: it is answered as refused, so no device holds a Device Certificate the platform does not know of.
      console.error("could not store a Device Certificate", err);
      return refused("the platform could not issue the Device Certificate; enroll again", true);
    }
    return { certificate: certificate.toString("pem"), certificates: [certificate.toString("pem"), ...issued.chainPem] };
  }

  /** The SCEP server of the profile with this public id, whatever its Organization: the id, unguessable, is all a device has. None when there is no such profile. */
  async function serverOf(publicId: string) {
    const [profile] = await db.select().from(enrollmentProfile).where(eq(enrollmentProfile.publicId, publicId));
    if (!profile) return undefined;
    const of = (await findIssuingCa(db, profile.organizationId, profile.issuingCaId))!;
    const above = [of.ca.chainPem, of.ca.rootCertificatePem].filter((pem): pem is string => pem !== null).flatMap((pem) => pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []);
    return new ScepServer({
      // A profile is made only on an Issuing CA that has its certificate, which it then keeps.
      ca: { certificate: of.issuing.certificatePem!, chain: above },
      ra: { certificate: profile.raCertificatePem, privateKey: await secrets.open(db, profile.organizationId, profile.raKeySecretId) },
      capabilities: CAPABILITIES,
      handler: { enroll: (request) => enroll(profile, request) },
    });
  }

  // Windows' SCEP client appends /pkiclient.exe to the URL it is given; others use it as it is.
  app.on(["GET", "POST"], ["/scep/:publicId", "/scep/:publicId/pkiclient.exe"], async (c) => {
    const server = await serverOf(c.req.param("publicId"));
    if (!server) return c.text("not found", 404);
    return server.fetchHandler(c.req.raw);
  });
}
