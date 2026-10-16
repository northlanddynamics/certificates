// The SCEP server (RFC 8894): public, unauthenticated routes at each Enrollment Profile's opaque public id, where devices
// enroll. ts-scep handles the protocol, running as the profile's RA: it opens each request's envelope with the RA key and
// verifies its signer, and signs the CertRep with the RA key, encrypted to the device. What is issued is decided here,
// per request: the device's key must be one the profile allows, its Enrollment Validator must allow the request, and
// then the Issuing CA signs a Device Certificate through the Private CA module, which is stored with its Audit Event in
// one Unit of Work. A device is always answered SUCCESS with its certificate or FAILURE with a failInfo, never PENDING.
import type { OpenAPIHono } from "@hono/zod-openapi";
import { eq } from "drizzle-orm";
import { createHash } from "node:crypto";
import { FailInfo, ScepServer, type EnrollmentRequest as ScepEnrollmentRequest, type ScepResult } from "ts-scep";
import { subjectAltNamesOf } from "./ca-certificates";
import type { Db } from "./db/client";
import { deviceCertificate, enrollmentProfile } from "./db/schema";
import { DEVICE_EXTENDED_KEY_USAGES } from "./enrollment-profile-kinds";
import type { EnrollmentValidators } from "./enrollment-validator";
import { IssuanceFailure } from "./issuance-failure";
import { findIssuingCa, type PrivateCas } from "./private-ca";
import type { Secrets } from "./secrets";
import type { UnitOfWork } from "./unit-of-work";

type ProfileRow = typeof enrollmentProfile.$inferSelect;

/** What GetCACaps advertises (RFC 8894, 3.5.2). Renewal is not: a device re-enrolls with PKCSReq. */
const CAPABILITIES = ["POSTPKIOperation", "SHA-256", "SHA-512", "AES", "SCEPStandard"];

const refused = (failInfoText: string, failInfo = FailInfo.badRequest): ScepResult => ({ status: "failure", failInfo, failInfoText });

/** The device key's type as a profile names it, such as "rsa-2048"; none for a key no profile can allow. */
function keyTypeOf(request: ScepEnrollmentRequest) {
  const key = request.csr.publicKey;
  return key.asymmetricKeyType === "rsa" ? `rsa-${key.asymmetricKeyDetails?.modulusLength}` : undefined;
}

export function registerScep(ctx: { app: OpenAPIHono; db: Db; unitOfWork: UnitOfWork; secrets: Secrets; privateCas: PrivateCas; validators: EnrollmentValidators }) {
  const { app, db, unitOfWork, secrets, privateCas, validators } = ctx;

  /** Decides a PKCSReq under the profile and, when it is allowed, issues and stores its Device Certificate. */
  async function enroll(profile: ProfileRow, request: ScepEnrollmentRequest): Promise<ScepResult> {
    if (request.renewal) return refused("RenewalReq is not supported: enroll again with PKCSReq");
    const keyType = keyTypeOf(request);
    if (!keyType || !(profile.allowedKeyTypes as string[]).includes(keyType)) {
      return refused(`the Enrollment Profile does not allow a ${keyType ?? request.csr.publicKey.asymmetricKeyType} key; it allows ${profile.allowedKeyTypes.join(", ")}`);
    }
    const validator = validators[profile.validatorKind];
    if (!validator) return refused(`the Enrollment Validator ${profile.validatorKind} is not available`);
    const decision = await validator.validate({ csr: request.csr.der, challengePassword: request.csr.challengePassword, transactionId: request.transactionId }).catch((err: unknown) => {
      console.error("the Enrollment Validator could not be asked", err);
      return { allowed: false as const, reason: "the Enrollment Validator could not be asked" };
    });
    if (!decision.allowed) return refused(decision.reason);

    let issued: Awaited<ReturnType<PrivateCas["issueDevice"]>>;
    try {
      issued = await privateCas.issueDevice(db, profile.organizationId, profile.issuingCaId, {
        csr: request.csr.der,
        validityDays: profile.validityDays,
        keyUsage: profile.keyUsage,
        extendedKeyUsages: profile.extendedKeyUsage.map((name) => DEVICE_EXTENDED_KEY_USAGES[name]),
      });
    } catch (err) {
      if (err instanceof IssuanceFailure) return refused(err.message);
      throw err;
    }
    const { certificate } = issued;
    const serial = certificate.serialNumber.toUpperCase();
    const subjectAltNames = subjectAltNamesOf(certificate);
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
    });
    return { status: "success", certificates: [certificate.toString("pem"), ...issued.chainPem] };
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
