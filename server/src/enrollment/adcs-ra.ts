// The SCEP RA certificates of Enrollment Profiles on an ADCS CA. The platform makes the RA's key, as for any profile (ADR
// 0007), and an Agent has ADCS issue its certificate under the profile's RA template (adcs-issuance.ts), which may take
// as long as any request to ADCS: the profile serves SCEP only once its first RA certificate is issued (scep.ts). Once a
// third of its life is left, a new key is made and ADCS asked again; the old RA certificate and key serve until the new
// certificate is issued, and are replaced by it then. A request that fails is asked again a day after, by the same pass,
// as is one an Organization Administrator asks for (a rotation, or the first RA certificate again after a failure).
import * as x509 from "@peculiar/x509";
import { and, desc, eq } from "drizzle-orm";
import { createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";
import { createCsr } from "ts-scep";
import type { Db, Tx } from "../platform/db/client";
import { adcsRequest, enrollmentProfile, secret } from "../platform/db/schema";
import type { Secrets } from "../platform/crypto/secrets";
import { OPEN_REQUEST_STATUSES, type AdcsIssuance } from "../adcs/adcs-issuance";
import { enrollmentIssuerOf, type EnrollmentIssuers } from "./enrollment-issuer";
import { RA_KEY_TYPE } from "./enrollment-profile-kinds";
import type { Change, UnitOfWork } from "../platform/unit-of-work";

type ProfileRow = typeof enrollmentProfile.$inferSelect;

/** How long after a request for an RA certificate failed it is asked again. */
export const RA_RETRY_AFTER_MS = 24 * 3600_000;

/** A new RA key (PKCS #8 PEM): a software RSA key, of the type an ADCS CA's RA template is checked to take. */
export const newRaKeyPem = () =>
  generateKeyPairSync("rsa", { modulusLength: Number(RA_KEY_TYPE.slice("rsa-".length)) })
    .privateKey.export({ format: "pem", type: "pkcs8" })
    .toString();

/** The RA certificate as Audit Events name it. */
export const raOf = (certificate: x509.X509Certificate) => ({ serial: certificate.serialNumber.toUpperCase(), notAfter: certificate.notAfter.toISOString() });

/** Whether an RA certificate has a third of its life left or less. */
export function raDue(pem: string, now: Date) {
  const ra = new x509.X509Certificate(pem);
  const life = ra.notAfter.getTime() - ra.notBefore.getTime();
  return now.getTime() >= ra.notAfter.getTime() - life / 3;
}

/** The SubjectPublicKeyInfo (DER) of a PKCS #8 PEM private key, or of a certificate (PEM), to tell which key a certificate is for. */
const spkiOfKey = (privateKeyPem: string) => createPublicKey(createPrivateKey(privateKeyPem)).export({ format: "der", type: "spki" });
const spkiOfCertificate = (pem: string) => Buffer.from(new x509.X509Certificate(pem).publicKey.rawData);

export interface AdcsRaCertificates {
  /**
   * Has ADCS asked, on the change, for an RA certificate for the profile (locked by the caller), which must be on an
   * ADCS CA and have no request open: for its key when it has no RA certificate yet, or else for a new key, which
   * replaces its RA key once the certificate is issued. Audited as `enrollment_profile.ra_requested`.
   */
  request(tx: Tx, change: Change, profile: ProfileRow): Promise<void>;
  /** Whether the profile has a request for an RA certificate open at ADCS. */
  requesting(db: Db | Tx, profileId: string): Promise<boolean>;
  /**
   * One pass at the clock's time: has ADCS asked for an RA certificate for each enabled profile on an ADCS CA that has
   * none, or whose RA certificate has a third of its life left, unless one is asked for already or the last failed less
   * than a day ago. Returns how many it asked for.
   */
  renewDue(): Promise<number>;
}

export function createAdcsRaCertificates({
  db,
  unitOfWork,
  secrets,
  issuers,
  adcs,
  clock,
}: {
  db: Db;
  unitOfWork: UnitOfWork;
  secrets: Secrets;
  issuers: EnrollmentIssuers;
  adcs: Pick<AdcsIssuance, "handle">;
  clock: () => Date;
}): AdcsRaCertificates {

  /** The profile's latest request for an RA certificate. */
  async function latestOf(dbOrTx: Db | Tx, profileId: string) {
    const [latest] = await dbOrTx
      .select({ status: adcsRequest.status, finishedAt: adcsRequest.finishedAt })
      .from(adcsRequest)
      .where(and(eq(adcsRequest.enrollmentProfileId, profileId), eq(adcsRequest.purpose, "ra")))
      .orderBy(desc(adcsRequest.createdAt))
      .limit(1);
    return latest;
  }

  const isOpen = (status: string | undefined) => (OPEN_REQUEST_STATUSES as readonly string[]).includes(status ?? "");
  const requesting = async (dbOrTx: Db | Tx, profileId: string) => isOpen((await latestOf(dbOrTx, profileId))?.status);

  async function request(tx: Tx, change: Change, profile: ProfileRow) {
    const issuer = enrollmentIssuerOf(profile);
    if (issuer.kind !== "adcs") throw new Error("only a profile on an ADCS CA has its RA certificate issued by ADCS");
    // The first RA certificate is for the key the profile was made with; any later one for a new key, kept aside until then.
    let keyPem: string;
    if (profile.raCertificatePem === null) {
      keyPem = await secrets.open(tx, profile.organizationId, profile.raKeySecretId);
    } else {
      keyPem = newRaKeyPem();
      const next = await secrets.create(tx, profile.organizationId, keyPem);
      const previous = profile.nextRaKeySecretId;
      await tx.update(enrollmentProfile).set({ nextRaKeySecretId: next }).where(eq(enrollmentProfile.id, profile.id));
      if (previous) await tx.delete(secret).where(and(eq(secret.id, previous), eq(secret.organizationId, profile.organizationId)));
    }
    const csr = createCsr({ subject: `CN=SCEP RA ${profile.publicId}`, privateKey: createPrivateKey(keyPem) });
    const csrPem = new x509.Pkcs10CertificateRequest(new Uint8Array(csr)).toString("pem");
    await issuers.requestFromAdcs(tx, change, profile.organizationId, issuer, { purpose: "ra", csrPem, enrollmentProfileId: profile.id });
    await change.audit({
      organizationId: profile.organizationId,
      action: "enrollment_profile.ra_requested",
      target: { type: "enrollment_profile", id: profile.id },
      detail: { name: profile.name, adcsCa: { id: issuer.adcsCaId }, raTemplate: { id: issuer.raTemplateId }, replacing: profile.raCertificatePem === null ? null : raOf(new x509.X509Certificate(profile.raCertificatePem)) },
    });
  }

  /** The profile the request is for, locked. */
  async function lockProfile(tx: Tx, id: string) {
    const [profile] = await tx.select().from(enrollmentProfile).where(eq(enrollmentProfile.id, id)).for("update");
    return profile!;
  }

  /** Forgets the key kept aside for an RA certificate that will not be issued now. */
  async function dropNext(tx: Tx, profile: ProfileRow) {
    if (!profile.nextRaKeySecretId) return;
    await tx.update(enrollmentProfile).set({ nextRaKeySecretId: null }).where(eq(enrollmentProfile.id, profile.id));
    await tx.delete(secret).where(and(eq(secret.id, profile.nextRaKeySecretId), eq(secret.organizationId, profile.organizationId)));
  }

  adcs.handle("ra", {
    async issued(tx, change, request, certificatePem) {
      const profile = await lockProfile(tx, request.enrollmentProfileId!);
      const issued = new x509.X509Certificate(certificatePem);
      const spki = spkiOfCertificate(certificatePem);
      const audit = (detail: Record<string, unknown>) =>
        change.audit({
          organizationId: profile.organizationId,
          action: "enrollment_profile.ra_issued",
          target: { type: "enrollment_profile", id: profile.id },
          detail: { name: profile.name, adcsRequestId: request.adcsRequestId, to: raOf(issued), ...detail },
        });
      // Which of its keys it is for: the one kept aside replaces the current one; the current one is certified for the first time.
      if (profile.nextRaKeySecretId) {
        const next = await secrets.open(tx, profile.organizationId, profile.nextRaKeySecretId);
        if (spki.equals(spkiOfKey(next))) {
          await secrets.replace(tx, profile.organizationId, profile.raKeySecretId, next);
          await dropNext(tx, profile);
          await tx.update(enrollmentProfile).set({ raCertificatePem: issued.toString("pem") }).where(eq(enrollmentProfile.id, profile.id));
          return audit({ from: profile.raCertificatePem ? raOf(new x509.X509Certificate(profile.raCertificatePem)) : null });
        }
      }
      const current = await secrets.open(tx, profile.organizationId, profile.raKeySecretId);
      if (profile.raCertificatePem === null && spki.equals(spkiOfKey(current))) {
        await tx.update(enrollmentProfile).set({ raCertificatePem: issued.toString("pem") }).where(eq(enrollmentProfile.id, profile.id));
        return audit({ from: null });
      }
      // For a key it no longer holds (asked for again since): the profile is left as it is.
      console.error("ADCS issued an RA certificate for a key the Enrollment Profile no longer holds", profile.id, request.adcsRequestId);
    },
    async failed(tx, change, request, failure) {
      const profile = await lockProfile(tx, request.enrollmentProfileId!);
      await dropNext(tx, profile);
      await change.audit({
        organizationId: profile.organizationId,
        action: "enrollment_profile.ra_request_failed",
        target: { type: "enrollment_profile", id: profile.id },
        detail: { name: profile.name, adcsRequestId: request.adcsRequestId, reason: failure.message },
      });
    },
  });

  return {
    request,
    requesting,
    async renewDue() {
      const now = clock();
      const profiles = await db
        .select({ id: enrollmentProfile.id, raCertificatePem: enrollmentProfile.raCertificatePem })
        .from(enrollmentProfile)
        .where(and(eq(enrollmentProfile.issuerKind, "adcs"), eq(enrollmentProfile.enabled, true)));
      let asked = 0;
      for (const { id, raCertificatePem } of profiles) {
        if (raCertificatePem !== null && !raDue(raCertificatePem, now)) continue;
        try {
          const did = await unitOfWork.run(null, async (tx, change) => {
            const profile = await lockProfile(tx, id);
            if (!profile.enabled || (profile.raCertificatePem !== null && !raDue(profile.raCertificatePem, change.occurredAt))) return false;
            const latest = await latestOf(tx, id);
            if (isOpen(latest?.status)) return false;
            if (latest?.status === "failed" && latest.finishedAt && change.occurredAt.getTime() - latest.finishedAt.getTime() < RA_RETRY_AFTER_MS) return false;
            await request(tx, change, profile);
            return true;
          });
          if (did) asked++;
        } catch (err) {
          console.error("could not ask ADCS for an RA certificate", id, err);
        }
      }
      return asked;
    },
  };
}
