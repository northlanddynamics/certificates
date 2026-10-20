// Reads everything an X.509 certificate says, for the Viewer: who it is for and from, when it is valid, its names, key,
// signature and extensions, and the fingerprints that name it. It decides nothing and does not build a chain: a
// certificate not signed by itself is signed by an issuer whose certificate is not here, so its signature is left
// unchecked. Pure, with no fetch, so a pasted certificate goes nowhere.
import * as x509 from "@peculiar/x509";
import {
  SUBJECT_ALTERNATIVE_NAME,
  alternativeNames,
  digest,
  extensionsOf,
  isCaExtension,
  signatureLabel,
  subjectFields,
  summarizeKey,
  type KeySummary,
  type PkiExtension,
  type PkiName,
  type SignatureCheck,
  type SubjectField,
} from "./pki-common";

const DAY = 86_400_000;
/** How soon before it ends a certificate is said to be about to expire. */
export const EXPIRY_WARNING_DAYS = 30;

export type Validity = "valid" | "expired" | "not-yet-valid";

export interface CertificateDetails {
  subject: SubjectField[];
  issuer: SubjectField[];
  /** Lower-case hex, as the certificate holds it. */
  serialNumber: string;
  validity: {
    /** ISO 8601. */
    notBefore: string;
    notAfter: string;
    status: Validity;
    /** Whole days left when valid, since it ended when expired, and until it begins when not yet valid. */
    days: number;
    /** Whole days from the start to the end. */
    lifetimeDays: number;
  };
  names: PkiName[];
  /** Its issuer is its subject: it signed itself, or is a root. */
  selfIssued: boolean;
  /** Basic constraints say it is a CA. */
  isCa: boolean;
  key: KeySummary;
  /** `check` is unchecked for a certificate its issuer signed, which this browser does not hold. */
  signature: { algorithm: string; check: SignatureCheck };
  extensions: PkiExtension[];
  warnings: string[];
  /** SHA-256 of the certificate's DER, lower-case hex: how the platform names a Certificate. */
  fingerprint: string;
  /** SHA-1 of the DER, the thumbprint many tools still show. */
  sha1: string;
  derLength: number;
  /** The certificate as one clean PEM block. */
  pem: string;
}

export type CertificateReading = { ok: true; details: CertificateDetails } | { ok: false; error: string };

async function checkSignature(certificate: x509.X509Certificate, selfIssued: boolean, mlDsa: boolean): Promise<SignatureCheck> {
  if (!selfIssued) return "unchecked";
  if (await certificate.verify({ signatureOnly: true }).catch(() => false)) return "valid";
  if (!mlDsa) return "invalid";
  try {
    return (await import("./csr-ml-dsa")).verifyMlDsaCertificate(certificate.rawData, certificate.publicKey.rawData) ? "valid" : "invalid";
  } catch {
    return "unchecked";
  }
}

/** Everything a PEM certificate says, or why it cannot be read, in words. `now` is when its validity is judged. */
export async function parseCertificateDetails(pem: string, now: Date = new Date()): Promise<CertificateReading> {
  let certificate: x509.X509Certificate;
  try {
    certificate = new x509.X509Certificate(pem.trim());
  } catch {
    return { ok: false, error: "This looks like a certificate but cannot be read as one. It may be cut short or damaged in copying." };
  }
  try {
    const mlDsa = certificate.publicKey.algorithm.name.startsWith("ML-DSA");
    const selfIssued = certificate.subject === certificate.issuer;
    const [check, key, fingerprint, sha1] = await Promise.all([
      checkSignature(certificate, selfIssued, mlDsa),
      summarizeKey(certificate.publicKey),
      digest("SHA-256", certificate.rawData),
      digest("SHA-1", certificate.rawData),
    ]);
    const extensions = extensionsOf(certificate.extensions);
    const names = alternativeNames(certificate.getExtension(SUBJECT_ALTERNATIVE_NAME));
    const isCa = extensions.some(isCaExtension);

    const { notBefore, notAfter } = certificate;
    const status: Validity = now < notBefore ? "not-yet-valid" : now > notAfter ? "expired" : "valid";
    const days = Math.floor(Math.abs((status === "valid" ? notAfter.getTime() - now.getTime() : status === "expired" ? now.getTime() - notAfter.getTime() : notBefore.getTime() - now.getTime()) / DAY));

    const warnings: string[] = [];
    if (status === "valid" && days < EXPIRY_WARNING_DAYS) warnings.push(`It expires in ${days === 0 ? "less than a day" : `${days} ${days === 1 ? "day" : "days"}`}.`);
    const { name, hash } = certificate.signatureAlgorithm as { name: string; hash?: { name: string } };
    if (name === "1.2.840.113549.1.1.4" || hash?.name === "SHA-1") warnings.push(`It is signed with ${name === "1.2.840.113549.1.1.4" ? "MD5" : "SHA-1"}, which browsers and most clients no longer trust.`);
    if (!isCa && names.length === 0) warnings.push("It has no subject alternative names. Browsers ignore the common name, so it would not be accepted by them for any site.");

    return {
      ok: true,
      details: {
        subject: subjectFields(certificate.subjectName),
        issuer: subjectFields(certificate.issuerName),
        serialNumber: certificate.serialNumber,
        validity: { notBefore: notBefore.toISOString(), notAfter: notAfter.toISOString(), status, days, lifetimeDays: Math.round((notAfter.getTime() - notBefore.getTime()) / DAY) },
        names,
        selfIssued,
        isCa,
        key,
        signature: { algorithm: signatureLabel(certificate.signatureAlgorithm), check },
        extensions,
        warnings,
        fingerprint,
        sha1,
        derLength: certificate.rawData.byteLength,
        pem: certificate.toString("pem"),
      },
    };
  } catch {
    return { ok: false, error: "This certificate is well formed but something in it could not be read." };
  }
}
