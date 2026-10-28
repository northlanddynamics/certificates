// An Enrollment Profile's issuer: the CA its RA certificate and its Device Certificates come from, which a Device
// Certificate records as the issuer it came from. Its kinds are an Issuing CA of one of the Organization's Private CAs,
// for now the only one. Creating and changing a profile, issuing its RA certificate and its Device Certificates, serving
// GetCACert and revoking a Device Certificate reach the CA through here, and tell its kinds apart nowhere else.
import * as x509 from "@peculiar/x509";
import type { Db, Tx } from "../platform/db/client";
import type { CertificateIssuer } from "../issuance/issuer";
import type { EnrollmentIssuerKind } from "./enrollment-profile-kinds";
import { fingerprintOf } from "../pki/fingerprint";
import { enrollmentProfileRefusal, findIssuingCa, issuingRefusal, type IssuingCaOf, type PrivateCas } from "../private-ca/private-ca";

/** An Enrollment Profile's issuer, as it and its Device Certificates store it: its kind and that kind's reference. */
export type EnrollmentIssuer = { kind: "private_ca"; issuingCaId: string };

/** The issuer as it is found: for a Private CA, the Issuing CA with its Private CA. */
export type FoundEnrollmentIssuer = { kind: "private_ca"; of: IssuingCaOf };

/** The columns that store an issuer, as an Enrollment Profile's and a Device Certificate's rows have them. */
type EnrollmentIssuerRow = { issuerKind: EnrollmentIssuerKind; issuingCaId: string | null };

/** An Enrollment Profile's or a Device Certificate's issuer from its row; the database checks that its kind's reference is there. */
export function enrollmentIssuerOf(row: EnrollmentIssuerRow): EnrollmentIssuer {
  switch (row.issuerKind) {
    case "private_ca":
      if (row.issuingCaId === null) throw new Error("the issuer has no Issuing CA");
      return { kind: "private_ca", issuingCaId: row.issuingCaId };
  }
}

/** The columns of an Enrollment Profile or a Device Certificate that store `issuer`. */
export const enrollmentIssuerColumns = (issuer: EnrollmentIssuer) => ({ issuerKind: issuer.kind, issuingCaId: issuer.issuingCaId });

/** The issuer a Device Certificate came from as a Certificate's Revocation names it (revocations.ts). */
export const asCertificateIssuer = (issuer: EnrollmentIssuer): CertificateIssuer => issuer;

/** The issuer a profile is created with or pointed at, as its API names it: by `issuingCaId`. */
export const enrollmentIssuerAsked = (body: { issuingCaId: string }): EnrollmentIssuer => ({ kind: "private_ca", issuingCaId: body.issuingCaId });

/** What tells issuers apart, which two of the same issuer share. */
export const enrollmentIssuerKey = (issuer: EnrollmentIssuer) => `${issuer.kind}:${issuer.issuingCaId}`;

/** What an Audit Event of an Enrollment Profile says of its issuer: which Issuing CA. */
export const enrollmentIssuerDetail = (found: FoundEnrollmentIssuer) => ({ id: found.of.issuing.id, subject: found.of.issuing.subject });

/**
 * What an Enrollment Profile shows of its issuer: the Issuing CA and its Private CA, and the SHA-256 fingerprint of the
 * CA certificate GetCACert serves. A profile is made only on an Issuing CA that has its certificate, which it then keeps.
 */
export const enrollmentIssuerFields = (found: FoundEnrollmentIssuer) => ({
  caFingerprint: fingerprintOf(new x509.X509Certificate(found.of.issuing.certificatePem!).rawData),
  issuingCaId: found.of.issuing.id,
  privateCaId: found.of.ca.id,
});

/** The CA certificate (PEM) devices must trust: the issuer's root, or the certificate of the CA that issues; none while the platform has none. */
export const enrollmentIssuerCaCertificate = (found: FoundEnrollmentIssuer, ca: "root" | "issuing") => (ca === "root" ? found.of.ca.rootCertificatePem : found.of.issuing.certificatePem);

export interface EnrollmentIssuers {
  /** The Organization's issuer, found; none when it has no such one (or for what cannot be its reference). */
  find(db: Db | Tx, organizationId: string, issuer: EnrollmentIssuer): Promise<FoundEnrollmentIssuer | undefined>;
  /** Why the issuer takes no Enrollment Profile now: it does not issue, or cannot sign an RA certificate SCEP clients verify. None when it takes one. */
  profileRefusal(found: FoundEnrollmentIssuer): string | undefined;
  /**
   * Has the issuer certify an Enrollment Profile's SCEP RA key (`publicKey`, DER SubjectPublicKeyInfo), valid from now
   * for `validityDays` but never past the CA's end. Throws an IssuanceFailure when the CA cannot issue.
   */
  issueRa(db: Db | Tx, organizationId: string, issuer: EnrollmentIssuer, request: { publicKey: Uint8Array; subject: x509.Name; validityDays: number }): Promise<x509.X509Certificate>;
  /**
   * Has the issuer issue a Device Certificate for the CSR (DER), with the CSR's subject and subject alternative names and
   * the key usages given, valid from now for `validityDays` but never past the CA's end. Resolves with it and the
   * certificates above it, up to the root (PEM, the CA's first). Throws an IssuanceFailure when the CA cannot issue it.
   */
  issueDevice(
    db: Db | Tx,
    organizationId: string,
    issuer: EnrollmentIssuer,
    request: { csr: Uint8Array; validityDays: number; keyUsage: (keyof typeof x509.KeyUsageFlags)[]; extendedKeyUsages: string[] },
  ): Promise<{ certificate: x509.X509Certificate; chainPem: string[] }>;
  /** Why `issueDevice` would refuse the CSR (DER) now. None when it would issue it. */
  deviceRefusal(db: Db | Tx, organizationId: string, issuer: EnrollmentIssuer, csr: Uint8Array): Promise<string | undefined>;
  /**
   * The certificate of the CA that issues for a profile on the issuer, and those above it up to the root (PEM, the CA's
   * first), as GetCACert serves them. A profile is made only on an issuer that has its certificate, which it then keeps.
   */
  chainOf(db: Db | Tx, organizationId: string, issuer: EnrollmentIssuer): Promise<string[]>;
}

/** The certificates of a PEM bundle, PEM, in order. */
const certificatesIn = (pem: string) => pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? [];

export function createEnrollmentIssuers({ privateCas }: { privateCas: PrivateCas }): EnrollmentIssuers {
  return {
    async find(db, organizationId, issuer) {
      const of = await findIssuingCa(db, organizationId, issuer.issuingCaId);
      return of && { kind: "private_ca", of };
    },
    profileRefusal: (found) => issuingRefusal(found.of) ?? enrollmentProfileRefusal(found.of.ca),
    issueRa: (db, organizationId, issuer, request) => privateCas.issueRa(db, organizationId, issuer.issuingCaId, request),
    issueDevice: (db, organizationId, issuer, request) => privateCas.issueDevice(db, organizationId, issuer.issuingCaId, request),
    deviceRefusal: (db, organizationId, issuer, csr) => privateCas.deviceRefusal(db, organizationId, issuer.issuingCaId, csr),
    async chainOf(db, organizationId, issuer) {
      const { issuing, ca } = (await findIssuingCa(db, organizationId, issuer.issuingCaId))!;
      return [issuing.certificatePem!, ...[ca.chainPem, ca.rootCertificatePem].filter((pem): pem is string => pem !== null).flatMap(certificatesIn)];
    },
  };
}
