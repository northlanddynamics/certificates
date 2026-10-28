// An Enrollment Profile's issuer: the CA its RA certificate and its Device Certificates come from, which a Device
// Certificate records as the issuer it came from. Its kinds are an Issuing CA of one of the Organization's Private CAs,
// which signs at once, and one of its ADCS CAs with the Certificate Templates its Device Certificates and its RA
// certificate are issued under, which an Agent asks and which answers later (adcs-issuance.ts). Creating and changing a
// profile, issuing its RA certificate and its Device Certificates, serving GetCACert and revoking a Device Certificate
// reach the CA through here, and tell its kinds apart nowhere else.
import * as x509 from "@peculiar/x509";
import type { Db, Tx } from "../platform/db/client";
import type { adcsCa, adcsTemplate } from "../platform/db/schema";
import type { CertificateIssuer } from "../issuance/issuer";
import type { EnrollmentIssuerKind } from "./enrollment-profile-kinds";
import { fingerprintOf } from "../pki/fingerprint";
import { subjectAltNamesOf } from "../pki/ca-certificates";
import { enrollmentProfileRefusal, findIssuingCa, issuingRefusal, type IssuingCaOf, type PrivateCas } from "../private-ca/private-ca";
import { adcsNamesRefusal, findAdcsIssuer, templateLabel, templateUnavailableRefusal, type AdcsIssuance } from "../adcs/adcs-issuance";
import { offeredFor, templateKeyRefusal, unavailableReason } from "../adcs/adcs-kinds";
import type { Change } from "../platform/unit-of-work";

type AdcsCaRow = typeof adcsCa.$inferSelect;
type TemplateRow = typeof adcsTemplate.$inferSelect;

/**
 * An Enrollment Profile's issuer, as it stores it: its kind and that kind's reference. For an ADCS CA, the Certificate
 * Template its Device Certificates are issued under, and the one its RA certificate is.
 */
export type EnrollmentIssuer = { kind: "private_ca"; issuingCaId: string } | { kind: "adcs"; adcsCaId: string; templateId: string; raTemplateId: string };

/** The issuer a Device Certificate came from, as it records it: for an ADCS CA, the template it was issued under and ADCS's ID of its request. */
export type DeviceCertificateIssuer = { kind: "private_ca"; issuingCaId: string } | { kind: "adcs"; adcsCaId: string; templateId: string; requestId: string };

/** The issuer as it is found: for a Private CA, the Issuing CA with its Private CA; for an ADCS CA, the CA and both its templates. */
export type FoundEnrollmentIssuer = { kind: "private_ca"; of: IssuingCaOf } | { kind: "adcs"; ca: AdcsCaRow; template: TemplateRow; raTemplate: TemplateRow };

/** The columns that store a profile's issuer. */
type EnrollmentIssuerRow = { issuerKind: EnrollmentIssuerKind; issuingCaId: string | null; adcsCaId: string | null; adcsTemplateId: string | null; adcsRaTemplateId: string | null };
/** The columns that store a Device Certificate's issuer. */
type DeviceIssuerRow = { issuerKind: EnrollmentIssuerKind; issuingCaId: string | null; adcsCaId: string | null; adcsTemplateId: string | null; adcsRequestId: string | null };

/** Whichever of a row's references its kind needs; the database checks that it is there. */
function reference<T>(value: T | null, what: string): T {
  if (value === null) throw new Error(`the issuer has no ${what}`);
  return value;
}

/** An Enrollment Profile's issuer from its row. */
export function enrollmentIssuerOf(row: EnrollmentIssuerRow): EnrollmentIssuer {
  switch (row.issuerKind) {
    case "private_ca":
      return { kind: "private_ca", issuingCaId: reference(row.issuingCaId, "Issuing CA") };
    case "adcs":
      return { kind: "adcs", adcsCaId: reference(row.adcsCaId, "ADCS CA"), templateId: reference(row.adcsTemplateId, "Certificate Template"), raTemplateId: reference(row.adcsRaTemplateId, "RA Certificate Template") };
  }
}

/** A Device Certificate's issuer from its row. */
export function deviceIssuerOf(row: DeviceIssuerRow): DeviceCertificateIssuer {
  switch (row.issuerKind) {
    case "private_ca":
      return { kind: "private_ca", issuingCaId: reference(row.issuingCaId, "Issuing CA") };
    case "adcs":
      return { kind: "adcs", adcsCaId: reference(row.adcsCaId, "ADCS CA"), templateId: reference(row.adcsTemplateId, "Certificate Template"), requestId: reference(row.adcsRequestId, "ADCS request ID") };
  }
}

/** The columns of an Enrollment Profile that store `issuer`. */
export const enrollmentIssuerColumns = (issuer: EnrollmentIssuer) => ({
  issuerKind: issuer.kind,
  issuingCaId: issuer.kind === "private_ca" ? issuer.issuingCaId : null,
  adcsCaId: issuer.kind === "adcs" ? issuer.adcsCaId : null,
  adcsTemplateId: issuer.kind === "adcs" ? issuer.templateId : null,
  adcsRaTemplateId: issuer.kind === "adcs" ? issuer.raTemplateId : null,
});

/** The columns of a Device Certificate that store the issuer it came from. */
export const deviceIssuerColumns = (issuer: DeviceCertificateIssuer) => ({
  issuerKind: issuer.kind,
  issuingCaId: issuer.kind === "private_ca" ? issuer.issuingCaId : null,
  adcsCaId: issuer.kind === "adcs" ? issuer.adcsCaId : null,
  adcsTemplateId: issuer.kind === "adcs" ? issuer.templateId : null,
  adcsRequestId: issuer.kind === "adcs" ? issuer.requestId : null,
});

/** The issuer a Device Certificate came from as a Certificate's Revocation names it (revocations.ts). */
export const asCertificateIssuer = (issuer: DeviceCertificateIssuer): CertificateIssuer => issuer;

/** What tells the issuers of Device Certificates apart, which the CA revokes together. */
export const deviceIssuerKey = (issuer: DeviceCertificateIssuer) => (issuer.kind === "private_ca" ? `private_ca:${issuer.issuingCaId}` : `adcs:${issuer.adcsCaId}:${issuer.requestId}`);

/** The issuer a profile is created with or pointed at, as its API names it: by `issuingCaId`, or by `adcs`. */
export const enrollmentIssuerAsked = (body: { issuingCaId?: string; adcs?: { adcsCaId: string; templateId: string; raTemplateId: string } }): EnrollmentIssuer =>
  body.adcs ? { kind: "adcs", ...body.adcs } : { kind: "private_ca", issuingCaId: body.issuingCaId! };

/** What tells issuers apart, which two of the same issuer share. */
export const enrollmentIssuerKey = (issuer: EnrollmentIssuer) =>
  issuer.kind === "private_ca" ? `private_ca:${issuer.issuingCaId}` : `adcs:${issuer.adcsCaId}:${issuer.templateId}:${issuer.raTemplateId}`;

/** What an Audit Event of an Enrollment Profile says of its issuer: which Issuing CA, or which ADCS CA and templates. */
export function enrollmentIssuerDetail(found: FoundEnrollmentIssuer) {
  if (found.kind === "private_ca") return { issuingCa: { id: found.of.issuing.id, subject: found.of.issuing.subject } };
  const named = (t: TemplateRow) => ({ id: t.id, name: t.name });
  return { adcsCa: { id: found.ca.id, name: found.ca.name }, template: named(found.template), raTemplate: named(found.raTemplate) };
}

/** The certificate of the CA that issues for a profile on the issuer, PEM. */
const issuingCertificateOf = (found: FoundEnrollmentIssuer) => (found.kind === "private_ca" ? found.of.issuing.certificatePem! : found.ca.caCertificatePem);

/**
 * What an Enrollment Profile shows of its issuer: the Issuing CA and its Private CA, or the ADCS CA and its templates
 * (with why its template is unavailable, while it is), and the SHA-256 fingerprint of the CA certificate GetCACert
 * serves. A profile is made only on an Issuing CA that has its certificate, which it then keeps.
 */
export function enrollmentIssuerFields(found: FoundEnrollmentIssuer) {
  const caFingerprint = fingerprintOf(new x509.X509Certificate(issuingCertificateOf(found)).rawData);
  if (found.kind === "private_ca") return { caFingerprint, issuingCaId: found.of.issuing.id, privateCaId: found.of.ca.id, adcs: null };
  const unavailable = unavailableReason(found.template) ?? unavailableReason(found.raTemplate);
  return {
    caFingerprint,
    issuingCaId: null,
    privateCaId: null,
    adcs: { adcsCaId: found.ca.id, templateId: found.template.id, raTemplateId: found.raTemplate.id, templateUnavailable: unavailable },
  };
}

/** The CA certificate (PEM) devices must trust: the issuer's root, or the certificate of the CA that issues; none while the platform has none. */
export function enrollmentIssuerCaCertificate(found: FoundEnrollmentIssuer, ca: "root" | "issuing") {
  if (found.kind === "private_ca") return ca === "root" ? found.of.ca.rootCertificatePem : found.of.issuing.certificatePem;
  return ca === "root" ? (found.ca.chainPem.at(-1) ?? found.ca.caCertificatePem) : found.ca.caCertificatePem;
}

/** The DNS names a CSR (DER) asks for, normalised, which a CA's permitted names are checked against. */
const dnsNamesOf = (csr: Uint8Array) =>
  subjectAltNamesOf(new x509.Pkcs10CertificateRequest(new Uint8Array(csr)))
    .filter((name) => name.type === "dns")
    .map((name) => name.value.toLowerCase().replace(/\.$/, ""));

export interface EnrollmentIssuers {
  /** The Organization's issuer, found; none when it has no such one (or for what cannot be its reference). */
  find(db: Db | Tx, organizationId: string, issuer: EnrollmentIssuer): Promise<FoundEnrollmentIssuer | undefined>;
  /**
   * Why the issuer takes no Enrollment Profile now: it does not issue, or cannot sign an RA certificate SCEP clients
   * verify; for an ADCS CA, its template is not offered for devices or its RA template is unavailable. None when it takes one.
   */
  profileRefusal(found: FoundEnrollmentIssuer): string | undefined;
  /**
   * Has an Issuing CA certify an Enrollment Profile's SCEP RA key (`publicKey`, DER SubjectPublicKeyInfo), valid from
   * now for `validityDays` but never past the CA's end. Throws an IssuanceFailure when the CA cannot issue.
   */
  issueRa(
    db: Db | Tx,
    organizationId: string,
    issuer: EnrollmentIssuer & { kind: "private_ca" },
    request: { publicKey: Uint8Array; subject: x509.Name; validityDays: number },
  ): Promise<x509.X509Certificate>;
  /**
   * Has an Issuing CA issue a Device Certificate for the CSR (DER), with the CSR's subject and subject alternative names
   * and the key usages given, valid from now for `validityDays` but never past the CA's end. Resolves with it and the
   * certificates above it, up to the root (PEM, the CA's first). Throws an IssuanceFailure when the CA cannot issue it.
   */
  issueDevice(
    db: Db | Tx,
    organizationId: string,
    issuer: EnrollmentIssuer & { kind: "private_ca" },
    request: { csr: Uint8Array; validityDays: number; keyUsage: (keyof typeof x509.KeyUsageFlags)[]; extendedKeyUsages: string[] },
  ): Promise<{ certificate: x509.X509Certificate; chainPem: string[] }>;
  /**
   * Has an Agent ask the ADCS CA, on the change, for the profile's RA certificate (`ra`, under its RA template) or a
   * device's Device Certificate (`device`, under its template) for the CSR (PEM); what comes of it goes to whoever
   * handles that purpose (AdcsIssuance.handle). Returns the request's id.
   */
  requestFromAdcs(
    tx: Tx,
    change: Change,
    organizationId: string,
    issuer: EnrollmentIssuer & { kind: "adcs" },
    request: { purpose: "ra" | "device"; csrPem: string; enrollmentProfileId: string },
  ): Promise<string>;
  /**
   * Why the issuer would refuse the CSR (DER) of a key of `keyType` now: it does not issue, or not for one of its DNS
   * names; for an ADCS CA, the template is unavailable, or does not take the key. None when it would issue it.
   */
  deviceRefusal(db: Db | Tx, organizationId: string, issuer: EnrollmentIssuer, csr: Uint8Array, keyType: string): Promise<string | undefined>;
  /**
   * The certificate of the CA that issues for a profile on the issuer, and those above it up to the root (PEM, the CA's
   * first), as GetCACert serves them. A profile is made only on an issuer that has its certificate, which it then keeps.
   */
  chainOf(db: Db | Tx, organizationId: string, issuer: EnrollmentIssuer): Promise<string[]>;
}

/** The certificates of a PEM bundle, PEM, in order. */
const certificatesIn = (pem: string) => pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? [];

export function createEnrollmentIssuers({ privateCas, adcs }: { privateCas: PrivateCas; adcs: Pick<AdcsIssuance, "request"> }): EnrollmentIssuers {
  /** The Organization's ADCS CA and both the profile's templates of it; none unless all are there. */
  async function findAdcs(db: Db | Tx, organizationId: string, issuer: EnrollmentIssuer & { kind: "adcs" }): Promise<FoundEnrollmentIssuer | undefined> {
    const { ca, template } = await findAdcsIssuer(db, organizationId, issuer);
    const { template: raTemplate } = await findAdcsIssuer(db, organizationId, { adcsCaId: issuer.adcsCaId, templateId: issuer.raTemplateId });
    return ca && template && raTemplate ? { kind: "adcs", ca, template, raTemplate } : undefined;
  }

  return {
    async find(db, organizationId, issuer) {
      if (issuer.kind === "adcs") return findAdcs(db, organizationId, issuer);
      const of = await findIssuingCa(db, organizationId, issuer.issuingCaId);
      return of && { kind: "private_ca", of };
    },
    profileRefusal(found) {
      if (found.kind === "private_ca") return issuingRefusal(found.of) ?? enrollmentProfileRefusal(found.of.ca);
      if (!offeredFor(found.template).includes("devices")) {
        const why = unavailableReason(found.template) ?? (found.template.hidden ? "an Organization Administrator hid it." : "It has no Client Authentication EKU.");
        return `${templateLabel(found.ca, found.template)} is not offered for devices: ${why}`;
      }
      // The RA template need only be available: an RA certificate is neither a TLS nor a device certificate.
      return templateUnavailableRefusal(found.ca, found.raTemplate);
    },
    issueRa: (db, organizationId, issuer, request) => privateCas.issueRa(db, organizationId, issuer.issuingCaId, request),
    issueDevice: (db, organizationId, issuer, request) => privateCas.issueDevice(db, organizationId, issuer.issuingCaId, request),
    requestFromAdcs: (tx, change, organizationId, issuer, { purpose, csrPem, enrollmentProfileId }) =>
      adcs.request(tx, change, { organizationId, adcsCaId: issuer.adcsCaId, templateId: purpose === "ra" ? issuer.raTemplateId : issuer.templateId, csrPem, purpose, enrollmentProfileId }),
    async deviceRefusal(db, organizationId, issuer, csr, keyType) {
      if (issuer.kind === "private_ca") return privateCas.deviceRefusal(db, organizationId, issuer.issuingCaId, csr);
      const found = await findAdcs(db, organizationId, issuer);
      if (!found || found.kind !== "adcs") return "the ADCS CA or its Certificate Template is gone";
      return templateUnavailableRefusal(found.ca, found.template) ?? adcsNamesRefusal(found.ca, dnsNamesOf(csr)) ?? templateKeyRefusal(found.template, keyType) ?? undefined;
    },
    async chainOf(db, organizationId, issuer) {
      if (issuer.kind === "adcs") {
        const found = (await findAdcs(db, organizationId, issuer))!;
        return found.kind === "adcs" ? [found.ca.caCertificatePem, ...found.ca.chainPem] : [];
      }
      const { issuing, ca } = (await findIssuingCa(db, organizationId, issuer.issuingCaId))!;
      return [issuing.certificatePem!, ...[ca.chainPem, ca.rootCertificatePem].filter((pem): pem is string => pem !== null).flatMap(certificatesIn)];
    },
  };
}
