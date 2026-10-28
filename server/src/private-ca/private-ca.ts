// An Organization's Private CAs: its own CAs, from which a Managed Certificate can be issued instead of from an ACME CA,
// with no DCV. A Private CA is a root and the Issuing CAs under it, each Issuing CA with its own key, permitted name rules
// and validity limits. An Organization Administrator creates one; with a platform-made root, the platform makes a
// self-signed root and a first Issuing CA under it, each with its own key in the KMS (ADR 0007), and later adds more
// Issuing CAs under the same root, so that relying parties trust the root once. Everyone in the Organization may see them
// and download the root and each Issuing CA's chain. Issuing from an Issuing CA is the Private CA kind of issuer
// (issuer.ts), which signs through `issueFrom` here and has a revocation put on the Issuing CA's CRL (crl.ts) through
// `publishRevocation`.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import * as x509 from "@peculiar/x509";
import { and, asc, eq, inArray } from "drizzle-orm";
import { randomUUID } from "node:crypto";
import type { Authorizer } from "../tenancy/authorization";
import { makeCaCsr, makeDeviceCertificate, makeIssuingCa, makeRaCertificate, makeRoot, makeTlsServer, nameConstraintsOf, parseSubject, rootSubjectOf, signedCertificateRefusal, subjectAltNamesOf, type CaKey, type Signer } from "../pki/ca-certificates";
import { CertificateAuthorityError } from "../issuance/acme/certificate-authority";
import { AcmeCaId, DEFAULT_ACME_CA_ID, type AcmeCas } from "../issuance/acme/acme-cas";
import { publicationOf, type Crls } from "./crl";
import { KEY_ALGORITHMS, certificateKeyAlgorithmsOn, isMlDsa, mixedChainReason, type KeyAlgorithm, type SigningKeyAlgorithm } from "../pki/csr";
import type { Db, Tx } from "../platform/db/client";
import { issuingCa, privateCa } from "../platform/db/schema";
import { HttpError, OrgParam, PemResponse, errors, fileNameOf, isUniqueViolation, json, pemFile } from "../platform/http";
import { IssuanceFailure } from "../issuance/issuance-failure";
import type { Issuer } from "../issuance/issuer";
import type { Kms } from "../platform/crypto/kms";
import { constraintNamesOf, namesOutside, normalizePermittedNames, samePermittedNames, type PermittedNames } from "./permitted-names";
import { DEFAULT_LIFETIME_YEARS, DEFAULT_VALIDITY_DAYS, ISSUING_CA_STATUSES, MAX_LIFETIME_YEARS, MAX_VALIDITY_DAYS, PRIVATE_CA_KINDS, PRIVATE_CA_STATUSES, type PrivateCaKind } from "./private-ca-kinds";
import { ISSUING_CA_REVOCATION_REASONS } from "../pki/revocation-reasons";
import type { Actor, Change, UnitOfWork } from "../platform/unit-of-work";

const DAY_MS = 24 * 60 * 60 * 1000;

type PrivateCaRow = typeof privateCa.$inferSelect;
type IssuingCaRow = typeof issuingCa.$inferSelect;
/** An Issuing CA with the Private CA it is under. */
export type IssuingCaOf = { issuing: IssuingCaRow; ca: PrivateCaRow };

export const PrivateCaParams = OrgParam.extend({ id: z.string().openapi({ param: { name: "id", in: "path" } }) });
const IssuingCaParams = PrivateCaParams.extend({ issuingCaId: z.string().openapi({ param: { name: "issuingCaId", in: "path" } }) });

const MAX_RULES = 100;

/** An Issuing CA's permitted name rules, as they are given and shown. */
const PermittedNamesField = z
  .object({
    exact: z.array(z.string().max(255)).max(MAX_RULES).default([]).openapi({ description: "Names permitted exactly: a DNS name, or a wildcard (`*.` then a DNS name), which permits that wildcard alone." }),
    zones: z.array(z.string().max(255)).max(MAX_RULES).default([]).openapi({ description: "Zones: each permits the name and every name beneath it, wildcards included. Never a wildcard." }),
  })
  .openapi({ description: "The names the Issuing CA may issue for, normalised as names are (lower case, no trailing dot). No IP addresses." });

/** The rules given, normalised; a 400 when they cannot be rules. */
function permittedNamesAsked(rules: PermittedNames): PermittedNames {
  const normal = normalizePermittedNames(rules);
  if ("invalid" in normal) throw new HttpError(400, normal.invalid);
  return normal.rules;
}

/** A number of days a TLS Certificate is valid for. */
export const validityDaysField = z.number().int().min(1).max(MAX_VALIDITY_DAYS);

/** An Issuing CA's validity limits, as they are given and shown. */
const ValidityField = z
  .object({
    maximumDays: validityDaysField.openapi({ description: "The longest a Managed Certificate on it may choose." }),
    defaultDays: validityDaysField.openapi({ description: "What one that chooses none gets; at most `maximumDays`." }),
  })
  .openapi({ description: "How long the TLS Certificates it issues are valid for, in days. Never past the Issuing CA's end, whatever these say." });
type Validity = z.infer<typeof ValidityField>;
const DEFAULT_VALIDITY: Validity = { maximumDays: DEFAULT_VALIDITY_DAYS, defaultDays: DEFAULT_VALIDITY_DAYS };

/** The limits given; a 422 when the default is above the maximum. */
function validityAsked(validity: Validity): Validity {
  if (validity.defaultDays > validity.maximumDays) throw new HttpError(422, `the default validity (${validity.defaultDays} days) is above the maximum (${validity.maximumDays} days)`);
  return validity;
}

/** Each of the limits `to` changes from `from`, as `{ from, to }`; none when it changes none. */
function validityChanges(from: Validity, to: Validity) {
  const changed = (["maximumDays", "defaultDays"] as const).filter((field) => from[field] !== to[field]);
  return changed.length === 0 ? undefined : Object.fromEntries(changed.map((field) => [field, { from: from[field], to: to[field] }]));
}

/** An Issuing CA's validity limits, from its row. */
const validityOf = (row: IssuingCaRow): Validity => ({ maximumDays: row.maxValidityDays, defaultDays: row.defaultValidityDays });

/** An Issuing CA's rules, from its row. */
const permittedNamesOf = (row: IssuingCaRow): PermittedNames => ({ exact: row.permittedExactNames, zones: row.permittedZones });

/** The subject given, as a distinguished name; a 400 when it is not one with a common name. */
function subjectAsked(subject: string): x509.Name {
  const name = parseSubject(subject);
  if (!name) throw new HttpError(400, "the subject must be a distinguished name with a common name, such as CN=Acme Internal TLS, O=Acme");
  return name;
}

export const IssuingCa = z.object({
  id: z.string(),
  subject: z.string().openapi({ description: "Its subject, as a distinguished name; no other Issuing CA of its Private CA has it." }),
  status: z.enum(ISSUING_CA_STATUSES).openapi({ description: "Only an `active` one, under an `active` root, issues." }),
  notAfter: z.string().nullable().openapi({ description: "When it ends; none until it has a certificate." }),
  permittedNames: z
    .object({ exact: z.array(z.string()), zones: z.array(z.string()) })
    .openapi({ description: "Its permitted name rules: it issues for no other name. One made before there were rules has none, and issues for nothing until they are set." }),
  validity: ValidityField,
  nameConstraints: z
    .object({ permitted: z.array(z.string()), excluded: z.array(z.string()) })
    .nullable()
    .openapi({
      description:
        "The name constraints in its certificate, which relying parties enforce: each subtree as `dns:`, `ip:` (CIDR), `email:`, `uri:` or `dn:` and its base. " +
        "A platform-made one's are its rules as they were when it was made; under an Organization's own root, whatever that root put there. None when its certificate has none, or it has no certificate yet.",
    }),
});

export const PrivateCa = z.object({
  id: z.string(),
  name: z.string(),
  kind: z.enum(PRIVATE_CA_KINDS).openapi({ description: "`platform_root`: the platform made its root, which signs its Issuing CAs. `organization_root`: the Organization's own root signs them." }),
  status: z.enum(PRIVATE_CA_STATUSES).openapi({ description: "Its root's: a `revoked` root's Issuing CAs issue nothing." }),
  keyAlgorithm: z.enum(KEY_ALGORITHMS).openapi({ description: "The algorithm of its keys, the root's and its Issuing CAs'." }),
  certificateKeyAlgorithms: z
    .array(z.enum(KEY_ALGORITHMS))
    .openapi({ description: "The key algorithms a Managed Certificate issued from it may have: ML-DSA ones on an ML-DSA Private CA, and only there, so that a chain is all ML-DSA or none of it." }),
  enrollmentProfileRefusal: z
    .string()
    .nullable()
    .openapi({ description: "Why an Enrollment Profile cannot be created on, or repointed to, its Issuing CAs (the keys are ML-DSA, which SCEP clients cannot verify); none when it can." }),
  root: z
    .object({ subject: z.string(), notAfter: z.string() })
    .nullable()
    .openapi({ description: "The root that signs its Issuing CAs: its subject, as a distinguished name, and when it ends. None when the platform does not hold it." }),
  issuingCas: z.array(IssuingCa).openapi({ description: "Its Issuing CAs, oldest first: a Managed Certificate is issued from one of them." }),
  createdAt: z.string(),
});

const certificateOf = (pem: string | null) => (pem ? new x509.X509Certificate(pem) : null);

/** The Private CA's root, when the platform holds it. */
function rootOf(row: PrivateCaRow) {
  const root = certificateOf(row.rootCertificatePem);
  return root ? { subject: root.subject, notAfter: root.notAfter.toISOString() } : null;
}

function toIssuingCa(row: IssuingCaRow): z.infer<typeof IssuingCa> {
  const certificate = certificateOf(row.certificatePem);
  return {
    id: row.id,
    subject: row.subject,
    status: row.status,
    notAfter: certificate?.notAfter.toISOString() ?? null,
    permittedNames: permittedNamesOf(row),
    validity: validityOf(row),
    nameConstraints: certificate && nameConstraintsOf(certificate),
  };
}

const toPrivateCa = (row: PrivateCaRow, issuingCas: IssuingCaRow[]): z.infer<typeof PrivateCa> => ({
  id: row.id,
  name: row.name,
  kind: row.kind,
  status: row.status,
  keyAlgorithm: row.keyAlgorithm,
  certificateKeyAlgorithms: [...certificateKeyAlgorithmsOn(row.keyAlgorithm)],
  enrollmentProfileRefusal: enrollmentProfileRefusal(row) ?? null,
  root: rootOf(row),
  issuingCas: issuingCas.filter((i) => i.privateCaId === row.id).map(toIssuingCa),
  createdAt: row.createdAt.toISOString(),
});

/** The Issuing CAs of the Private CAs, oldest first. */
const issuingCasOf = (db: Db | Tx, privateCaIds: string[]) =>
  privateCaIds.length === 0 ? Promise.resolve([]) : db.select().from(issuingCa).where(inArray(issuingCa.privateCaId, privateCaIds)).orderBy(asc(issuingCa.createdAt), asc(issuingCa.id));

/** The Private CA as the API shows it, with its Issuing CAs. */
const shown = async (db: Db | Tx, row: PrivateCaRow) => toPrivateCa(row, await issuingCasOf(db, [row.id]));

const isId = (id: string) => z.uuid().safeParse(id).success;

/** The Organization's Private CA, or none (also for what cannot be an id). */
async function findPrivateCa(db: Db | Tx, organizationId: string, id: string): Promise<PrivateCaRow | undefined> {
  if (!isId(id)) return undefined;
  const [row] = await db
    .select()
    .from(privateCa)
    .where(and(eq(privateCa.organizationId, organizationId), eq(privateCa.id, id)));
  return row;
}

/** The Organization's Issuing CA with its Private CA, or none (also for what cannot be an id). */
export async function findIssuingCa(db: Db | Tx, organizationId: string, issuingCaId: string): Promise<IssuingCaOf | undefined> {
  if (!isId(issuingCaId)) return undefined;
  const [row] = await db
    .select({ issuing: issuingCa, ca: privateCa })
    .from(issuingCa)
    .innerJoin(privateCa, eq(privateCa.id, issuingCa.privateCaId))
    .where(and(eq(issuingCa.organizationId, organizationId), eq(issuingCa.id, issuingCaId)));
  return row;
}

/** The Issuing CA in words, by its common name and its Private CA's name. */
export const issuingCaLabel = ({ issuing, ca }: IssuingCaOf) => `the Issuing CA ${new x509.Name(issuing.subject).getField("CN")[0] ?? issuing.subject} of the Private CA ${ca.name}`;

/** Why the Issuing CA issues nothing now: its root is revoked, or it is not active. None when it issues. */
export function issuingRefusal(of: IssuingCaOf) {
  if (of.ca.status !== "active") return `the root of the Private CA ${of.ca.name} is ${of.ca.status}, so its Issuing CAs issue nothing`;
  if (of.issuing.status !== "active" || !of.issuing.certificatePem) return `${issuingCaLabel(of)} is ${of.issuing.status}, so it issues nothing`;
  return undefined;
}

/**
 * Why the Private CA takes no Enrollment Profile: its keys are ML-DSA. Device keys stay RSA, and a profile's SCEP RA
 * certificate, signed by its Issuing CA, would carry an ML-DSA signature that SCEP clients (Intune, Iru, network gear)
 * cannot verify. None when it takes them.
 */
export const enrollmentProfileRefusal = (ca: Pick<PrivateCaRow, "name" | "keyAlgorithm">) =>
  isMlDsa(ca.keyAlgorithm) ? `the Private CA ${ca.name} has ${ca.keyAlgorithm} keys, and SCEP clients cannot verify the ML-DSA signature of a profile's RA certificate, so devices cannot enroll under an ML-DSA Issuing CA` : undefined;

/** Why a Managed Certificate on the Issuing CA may not choose `validityDays`: it is above the maximum. None when it may, or chooses none. */
export const validityRefusal = (of: IssuingCaOf, validityDays: number | null) =>
  validityDays !== null && validityDays > of.issuing.maxValidityDays ? `a validity of ${validityDays} days is above the maximum of ${of.issuing.maxValidityDays} days of ${issuingCaLabel(of)}` : undefined;

/** Why the Issuing CA may not issue for the names (normalised): those its permitted name rules do not permit. None when it may. */
export function namesRefusal(of: IssuingCaOf, names: string[]) {
  const outside = namesOutside(permittedNamesOf(of.issuing), names);
  return outside.length === 0 ? undefined : `${outside.join(", ")} ${outside.length === 1 ? "is" : "are"} outside the permitted names of ${issuingCaLabel(of)}`;
}

/** Why a Managed Certificate with a key of `keyAlgorithm` may not be issued from the CA, whose own key is `caKeyAlgorithm` (none for an ACME CA). None when it may. */
export function keyAlgorithmRefusal(keyAlgorithm: KeyAlgorithm, on: { caKeyAlgorithm?: KeyAlgorithm; label: string }) {
  const taken = certificateKeyAlgorithmsOn(on.caKeyAlgorithm);
  if (taken.includes(keyAlgorithm)) return undefined;
  return `${on.label} takes keys of ${taken.join(", ")}, not ${keyAlgorithm}: ${mixedChainReason(keyAlgorithm)}`;
}

/**
 * Why a Managed Certificate may not ask the issuer for the names (normalised), the validity and, when given, the key
 * algorithm: a 422 when it is an Issuing CA that is not the Organization's, or does not issue (it or its root), or does
 * not permit the names, or allows no such validity, or when the issuer takes no such key algorithm; a 400 for a
 * validity asked of an ACME CA, which decides its own (and checks control of the names instead). None when it may.
 */
export async function issuerRefusal(db: Db | Tx, organizationId: string, issuer: Issuer, asked: { names: string[]; validityDays: number | null; keyAlgorithm?: KeyAlgorithm }) {
  const refused = (status: 400 | 422, message: string) => ({ status, message });
  if (issuer.kind !== "private_ca") {
    if (asked.validityDays !== null) return refused(400, "a validity can be chosen only for a Managed Certificate issued from a Private CA");
    const refusal = asked.keyAlgorithm && keyAlgorithmRefusal(asked.keyAlgorithm, { label: "an ACME CA" });
    return refusal ? refused(422, refusal) : undefined;
  }
  const of = await findIssuingCa(db, organizationId, issuer.issuingCaId);
  if (!of) return refused(422, "the Organization has no such Issuing CA");
  const refusal =
    issuingRefusal(of) ??
    namesRefusal(of, asked.names) ??
    validityRefusal(of, asked.validityDays) ??
    (asked.keyAlgorithm && keyAlgorithmRefusal(asked.keyAlgorithm, { caKeyAlgorithm: of.ca.keyAlgorithm, label: issuingCaLabel(of) }));
  return refusal ? refused(422, refusal) : undefined;
}

/** The issuer a Managed Certificate is created or proposed with, or a Deployment set up with. */
export const IssuerField = z
  .discriminatedUnion("kind", [
    z.object({ kind: z.literal("acme"), acmeCaId: AcmeCaId.default(DEFAULT_ACME_CA_ID) }),
    z.object({ kind: z.literal("private_ca"), issuingCaId: z.string() }),
  ])
  .openapi({ description: "`acme`: through the Organization's ACME account with the ACME CA `acmeCaId`, Let's Encrypt Staging unless given. `private_ca`: from an active Issuing CA of one of the Organization's Private CAs, with no DCV." });

/**
 * The issuer asked for: `issuer`, or the ACME kind with the ACME CA `acmeCaId` (Let's Encrypt Staging unless given), which
 * must be one the Organization can use. An Issuing CA must be one of the Organization's, active under an active root,
 * permit the names (normalised), and allow the validity chosen, which only a Private CA lets be chosen.
 */
export async function issuerAsked(
  db: Db,
  acmeCas: AcmeCas,
  orgId: string,
  body: { acmeCaId?: string; issuer?: z.infer<typeof IssuerField>; validityDays?: number; keyAlgorithm: KeyAlgorithm },
  names: string[],
): Promise<Issuer> {
  if (body.issuer && body.acmeCaId) throw new HttpError(400, "give either `issuer` or `acmeCaId`, not both");
  const issuer = body.issuer ?? { kind: "acme", acmeCaId: body.acmeCaId ?? DEFAULT_ACME_CA_ID };
  if (issuer.kind === "acme" && !(await acmeCas.find(orgId, issuer.acmeCaId))) throw new HttpError(422, "the Organization has no such ACME CA");
  const validityDays = body.validityDays ?? null;
  const refusal = await issuerRefusal(db, orgId, issuer, { names, validityDays, keyAlgorithm: body.keyAlgorithm });
  if (refusal) throw new HttpError(refusal.status, refusal.message);
  return issuer;
}

/** What the Private CA kind of issuer issues with: signing a CSR from an Issuing CA, revoking from it, and its root. */
export interface PrivateCas {
  /**
   * Signs a TLS server Certificate for the CSR and its names from the Organization's Issuing CA, valid from now for
   * `validityDays` (its default when none), but never longer than its maximum nor past the Issuing CA's end. Resolves
   * with the chain (PEM, the Certificate then the Issuing CA) and its Private CA's name. Throws an IssuanceFailure when
   * the Issuing CA cannot issue, or not for one of the names.
   */
  issueFrom(db: Db | Tx, organizationId: string, issuingCaId: string, request: { csr: string; names: string[]; validityDays: number | null }): Promise<{ chainPem: string; name: string }>;
  /**
   * Has the Issuing CA distrust a Certificate it signed whose revocation is recorded on the transaction: its CRL is
   * reissued there, so the revocation is published if and only if it commits. Throws a CertificateAuthorityError when
   * the KMS does not sign it.
   */
  publishRevocation(tx: Tx, change: Change, organizationId: string, issuingCaId: string): Promise<void>;
  /** The root (PEM) of the Issuing CA's Private CA, when the platform has it. */
  rootsOf(db: Db | Tx, organizationId: string, issuingCaId: string): Promise<string[]>;
  /**
   * Signs an Enrollment Profile's SCEP RA certificate for the RA's key (`publicKey`, DER SubjectPublicKeyInfo) from the
   * Organization's Issuing CA, valid from now for `validityDays` but never past the Issuing CA's end. Throws an
   * IssuanceFailure when the Issuing CA cannot issue.
   */
  issueRa(db: Db | Tx, organizationId: string, issuingCaId: string, request: { publicKey: Uint8Array; subject: x509.Name; validityDays: number }): Promise<x509.X509Certificate>;
  /**
   * Signs a Device Certificate for the CSR (DER) from the Organization's Issuing CA, with the CSR's subject and subject
   * alternative names and the key usages given, valid from now for `validityDays` but never past the Issuing CA's end.
   * Resolves with it and the certificates above it, up to the root (PEM, the Issuing CA first). Throws an
   * IssuanceFailure when the Issuing CA cannot issue, or not for one of the CSR's DNS names.
   */
  issueDevice(
    db: Db | Tx,
    organizationId: string,
    issuingCaId: string,
    request: { csr: Uint8Array; validityDays: number; keyUsage: (keyof typeof x509.KeyUsageFlags)[]; extendedKeyUsages: string[] },
  ): Promise<{ certificate: x509.X509Certificate; chainPem: string[] }>;
  /** Why `issueDevice` would refuse the CSR (DER) now: the Issuing CA does not issue, or not for one of its DNS names. None when it would sign it. */
  deviceRefusal(db: Db | Tx, organizationId: string, issuingCaId: string, csr: Uint8Array): Promise<string | undefined>;
}

/**
 * The Organization's Issuing CA, when it issues: what signs with it, and the end of what it may issue (its own, or
 * anything's above it, an Organization's own root may have signed it for longer than itself). Throws an IssuanceFailure otherwise.
 */
async function issuingAt(db: Db | Tx, organizationId: string, issuingCaId: string, now: Date) {
  const of = await findIssuingCa(db, organizationId, issuingCaId);
  if (!of) throw new IssuanceFailure("internal", "the Issuing CA is gone");
  const refusal = issuingRefusal(of);
  if (refusal) throw new IssuanceFailure("ca_rejected", refusal);
  const { issuing, ca } = of;
  const certificate = new x509.X509Certificate(issuing.certificatePem!);
  const above = certificatesAsked([ca.chainPem, ca.rootCertificatePem].filter(Boolean).join("\n"), "the chain", { none: true });
  const end = Math.min(certificate.notAfter.getTime(), ...above.map((cert) => cert.notAfter.getTime()));
  if (end <= now.getTime()) throw new IssuanceFailure("ca_rejected", `${issuingCaLabel(of)} has ended, or its root has`);
  const signer: Signer = { key: issuing.key, context: organizationId, algorithm: ca.keyAlgorithm, certificate };
  return { of, signer, end, above };
}

/**
 * The Issuing CA as `issuingAt` gives it, when it may sign a Device Certificate for the CSR (DER): it issues for no DNS
 * name outside its rules, which a platform-made one also carries as name constraints that relying parties enforce.
 * Throws an IssuanceFailure otherwise.
 */
async function deviceIssuingAt(db: Db | Tx, organizationId: string, issuingCaId: string, csr: Uint8Array, now: Date) {
  const at = await issuingAt(db, organizationId, issuingCaId, now);
  const dnsNames = subjectAltNamesOf(new x509.Pkcs10CertificateRequest(new Uint8Array(csr))).filter((name) => name.type === "dns").map((name) => name.value.toLowerCase().replace(/\.$/, ""));
  const outside = namesRefusal(at.of, dnsNames);
  if (outside) throw new IssuanceFailure("name_not_permitted", outside);
  return at;
}

export function createPrivateCas({ kms, clock, crls, pkiBaseURL }: { kms: Kms; clock: () => Date; crls: Crls; pkiBaseURL: string }): PrivateCas {
  return {
    async issueFrom(db, organizationId, issuingCaId, { csr, names, validityDays }) {
      const notBefore = clock();
      // Nothing it issues outlives it, nor anything above it.
      const { of, signer, end } = await issuingAt(db, organizationId, issuingCaId, notBefore);
      // A backstop: names outside the rules are refused when they are asked for, but the rules may have changed since.
      const outside = namesRefusal(of, names);
      if (outside) throw new IssuanceFailure("name_not_permitted", outside);
      const { issuing, ca } = of;
      // The maximum may have been lowered since the Managed Certificate chose its validity.
      const days = Math.min(validityDays ?? issuing.defaultValidityDays, issuing.maxValidityDays);
      const notAfter = new Date(Math.min(notBefore.getTime() + days * DAY_MS, end));
      const leaf = await makeTlsServer(kms, signer, { csr, names, notBefore, notAfter, publication: publicationOf(pkiBaseURL, { signer: "issuing", id: issuing.id }) });
      // The root is not in it: whoever downloads the chain is given it (`rootsOf`) when they ask for it.
      return { chainPem: [leaf.toString("pem"), issuing.certificatePem, ...(ca.chainPem ? [ca.chainPem] : [])].join("\n"), name: ca.name };
    },
    publishRevocation: (tx, change, organizationId, issuingCaId) => crls.publish(tx, change, organizationId, { signer: "issuing", id: issuingCaId }),
    async rootsOf(db, organizationId, issuingCaId) {
      const of = await findIssuingCa(db, organizationId, issuingCaId);
      return of?.ca.rootCertificatePem ? [of.ca.rootCertificatePem] : [];
    },
    async issueRa(db, organizationId, issuingCaId, { publicKey, subject, validityDays }) {
      const notBefore = clock();
      const { signer, end } = await issuingAt(db, organizationId, issuingCaId, notBefore);
      const notAfter = new Date(Math.min(notBefore.getTime() + validityDays * DAY_MS, end));
      return makeRaCertificate(kms, signer, { publicKey, subject, notBefore, notAfter, publication: publicationOf(pkiBaseURL, { signer: "issuing", id: issuingCaId }) });
    },
    async issueDevice(db, organizationId, issuingCaId, { csr, validityDays, keyUsage, extendedKeyUsages }) {
      const notBefore = clock();
      const { of, signer, end, above } = await deviceIssuingAt(db, organizationId, issuingCaId, csr, notBefore);
      const notAfter = new Date(Math.min(notBefore.getTime() + validityDays * DAY_MS, end));
      const certificate = await makeDeviceCertificate(kms, signer, { csr, keyUsage, extendedKeyUsages, notBefore, notAfter, publication: publicationOf(pkiBaseURL, { signer: "issuing", id: issuingCaId }) });
      return { certificate, chainPem: [of.issuing.certificatePem!, ...above.map((cert) => cert.toString("pem"))] };
    },
    async deviceRefusal(db, organizationId, issuingCaId, csr) {
      try {
        await deviceIssuingAt(db, organizationId, issuingCaId, csr, clock());
        return undefined;
      } catch (err) {
        if (err instanceof IssuanceFailure) return err.message;
        throw err;
      }
    },
  };
}

/** `from` plus `years` years. */
function yearsAfter(from: Date, years: number) {
  const to = new Date(from);
  to.setUTCFullYear(to.getUTCFullYear() + years);
  return to;
}

const sameCertificates = (a: x509.X509Certificate[], b: x509.X509Certificate[]) => a.length === b.length && a.every((cert, i) => cert.equal(b[i]!));

/**
 * A Private CA's key algorithm as asked: any CA key but ML-DSA-44, too weak for one, under either kind of root. Under an
 * Organization's own root an ML-DSA Issuing CA needs a root of its algorithm, which an upload is checked for
 * (`signedCertificateRefusal`), so that a chain is never part post-quantum.
 */
function caKeyAlgorithmAsked(algorithm: KeyAlgorithm): SigningKeyAlgorithm {
  if (algorithm === "ml-dsa-44") throw new HttpError(422, "ML-DSA-44 is too weak for a CA key, which outlives and outweighs every Certificate it signs; choose ML-DSA-65 or ML-DSA-87");
  return algorithm;
}

/** A lifetime asked of an Issuing CA under the Organization's own root, which decides it. */
const noLifetimeUnderOwnRoot = () => new HttpError(422, "the Organization's own root decides how long an Issuing CA under it lasts, so no lifetime can be given");

const PEM_CERTIFICATE = /-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g;

/** The certificates of a PEM bundle, in order; a 400 naming `what` when one cannot be read or there is none (unless `none` may be). */
function certificatesAsked(pem: string, what: string, { none = false } = {}): x509.X509Certificate[] {
  const blocks = pem.match(PEM_CERTIFICATE) ?? [];
  if (blocks.length === 0 && !none) throw new HttpError(400, `${what} is not a PEM-encoded certificate`);
  try {
    return blocks.map((block) => new x509.X509Certificate(block));
  } catch {
    throw new HttpError(400, `${what} is not a PEM-encoded certificate`);
  }
}

/** A new Issuing CA under an Organization's own root, as it is stored until that root has signed it: its key, and no certificate. */
const awaitingSignature = (organizationId: string, privateCaId: string, subject: x509.Name, key: string, permittedNames: PermittedNames, validity: Validity) => ({
  organizationId,
  privateCaId,
  subject: subject.toString(),
  key,
  status: "awaiting_signature" as const,
  permittedExactNames: permittedNames.exact,
  permittedZones: permittedNames.zones,
  maxValidityDays: validity.maximumDays,
  defaultValidityDays: validity.defaultDays,
});

/** The SHA-256 fingerprint of a CA certificate, lower-case hex, and its serial, as Audit Events name it. */
const identityOf = async (certificate: x509.X509Certificate) => ({ serial: certificate.serialNumber, fingerprint: Buffer.from(await certificate.getThumbprint("SHA-256")).toString("hex") });

/** Where relying parties fetch what the Private CAs publish, which every Certificate they sign names and which cannot change for those already signed. */
const Publication = z.object({
  baseUrl: z.string().openapi({ description: "The PKI base URL: CRLs and CA certificates are served under its `/pki`. It should be plain HTTP, reachable by every relying party." }),
  configured: z.boolean().openapi({ description: "Whether the platform's operator set it (`PKI_BASE_URL`); when not, it is the address the API is served at." }),
});

export function registerPrivateCas(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  kms: Kms;
  clock: () => Date;
  crls: Crls;
  /** Where what Private CAs publish is served, which the certificates they sign name (crl.ts). */
  pkiBaseURL: string;
  /** Whether `pkiBaseURL` was configured as such, rather than falling back to where the API is served. */
  pkiBaseURLConfigured: boolean;
}) {
  const { app, db, requireUser, authorize, unitOfWork, kms, clock, crls, pkiBaseURL, pkiBaseURLConfigured } = ctx;

  async function findReadable(actor: Actor, orgId: string, id: string) {
    await authorize(actor, orgId, { privateCa: ["read"] });
    const row = await findPrivateCa(db, orgId, id);
    if (!row) throw new HttpError(404, "Private CA not found");
    return row;
  }

  async function findReadableIssuingCa(actor: Actor, orgId: string, id: string, issuingCaId: string) {
    await authorize(actor, orgId, { privateCa: ["read"] });
    const of = await findIssuingCa(db, orgId, issuingCaId);
    if (!of || of.ca.id !== id) throw new HttpError(404, "Issuing CA not found");
    return of;
  }

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/private-cas",
      tags: ["Private CAs"],
      summary: "The Organization's Private CAs, oldest first, each with its Issuing CAs",
      description: "Everyone in the Organization may ask, so as to propose a Managed Certificate against the right Issuing CA.",
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(PrivateCa), publication: Publication })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { privateCa: ["read"] });
      const rows = await db.select().from(privateCa).where(eq(privateCa.organizationId, orgId)).orderBy(asc(privateCa.createdAt), asc(privateCa.id));
      const issuingCas = await issuingCasOf(db, rows.map((r) => r.id));
      return c.json({ items: rows.map((row) => toPrivateCa(row, issuingCas)), publication: { baseUrl: pkiBaseURL, configured: pkiBaseURLConfigured } }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/private-cas",
      tags: ["Private CAs"],
      summary: "Create a Private CA and its first Issuing CA, under a platform-made root or the Organization's own",
      description:
        "`kind` `platform_root` (the default): the platform makes two keys in the KMS, of the algorithm given: a self-signed root's, and an Issuing CA's, which the root signs and which signs Certificates (pathLen 0). " +
        "`subject` is the Issuing CA's distinguished name and must have a common name; the root's is the same with \" Root\" added to the common name. Both are valid from now for `lifetimeYears` (10 unless given). " +
        "The Private CA is active at once, and its root and Issuing CA each publish a CRL at once. " +
        "`kind` `organization_root`: the platform makes only the Issuing CA's key in the KMS, and the Issuing CA is `awaiting_signature` until the Organization's own root has signed its CSR (`.../csr`) and the result is uploaded (`.../certificate`); that root decides how long it lasts, so `lifetimeYears` is refused with 422. " +
        "Either way, `permittedNames` and `validity` are the Issuing CA's: `validity` sets how long its TLS Certificates are valid for (397 days for both unless given); a default above the maximum is refused with 422. " +
        "More Issuing CAs can be added under its root later. Only Organization Administrators may.",
      request: {
        params: OrgParam,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                name: z.string().trim().min(1).max(100),
                kind: z.enum(PRIVATE_CA_KINDS).default("platform_root"),
                subject: z.string().min(1).max(1000).openapi({ example: "CN=Acme Internal TLS, O=Acme" }),
                keyAlgorithm: z
                  .enum(KEY_ALGORITHMS)
                  .default("ecdsa-p256")
                  .openapi({
                    description:
                      "Its keys', the root's and its Issuing CAs'. Refused with 422: `ml-dsa-44`, too weak for a CA key (`/api/key-algorithms` lists what each kind takes). Under the Organization's own root an ML-DSA Issuing CA needs a root, and anything between, of the same ML-DSA algorithm, which the certificate uploaded for it is checked for. " +
                      "ML-DSA is verified only by recent clients, such as OpenSSL 3.5 or later and Chrome 150 or later.",
                  }),
                lifetimeYears: z.number().int().min(1).max(MAX_LIFETIME_YEARS).optional().openapi({ description: "For a platform-made root and its Issuing CA: 10 unless given. Not for an Organization's own root." }),
                permittedNames: PermittedNamesField,
                validity: ValidityField.default(DEFAULT_VALIDITY),
              }),
            },
          },
        },
      },
      responses: { 201: json(PrivateCa, "Created: active, its first Issuing CA active or, under the Organization's own root, awaiting signature"), ...errors(400, 401, 403, 404, 409, 422) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { privateCa: ["create"] });
      const subject = subjectAsked(body.subject);
      const permittedNames = permittedNamesAsked(body.permittedNames);
      const validity = validityAsked(body.validity);
      const keyAlgorithm = caKeyAlgorithmAsked(body.keyAlgorithm);
      if (body.kind === "organization_root" && body.lifetimeYears !== undefined) throw noLifetimeUnderOwnRoot();

      const taken = () => new HttpError(409, `the Organization already has a Private CA named ${body.name}`);
      const [named] = await db
        .select({ id: privateCa.id })
        .from(privateCa)
        .where(and(eq(privateCa.organizationId, orgId), eq(privateCa.name, body.name)));
      if (named) throw taken();

      if (body.kind === "organization_root") {
        // As below, the key is made first; one not stored then leaves only a key nothing refers to.
        const key = await kms.createSigningKey(keyAlgorithm, orgId);
        try {
          const row = await unitOfWork.run(actor, async (tx, change) => {
            const [row] = await tx.insert(privateCa).values({ organizationId: orgId, name: body.name, kind: "organization_root", status: "active", keyAlgorithm }).returning();
            const [first] = await tx
              .insert(issuingCa)
              .values({ ...awaitingSignature(orgId, row!.id, subject, key, permittedNames, validity) })
              .returning({ id: issuingCa.id });
            await change.audit({
              organizationId: orgId,
              action: "private_ca.created",
              target: { type: "private_ca", id: row!.id },
              detail: { name: body.name, kind: "organization_root", keyAlgorithm, subject: subject.toString(), permittedNames, validity, issuingCa: { id: first!.id } },
            });
            return row!;
          });
          return c.json(await shown(db, row), 201);
        } catch (err) {
          if (isUniqueViolation(err)) throw taken();
          throw err;
        }
      }

      // The keys are made in the KMS first; a Private CA that is then not stored (one of the same name was made meanwhile) leaves only keys nothing refers to.
      // Its id is chosen here: its Issuing CA names where the root publishes, under it.
      const id = randomUUID();
      const notBefore = clock();
      const notAfter = yearsAfter(notBefore, body.lifetimeYears ?? DEFAULT_LIFETIME_YEARS);
      const rootKey: CaKey = { key: await kms.createSigningKey(keyAlgorithm, orgId), context: orgId, algorithm: keyAlgorithm };
      const issuingKey: CaKey = { key: await kms.createSigningKey(keyAlgorithm, orgId), context: orgId, algorithm: keyAlgorithm };
      const root = await makeRoot(kms, rootKey, { subject: rootSubjectOf(subject), notBefore, notAfter });
      const issuing = await makeIssuingCa(kms, { ...rootKey, certificate: root }, issuingKey, {
        subject,
        notBefore,
        notAfter,
        permittedDnsNames: constraintNamesOf(permittedNames),
        publication: publicationOf(pkiBaseURL, { signer: "root", id }),
      });

      try {
        const row = await unitOfWork.run(actor, async (tx, change) => {
          const [row] = await tx
            .insert(privateCa)
            .values({ id, organizationId: orgId, name: body.name, kind: "platform_root", status: "active", keyAlgorithm, rootCertificatePem: root.toString("pem"), rootKey: rootKey.key })
            .returning();
          const [first] = await tx
            .insert(issuingCa)
            .values({
              organizationId: orgId,
              privateCaId: row!.id,
              subject: subject.toString(),
              certificatePem: issuing.toString("pem"),
              key: issuingKey.key,
              status: "active",
              permittedExactNames: permittedNames.exact,
              permittedZones: permittedNames.zones,
              maxValidityDays: validity.maximumDays,
              defaultValidityDays: validity.defaultDays,
            })
            .returning({ id: issuingCa.id });
          await crls.publish(tx, change, orgId, { signer: "root", id });
          await crls.publish(tx, change, orgId, { signer: "issuing", id: first!.id });
          await change.audit({
            organizationId: orgId,
            action: "private_ca.created",
            target: { type: "private_ca", id: row!.id },
            detail: {
              name: body.name,
              kind: "platform_root",
              keyAlgorithm,
              subject: subject.toString(),
              notAfter: notAfter.toISOString(),
              permittedNames,
              validity,
              root: await identityOf(root),
              issuingCa: { id: first!.id, ...(await identityOf(issuing)) },
            },
          });
          return row!;
        });
        return c.json(await shown(db, row), 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw taken();
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/private-cas/{id}",
      tags: ["Private CAs"],
      request: { params: PrivateCaParams },
      responses: { 200: json(PrivateCa), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      return c.json(await shown(db, await findReadable(await requireUser(c), orgId, id)), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/private-cas/{id}/issuing-cas",
      tags: ["Private CAs"],
      summary: "Add an Issuing CA under a Private CA's root",
      description:
        "The platform makes a new key in the KMS, of the Private CA's algorithm. " +
        "Under a platform-made root, it has the root sign it: pathLen 0, with `permittedNames` as critical dNSName name constraints, valid from now for `lifetimeYears`, but never past the root's end, which is also what it gets when none is given. It is active at once, and publishes a CRL at once. " +
        "Under the Organization's own root, it is `awaiting_signature` until that root has signed its CSR and the result is uploaded; that root decides how long it lasts, so `lifetimeYears` is refused with 422. " +
        "`subject` must have a common name, and is refused with 422 when another Issuing CA of the Private CA has it. A default validity above the maximum is refused with 422. " +
        "The others under the root are unaffected. Only Organization Administrators may.",
      request: {
        params: PrivateCaParams,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                subject: z.string().min(1).max(1000).openapi({ example: "CN=Acme Devices, O=Acme" }),
                lifetimeYears: z.number().int().min(1).max(MAX_LIFETIME_YEARS).optional(),
                permittedNames: PermittedNamesField,
                validity: ValidityField.default(DEFAULT_VALIDITY),
              }),
            },
          },
        },
      },
      responses: { 201: json(IssuingCa, "Added: active, or awaiting signature under the Organization's own root"), ...errors(400, 401, 403, 404, 422) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { privateCa: ["update"] });
      const subject = subjectAsked(body.subject);
      const permittedNames = permittedNamesAsked(body.permittedNames);
      const validity = validityAsked(body.validity);
      const ca = await findPrivateCa(db, orgId, id);
      if (!ca) throw new HttpError(404, "Private CA not found");
      if (ca.status !== "active") throw new HttpError(422, `the root of the Private CA ${ca.name} is ${ca.status}`);

      const repeated = () => new HttpError(422, `the Private CA ${ca.name} already has an Issuing CA with the subject ${subject.toString()}`);
      const [same] = await db
        .select({ id: issuingCa.id })
        .from(issuingCa)
        .where(and(eq(issuingCa.privateCaId, ca.id), eq(issuingCa.subject, subject.toString())));
      if (same) throw repeated();

      if (ca.kind === "organization_root") {
        if (body.lifetimeYears !== undefined) throw noLifetimeUnderOwnRoot();
        const key = await kms.createSigningKey(ca.keyAlgorithm, orgId);
        try {
          const row = await unitOfWork.run(actor, async (tx, change) => {
            const [row] = await tx.insert(issuingCa).values(awaitingSignature(orgId, ca.id, subject, key, permittedNames, validity)).returning();
            await change.audit({
              organizationId: orgId,
              action: "private_ca.issuing_ca_added",
              target: { type: "private_ca", id: ca.id },
              detail: { name: ca.name, issuingCa: { id: row!.id, subject: row!.subject, status: row!.status, permittedNames, validity } },
            });
            return row!;
          });
          return c.json(toIssuingCa(row), 201);
        } catch (err) {
          if (isUniqueViolation(err)) throw repeated();
          throw err;
        }
      }

      if (!ca.rootCertificatePem || !ca.rootKey) throw new HttpError(422, `the platform does not hold the root of the Private CA ${ca.name}, so it cannot sign an Issuing CA`);
      const root = new x509.X509Certificate(ca.rootCertificatePem);
      const notBefore = clock();
      if (root.notAfter <= notBefore) throw new HttpError(422, `the root of the Private CA ${ca.name} has ended`);

      // As when a Private CA is created, the key is made first; one not stored then leaves only a key nothing refers to.
      const asked = body.lifetimeYears ? yearsAfter(notBefore, body.lifetimeYears) : root.notAfter;
      const notAfter = new Date(Math.min(asked.getTime(), root.notAfter.getTime()));
      const rootKey: CaKey = { key: ca.rootKey, context: orgId, algorithm: ca.keyAlgorithm };
      const issuingKey: CaKey = { key: await kms.createSigningKey(ca.keyAlgorithm, orgId), context: orgId, algorithm: ca.keyAlgorithm };
      const certificate = await makeIssuingCa(kms, { ...rootKey, certificate: root }, issuingKey, {
        subject,
        notBefore,
        notAfter,
        permittedDnsNames: constraintNamesOf(permittedNames),
        publication: publicationOf(pkiBaseURL, { signer: "root", id: ca.id }),
      });

      try {
        const row = await unitOfWork.run(actor, async (tx, change) => {
          const [row] = await tx
            .insert(issuingCa)
            .values({
              organizationId: orgId,
              privateCaId: ca.id,
              subject: subject.toString(),
              certificatePem: certificate.toString("pem"),
              key: issuingKey.key,
              status: "active",
              permittedExactNames: permittedNames.exact,
              permittedZones: permittedNames.zones,
              maxValidityDays: validity.maximumDays,
              defaultValidityDays: validity.defaultDays,
            })
            .returning();
          await crls.publish(tx, change, orgId, { signer: "issuing", id: row!.id });
          await change.audit({
            organizationId: orgId,
            action: "private_ca.issuing_ca_added",
            target: { type: "private_ca", id: ca.id },
            detail: {
              name: ca.name,
              issuingCa: { id: row!.id, subject: row!.subject, notAfter: notAfter.toISOString(), permittedNames, validity, ...(await identityOf(certificate)) },
            },
          });
          return row!;
        });
        return c.json(toIssuingCa(row), 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw repeated();
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/api/organizations/{orgId}/private-cas/{id}/issuing-cas/{issuingCaId}",
      tags: ["Private CAs"],
      summary: "Change an Issuing CA's permitted name rules or validity limits",
      description:
        "What is given replaces what it had, and decides what it issues from then on: what it has already issued is unaffected. " +
        "A platform-made Issuing CA keeps the name constraints it was made with, which relying parties enforce; going beyond them needs a new Issuing CA. " +
        "A default validity above the maximum is refused with 422. A Managed Certificate that chose a validity above a lowered maximum gets the maximum. " +
        "Only Organization Administrators may.",
      request: {
        params: IssuingCaParams,
        body: { content: { "application/json": { schema: z.object({ permittedNames: PermittedNamesField.optional(), validity: ValidityField.optional() }) } } },
      },
      responses: { 200: json(IssuingCa, "Changed"), ...errors(400, 401, 403, 404, 422) },
    }),
    async (c) => {
      const { orgId, id, issuingCaId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { privateCa: ["update"] });
      const permittedNames = body.permittedNames && permittedNamesAsked(body.permittedNames);
      const validity = body.validity && validityAsked(body.validity);
      const notFound = () => new HttpError(404, "Issuing CA not found");
      if (!isId(id) || !isId(issuingCaId)) throw notFound();
      const row = await unitOfWork.run(actor, async (tx, change) => {
        // Under the row's lock, so what the Audit Event says it changed from is what it replaced.
        const [found] = await tx
          .select({ issuing: issuingCa, name: privateCa.name })
          .from(issuingCa)
          .innerJoin(privateCa, eq(privateCa.id, issuingCa.privateCaId))
          .where(and(eq(issuingCa.organizationId, orgId), eq(issuingCa.privateCaId, id), eq(issuingCa.id, issuingCaId)))
          .for("update", { of: issuingCa });
        if (!found) throw notFound();
        const { issuing, name } = found;
        const namesChanged = permittedNames && !samePermittedNames(permittedNamesOf(issuing), permittedNames) ? { from: permittedNamesOf(issuing), to: permittedNames } : undefined;
        const validityChanged = validity && validityChanges(validityOf(issuing), validity);
        if (!namesChanged && !validityChanged) return issuing;
        const [updated] = await tx
          .update(issuingCa)
          .set({
            ...(namesChanged && { permittedExactNames: namesChanged.to.exact, permittedZones: namesChanged.to.zones }),
            ...(validityChanged && { maxValidityDays: validity.maximumDays, defaultValidityDays: validity.defaultDays }),
          })
          .where(eq(issuingCa.id, issuing.id))
          .returning();
        await change.audit({
          organizationId: orgId,
          action: "private_ca.updated",
          target: { type: "private_ca", id },
          detail: { name, issuingCa: { id: issuing.id, subject: issuing.subject }, ...(namesChanged && { permittedNames: namesChanged }), ...(validityChanged && { validity: validityChanged }) },
        });
        return updated!;
      });
      return c.json(toIssuingCa(row), 200);
    },
  );

  /** The Issuing CA, locked, with its Private CA's name; a 404 when the Organization's Private CA has none such. */
  async function lockIssuingCa(tx: Tx, orgId: string, id: string, issuingCaId: string) {
    const notFound = () => new HttpError(404, "Issuing CA not found");
    if (!isId(id) || !isId(issuingCaId)) throw notFound();
    const [found] = await tx
      .select({ issuing: issuingCa, ca: privateCa })
      .from(issuingCa)
      .innerJoin(privateCa, eq(privateCa.id, issuingCa.privateCaId))
      .where(and(eq(issuingCa.organizationId, orgId), eq(issuingCa.privateCaId, id), eq(issuingCa.id, issuingCaId)))
      .for("update", { of: issuingCa });
    if (!found) throw notFound();
    return found;
  }

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/private-cas/{id}/issuing-cas/{issuingCaId}/retire",
      tags: ["Private CAs"],
      summary: "Retire an Issuing CA: it issues nothing more, and keeps publishing its CRL until its last Certificate expires",
      description:
        "Only an `active` Issuing CA may be retired (422 otherwise), and it cannot be made active again. Its Certificates stay valid until they end or are revoked, " +
        "and revoking one still puts it on its CRL. A Managed Certificate on it can no longer be issued or renewed until it is repointed to another Issuing CA. " +
        "The other Issuing CAs under its root are unaffected. Only Organization Administrators may.",
      request: { params: IssuingCaParams },
      responses: { 200: json(IssuingCa, "Retired"), ...errors(401, 403, 404, 422) },
    }),
    async (c) => {
      const { orgId, id, issuingCaId } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { privateCa: ["retire"] });
      const row = await unitOfWork.run(actor, async (tx, change) => {
        const of = await lockIssuingCa(tx, orgId, id, issuingCaId);
        if (of.issuing.status !== "active") throw new HttpError(422, `${issuingCaLabel(of)} is ${of.issuing.status}, so it cannot be retired`);
        const [updated] = await tx.update(issuingCa).set({ status: "retired" }).where(eq(issuingCa.id, of.issuing.id)).returning();
        await change.audit({
          organizationId: orgId,
          action: "private_ca.retired",
          target: { type: "private_ca", id },
          detail: { name: of.ca.name, issuingCa: { id: of.issuing.id, subject: of.issuing.subject } },
        });
        return updated!;
      });
      return c.json(toIssuingCa(row), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/private-cas/{id}/issuing-cas/{issuingCaId}/revocation",
      tags: ["Private CAs"],
      summary: "Revoke a platform-made Issuing CA: its root's CRL lists it at once, and it issues nothing more",
      description:
        "Only for an Issuing CA under a platform-made root (422 under the Organization's own root, which revokes it itself), and one that is `active` or `retired` (422 otherwise). " +
        "`reason` is the RFC 5280 reason its root's CRL gives. The root's CRL is reissued in the same change, so it is revoked if and only if the KMS signs that CRL (502 when it does not). " +
        "A Managed Certificate on it can no longer be issued or renewed until it is repointed to another Issuing CA. The other Issuing CAs under its root are unaffected. Only Organization Administrators may.",
      request: {
        params: IssuingCaParams,
        body: { content: { "application/json": { schema: z.object({ reason: z.enum(ISSUING_CA_REVOCATION_REASONS) }) } } },
      },
      responses: { 200: json(IssuingCa, "Revoked"), ...errors(400, 401, 403, 404, 422, 502) },
    }),
    async (c) => {
      const { orgId, id, issuingCaId } = c.req.valid("param");
      const { reason } = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { privateCa: ["revoke"] });
      const row = await unitOfWork.run(actor, async (tx, change) => {
        const of = await lockIssuingCa(tx, orgId, id, issuingCaId);
        if (of.ca.kind !== "platform_root") throw new HttpError(422, `the Organization's own root signed ${issuingCaLabel(of)}, so it is that root that revokes it`);
        if (of.issuing.status !== "active" && of.issuing.status !== "retired") throw new HttpError(422, `${issuingCaLabel(of)} is ${of.issuing.status}, so it cannot be revoked`);
        const [updated] = await tx.update(issuingCa).set({ status: "revoked", revokedAt: change.occurredAt, revocationReason: reason }).where(eq(issuingCa.id, of.issuing.id)).returning();
        try {
          await crls.publish(tx, change, orgId, { signer: "root", id: of.ca.id });
        } catch (err) {
          if (err instanceof CertificateAuthorityError) throw new HttpError(err.kind === "unreachable" ? 502 : 422, err.message);
          throw err;
        }
        await change.audit({
          organizationId: orgId,
          action: "private_ca.revoked",
          target: { type: "private_ca", id },
          detail: { name: of.ca.name, issuingCa: { id: of.issuing.id, subject: of.issuing.subject, ...(await identityOf(new x509.X509Certificate(of.issuing.certificatePem!))) }, reason },
        });
        return updated!;
      });
      return c.json(toIssuingCa(row), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/private-cas/{id}/issuing-cas/{issuingCaId}/csr",
      tags: ["Private CAs"],
      summary: "Download an Issuing CA's CSR, for the Organization's own root to sign",
      description:
        "PEM. Only for an Issuing CA under the Organization's own root (422 otherwise). Its subject, and its key in the KMS, which signs it; it asks for a CA that signs end-entity certificates only (pathLen 0). " +
        "Each download is signed anew, so two downloads differ in their signature but not in what they ask for. Only Organization Administrators may.",
      request: { params: IssuingCaParams },
      responses: { 200: { description: "The CSR, PEM", content: { "application/pkcs10": { schema: z.string() } } }, ...errors(401, 403, 404, 422) },
    }),
    async (c) => {
      const { orgId, id, issuingCaId } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { privateCa: ["update"] });
      const of = await findIssuingCa(db, orgId, issuingCaId);
      if (!of || of.ca.id !== id) throw new HttpError(404, "Issuing CA not found");
      const { issuing, ca } = of;
      if (ca.kind !== "organization_root") throw new HttpError(422, `the platform's own root signs the Issuing CAs of the Private CA ${ca.name}, so they have no CSR`);
      const csr = await makeCaCsr(kms, { key: issuing.key, context: orgId, algorithm: ca.keyAlgorithm }, new x509.Name(issuing.subject));
      const commonName = new x509.Name(issuing.subject).getField("CN")[0] ?? "";
      return c.body(csr.toString("pem"), 200, { "content-type": "application/pkcs10", "content-disposition": `attachment; filename="${fileNameOf(`${ca.name} ${commonName}`, "issuing-ca")}.csr"` });
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/private-cas/{id}/issuing-cas/{issuingCaId}/certificate",
      tags: ["Private CAs"],
      summary: "Upload the certificate the Organization's own root signed for an Issuing CA's CSR",
      description:
        "Only for an Issuing CA under the Organization's own root that is `awaiting_signature` (422 otherwise). `certificate` is PEM. " +
        "With the first Issuing CA of the Private CA to be signed, `root` (PEM, self-signed) is required, and `chain` (PEM, the one that signs the Issuing CA first, then on up; none when the root signs it itself) is given if there is one: the Private CA keeps them for all its Issuing CAs. " +
        "Later ones are checked against what it keeps, and may give the same again but nothing else. " +
        "Refused with 422 when the certificate is not for the CSR's key or subject, is not a CA certificate, has ended, or does not verify up to the root through the chain. " +
        "Once accepted the Issuing CA is `active`, publishes a CRL at once and issues, within its permitted name rules. Only Organization Administrators may.",
      request: {
        params: IssuingCaParams,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                certificate: z.string().min(1).max(64_000),
                root: z.string().max(64_000).optional(),
                chain: z.string().max(256_000).optional(),
              }),
            },
          },
        },
      },
      responses: { 200: json(IssuingCa, "Accepted: the Issuing CA is active"), ...errors(400, 401, 403, 404, 422) },
    }),
    async (c) => {
      const { orgId, id, issuingCaId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { privateCa: ["update"] });
      const [certificate, ...more] = certificatesAsked(body.certificate, "certificate");
      if (more.length > 0) throw new HttpError(400, "certificate must be the Issuing CA's certificate alone; give what is above it as `chain` and `root`");
      const rootGiven = body.root === undefined ? undefined : certificatesAsked(body.root, "root");
      if (rootGiven && rootGiven.length > 1) throw new HttpError(400, "root must be one certificate; give what is between it and the Issuing CA as `chain`");
      const chainGiven = body.chain === undefined ? undefined : certificatesAsked(body.chain, "chain", { none: true });
      const notFound = () => new HttpError(404, "Issuing CA not found");
      if (!isId(id) || !isId(issuingCaId)) throw notFound();

      const row = await unitOfWork.run(actor, async (tx, change) => {
        // The Private CA first, then its Issuing CA, both locked: two first uploads at once must not each keep their own root.
        const [ca] = await tx
          .select()
          .from(privateCa)
          .where(and(eq(privateCa.organizationId, orgId), eq(privateCa.id, id)))
          .for("update");
        const [issuing] = ca ? await tx.select().from(issuingCa).where(and(eq(issuingCa.privateCaId, ca.id), eq(issuingCa.id, issuingCaId))).for("update") : [];
        if (!ca || !issuing) throw notFound();
        if (ca.kind !== "organization_root") throw new HttpError(422, `the platform's own root signs the Issuing CAs of the Private CA ${ca.name}, so none can be uploaded`);
        if (ca.status !== "active") throw new HttpError(422, `the root of the Private CA ${ca.name} is ${ca.status}`);
        if (issuing.status !== "awaiting_signature") throw new HttpError(422, `${issuingCaLabel({ ca, issuing })} is ${issuing.status}, not awaiting signature`);

        const kept = ca.rootCertificatePem ? { root: new x509.X509Certificate(ca.rootCertificatePem), chain: certificatesAsked(ca.chainPem ?? "", "the chain", { none: true }) } : undefined;
        // Compared by bytes: `equal` is a type guard, which would leave nothing to name in the refusal.
        if (kept && rootGiven && !Buffer.from(rootGiven[0]!.rawData).equals(Buffer.from(kept.root.rawData))) throw new HttpError(422, `the Private CA ${ca.name} already has a root, ${kept.root.subject}, which its Issuing CAs share`);
        if (kept && chainGiven && !sameCertificates(chainGiven, kept.chain)) throw new HttpError(422, `the Private CA ${ca.name} already has a chain above its Issuing CAs, which they share`);
        const root = kept?.root ?? rootGiven?.[0];
        if (!root) throw new HttpError(422, `the first Issuing CA of the Private CA ${ca.name} to be signed needs its root uploaded with it`);
        const chain = kept?.chain ?? chainGiven ?? [];

        const publicKey = await kms.publicKey(issuing.key, orgId);
        const refusal = await signedCertificateRefusal(certificate!, { publicKey, keyAlgorithm: ca.keyAlgorithm, subject: issuing.subject, root, chain, now: clock() });
        if (refusal) throw new HttpError(422, refusal);

        if (!kept) {
          await tx
            .update(privateCa)
            .set({ rootCertificatePem: root.toString("pem"), chainPem: chain.length > 0 ? chain.map((cert) => cert.toString("pem")).join("\n") : null })
            .where(eq(privateCa.id, ca.id));
        }
        const [updated] = await tx.update(issuingCa).set({ certificatePem: certificate!.toString("pem"), status: "active" }).where(eq(issuingCa.id, issuing.id)).returning();
        await crls.publish(tx, change, orgId, { signer: "issuing", id: issuing.id });
        await change.audit({
          organizationId: orgId,
          action: "private_ca.csr_signed",
          target: { type: "private_ca", id: ca.id },
          detail: {
            name: ca.name,
            issuingCa: { id: issuing.id, subject: issuing.subject, notAfter: certificate!.notAfter.toISOString(), ...(await identityOf(certificate!)) },
            ...(!kept && { root: { subject: root.subject, ...(await identityOf(root)) }, chain: await Promise.all(chain.map(async (cert) => ({ subject: cert.subject, ...(await identityOf(cert)) }))) }),
          },
        });
        return updated!;
      });
      return c.json(toIssuingCa(row), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/private-cas/{id}/chain",
      tags: ["Private CAs"],
      summary: "Download the Private CA's root",
      description: "PEM. Distribute it to whatever must trust the Certificates its Issuing CAs issue.",
      request: { params: PrivateCaParams },
      responses: PemResponse("The root, PEM"),
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const row = await findReadable(await requireUser(c), orgId, id);
      return pemFile(c, row.rootCertificatePem ?? "", `${fileNameOf(row.name, "private-ca")}.root.pem`);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/private-cas/{id}/issuing-cas/{issuingCaId}/chain",
      tags: ["Private CAs"],
      summary: "Download an Issuing CA's chain: the Issuing CA, then anything between it and its root, then its root",
      description: "PEM. Empty while it awaits its signature.",
      request: { params: IssuingCaParams },
      responses: PemResponse("The chain, PEM"),
    }),
    async (c) => {
      const { orgId, id, issuingCaId } = c.req.valid("param");
      const { issuing, ca } = await findReadableIssuingCa(await requireUser(c), orgId, id, issuingCaId);
      const chain = issuing.certificatePem ? [issuing.certificatePem, ca.chainPem, ca.rootCertificatePem].filter((pem): pem is string => pem !== null).join("\n") : "";
      const commonName = new x509.Name(issuing.subject).getField("CN")[0] ?? "";
      return pemFile(c, chain, `${fileNameOf(`${ca.name} ${commonName}`, "issuing-ca")}.chain.pem`);
    },
  );
}
