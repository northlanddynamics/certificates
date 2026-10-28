// A Managed Certificate's issuer: which kind of CA its Certificates come from, and that kind's reference. ACME carries
// the ACME CA (acme-cas.ts), by id, whose ACME Account they are obtained through; a Private CA (private-ca.ts) carries which of its Issuing
// CAs, and has no DCV. Issuance, Renewal, the asking about renewal windows, Revocation and exports reach the CA through here and never
// assume ACME: accounts, DCV and ARI are the ACME kind's concern (certificate-authority.ts). An ADCS CA (adcs-issuance.ts)
// carries the CA and the Certificate Template it issues under, has no DCV, and answers later: an Agent submits the CSR,
// and revokes (adcs-revocation.ts).
import { and, eq, type SQL } from "drizzle-orm";
import { CertificateAuthorityError, type AcmeCertificateAuthority, type DnsChallengeResponder, type RenewalInfo, type RevocationReason } from "./acme/certificate-authority";
import type { AcmeCas } from "./acme/acme-cas";
import type { Db, Tx } from "../platform/db/client";
import { acmeAccount } from "../platform/db/schema";
import { IssuanceFailure } from "./issuance-failure";
import { ISSUER_KINDS, type IssuerKind } from "./issuer-kinds";
import type { PrivateCas } from "../private-ca/private-ca";
import type { AdcsIssuance } from "../adcs/adcs-issuance";
import type { AdcsRevocation } from "../adcs/adcs-revocation";
import { REVOCATION_REASONS_OF } from "../pki/revocation-reasons";
import type { Secrets } from "../platform/crypto/secrets";
import type { Change } from "../platform/unit-of-work";

const ISSUER_KIND_LABELS: Record<IssuerKind, string> = { acme: "an ACME CA", private_ca: "a Private CA", adcs: "an ADCS CA" };

/** A Managed Certificate's issuer, as it is stored: its kind and that kind's reference. */
export type Issuer = { kind: "acme"; acmeCaId: string } | { kind: "private_ca"; issuingCaId: string } | { kind: "adcs"; adcsCaId: string; templateId: string };

/**
 * The issuer a Certificate came from, as it records it: its Managed Certificate's issuer then, and for ACME the ACME
 * Account it was obtained through, for a Private CA the Issuing CA that signed it, and for an ADCS CA the ID ADCS gave
 * the request that issued it.
 */
export type CertificateIssuer =
  | { kind: "acme"; acmeCaId: string; acmeAccountId: string }
  | { kind: "private_ca"; issuingCaId: string }
  | { kind: "adcs"; adcsCaId: string; templateId: string; requestId: string };

/** The columns that store an issuer, as a Managed Certificate's and a Certificate's rows have them; a Certificate Profile's have no ADCS ones yet. */
type IssuerRow = { issuerKind: IssuerKind; acmeCaId: string | null; issuingCaId: string | null; adcsCaId?: string | null; adcsTemplateId?: string | null };

/** Whichever of an issuer row's references its kind needs; the database checks that it is there. */
function reference<T>(value: T | null, what: string): T {
  if (value === null) throw new Error(`the issuer has no ${what}`);
  return value;
}

/** A Managed Certificate's issuer from its row. */
export function issuerOf(row: IssuerRow): Issuer {
  switch (row.issuerKind) {
    case "acme":
      return { kind: "acme", acmeCaId: reference(row.acmeCaId, "ACME CA") };
    case "private_ca":
      return { kind: "private_ca", issuingCaId: reference(row.issuingCaId, "Issuing CA") };
    case "adcs":
      return { kind: "adcs", adcsCaId: reference(row.adcsCaId ?? null, "ADCS CA"), templateId: reference(row.adcsTemplateId ?? null, "Certificate Template") };
  }
}

/** The columns of a Managed Certificate that store `issuer`. */
export const issuerColumns = (issuer: Issuer) => ({
  issuerKind: issuer.kind,
  acmeCaId: issuer.kind === "acme" ? issuer.acmeCaId : null,
  issuingCaId: issuer.kind === "private_ca" ? issuer.issuingCaId : null,
  adcsCaId: issuer.kind === "adcs" ? issuer.adcsCaId : null,
  adcsTemplateId: issuer.kind === "adcs" ? issuer.templateId : null,
});

/** The issuer a Certificate came from, from its row. */
export function certificateIssuerOf(row: IssuerRow & { acmeAccountId: string | null; adcsRequestId?: string | null }): CertificateIssuer {
  switch (row.issuerKind) {
    case "acme":
      return { kind: "acme", acmeCaId: reference(row.acmeCaId, "ACME CA"), acmeAccountId: reference(row.acmeAccountId, "ACME account") };
    case "private_ca":
      return { kind: "private_ca", issuingCaId: reference(row.issuingCaId, "Issuing CA") };
    case "adcs":
      return { ...(issuerOf(row) as Issuer & { kind: "adcs" }), requestId: reference(row.adcsRequestId ?? null, "ADCS request ID") };
  }
}

/** The columns of a Certificate that record the issuer it came from. */
export const certificateIssuerColumns = (issuedBy: CertificateIssuer) => ({
  ...issuerColumns(issuedBy.kind === "adcs" ? { kind: "adcs", adcsCaId: issuedBy.adcsCaId, templateId: issuedBy.templateId } : issuedBy),
  acmeAccountId: issuedBy.kind === "acme" ? issuedBy.acmeAccountId : null,
  adcsRequestId: issuedBy.kind === "adcs" ? issuedBy.requestId : null,
});

/**
 * What an Audit Event of an Issuance says of its issuer: nothing for ACME, as before there were other kinds; which Issuing
 * CA for a Private CA; which ADCS CA and template for an ADCS CA, and the ID ADCS gave the request once it is known.
 */
export function issuerDetail(issuer: Issuer | CertificateIssuer) {
  switch (issuer.kind) {
    case "acme":
      return {};
    case "private_ca":
      return { issuer: { kind: issuer.kind, issuingCaId: issuer.issuingCaId } };
    case "adcs":
      return { issuer: { kind: issuer.kind, adcsCaId: issuer.adcsCaId, templateId: issuer.templateId, ...("requestId" in issuer && { adcsRequestId: issuer.requestId }) } };
  }
}

/** What the Audit Event of a Managed Certificate created or proposed says of its issuer: the ACME CA, or which Issuing CA, and the validity it chose (`validityDays` given). */
export const issuerAuditDetail = (issuer: Issuer, validityDays: number | undefined) => ({
  ...(issuer.kind === "acme" && { acmeCaId: issuer.acmeCaId }),
  ...issuerDetail(issuer),
  ...(validityDays !== undefined && { validityDays }),
});

/** What an issuer's CA served for a CSR: the chain (PEM, the Certificate first), what the CA calls itself, and the issuer to record on the Certificate. */
export interface Issued {
  chainPem: string;
  ca: string;
  issuedBy: CertificateIssuer;
}

/**
 * What an issuer's CA answers when it issues later, as a CA reached through an Agent may: the `handle` its kind keeps the
 * request by, which the Issuance records, and the `deadline` by which it must report the result (Issuances.report) or
 * the Issuance fails as timed out.
 */
export interface Pending {
  pending: { handle: string; deadline: Date };
}

/**
 * What an Issuance asks the issuer's CA for: a Certificate for the CSR and the Managed Certificate's (approved) `names`,
 * which the CSR asks for, valid for the `validityDays` the Managed Certificate chose (none for the CA's default). Only a
 * Private CA lets one be chosen; an ACME CA decides its own, and that kind ignores it. `dcv` gives the DNS challenge
 * responder for a kind whose CA validates control of the names; another kind never asks for it. `replaces` is the
 * Certificate (PEM) a Renewal replaces, for a CA that coordinates Renewals.
 */
export interface IssueRequest {
  /** The Issuance asking, which a kind that answers Pending names when it reports the result. */
  issuanceId: string;
  csr: string;
  names: string[];
  validityDays: number | null;
  replaces?: string;
  dcv: () => DnsChallengeResponder;
}

/**
 * One Certificate (PEM, its chain or the leaf alone) an issuer's CA is asked to revoke for `reason`. Its kind calls
 * `record` once the CA has revoked it, which records the Revocation and its Audit Event on the change; a kind whose CA
 * publishes what is recorded (a Private CA's CRL) records first. `requestId` names it when the kind reports later.
 */
export interface RevocationRequest {
  requestId: string;
  certificate: string;
  reason: RevocationReason;
  record(): Promise<void>;
}

/**
 * What an issuer's kind answers for a Certificate its CA confirms the revocation of later, as a CA reached through an
 * Agent does: the `handle` its kind keeps the request by, and the `deadline` by which it must report the result
 * (Revocations.report) or the request fails as timed out. Nothing is recorded meanwhile.
 */
export interface PendingRevocation {
  pending: { handle: string; deadline: Date };
}

export type RevocationAnswer = "revoked" | PendingRevocation;

export interface Issuers {
  /**
   * Has the issuer's CA issue for the request: what it served, or Pending when it will answer later. Throws an
   * IssuanceFailure when the issuer cannot issue for the Organization (it has no ACME Account with the ACME CA), and a
   * CertificateAuthorityError when the CA says no or does not answer.
   */
  issue(db: Db | Tx, organizationId: string, issuer: Issuer, request: IssueRequest): Promise<Issued | Pending>;
  /**
   * Asks the CA the Certificates came from (all from `issuedBy`) to revoke each, answering for each in turn: "revoked"
   * once the CA has revoked it and its `record` has recorded it on the change's transaction, or Pending when the CA
   * confirms later, with nothing recorded. Throws a CertificateAuthorityError when the CA says no (it does not take a
   * reason from that kind of issuer, REVOCATION_REASONS_OF) or does not answer; the change then rolls back.
   */
  revoke(tx: Tx, change: Change, organizationId: string, issuedBy: CertificateIssuer, requests: RevocationRequest[]): Promise<RevocationAnswer[]>;
  /** What the CA a Certificate of the Organization came from suggests about renewing it; null when it offers nothing. Throws a CertificateAuthorityError when it does not answer. */
  renewalInfo(organizationId: string, issuedBy: CertificateIssuer, certificate: string): Promise<RenewalInfo | null>;
  /** The kinds of issuer whose CAs may suggest when to renew (ARI); a Certificate from any other kind is never asked about, and renews by its Renewal Policy alone. */
  readonly renewalInfoKinds: readonly IssuerKind[];
  /** The root certificates (PEM) the chains of the CA a Certificate came from end in, as far as the platform knows them. */
  roots(db: Db | Tx, organizationId: string, issuedBy: CertificateIssuer): Promise<string[]>;
}

/** What one kind of issuer does for the issuers of its kind: `Issuers`, for a Managed Certificate's issuer and a Certificate's of that kind. */
interface KindOfIssuer<M extends Issuer, C extends CertificateIssuer> {
  issue(db: Db | Tx, organizationId: string, issuer: M, request: IssueRequest): Promise<Issued | Pending>;
  revoke(tx: Tx, change: Change, organizationId: string, issuedBy: C, requests: RevocationRequest[]): Promise<RevocationAnswer[]>;
  /** Whether its CAs may suggest when to renew; `renewalInfo` is never asked of a kind whose do not. */
  offersRenewalInfo: boolean;
  renewalInfo(organizationId: string, issuedBy: C, certificate: string): Promise<RenewalInfo | null>;
  roots(db: Db | Tx, organizationId: string, issuedBy: C): Promise<string[]>;
}

export function createIssuers({
  acme,
  acmeCas,
  secrets,
  privateCas,
  adcs,
  adcsRevocation,
}: {
  acme: AcmeCertificateAuthority;
  acmeCas: AcmeCas;
  secrets: Secrets;
  privateCas: PrivateCas;
  adcs: AdcsIssuance;
  adcsRevocation: AdcsRevocation;
}): Issuers {
  /** The Organization's ACME account that `which` selects, and its key; none when it has no such account. */
  async function openAccount(db: Db | Tx, organizationId: string, which: SQL) {
    const [account] = await db
      .select()
      .from(acmeAccount)
      .where(and(eq(acmeAccount.organizationId, organizationId), which));
    if (!account) return null;
    return { id: account.id, accountUrl: account.accountUrl, accountKey: await secrets.open(db, organizationId, account.secretId) };
  }

  const acmeKind: KindOfIssuer<Issuer & { kind: "acme" }, CertificateIssuer & { kind: "acme" }> = {
    async issue(db, organizationId, issuer, { csr, replaces, dcv }) {
      const ca = await acmeCas.get(organizationId, issuer.acmeCaId);
      const account = await openAccount(db, organizationId, eq(acmeAccount.acmeCaId, issuer.acmeCaId));
      if (!account) throw new IssuanceFailure("no_acme_account", `the Organization has no ACME account with ${ca.name}; register one first`);
      const chainPem = await acme.issue(ca, account, { csr, responder: dcv(), replaces });
      // A custom ACME CA is recorded by its name; the built-in ones by what the CA calls itself.
      return { chainPem, ca: ca.builtIn ? acme.name : ca.name, issuedBy: { kind: "acme", acmeCaId: issuer.acmeCaId, acmeAccountId: account.id } };
    },
    async revoke(tx, _change, organizationId, issuedBy, requests) {
      const account = await openAccount(tx, organizationId, eq(acmeAccount.id, issuedBy.acmeAccountId));
      if (!account) throw new Error("the ACME account the Certificate was issued through is gone");
      const ca = await acmeCas.get(organizationId, issuedBy.acmeCaId);
      for (const { certificate, reason, record } of requests) {
        await acme.revoke(ca, account, { certificate, reason });
        await record();
      }
      return requests.map(() => "revoked" as const);
    },
    offersRenewalInfo: true,
    renewalInfo: async (organizationId, issuedBy, certificate) => acme.renewalInfo(await acmeCas.get(organizationId, issuedBy.acmeCaId), certificate),
    roots: async (_db, organizationId, issuedBy) => acme.roots(await acmeCas.get(organizationId, issuedBy.acmeCaId)),
  };

  // No DCV: the names a Private CA may issue for are the Organization's to decide. No ARI either: its Certificates renew by the Renewal Policy alone.
  const privateCaKind: KindOfIssuer<Issuer & { kind: "private_ca" }, CertificateIssuer & { kind: "private_ca" }> = {
    async issue(db, organizationId, issuer, { csr, names, validityDays }) {
      const { chainPem, name } = await privateCas.issueFrom(db, organizationId, issuer.issuingCaId, { csr, names, validityDays });
      return { chainPem, ca: name, issuedBy: { kind: "private_ca", issuingCaId: issuer.issuingCaId } };
    },
    // The Private CA revokes by publishing the revocations recorded on the transaction in its CRL, reissued once for them all.
    async revoke(tx, change, organizationId, issuedBy, requests) {
      for (const { record } of requests) await record();
      await privateCas.publishRevocation(tx, change, organizationId, issuedBy.issuingCaId);
      return requests.map(() => "revoked" as const);
    },
    offersRenewalInfo: false,
    renewalInfo: async () => null,
    roots: (db, organizationId, issuedBy) => privateCas.rootsOf(db, organizationId, issuedBy.issuingCaId),
  };

  // No DCV and no ARI: an Agent submits the CSR under the template, and the Issuance waits for its report. Its Certificates renew by the Renewal Policy alone.
  const adcsKind: KindOfIssuer<Issuer & { kind: "adcs" }, CertificateIssuer & { kind: "adcs" }> = {
    issue: (db, organizationId, issuer, request) => adcs.issue(db, organizationId, issuer, request),
    // An Agent asks ADCS to revoke, and the Revocation is recorded once it reports that ADCS has.
    revoke: (tx, change, organizationId, issuedBy, requests) => adcsRevocation.revoke(tx, change, organizationId, issuedBy.adcsCaId, requests),
    offersRenewalInfo: false,
    renewalInfo: async () => null,
    roots: (db, organizationId, issuedBy) => adcs.roots(db, organizationId, issuedBy.adcsCaId),
  };

  /** The kind an issuer is of: the one place a new kind is told apart. Each kind is only ever given issuers of its own. */
  function kindOf(issuer: { kind: IssuerKind }): KindOfIssuer<Issuer, CertificateIssuer> {
    switch (issuer.kind) {
      case "acme":
        return acmeKind;
      case "private_ca":
        return privateCaKind;
      case "adcs":
        return adcsKind;
    }
  }

  return {
    issue: (db, organizationId, issuer, request) => kindOf(issuer).issue(db, organizationId, issuer, request),
    async revoke(tx, change, organizationId, issuedBy, requests) {
      const refused = requests.find(({ reason }) => !REVOCATION_REASONS_OF[issuedBy.kind].includes(reason));
      if (refused) throw new CertificateAuthorityError("rejected", `a Certificate from ${ISSUER_KIND_LABELS[issuedBy.kind]} cannot be revoked for ${refused.reason}`);
      if (requests.length === 0) return [];
      return kindOf(issuedBy).revoke(tx, change, organizationId, issuedBy, requests);
    },
    renewalInfo: (organizationId, issuedBy, certificate) => kindOf(issuedBy).renewalInfo(organizationId, issuedBy, certificate),
    renewalInfoKinds: ISSUER_KINDS.filter((kind) => kindOf({ kind }).offersRenewalInfo),
    roots: (db, organizationId, issuedBy) => kindOf(issuedBy).roots(db, organizationId, issuedBy),
  };
}
