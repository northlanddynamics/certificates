// A Managed Certificate's issuer: which kind of CA its Certificates come from, and that kind's reference. ACME carries
// the environment whose ACME Account they are obtained through; a Private CA (private-ca.ts) carries which of its Issuing
// CAs, and has no DCV. Issuance, Renewal, the asking about renewal windows, Revocation and exports reach the CA through here and never
// assume ACME: accounts, DCV and ARI are the ACME kind's concern (certificate-authority.ts).
import { and, eq, type SQL } from "drizzle-orm";
import { CertificateAuthorityError, type AcmeCertificateAuthority, type AcmeEnvironment, type DnsChallengeResponder, type RenewalInfo, type RevocationReason } from "./acme/certificate-authority";
import type { Db, Tx } from "../platform/db/client";
import { acmeAccount } from "../platform/db/schema";
import { IssuanceFailure } from "./issuance-failure";
import { ISSUER_KINDS, type IssuerKind } from "./issuer-kinds";
import type { PrivateCas } from "../private-ca/private-ca";
import { REVOCATION_REASONS_OF } from "../pki/revocation-reasons";
import type { Secrets } from "../platform/crypto/secrets";
import type { Change } from "../platform/unit-of-work";

/** A Managed Certificate's issuer, as it is stored: its kind and that kind's reference. */
export type Issuer = { kind: "acme"; environment: AcmeEnvironment } | { kind: "private_ca"; issuingCaId: string };

/**
 * The issuer a Certificate came from, as it records it: its Managed Certificate's issuer then, and for ACME the ACME
 * Account it was obtained through, and for a Private CA the Issuing CA that signed it.
 */
export type CertificateIssuer = { kind: "acme"; environment: AcmeEnvironment; acmeAccountId: string } | { kind: "private_ca"; issuingCaId: string };

/** The columns that store an issuer, as a Managed Certificate's and a Certificate's rows have them. */
type IssuerRow = { issuerKind: IssuerKind; environment: AcmeEnvironment | null; issuingCaId: string | null };

/** Whichever of an issuer row's references its kind needs; the database checks that it is there. */
function reference<T>(value: T | null, what: string): T {
  if (value === null) throw new Error(`the issuer has no ${what}`);
  return value;
}

/** A Managed Certificate's issuer from its row. */
export function issuerOf(row: IssuerRow): Issuer {
  switch (row.issuerKind) {
    case "acme":
      return { kind: "acme", environment: reference(row.environment, "environment") };
    case "private_ca":
      return { kind: "private_ca", issuingCaId: reference(row.issuingCaId, "Issuing CA") };
  }
}

/** The columns of a Managed Certificate that store `issuer`. */
export const issuerColumns = (issuer: Issuer) =>
  issuer.kind === "acme" ? { issuerKind: issuer.kind, environment: issuer.environment, issuingCaId: null } : { issuerKind: issuer.kind, environment: null, issuingCaId: issuer.issuingCaId };

/** The issuer a Certificate came from, from its row. */
export function certificateIssuerOf(row: IssuerRow & { acmeAccountId: string | null }): CertificateIssuer {
  switch (row.issuerKind) {
    case "acme":
      return { kind: "acme", environment: reference(row.environment, "environment"), acmeAccountId: reference(row.acmeAccountId, "ACME account") };
    case "private_ca":
      return { kind: "private_ca", issuingCaId: reference(row.issuingCaId, "Issuing CA") };
  }
}

/** The columns of a Certificate that record the issuer it came from. */
export const certificateIssuerColumns = (issuedBy: CertificateIssuer) =>
  issuedBy.kind === "acme"
    ? { issuerKind: issuedBy.kind, environment: issuedBy.environment, acmeAccountId: issuedBy.acmeAccountId, issuingCaId: null }
    : { issuerKind: issuedBy.kind, environment: null, acmeAccountId: null, issuingCaId: issuedBy.issuingCaId };

/** What an Audit Event of an Issuance says of its issuer: nothing for ACME, as before there were other kinds; which Issuing CA for a Private CA. */
export const issuerDetail = (issuer: Issuer | CertificateIssuer) => (issuer.kind === "private_ca" ? { issuer: { kind: issuer.kind, issuingCaId: issuer.issuingCaId } } : {});

/** What the Audit Event of a Managed Certificate created or proposed says of its issuer: the ACME environment, or which Issuing CA, and the validity it chose (`validityDays` given). */
export const issuerAuditDetail = (issuer: Issuer, validityDays: number | undefined) => ({
  ...(issuer.kind === "acme" && { environment: issuer.environment }),
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
 * What an Issuance asks the issuer's CA for: a Certificate for the CSR and the Managed Certificate's (approved) `names`,
 * which the CSR asks for, valid for the `validityDays` the Managed Certificate chose (none for the CA's default). Only a
 * Private CA lets one be chosen; an ACME CA decides its own, and that kind ignores it. `dcv` gives the DNS challenge
 * responder for a kind whose CA validates control of the names; another kind never asks for it. `replaces` is the
 * Certificate (PEM) a Renewal replaces, for a CA that coordinates Renewals.
 */
export interface IssueRequest {
  csr: string;
  names: string[];
  validityDays: number | null;
  replaces?: string;
  dcv: () => DnsChallengeResponder;
}

export interface Issuers {
  /**
   * Has the issuer's CA issue for the request. Throws an IssuanceFailure when the issuer cannot issue for the
   * Organization (it has no ACME Account in the environment), and a CertificateAuthorityError when the CA says no or
   * does not answer.
   */
  issue(db: Db | Tx, organizationId: string, issuer: Issuer, request: IssueRequest): Promise<Issued>;
  /**
   * Has the CA a Certificate came from revoke it (PEM, its chain or the leaf alone) for `reason`, once its revocation is
   * recorded on the change's transaction. Throws a CertificateAuthorityError when the CA says no (it does not take the
   * reason from that kind of issuer, REVOCATION_REASONS_OF) or does not answer.
   */
  revoke(tx: Tx, change: Change, organizationId: string, issuedBy: CertificateIssuer, request: { certificate: string; reason: RevocationReason }): Promise<void>;
  /** What the CA a Certificate came from suggests about renewing it; null when it offers nothing. Throws a CertificateAuthorityError when it does not answer. */
  renewalInfo(issuedBy: CertificateIssuer, certificate: string): Promise<RenewalInfo | null>;
  /** The kinds of issuer whose CAs may suggest when to renew (ARI); a Certificate from any other kind is never asked about, and renews by its Renewal Policy alone. */
  readonly renewalInfoKinds: readonly IssuerKind[];
  /** The root certificates (PEM) the chains of the CA a Certificate came from end in, as far as the platform knows them. */
  roots(db: Db | Tx, organizationId: string, issuedBy: CertificateIssuer): Promise<string[]>;
}

/** What one kind of issuer does for the issuers of its kind: `Issuers`, for a Managed Certificate's issuer and a Certificate's of that kind. */
interface KindOfIssuer<M extends Issuer, C extends CertificateIssuer> {
  issue(db: Db | Tx, organizationId: string, issuer: M, request: IssueRequest): Promise<Issued>;
  revoke(tx: Tx, change: Change, organizationId: string, issuedBy: C, request: { certificate: string; reason: RevocationReason }): Promise<void>;
  /** Whether its CAs may suggest when to renew; `renewalInfo` is never asked of a kind whose do not. */
  offersRenewalInfo: boolean;
  renewalInfo(issuedBy: C, certificate: string): Promise<RenewalInfo | null>;
  roots(db: Db | Tx, organizationId: string, issuedBy: C): Promise<string[]>;
}

export function createIssuers({ acme, secrets, privateCas }: { acme: AcmeCertificateAuthority; secrets: Secrets; privateCas: PrivateCas }): Issuers {
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
      const account = await openAccount(db, organizationId, eq(acmeAccount.environment, issuer.environment));
      if (!account) throw new IssuanceFailure("no_acme_account", `the Organization has no ${issuer.environment} ACME account; register one first`);
      const chainPem = await acme.issue(issuer.environment, account, { csr, responder: dcv(), replaces });
      return { chainPem, ca: acme.name, issuedBy: { kind: "acme", environment: issuer.environment, acmeAccountId: account.id } };
    },
    async revoke(tx, _change, organizationId, issuedBy, request) {
      const account = await openAccount(tx, organizationId, eq(acmeAccount.id, issuedBy.acmeAccountId));
      if (!account) throw new Error("the ACME account the Certificate was issued through is gone");
      await acme.revoke(issuedBy.environment, account, request);
    },
    offersRenewalInfo: true,
    renewalInfo: (issuedBy, certificate) => acme.renewalInfo(issuedBy.environment, certificate),
    roots: (_db, _organizationId, issuedBy) => acme.roots(issuedBy.environment),
  };

  // No DCV: the names a Private CA may issue for are the Organization's to decide. No ARI either: its Certificates renew by the Renewal Policy alone.
  const privateCaKind: KindOfIssuer<Issuer & { kind: "private_ca" }, CertificateIssuer & { kind: "private_ca" }> = {
    async issue(db, organizationId, issuer, { csr, names, validityDays }) {
      const { chainPem, name } = await privateCas.issueFrom(db, organizationId, issuer.issuingCaId, { csr, names, validityDays });
      return { chainPem, ca: name, issuedBy: { kind: "private_ca", issuingCaId: issuer.issuingCaId } };
    },
    // The Private CA revokes by publishing the revocation recorded on the transaction in its CRL.
    revoke: (tx, change, organizationId, issuedBy) => privateCas.publishRevocation(tx, change, organizationId, issuedBy.issuingCaId),
    offersRenewalInfo: false,
    renewalInfo: async () => null,
    roots: (db, organizationId, issuedBy) => privateCas.rootsOf(db, organizationId, issuedBy.issuingCaId),
  };

  /** The kind an issuer is of: the one place a new kind is told apart. Each kind is only ever given issuers of its own. */
  function kindOf(issuer: { kind: IssuerKind }): KindOfIssuer<Issuer, CertificateIssuer> {
    switch (issuer.kind) {
      case "acme":
        return acmeKind;
      case "private_ca":
        return privateCaKind;
    }
  }

  return {
    issue: (db, organizationId, issuer, request) => kindOf(issuer).issue(db, organizationId, issuer, request),
    revoke(tx, change, organizationId, issuedBy, request) {
      if (!REVOCATION_REASONS_OF[issuedBy.kind].includes(request.reason)) {
        return Promise.reject(new CertificateAuthorityError("rejected", `a Certificate from ${issuedBy.kind === "acme" ? "an ACME CA" : "a Private CA"} cannot be revoked for ${request.reason}`));
      }
      return kindOf(issuedBy).revoke(tx, change, organizationId, issuedBy, request);
    },
    renewalInfo: (issuedBy, certificate) => kindOf(issuedBy).renewalInfo(issuedBy, certificate),
    renewalInfoKinds: ISSUER_KINDS.filter((kind) => kindOf({ kind }).offersRenewalInfo),
    roots: (db, organizationId, issuedBy) => kindOf(issuedBy).roots(db, organizationId, issuedBy),
  };
}
