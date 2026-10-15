// A Managed Certificate's issuer: which kind of CA its Certificates come from, and that kind's reference. ACME carries
// the environment whose ACME Account they are obtained through; a Private CA (private-ca.ts) carries which one, and has
// no DCV. Issuance, Renewal, the asking about renewal windows, Revocation and exports reach the CA through here and never
// assume ACME: accounts, DCV and ARI are the ACME kind's concern (certificate-authority.ts).
import { and, eq, type SQL } from "drizzle-orm";
import { CertificateAuthorityError, type AcmeCertificateAuthority, type AcmeEnvironment, type DnsChallengeResponder, type RenewalInfo, type RevocationReason } from "./certificate-authority";
import { parseCsr } from "./csr";
import type { Db, Tx } from "./db/client";
import { acmeAccount } from "./db/schema";
import { IssuanceFailure } from "./issuance-failure";
import type { IssuerKind } from "./issuer-kinds";
import type { PrivateCas } from "./private-ca";
import type { Secrets } from "./secrets";

/** A Managed Certificate's issuer, as it is stored: its kind and that kind's reference. */
export type Issuer = { kind: "acme"; environment: AcmeEnvironment } | { kind: "private_ca"; privateCaId: string };

/**
 * The issuer a Certificate came from, as it records it: its Managed Certificate's issuer then, and for ACME the ACME
 * Account it was obtained through.
 */
export type CertificateIssuer = { kind: "acme"; environment: AcmeEnvironment; acmeAccountId: string } | { kind: "private_ca"; privateCaId: string };

/** The columns that store an issuer, as a Managed Certificate's and a Certificate's rows have them. */
type IssuerRow = { issuerKind: IssuerKind; environment: AcmeEnvironment | null; privateCaId: string | null };

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
      return { kind: "private_ca", privateCaId: reference(row.privateCaId, "Private CA") };
  }
}

/** The columns of a Managed Certificate that store `issuer`. */
export const issuerColumns = (issuer: Issuer) =>
  issuer.kind === "acme" ? { issuerKind: issuer.kind, environment: issuer.environment, privateCaId: null } : { issuerKind: issuer.kind, environment: null, privateCaId: issuer.privateCaId };

/** The issuer a Certificate came from, from its row. */
export function certificateIssuerOf(row: IssuerRow & { acmeAccountId: string | null }): CertificateIssuer {
  switch (row.issuerKind) {
    case "acme":
      return { kind: "acme", environment: reference(row.environment, "environment"), acmeAccountId: reference(row.acmeAccountId, "ACME account") };
    case "private_ca":
      return { kind: "private_ca", privateCaId: reference(row.privateCaId, "Private CA") };
  }
}

/** The columns of a Certificate that record the issuer it came from. */
export const certificateIssuerColumns = (issuedBy: CertificateIssuer) =>
  issuedBy.kind === "acme"
    ? { issuerKind: issuedBy.kind, environment: issuedBy.environment, acmeAccountId: issuedBy.acmeAccountId, privateCaId: null }
    : { issuerKind: issuedBy.kind, environment: null, acmeAccountId: null, privateCaId: issuedBy.privateCaId };

/** What an Audit Event of an Issuance says of its issuer: nothing for ACME, as before there were other kinds; which Private CA for that kind. */
export const issuerDetail = (issuer: Issuer | CertificateIssuer) => (issuer.kind === "private_ca" ? { issuer: { kind: issuer.kind, privateCaId: issuer.privateCaId } } : {});

/** What an issuer's CA served for a CSR: the chain (PEM, the Certificate first), what the CA calls itself, and the issuer to record on the Certificate. */
export interface Issued {
  chainPem: string;
  ca: string;
  issuedBy: CertificateIssuer;
}

export interface Issuers {
  /**
   * Has the issuer's CA issue for the CSR. `dcv` gives the DNS challenge responder for a kind whose CA validates control
   * of the names; another kind never asks for it. `replaces` is the Certificate (PEM) a Renewal replaces, for a CA that
   * coordinates Renewals. Throws an IssuanceFailure when the issuer cannot issue for the Organization (it has no ACME
   * Account in the environment), and a CertificateAuthorityError when the CA says no or does not answer.
   */
  issue(
    db: Db | Tx,
    organizationId: string,
    issuer: Issuer,
    request: { csr: string; replaces?: string; dcv: () => DnsChallengeResponder },
  ): Promise<Issued>;
  /** Has the CA a Certificate came from revoke it (PEM, its chain or the leaf alone) for `reason`. Throws a CertificateAuthorityError when the CA says no or does not answer. */
  revoke(db: Db | Tx, organizationId: string, issuedBy: CertificateIssuer, request: { certificate: string; reason: RevocationReason }): Promise<void>;
  /** What the CA a Certificate came from suggests about renewing it; null when it offers nothing. Throws a CertificateAuthorityError when it does not answer. */
  renewalInfo(issuedBy: CertificateIssuer, certificate: string): Promise<RenewalInfo | null>;
  /** The root certificates (PEM) the chains of the CA a Certificate came from end in, as far as the platform knows them. */
  roots(db: Db | Tx, organizationId: string, issuedBy: CertificateIssuer): Promise<string[]>;
}

/** What one kind of issuer does for the issuers of its kind: `Issuers`, for a Managed Certificate's issuer and a Certificate's of that kind. */
interface KindOfIssuer<M extends Issuer, C extends CertificateIssuer> {
  issue(db: Db | Tx, organizationId: string, issuer: M, request: { csr: string; replaces?: string; dcv: () => DnsChallengeResponder }): Promise<Issued>;
  revoke(db: Db | Tx, organizationId: string, issuedBy: C, request: { certificate: string; reason: RevocationReason }): Promise<void>;
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
    async revoke(db, organizationId, issuedBy, request) {
      const account = await openAccount(db, organizationId, eq(acmeAccount.id, issuedBy.acmeAccountId));
      if (!account) throw new Error("the ACME account the Certificate was issued through is gone");
      await acme.revoke(issuedBy.environment, account, request);
    },
    renewalInfo: (issuedBy, certificate) => acme.renewalInfo(issuedBy.environment, certificate),
    roots: (_db, _organizationId, issuedBy) => acme.roots(issuedBy.environment),
  };

  // No DCV: the names a Private CA may issue for are the Organization's to decide. No ARI either.
  const privateCaKind: KindOfIssuer<Issuer & { kind: "private_ca" }, CertificateIssuer & { kind: "private_ca" }> = {
    async issue(db, organizationId, issuer, { csr }) {
      const { names } = await parseCsr(csr);
      const { chainPem, name } = await privateCas.issueFrom(db, organizationId, issuer.privateCaId, { csr, names });
      return { chainPem, ca: name, issuedBy: { kind: "private_ca", privateCaId: issuer.privateCaId } };
    },
    async revoke() {
      throw new CertificateAuthorityError("rejected", "a Certificate from a Private CA cannot be revoked yet");
    },
    renewalInfo: async () => null,
    roots: (db, organizationId, issuedBy) => privateCas.rootsOf(db, organizationId, issuedBy.privateCaId),
  };

  /** The kind an issuer is of: the one place a new kind is told apart. Each kind is only ever given issuers of its own. */
  function kindOf(issuer: Issuer | CertificateIssuer): KindOfIssuer<Issuer, CertificateIssuer> {
    switch (issuer.kind) {
      case "acme":
        return acmeKind;
      case "private_ca":
        return privateCaKind;
    }
  }

  return {
    issue: (db, organizationId, issuer, request) => kindOf(issuer).issue(db, organizationId, issuer, request),
    revoke: (db, organizationId, issuedBy, request) => kindOf(issuedBy).revoke(db, organizationId, issuedBy, request),
    renewalInfo: (issuedBy, certificate) => kindOf(issuedBy).renewalInfo(issuedBy, certificate),
    roots: (db, organizationId, issuedBy) => kindOf(issuedBy).roots(db, organizationId, issuedBy),
  };
}
