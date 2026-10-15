// A Managed Certificate's issuer: which kind of CA its Certificates come from, and that kind's reference. ACME, which
// carries the environment whose ACME Account they are obtained through, is the only kind so far. Issuance, Renewal, the
// asking about renewal windows, Revocation and exports reach the CA through here and never assume ACME: accounts, DCV
// and ARI are the ACME kind's concern (certificate-authority.ts).
import { and, eq } from "drizzle-orm";
import type { AcmeCertificateAuthority, AcmeEnvironment, DnsChallengeResponder, RenewalInfo, RevocationReason } from "./certificate-authority";
import type { Db, Tx } from "./db/client";
import { acmeAccount } from "./db/schema";
import { IssuanceFailure } from "./issuance-failure";
import type { Secrets } from "./secrets";

export const ISSUER_KINDS = ["acme"] as const;
export type IssuerKind = (typeof ISSUER_KINDS)[number];

/** A Managed Certificate's issuer, as it is stored: its kind and that kind's reference. */
export type Issuer = { kind: "acme"; environment: AcmeEnvironment };

/** The issuer a Certificate came from, as it records it: its Managed Certificate's issuer then, and the ACME Account it was obtained through. */
export type CertificateIssuer = { kind: "acme"; environment: AcmeEnvironment; acmeAccountId: string };

/** A Managed Certificate's issuer from its row. */
export const issuerOf = (row: { issuerKind: IssuerKind; environment: AcmeEnvironment }): Issuer => ({ kind: row.issuerKind, environment: row.environment });

/** The columns of a Managed Certificate that store `issuer`. */
export const issuerColumns = (issuer: Issuer) => ({ issuerKind: issuer.kind, environment: issuer.environment });

/** The issuer a Certificate came from, from its row. */
export const certificateIssuerOf = (row: { issuerKind: IssuerKind; environment: AcmeEnvironment; acmeAccountId: string }): CertificateIssuer => ({
  kind: row.issuerKind,
  environment: row.environment,
  acmeAccountId: row.acmeAccountId,
});

/** The columns of a Certificate that record the issuer it came from. */
export const certificateIssuerColumns = (issuedBy: CertificateIssuer) => ({ issuerKind: issuedBy.kind, environment: issuedBy.environment, acmeAccountId: issuedBy.acmeAccountId });

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
  roots(issuedBy: CertificateIssuer): Promise<string[]>;
}

export function createIssuers({ acme, secrets }: { acme: AcmeCertificateAuthority; secrets: Secrets }): Issuers {
  return {
    async issue(db, organizationId, issuer, { csr, replaces, dcv }) {
      switch (issuer.kind) {
        case "acme": {
          const [account] = await db
            .select()
            .from(acmeAccount)
            .where(and(eq(acmeAccount.organizationId, organizationId), eq(acmeAccount.environment, issuer.environment)));
          if (!account) throw new IssuanceFailure("no_acme_account", `the Organization has no ${issuer.environment} ACME account; register one first`);
          const accountKey = await secrets.open(db, organizationId, account.secretId);
          const chainPem = await acme.issue(issuer.environment, { accountUrl: account.accountUrl, accountKey }, { csr, responder: dcv(), replaces });
          return { chainPem, ca: acme.name, issuedBy: { kind: "acme", environment: issuer.environment, acmeAccountId: account.id } };
        }
      }
    },
    async revoke(db, organizationId, issuedBy, request) {
      switch (issuedBy.kind) {
        case "acme": {
          const [account] = await db
            .select()
            .from(acmeAccount)
            .where(and(eq(acmeAccount.id, issuedBy.acmeAccountId), eq(acmeAccount.organizationId, organizationId)));
          if (!account) throw new Error("the ACME account the Certificate was issued through is gone");
          const accountKey = await secrets.open(db, organizationId, account.secretId);
          return acme.revoke(issuedBy.environment, { accountUrl: account.accountUrl, accountKey }, request);
        }
      }
    },
    async renewalInfo(issuedBy, certificate) {
      switch (issuedBy.kind) {
        case "acme":
          return acme.renewalInfo(issuedBy.environment, certificate);
      }
    },
    async roots(issuedBy) {
      switch (issuedBy.kind) {
        case "acme":
          return acme.roots(issuedBy.environment);
      }
    },
  };
}
