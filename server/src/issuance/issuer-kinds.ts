// Every kind of issuer a Managed Certificate can have (issuer.ts). A new kind is an entry here, which the database checks
// on `managed_certificate.issuer_kind` and `certificate.issuer_kind` (schema.ts) must list too.
export const ISSUER_KINDS = [
  /** An ACME CA (acme-cas.ts), through the Organization's ACME account with it. */
  "acme",
  /** One of the Organization's Private CAs, with no DCV. */
  "private_ca",
  /** One of the Organization's ADCS CAs, under one of its Certificate Templates, reached only through Agents, with no DCV. */
  "adcs",
] as const;
export type IssuerKind = (typeof ISSUER_KINDS)[number];
