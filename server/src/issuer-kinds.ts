// Every kind of issuer a Managed Certificate can have (issuer.ts). A new kind is an entry here, which the database checks
// on `managed_certificate.issuer_kind` and `certificate.issuer_kind` (schema.ts) must list too.
export const ISSUER_KINDS = [
  /** An ACME CA, through the Organization's ACME account in an environment. */
  "acme",
] as const;
export type IssuerKind = (typeof ISSUER_KINDS)[number];
