// What a Private CA (private-ca.ts) and its Issuing CAs can be. A new kind or status is an entry here, which the database
// checks on `private_ca` and `issuing_ca` (schema.ts) must list too.
export const PRIVATE_CA_KINDS = [
  /** The platform made a self-signed root, which signs its Issuing CAs. */
  "platform_root",
  /** The Organization's own root signs its Issuing CAs, whose CSRs the platform gives out. */
  "organization_root",
] as const;
export type PrivateCaKind = (typeof PRIVATE_CA_KINDS)[number];

/** A Private CA's own status: its root's. A revoked root's Issuing CAs issue nothing. */
export const PRIVATE_CA_STATUSES = [
  /** Its Issuing CAs issue, each as its own status allows. */
  "active",
  /** Its root was revoked. */
  "revoked",
] as const;
export type PrivateCaStatus = (typeof PRIVATE_CA_STATUSES)[number];

/** An Issuing CA's status. A new one is an entry here, which the database check on `issuing_ca` (schema.ts) must list too. */
export const ISSUING_CA_STATUSES = [
  /** An Organization-root Issuing CA whose signed certificate has not been uploaded yet: it cannot issue. */
  "awaiting_signature",
  /** It issues. */
  "active",
  /** It issues nothing more, and keeps publishing its CRL until its last Certificate expires. */
  "retired",
  /** It was revoked. */
  "revoked",
] as const;
export type IssuingCaStatus = (typeof ISSUING_CA_STATUSES)[number];

// How long an Issuing CA's TLS Certificates may be valid for, in days. The web imports these too, so that what it offers
// is what the API accepts; this module imports nothing, so either side can.
/** An Issuing CA's maximum and default validity unless it sets its own: what browsers accept of a public CA's TLS Certificates. */
export const DEFAULT_VALIDITY_DAYS = 397;
/** The longest a Private CA's root and Issuing CAs may be made to last, in years. */
export const MAX_LIFETIME_YEARS = 30;
/** The longest any Issuing CA may let its TLS Certificates be valid for: ten years. */
export const MAX_VALIDITY_DAYS = 3650;
