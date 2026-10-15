// What a Private CA (private-ca.ts) can be. A new kind or status is an entry here, which the database checks on
// `private_ca` (schema.ts) must list too.
export const PRIVATE_CA_KINDS = [
  /** The platform made a self-signed root and the Issuing CA under it. */
  "platform_root",
  /** The Organization's own root signs the Issuing CA, whose CSR the platform gives out. */
  "organization_root",
] as const;
export type PrivateCaKind = (typeof PRIVATE_CA_KINDS)[number];

export const PRIVATE_CA_STATUSES = [
  /** An Organization-root Issuing CA whose signed certificate has not been uploaded yet: it cannot issue. */
  "awaiting_signature",
  /** It issues. */
  "active",
  /** It issues nothing more, and keeps publishing its CRL until its last Certificate expires. */
  "retired",
  /** Its Issuing CA was revoked. */
  "revoked",
] as const;
export type PrivateCaStatus = (typeof PRIVATE_CA_STATUSES)[number];

// How long a Private CA's TLS Certificates may be valid for, in days. The web imports these too, so that what it offers
// is what the API accepts; this module imports nothing, so either side can.
/** A Private CA's maximum and default validity unless it sets its own: what browsers accept of a public CA's TLS Certificates. */
export const DEFAULT_VALIDITY_DAYS = 397;
/** The longest any Private CA may let its TLS Certificates be valid for: ten years. */
export const MAX_VALIDITY_DAYS = 3650;
