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
