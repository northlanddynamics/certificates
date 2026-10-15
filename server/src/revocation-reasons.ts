// The RFC 5280 reasons a Certificate may be revoked for, and which of them each kind of issuer (issuer-kinds.ts) offers:
// an ACME CA takes the four ACME allows a subscriber, a Private CA those and the two an Organization's own PKI needs,
// and neither offers certificateHold. The web imports these too, so that what it offers is what the API accepts; this
// module imports only types, so either side can. A new reason is an entry here, which the database checks on
// `certificate_revocation` (schema.ts) must list too.
import type { IssuerKind } from "./issuer-kinds";

/** Each reason's name, as the API takes it, and its RFC 5280 CRLReason code. */
export const REVOCATION_REASONS = {
  unspecified: 0,
  keyCompromise: 1,
  affiliationChanged: 3,
  superseded: 4,
  cessationOfOperation: 5,
  privilegeWithdrawn: 9,
} as const;
export type RevocationReason = keyof typeof REVOCATION_REASONS;

/** The reasons a Certificate from each kind of issuer may be revoked for. */
export const REVOCATION_REASONS_OF: Record<IssuerKind, readonly RevocationReason[]> = {
  acme: ["unspecified", "keyCompromise", "superseded", "cessationOfOperation"],
  private_ca: ["unspecified", "keyCompromise", "affiliationChanged", "superseded", "cessationOfOperation", "privilegeWithdrawn"],
};
