// Why an Issuance failed, in terms a person can act on. Every failure of DCV or of the CA ends as one of these.
export const ISSUANCE_FAILURE_CODES = [
  /** The Organization has no ACME account in the Managed Certificate's environment. */
  "no_acme_account",
  /** No DNS Provider of the Organization publishes records for one of the names. */
  "no_dns_provider",
  /** The DNS Provider answered and refused to publish the challenge record. */
  "dns_update_rejected",
  /** The DNS Provider did not answer. */
  "dns_provider_unreachable",
  /** The challenge record was published but never showed up in DNS. */
  "record_not_visible",
  /** The CA answered and said no: refused the names, did not accept the challenge, refused the order. */
  "ca_rejected",
  /** The CA did not answer. */
  "ca_unreachable",
  /** The platform stopped while the Issuance was running. */
  "interrupted",
  /** Something went wrong in the platform itself. */
  "internal",
] as const;
export type IssuanceFailureCode = (typeof ISSUANCE_FAILURE_CODES)[number];

export class IssuanceFailure extends Error {
  constructor(
    readonly code: IssuanceFailureCode,
    message: string,
  ) {
    super(message);
  }
}
