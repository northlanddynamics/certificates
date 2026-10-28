// Why an Issuance failed, in terms a person can act on. Every failure of DCV or of the CA ends as one of these.
export const ISSUANCE_FAILURE_CODES = [
  /** The Organization has no ACME account with the Managed Certificate's ACME CA. */
  "no_acme_account",
  /** No DNS Provider of the Organization publishes records for one of the names. */
  "no_dns_provider",
  /** The DNS Provider answered and refused to publish the challenge record. */
  "dns_update_rejected",
  /** The DNS Provider did not answer. */
  "dns_provider_unreachable",
  /** Delegated DCV: the CNAME that delegates the challenge name to the Validation Zone is not in DNS, or points elsewhere. */
  "cname_missing",
  /** The challenge record was published but never showed up in DNS. */
  "record_not_visible",
  /** The CA answered and said no: refused the names, did not accept the challenge, refused the order. */
  "ca_rejected",
  /** A Private CA's permitted name rules do not permit one of the names: they changed after the names were accepted. */
  "name_not_permitted",
  /** The CA did not answer: for an ADCS CA, no assigned Agent that was asked could reach it. */
  "ca_unreachable",
  /** An ADCS CA: no Agent assigned to it was online to submit the request for 7 days. */
  "no_agent_available",
  /** An ADCS CA: the Certificate Template is no longer available (published, enrollable by the Agents' account, supplying the subject from the request). */
  "template_unavailable",
  /** The Agent that holds the key did not make a new one: it could not, was revoked first, or sent a CSR that could not be used. */
  "agent_key_failed",
  /** The Managed Certificate was archived while the Issuance waited for its Agent's key. */
  "archived",
  /** The CA answered that it would issue later, and did not report by the deadline its kind set. */
  "timed_out",
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
