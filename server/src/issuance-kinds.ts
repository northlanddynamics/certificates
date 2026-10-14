// What an Issuance is for, decided when it begins from the Managed Certificate's Certificates and names. A new kind is
// an entry here, which the database check on `issuance.kind` (schema.ts) must list too.
export const ISSUANCE_KINDS = [
  /** The Managed Certificate had no Certificate yet: its first, or a person trying it again. */
  "first_issue",
  /** It had a Certificate for the names it has: a Renewal. */
  "renewal",
  /** It had a Certificate, for other names than it now has: the Issuance that applying a Name Change begins, or a person trying that again. */
  "name_change",
] as const;
export type IssuanceKind = (typeof ISSUANCE_KINDS)[number];
