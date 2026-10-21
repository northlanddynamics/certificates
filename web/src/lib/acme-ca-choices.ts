// Which ACME CAs the issuer picker lists, and which of them can be chosen. Pure and free of the app's imports, so the
// server's tests can run it.

/** What the picker needs to know of an ACME CA: its tag, and whether the Organization has an account with it. */
export interface AcmeCaChoosable {
  id: string;
  tag: "staging" | "production" | null;
  hasAccount: boolean;
}

/** What the picker's ACME CAs are filtered by: every one, those with a tag, or those with none. */
export const ACME_CA_FILTERS = ["all", "staging", "production", "untagged"] as const;
export type AcmeCaFilter = (typeof ACME_CA_FILTERS)[number];

/**
 * The ACME CAs to list, in the order given, those `filter` keeps, each disabled when the Organization has no account
 * with it, as issuing from it would fail.
 */
export function acmeCaChoices<T extends AcmeCaChoosable>(acmeCas: T[], filter: AcmeCaFilter): { ca: T; disabled: boolean }[] {
  return acmeCas.filter((ca) => filter === "all" || (filter === "untagged" ? ca.tag === null : ca.tag === filter)).map((ca) => ({ ca, disabled: !ca.hasAccount }));
}
