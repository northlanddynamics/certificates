// The DNS names a Managed Certificate is issued for. A name is a hostname in lower case (internationalised names in
// their punycode form), or a wildcard: `*.` and then a hostname. No IP addresses, and no underscores, which the CA
// would refuse.
const LABEL = "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?";
const HOSTNAME = new RegExp(`^(?=.{1,253}$)${LABEL}(\\.${LABEL})+$`);
const ALL_NUMERIC = /^[0-9.]+$/;

/** Let's Encrypt's limit on names in one Certificate; lower limits at other CAs can be enforced by them. */
export const MAX_NAMES = 100;

/** `name` as it is kept (lower case, no trailing dot), or null when it cannot be a name to issue for. */
export function normalizeName(name: string): string | null {
  const lower = name.trim().toLowerCase().replace(/\.$/, "");
  const host = lower.startsWith("*.") ? lower.slice(2) : lower;
  if (!HOSTNAME.test(host) || ALL_NUMERIC.test(host)) return null;
  return lower;
}

/** The names, normalised and without repeats, or the first one that cannot be a name. */
export function normalizeNames(names: string[]): { names: string[] } | { invalid: string } {
  const seen = new Set<string>();
  for (const name of names) {
    const normal = normalizeName(name);
    if (normal === null) return { invalid: name };
    seen.add(normal);
  }
  return { names: [...seen] };
}

/** Whether two lists name the same set of names, in any order. Both are already normalised. */
export const sameNames = (a: string[], b: string[]) => a.length === b.length && new Set([...a, ...b]).size === a.length;

/** `name` as a domain that a DCV rule or a Validation Zone is for: a name as above, but never a wildcard. Null when it cannot be one. */
export function normalizeDomain(name: string): string | null {
  const normal = normalizeName(name);
  return normal === null || normal.startsWith("*.") ? null : normal;
}
