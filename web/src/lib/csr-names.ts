// The names a CSR may ask for, checked as the platform checks them: these rules are a copy of `normalizeName` in
// server/src/pki/names.ts (the web package shares no code with the server), and server/test/csr-generator.test.ts holds
// the two to each other. A name is a hostname in lower case, or a wildcard: `*.` and then a hostname. No IP
// addresses, and no underscores.
const LABEL = "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?";
const HOSTNAME = new RegExp(`^(?=.{1,253}$)${LABEL}(\\.${LABEL})+$`);
const ALL_NUMERIC = /^[0-9.]+$/;

/** The most names one Managed Certificate may have. */
export const MAX_NAMES = 100;

/** `name` as it is kept (lower case, no trailing dot), or null when it cannot be a name to issue for. */
export function normalizeName(name: string): string | null {
  const lower = name.trim().toLowerCase().replace(/\.$/, "");
  const host = lower.startsWith("*.") ? lower.slice(2) : lower;
  if (!HOSTNAME.test(host) || ALL_NUMERIC.test(host)) return null;
  return lower;
}

/** The names as typed (a name to a line or a comma), without blanks. */
export const splitNames = (text: string) => text.split(/[\s,]+/).filter(Boolean);

/** The names, normalised and without repeats. Only call it with names that have no problems. */
export const normalizedNames = (names: string[]) => [...new Set(names.map((n) => normalizeName(n)).filter((n): n is string => n !== null))];

/** What is wrong with the names, in words, each problem once; empty when they are all right. */
export function nameProblems(names: string[]): string[] {
  if (names.length === 0) return ["Enter at least one name."];
  const problems: string[] = [];
  const invalid = names.filter((n) => normalizeName(n) === null);
  for (const name of invalid) {
    if (ALL_NUMERIC.test(name) || name.includes(":"))
      problems.push(`"${name}" is an IP address; only DNS names are supported.`);
    else if (name.includes("_")) problems.push(`"${name}" has an underscore, which a CA refuses in a name.`);
    else problems.push(`"${name}" is not a DNS name. Use a hostname such as www.example.com, or a wildcard such as *.example.com.`);
  }
  const distinct = normalizedNames(names).length;
  if (distinct > MAX_NAMES) problems.push(`A certificate may have at most ${MAX_NAMES} names; there are ${distinct}.`);
  return problems;
}
