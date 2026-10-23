// A Certificate Profile's name rules: which names a non-administrator's request through it may name. Exact names and
// zones (a zone being a name and everything beneath it) limit the names, `maxNames` how many, and `wildcards` whether
// any may be a wildcard. With no exact names and no zones any name is allowed. They narrow the issuer's limits and never
// widen them: an Issuing CA's permitted name rules and ACME DCV still apply afterwards. Proposals and Name Changes
// are checked against the rules as they are now (ADR 0012).
import { z } from "@hono/zod-openapi";
import { MAX_NAMES, normalizeDomain, normalizeName } from "../pki/names";
import { namesOutside } from "../private-ca/permitted-names";

const MAX_RULES = 100;

export interface ProfileNameRules {
  exact: string[];
  zones: string[];
  maxNames: number | null;
  wildcards: boolean;
}

/** No rules: any names the issuer takes. */
export const NO_NAME_RULES: ProfileNameRules = { exact: [], zones: [], maxNames: null, wildcards: true };

/** The rules as they are given and shown. */
export const ProfileNameRulesField = z
  .object({
    exact: z.array(z.string().max(255)).max(MAX_RULES).default([]).openapi({ description: "Names allowed exactly: a DNS name, or a wildcard (`*.` then a DNS name), which allows that wildcard alone." }),
    zones: z.array(z.string().max(255)).max(MAX_RULES).default([]).openapi({ description: "Zones: each allows the name and every name beneath it, wildcards included when they are allowed. Never a wildcard." }),
    maxNames: z.number().int().min(1).max(MAX_NAMES).nullable().default(null).openapi({ description: "The most names a request may carry; none for no limit but the issuer's." }),
    wildcards: z.boolean().default(true).openapi({ description: "Whether a name may be a wildcard." }),
  })
  .openapi({
    description:
      "What a non-administrator's names must keep to, normalised as names are (lower case, no trailing dot). With no exact names and no zones any name is allowed. " +
      "They narrow the issuer's limits and never widen them, and an Organization Administrator is held only to the issuer's.",
  });

/** The rules normalised and without repeats, or what is wrong with them. */
export function normalizeProfileNameRules(rules: ProfileNameRules): { rules: ProfileNameRules } | { invalid: string } {
  const exact = new Set<string>();
  for (const name of rules.exact) {
    const normal = normalizeName(name);
    if (normal === null) return { invalid: `${name} cannot be an allowed name: give a DNS name, or one with a leading *.` };
    if (normal.startsWith("*.") && !rules.wildcards) return { invalid: `${name} is a wildcard, but the name rules allow no wildcards` };
    exact.add(normal);
  }
  const zones = new Set<string>();
  for (const zone of rules.zones) {
    const normal = normalizeDomain(zone);
    if (normal === null) return { invalid: `${zone} cannot be an allowed zone: give a DNS name, with no wildcard` };
    zones.add(normal);
  }
  return { rules: { exact: [...exact], zones: [...zones], maxNames: rules.maxNames, wildcards: rules.wildcards } };
}

/** Why the names (normalised) break the rules of the profile named `profileName`, naming the offending names; none when they keep them. */
export function profileNamesRefusal(profileName: string, rules: ProfileNameRules, names: string[]): string | undefined {
  const of = `the Certificate Profile ${profileName}`;
  if (rules.maxNames !== null && names.length > rules.maxNames) return `${of} allows at most ${rules.maxNames} ${rules.maxNames === 1 ? "name" : "names"}, not ${names.length}`;
  const wildcards = rules.wildcards ? [] : names.filter((name) => name.startsWith("*."));
  if (wildcards.length > 0) return `${wildcards.join(", ")}: ${of} allows no wildcards`;
  const outside = rules.exact.length + rules.zones.length === 0 ? [] : namesOutside(rules, names);
  if (outside.length > 0) return `${outside.join(", ")} ${outside.length === 1 ? "is" : "are"} outside the name rules of ${of}`;
  return undefined;
}
