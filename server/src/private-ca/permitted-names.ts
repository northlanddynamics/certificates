// A Private CA's permitted name rules: the names it may issue for. An exact name permits that name alone (a wildcard
// one, that wildcard alone); a zone permits the name and everything beneath it, wildcards included. They are normalised
// as Managed Certificates' names are (names.ts), and a zone is never a wildcard. An ADCS CA may carry them too
// (adcs-ca.ts), which the platform alone enforces.
import { z } from "@hono/zod-openapi";
import { HttpError } from "../platform/http";
import { normalizeDomain, normalizeName, sameNames } from "../pki/names";

export interface PermittedNames {
  exact: string[];
  zones: string[];
}

/** The rules normalised and without repeats, or what is wrong with them. */
export function normalizePermittedNames(rules: PermittedNames): { rules: PermittedNames } | { invalid: string } {
  const exact = new Set<string>();
  for (const name of rules.exact) {
    const normal = normalizeName(name);
    if (normal === null) return { invalid: `${name} cannot be a permitted name: give a DNS name, or one with a leading *.` };
    exact.add(normal);
  }
  const zones = new Set<string>();
  for (const zone of rules.zones) {
    const normal = normalizeDomain(zone);
    if (normal === null) return { invalid: `${zone} cannot be a permitted zone: give a DNS name, with no wildcard` };
    zones.add(normal);
  }
  if (exact.size + zones.size === 0) return { invalid: "give at least one permitted name or zone" };
  return { rules: { exact: [...exact], zones: [...zones] } };
}

/** Whether two sets of rules (normalised) are the same, in any order. */
export const samePermittedNames = (a: PermittedNames, b: PermittedNames) => sameNames(a.exact, b.exact) && sameNames(a.zones, b.zones);

/** Whether `name` (normalised) is `zone` or beneath it; a wildcard is beneath it when what it stands for is. */
const inZone = (name: string, zone: string) => {
  const host = name.startsWith("*.") ? name.slice(2) : name;
  return host === zone || host.endsWith(`.${zone}`);
};

/** The names (normalised) the rules do not permit, in their order. */
export const namesOutside = (rules: PermittedNames, names: string[]) => names.filter((name) => !rules.exact.includes(name) && !rules.zones.some((zone) => inZone(name, zone)));

/**
 * The DNS names an Issuing CA's name constraints permit for the rules: each zone, and each exact name (a wildcard's
 * without its `*.`), without repeats. A dNSName constraint permits a name and everything beneath it, so for an exact
 * name it permits more than the rule does, which the platform still enforces.
 */
export const constraintNamesOf = (rules: PermittedNames) => [...new Set([...rules.exact.map((name) => (name.startsWith("*.") ? name.slice(2) : name)), ...rules.zones])];

const MAX_RULES = 100;

/** Permitted name rules as they are given and shown; `description` says whose. */
export const permittedNamesField = (description: string) =>
  z
    .object({
      exact: z.array(z.string().max(255)).max(MAX_RULES).default([]).openapi({ description: "Names permitted exactly: a DNS name, or a wildcard (`*.` then a DNS name), which permits that wildcard alone." }),
      zones: z.array(z.string().max(255)).max(MAX_RULES).default([]).openapi({ description: "Zones: each permits the name and every name beneath it, wildcards included. Never a wildcard." }),
    })
    .openapi({ description });

/** The rules given, normalised; a 400 when they cannot be rules. */
export function permittedNamesAsked(rules: PermittedNames): PermittedNames {
  const normal = normalizePermittedNames(rules);
  if ("invalid" in normal) throw new HttpError(400, normal.invalid);
  return normal.rules;
}
