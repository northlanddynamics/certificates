// Name rules: what an Enrollment Profile whose Enrollment Validator does not vouch for names (enrollment-validator.ts)
// lets a device put in its subject and subject alternative names. A validator such as Intune checks the names itself; one
// that only checks a static challenge cannot, so without these rules any device that knows the challenge could get any
// name. The rules are strict: a subject attribute or a SAN type the rules do not name is refused.
//
// Patterns are wildcards, matched against the whole value and ignoring case: `*` stands for any run of characters, and
// nothing else is special. They are matched in time proportional to the pattern's length times the value's, never by a
// regular expression, so that no device's input can make an administrator's pattern slow.
import { z } from "@hono/zod-openapi";
import * as x509 from "@peculiar/x509";
import { subjectAltNamesOf } from "../pki/ca-certificates";

/** The SAN types rules may allow, as @peculiar/x509 and the platform name them; `url` is a URI. */
export const SAN_TYPES = ["dns", "email", "ip", "url", "upn"] as const;
export type SanType = (typeof SAN_TYPES)[number];

/** A subject attribute by its short name (CN, O, OU, ...) or OID, as @peculiar/x509 renders a subject. */
const Attribute = z
  .string()
  .regex(/^([A-Za-z][A-Za-z0-9-]*|\d+(\.\d+)+)$/, "a subject attribute's short name, such as CN, or its OID")
  .transform((name) => name.toUpperCase());
const Patterns = z.array(z.string().min(1).max(255)).min(1).max(50);

export const NameRules = z
  .object({
    requiredSubjectAttributes: z.array(Attribute).default([]).openapi({ description: "Subject attributes a request must have, such as CN." }),
    subjectPatterns: z.record(Attribute, Patterns).default({}).openapi({ description: "Per subject attribute, the patterns each of its values must match one of. An attribute neither required nor here is refused." }),
    allowedSanTypes: z.array(z.enum(SAN_TYPES)).default([]).openapi({ description: "The SAN types a request may have; any other is refused." }),
    sanPatterns: z.partialRecord(z.enum(SAN_TYPES), Patterns).default({}).openapi({ description: "Per allowed SAN type, the patterns each name of it must match one of; a type without patterns takes any name." }),
  })
  .strict()
  .refine((rules) => Object.keys(rules.sanPatterns).every((type) => rules.allowedSanTypes.includes(type as SanType)), "sanPatterns may only name allowed SAN types")
  .openapi({ description: "Patterns are matched against the whole value, ignoring case; `*` stands for any run of characters." });
export type NameRules = z.infer<typeof NameRules>;

/** Whether the whole value matches the wildcard pattern, ignoring case: one pass, falling back only to the latest `*`. */
function matches(pattern: string, value: string) {
  const p = pattern.toLowerCase();
  const v = value.toLowerCase();
  let i = 0;
  let j = 0;
  let star = -1;
  let resume = 0;
  while (j < v.length) {
    if (i < p.length && p[i] === "*") {
      star = i++;
      resume = j;
    } else if (i < p.length && p[i] === v[j]) {
      i++;
      j++;
    } else if (star >= 0) {
      i = star + 1;
      j = ++resume;
    } else return false;
  }
  while (i < p.length && p[i] === "*") i++;
  return i === p.length;
}
const matchesOne = (patterns: string[], value: string) => patterns.some((pattern) => matches(pattern, value));

/** Why the CSR (DER) breaks the rules, naming the first thing it breaks; none when it keeps them. */
export function nameRulesRefusal(rules: NameRules, csr: Uint8Array): string | undefined {
  const request = new x509.Pkcs10CertificateRequest(new Uint8Array(csr));
  const subject = new Map<string, string[]>();
  for (const rdn of request.subjectName.toJSON()) {
    for (const [attribute, values] of Object.entries(rdn)) subject.set(attribute.toUpperCase(), [...(subject.get(attribute.toUpperCase()) ?? []), ...values]);
  }
  for (const attribute of rules.requiredSubjectAttributes) {
    if (!subject.get(attribute)?.length) return `the Enrollment Profile requires a subject with ${attribute}`;
  }
  for (const [attribute, values] of subject) {
    const patterns = rules.subjectPatterns[attribute];
    if (!patterns) {
      if (rules.requiredSubjectAttributes.includes(attribute)) continue;
      return `the Enrollment Profile does not allow ${attribute} in the subject`;
    }
    const outside = values.find((value) => !matchesOne(patterns, value));
    if (outside !== undefined) return `the subject's ${attribute} ${outside} matches none of the Enrollment Profile's patterns`;
  }
  for (const { type, value } of subjectAltNamesOf(request)) {
    if (!rules.allowedSanTypes.includes(type as SanType)) return `the Enrollment Profile does not allow ${type} subject alternative names`;
    const patterns = rules.sanPatterns[type as SanType];
    if (patterns && !matchesOne(patterns, value)) return `the ${type} name ${value} matches none of the Enrollment Profile's patterns`;
  }
  return undefined;
}
