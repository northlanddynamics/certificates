// How DCV is to be done for one name of an Organization: Direct, by publishing the challenge record in the domain's own
// zone, or Delegated, by publishing it in a Validation Zone that the domain's `_acme-challenge` is a CNAME into. The
// Organization's DCV Rules decide (the most specific one), and without one DCV is Direct through whichever of its DNS
// Providers publishes the name. DCV carries a plan out, and the API shows it, so what it shows is what will happen.
import { and, eq } from "drizzle-orm";
import type { Db, Tx } from "../../platform/db/client";
import { dcvRule, validationZone } from "../../platform/db/schema";
import type { DnsProviders } from "./dns-providers";

export const DCV_SCOPES = ["name", "zone"] as const;
export type DcvScope = (typeof DCV_SCOPES)[number];
export const DCV_METHODS = ["direct", "delegated"] as const;
export type DcvMethod = (typeof DCV_METHODS)[number];

export interface DcvRule {
  id: string;
  scope: DcvScope;
  domain: string;
  method: DcvMethod;
  dnsProviderId: string | null;
  validationZoneId: string | null;
}

/** The domain a CA challenges for a name: a wildcard is challenged at its base domain. */
export const baseDomain = (name: string) => name.replace(/^\*\./, "");

/** The record a CA looks the DNS-01 challenge of a name up at. */
export const challengeName = (name: string) => `_acme-challenge.${baseDomain(name)}`;

/**
 * The rule that decides for `domain` (a base domain): the rule for that very name if there is one, else the rule for
 * the longest zone containing it (the zone itself or anything beneath it).
 */
export function ruleFor<R extends Pick<DcvRule, "scope" | "domain">>(rules: R[], domain: string): R | null {
  let best: R | null = null;
  for (const rule of rules) {
    if (rule.scope === "name") {
      if (rule.domain === domain) return rule;
    } else if ((domain === rule.domain || domain.endsWith(`.${rule.domain}`)) && (!best || rule.domain.length > best.domain.length)) {
      best = rule;
    }
  }
  return best;
}

export interface DcvPlan {
  /** The name as asked about, normalised: a wildcard stays one. */
  name: string;
  /** The domain the CA challenges: the name, without a wildcard's `*.`. */
  domain: string;
  /** The record the CA looks the challenge up at. */
  challengeName: string;
  method: DcvMethod;
  rule: DcvRule | null;
  /** Where the platform writes the TXT record: the challenge name when Direct, the delegation target when Delegated. */
  recordName: string;
  /** The DNS Provider that publishes there, or null when none does. */
  dnsProvider: { id: string; name: string } | null;
  validationZone: { id: string; name: string } | null;
  /** The record the Organization must create in the domain's own DNS, for a Delegated name. */
  cname: { name: string; type: "CNAME"; value: string } | null;
}

export interface DcvPlans {
  /** How DCV is done for `name` (as the CA asks about it, so a wildcard is fine) for the Organization, as its rules stand now. */
  plan(db: Db | Tx, organizationId: string, name: string): Promise<DcvPlan>;
}

export function createDcvPlans(dnsProviders: DnsProviders): DcvPlans {
  return {
    async plan(db, organizationId, name) {
      const domain = baseDomain(name);
      const challenge = challengeName(name);
      const rules = await db.select().from(dcvRule).where(eq(dcvRule.organizationId, organizationId));
      const rule = ruleFor(rules, domain);

      if (rule?.method === "delegated") {
        const [zone] = await db
          .select()
          .from(validationZone)
          .where(and(eq(validationZone.organizationId, organizationId), eq(validationZone.id, rule.validationZoneId!)));
        if (!zone) throw new Error("the Validation Zone of a DCV Rule is gone");
        // One record name per delegated domain, so a name's challenge never meets another's in the Validation Zone.
        const target = `${domain}.${zone.name}`;
        const located = await dnsProviders.locate(db, organizationId, target, zone.dnsProviderId);
        return {
          name,
          domain,
          challengeName: challenge,
          method: "delegated",
          rule,
          recordName: target,
          dnsProvider: located && { id: located.id, name: located.name },
          validationZone: { id: zone.id, name: zone.name },
          cname: { name: challenge, type: "CNAME", value: target },
        };
      }

      const located = await dnsProviders.locate(db, organizationId, challenge, rule?.dnsProviderId ?? undefined);
      return {
        name,
        domain,
        challengeName: challenge,
        method: "direct",
        rule,
        recordName: challenge,
        dnsProvider: located && { id: located.id, name: located.name },
        validationZone: null,
        cname: null,
      };
    },
  };
}
