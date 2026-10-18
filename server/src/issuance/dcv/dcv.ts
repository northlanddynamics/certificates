// Domain Control Validation: the platform proves control of a name by publishing the CA's challenge as a TXT record
// through the Organization's own DNS Provider, and takes it away again. Direct DCV publishes it at
// `_acme-challenge.<name>`; Delegated DCV publishes it in a Validation Zone that `_acme-challenge.<name>` is a CNAME
// into (dcv-plan.ts decides which, and where). It waits until the record can be seen at `_acme-challenge.<name>`, where
// the CA looks, before the CA is told to look, and says which step failed and why.
import { Resolver } from "node:dns/promises";
import type { DnsChallengeResponder } from "../acme/certificate-authority";
import type { Db } from "../../platform/db/client";
import { DnsProviderError, type DnsProvider } from "./dns-provider";
import { challengeName, type DcvPlan, type DcvPlans } from "./dcv-plan";
import type { DnsProviders } from "./dns-providers";
import { IssuanceFailure, type IssuanceFailureCode } from "../issuance-failure";

export type DcvFailureCode = Extract<IssuanceFailureCode, "no_dns_provider" | "dns_update_rejected" | "dns_provider_unreachable" | "cname_missing" | "record_not_visible">;

export class DcvError extends IssuanceFailure {
  constructor(
    readonly code: DcvFailureCode,
    message: string,
  ) {
    super(code, message);
  }
}

/** How the platform looks DNS up to see that a record was published, and that a delegation is in place. */
export interface TxtResolver {
  /** The TXT records at `name`, each as one string (those at what a CNAME points to, if it is one); none when there are none or the lookup failed. */
  lookupTxt(name: string): Promise<string[]>;
  /** What the CNAME record at `name` points to, in lower case without a trailing dot; none when it is not a CNAME or the lookup failed. */
  lookupCname(name: string): Promise<string[]>;
}

/**
 * Looks records up through the resolvers the host is configured with, or through `servers` ("ip" or "ip:port") when
 * given. Each lookup has a resolver of its own: a shared one answers from a cache, and a cached answer can say a
 * record is not there after it has been published, or is there after it has been removed.
 */
export function createTxtResolver(servers?: string[]): TxtResolver {
  const resolverFor = () => {
    const resolver = new Resolver({ timeout: 3000, tries: 1 });
    if (servers) resolver.setServers(servers);
    return resolver;
  };
  const lookupCname = (name: string) =>
    resolverFor()
      .resolveCname(name)
      .then(
        (targets) => targets.map((target) => target.toLowerCase().replace(/\.$/, "")),
        () => [],
      );
  /** Follows a CNAME itself rather than rely on the resolver to chase it: a name Delegated DCV validates is one. */
  async function lookupTxt(name: string, hops = 0): Promise<string[]> {
    const records = await resolverFor()
      .resolveTxt(name)
      .then(
        (found) => found.map((chunks) => chunks.join("")),
        () => [],
      );
    if (records.length > 0 || hops >= MAX_CNAME_HOPS) return records;
    const [target] = await lookupCname(name);
    return target ? lookupTxt(target, hops + 1) : [];
  }
  return { lookupTxt: (name) => lookupTxt(name), lookupCname };
}

/** How many CNAMEs in a row a lookup follows; a chain longer than that is a loop or not worth waiting for. */
const MAX_CNAME_HOPS = 8;

export interface DcvConfig {
  resolver: TxtResolver;
  /** How long a published record may take to be visible before the validation is given up. */
  visibilityTimeoutMs: number;
  /** How often to look while waiting. */
  pollIntervalMs: number;
}

export const DEFAULT_DCV_CONFIG: Omit<DcvConfig, "resolver"> = { visibilityTimeoutMs: 120_000, pollIntervalMs: 2_000 };

/** The longest name DNS allows, which a delegation target (the domain and then the Validation Zone) can exceed. */
const MAX_NAME_LENGTH = 253;

export interface Dcv {
  /**
   * Satisfies a CA's DNS challenges for one Organization, Direct or Delegated as its DCV Rules say. `leftovers` lists the
   * records that could not be removed again, so someone can be told to delete them by hand.
   */
  responderFor(db: Db, organizationId: string): DnsChallengeResponder & { leftovers(): string[] };
}

export function createDcv(dnsProviders: DnsProviders, plans: DcvPlans, config: DcvConfig): Dcv {
  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

  /** Waits until the CA, looking at the challenge name, would see `value`; says why not when it would not. */
  async function visible(plan: DcvPlan, value: string) {
    const deadline = Date.now() + config.visibilityTimeoutMs;
    for (;;) {
      if ((await config.resolver.lookupTxt(plan.challengeName)).includes(value)) return;
      if (Date.now() >= deadline) break;
      await sleep(config.pollIntervalMs);
    }
    const seconds = Math.round(config.visibilityTimeoutMs / 1000);
    if (plan.cname) {
      const pointsTo = await config.resolver.lookupCname(plan.cname.name);
      if (!pointsTo.includes(plan.cname.value)) {
        const found = pointsTo.length > 0 ? `; it points to ${pointsTo.join(", ")} instead` : "";
        throw new DcvError(
          "cname_missing",
          `the TXT record was published at ${plan.recordName}, but ${plan.cname.name} is not a CNAME to it${found}; create the CNAME ${plan.cname.name} -> ${plan.cname.value} in the DNS of ${plan.domain}`,
        );
      }
    }
    throw new DcvError("record_not_visible", `the TXT record at ${plan.recordName} was published but ${plan.challengeName} did not show it in DNS within ${seconds} seconds`);
  }

  return {
    responderFor(db, organizationId) {
      const leftovers = new Set<string>();
      // A domain is planned once per Issuance, so the record that is cleaned up is the one that was published even if its rules change meanwhile.
      const planned = new Map<string, Promise<{ plan: DcvPlan; providerName: string; provider: DnsProvider }>>();

      function providerFor(domain: string) {
        const key = challengeName(domain);
        let found = planned.get(key);
        if (!found) {
          found = (async () => {
            const plan = await plans.plan(db, organizationId, domain);
            if (!plan.dnsProvider) throw new DcvError("no_dns_provider", noProvider(plan));
            if (plan.recordName.length > MAX_NAME_LENGTH) {
              throw new DcvError("dns_update_rejected", `the name ${plan.recordName} to publish the challenge record at is longer than DNS allows; delegate to a shorter Validation Zone`);
            }
            return { plan, providerName: plan.dnsProvider.name, provider: await dnsProviders.open(db, organizationId, plan.dnsProvider.id) };
          })();
          planned.set(key, found);
        }
        return found;
      }

      return {
        async present(domain, value) {
          const { plan, providerName, provider } = await providerFor(domain);
          try {
            await provider.presentTxt({ name: plan.recordName, value });
          } catch (err) {
            if (!(err instanceof DnsProviderError)) throw err;
            const code = err.kind === "unreachable" ? "dns_provider_unreachable" : "dns_update_rejected";
            throw new DcvError(code, `publishing the TXT record at ${plan.recordName} through DNS Provider "${providerName}" failed: ${err.message}`);
          }
          await visible(plan, value);
        },
        async cleanUp(domain, value) {
          const { plan, provider } = await providerFor(domain);
          try {
            await provider.cleanUpTxt({ name: plan.recordName, value });
          } catch (err) {
            leftovers.add(`${plan.recordName} (${value})`);
            throw err;
          }
        },
        leftovers: () => [...leftovers],
      };
    },
  };
}

/** Why no DNS Provider can publish the challenge record, in terms of what to change. */
function noProvider(plan: DcvPlan): string {
  const domain = plan.domain;
  if (plan.validationZone) {
    return `no DNS Provider publishes records in the Validation Zone ${plan.validationZone.name}, which the DCV Rule for ${plan.rule!.domain} delegates ${domain} to; check the DNS Provider the zone is on`;
  }
  if (plan.rule?.dnsProviderId) {
    return `the DNS Provider that the DCV Rule for ${plan.rule.domain} names does not publish records for ${plan.recordName}; change the rule or the provider's zone`;
  }
  return `no DNS Provider of the Organization publishes records for ${plan.recordName}; add one whose zone contains ${domain}`;
}
