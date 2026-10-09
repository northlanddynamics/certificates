// Domain Control Validation, Direct: the platform proves control of a name by publishing the CA's challenge as a TXT
// record at `_acme-challenge.<name>`, through the Organization's own DNS Provider for that name, and takes it away
// again. It waits until the record can be seen before the CA is told to look, and says which step failed and why.
import { Resolver } from "node:dns/promises";
import type { DnsChallengeResponder } from "./certificate-authority";
import type { Db } from "./db/client";
import { DnsProviderError } from "./dns-provider";
import type { DnsProviders } from "./dns-providers";
import { IssuanceFailure, type IssuanceFailureCode } from "./issuance-failure";

export type DcvFailureCode = Extract<IssuanceFailureCode, "no_dns_provider" | "dns_update_rejected" | "dns_provider_unreachable" | "record_not_visible">;

export class DcvError extends IssuanceFailure {
  constructor(
    readonly code: DcvFailureCode,
    message: string,
  ) {
    super(code, message);
  }
}

/** How the platform looks a TXT record up to see that it was published. */
export interface TxtResolver {
  /** The TXT records at `name`, each as one string; none when there are none or the lookup failed. */
  lookupTxt(name: string): Promise<string[]>;
}

/**
 * Looks records up through the resolvers the host is configured with, or through `servers` ("ip" or "ip:port") when
 * given. Each lookup has a resolver of its own: a shared one answers from a cache, and a cached answer can say a
 * record is not there after it has been published, or is there after it has been removed.
 */
export function createTxtResolver(servers?: string[]): TxtResolver {
  return {
    lookupTxt(name) {
      const resolver = new Resolver({ timeout: 3000, tries: 1 });
      if (servers) resolver.setServers(servers);
      return resolver.resolveTxt(name).then(
        (records) => records.map((chunks) => chunks.join("")),
        () => [],
      );
    },
  };
}

export interface DcvConfig {
  resolver: TxtResolver;
  /** How long a published record may take to be visible before the validation is given up. */
  visibilityTimeoutMs: number;
  /** How often to look while waiting. */
  pollIntervalMs: number;
}

export const DEFAULT_DCV_CONFIG: Omit<DcvConfig, "resolver"> = { visibilityTimeoutMs: 120_000, pollIntervalMs: 2_000 };

/** The challenge record's name for a domain the CA asks about (a wildcard's challenge is at its base domain). */
export const challengeName = (domain: string) => `_acme-challenge.${domain.replace(/^\*\./, "")}`;

export interface Dcv {
  /**
   * Satisfies a CA's DNS challenges for one Organization by Direct DCV. `leftovers` lists the records that could not be
   * removed again, so someone can be told to delete them by hand.
   */
  directFor(db: Db, organizationId: string): DnsChallengeResponder & { leftovers(): string[] };
}

export function createDcv(dnsProviders: DnsProviders, config: DcvConfig): Dcv {
  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

  async function visible(name: string, value: string) {
    const deadline = Date.now() + config.visibilityTimeoutMs;
    for (;;) {
      if ((await config.resolver.lookupTxt(name)).includes(value)) return;
      if (Date.now() >= deadline) {
        throw new DcvError("record_not_visible", `the TXT record at ${name} was published but did not appear in DNS within ${Math.round(config.visibilityTimeoutMs / 1000)} seconds`);
      }
      await sleep(config.pollIntervalMs);
    }
  }

  return {
    directFor(db, organizationId) {
      const leftovers = new Set<string>();

      async function providerFor(domain: string) {
        const recordName = challengeName(domain);
        const found = await dnsProviders.findFor(db, organizationId, recordName);
        if (!found) throw new DcvError("no_dns_provider", `no DNS Provider of the Organization publishes records for ${recordName}; add one whose zone contains ${domain}`);
        return { recordName, providerName: found.name, provider: found.provider };
      }

      return {
        async present(domain, value) {
          const { recordName, providerName, provider } = await providerFor(domain);
          try {
            await provider.presentTxt({ name: recordName, value });
          } catch (err) {
            if (!(err instanceof DnsProviderError)) throw err;
            const code = err.kind === "unreachable" ? "dns_provider_unreachable" : "dns_update_rejected";
            throw new DcvError(code, `publishing the TXT record at ${recordName} through DNS Provider "${providerName}" failed: ${err.message}`);
          }
          await visible(recordName, value);
        },
        async cleanUp(domain, value) {
          const { recordName, provider } = await providerFor(domain);
          try {
            await provider.cleanUpTxt({ name: recordName, value });
          } catch (err) {
            leftovers.add(`${recordName} (${value})`);
            throw err;
          }
        },
        leftovers: () => [...leftovers],
      };
    },
  };
}
