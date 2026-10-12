// The DNS Provider interface: what Domain Control Validation needs from an Organization's DNS, whatever the DNS
// service is. A provider is described by plain data (a kind, its settings and its secret) and nothing else, so it
// can run in the platform or be handed to an Agent to run beside the DNS (relayed execution), and callers hold only
// a `DnsProvider` either way. Each kind is an entry in DNS_PROVIDER_KINDS (dns-provider-kinds.ts).
import { z } from "@hono/zod-openapi";
import { randomBytes } from "node:crypto";

const DOMAIN_NAME = /^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$/;
/** A domain name as the platform keeps it: lower case, no trailing dot. */
export const domainName = z
  .string()
  .transform((name) => name.toLowerCase().replace(/\.$/, ""))
  .refine((name) => DOMAIN_NAME.test(name), "not a domain name");

export class DnsProviderError extends Error {
  constructor(
    /** "rejected": the DNS service answered and said no. "unreachable": it did not answer. */
    readonly kind: "rejected" | "unreachable",
    message: string,
  ) {
    super(message);
  }
}

export interface TxtRecord {
  /** Fully qualified, with or without the trailing dot, and inside the provider's zone. */
  name: string;
  value: string;
}

export interface DnsProvider {
  /** Publishes the record, leaving any other TXT records at its name alone. Throws a DnsProviderError. */
  presentTxt(record: TxtRecord): Promise<void>;
  /** Removes that record only, and succeeds when it is already gone. Throws a DnsProviderError. */
  cleanUpTxt(record: TxtRecord): Promise<void>;
  /** Resolves when the provider can publish and remove records in its zone, shown by doing both with a throwaway record. */
  testConnection(): Promise<void>;
}

/** One kind of DNS service: what it is configured with, and how to run a provider from that. */
export interface DnsProviderKind<Settings = any> {
  /** The non-secret configuration, which an API may show. */
  settings: z.ZodType<Settings>;
  /** The write-only value, as the string the Organization supplies; refuses what could not possibly be one. */
  secret: z.ZodType<string>;
  create(settings: Settings, secret: string): DnsProvider;
  /** The zone of this provider's `name` falls in (lower case, no trailing dot), or null when the provider cannot publish there. */
  zoneOf(settings: Settings, name: string): string | null;
}

/** The record's name as kept here (lower case, no trailing dot), which must be the zone or inside it. Throws a DnsProviderError otherwise. */
export function nameInZone(zone: string, record: TxtRecord): string {
  const name = record.name.toLowerCase().replace(/\.$/, "");
  if (name !== zone && !name.endsWith(`.${zone}`)) throw new DnsProviderError("rejected", `${name} is not inside the zone ${zone}`);
  return name;
}

/**
 * A connection test for a provider: publishes a throwaway TXT record where a challenge for the zone's own name goes,
 * which any policy that lets the provider do its job allows, and removes it again. If the removal fails the error
 * names the record to delete by hand.
 */
export async function testByThrowawayRecord(zone: string, dns: Pick<DnsProvider, "presentTxt" | "cleanUpTxt">): Promise<void> {
  const record = { name: `_acme-challenge.${zone}`, value: `certificate-platform-connection-test-${randomBytes(8).toString("hex")}` };
  await dns.presentTxt(record);
  await dns.cleanUpTxt(record).catch((err) => {
    if (!(err instanceof DnsProviderError)) throw err;
    throw new DnsProviderError(err.kind, `the test record was published but not removed (${err.message}); remove the TXT record "${record.value}" at ${record.name} by hand`);
  });
}
