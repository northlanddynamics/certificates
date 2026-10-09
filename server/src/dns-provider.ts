// The DNS Provider interface: what Domain Control Validation needs from an Organization's DNS, whatever the DNS
// service is. A provider is described by plain data (a kind, its settings and its secret) and nothing else, so it
// can run in the platform or be handed to an Agent to run beside the DNS (relayed execution), and callers hold only
// a `DnsProvider` either way. Infoblox joins as another entry in DNS_PROVIDER_KINDS (dns-provider-kinds.ts).
import type { z } from "@hono/zod-openapi";

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
