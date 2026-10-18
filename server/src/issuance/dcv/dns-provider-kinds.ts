// Every kind of DNS service the platform can connect to. A new one is a module like rfc2136.ts and an entry here.
import type { DnsProviderKind } from "./dns-provider";
import { infoblox } from "./infoblox";
import { rfc2136 } from "./rfc2136";

const kinds = { rfc2136, infoblox } satisfies Record<string, DnsProviderKind>;
export type DnsProviderType = keyof typeof kinds;
/** Typed by what every kind has in common: whoever holds a stored provider knows its type, not which kind's settings it has. */
export const DNS_PROVIDER_KINDS: Record<DnsProviderType, DnsProviderKind> = kinds;
export const DNS_PROVIDER_TYPES = Object.keys(DNS_PROVIDER_KINDS) as [DnsProviderType, ...DnsProviderType[]];
