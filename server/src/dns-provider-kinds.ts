// Every kind of DNS service the platform can connect to. A new one is a module like rfc2136.ts and an entry here.
import type { DnsProviderKind } from "./dns-provider";
import { rfc2136 } from "./rfc2136";

export const DNS_PROVIDER_KINDS = { rfc2136 } satisfies Record<string, DnsProviderKind>;
export type DnsProviderType = keyof typeof DNS_PROVIDER_KINDS;
export const DNS_PROVIDER_TYPES = Object.keys(DNS_PROVIDER_KINDS) as [DnsProviderType, ...DnsProviderType[]];
