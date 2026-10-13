// Relayed DNS Providers: a DNS Provider whose operations an Agent of the Organization carries out, beside DNS the hosted
// platform cannot reach. To a caller it is a `DnsProvider` like any other (dns-provider.ts); behind it, each operation is
// a work item for one online relay Agent, which runs the same provider code (the Agent has its own implementation of each
// kind) and reports what happened. Any online relay Agent will do: one that is offline is passed over, and one that takes
// an item and does not answer in time is given up on for the next. The provider's credentials are put into the work item
// only when the Agent is given it (work-items.ts), and the platform reads them for nothing else when the provider is relayed.
import { and, asc, desc, eq, inArray } from "drizzle-orm";
import type { Db, Tx } from "./db/client";
import { agent, dnsProvider, dnsProviderRelayAgent } from "./db/schema";
import { DnsProviderError, type DnsProvider, type TxtRecord } from "./dns-provider";
import { DNS_PROVIDER_KINDS } from "./dns-provider-kinds";
import { HttpError } from "./http";
import type { Secrets } from "./secrets";
import type { WorkItems } from "./work-items";

export interface DnsRelayConfig {
  /** How long one Agent has to report on an operation before another online one is tried. */
  attemptTimeoutMs: number;
  /** How often the wait for an Agent's report looks for it. */
  pollMs: number;
  /** How long a work item may wait to be given to its Agent before it is dropped as stale. */
  maxWaitMs: number;
}

export const DEFAULT_DNS_RELAY: DnsRelayConfig = { attemptTimeoutMs: 45_000, pollMs: 250, maxWaitMs: 10 * 60_000 };

export const DNS_WORK_TYPES = { present: "dns.present", cleanUp: "dns.cleanup", test: "dns.test" } as const;
type DnsWorkType = (typeof DNS_WORK_TYPES)[keyof typeof DNS_WORK_TYPES];

/** The most Agents that may relay one DNS Provider. */
export const MAX_RELAY_AGENTS = 20;

export interface DnsRelay {
  /** The Agents assigned to relay each of the Organization's DNS Providers (those with none are absent). */
  assignments(db: Db | Tx, organizationId: string): Promise<Map<string, string[]>>;
  /** The Agents assigned to relay one DNS Provider; none when it runs directly. */
  assignmentsOf(db: Db | Tx, providerId: string): Promise<string[]>;
  /**
   * Makes `agentIds` the Agents that relay the provider (none: it runs directly), on the transaction. Throws a 400 for one
   * that is not an Agent of the Organization, is revoked or is listed twice. Returns the ones it had.
   */
  assign(tx: Tx, organizationId: string, providerId: string, agentIds: string[]): Promise<string[]>;
  /** The provider as a `DnsProvider` whose operations the Agents `agentIds` carry out. */
  provider(input: { organizationId: string; providerId: string; agentIds: string[] }): DnsProvider;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function ago(ms: number): string {
  const minutes = Math.round(ms / 60_000);
  if (minutes < 1) return `${Math.max(Math.round(ms / 1000), 0)} seconds`;
  if (minutes < 120) return `${minutes} minutes`;
  return minutes < 48 * 60 ? `${Math.round(minutes / 60)} hours` : `${Math.round(minutes / 1440)} days`;
}

export function createDnsRelay(ctx: { db: Db; workItems: WorkItems; secrets: Secrets; clock: () => Date; offlineAfterSeconds: number; config: DnsRelayConfig }): DnsRelay {
  const { db, workItems, secrets, clock, offlineAfterSeconds, config } = ctx;

  // What an Agent is given to carry out an operation: the provider as plain data, which is all a provider is, and the record.
  const materialize = async (tx: Tx, item: { organizationId: string; payload: Record<string, unknown> }) => {
    const { providerId, record } = item.payload as { providerId: string; record?: TxtRecord };
    const [row] = await tx.select().from(dnsProvider).where(and(eq(dnsProvider.organizationId, item.organizationId), eq(dnsProvider.id, providerId)));
    if (!row) throw new Error("no such DNS Provider");
    const settings = DNS_PROVIDER_KINDS[row.type].settings.parse(row.settings);
    return { provider: { type: row.type, settings, secret: await secrets.open(tx, item.organizationId, row.secretId) }, ...(record ? { record } : {}) };
  };
  for (const type of Object.values(DNS_WORK_TYPES)) workItems.register(type, materialize);

  async function run(organizationId: string, providerId: string, agentIds: string[], type: DnsWorkType, record?: TxtRecord): Promise<void> {
    const tried = new Map<string, string>();
    for (;;) {
      const agents = await db
        .select()
        .from(agent)
        .where(and(eq(agent.organizationId, organizationId), inArray(agent.id, agentIds)))
        .orderBy(desc(agent.lastContactAt), asc(agent.id));
      const now = clock();
      const online = (a: (typeof agents)[number]) => !a.revokedAt && now.getTime() - a.lastContactAt.getTime() <= offlineAfterSeconds * 1000;
      const next = agents.find((a) => online(a) && !tried.has(a.id));
      if (!next) {
        if (tried.size > 0) {
          throw new DnsProviderError("unreachable", `no Agent that relays this DNS Provider answered in time (${[...tried.values()].join("; ")})`);
        }
        const states = agents.map((a) => `${a.hostName} (${a.revokedAt ? "revoked" : `last contact ${ago(now.getTime() - a.lastContactAt.getTime())} ago`})`);
        throw new DnsProviderError("unreachable", `no Agent that relays this DNS Provider is online${states.length > 0 ? `: ${states.join(", ")}` : ""}`);
      }
      const id = await workItems.enqueue(organizationId, next.id, type, { providerId, ...(record ? { record } : {}) });
      const outcome = await workItems.outcome(id, config.attemptTimeoutMs);
      if (outcome === "expired") {
        tried.set(next.id, `${next.hostName} did not answer within ${config.attemptTimeoutMs / 1000} seconds`);
        continue;
      }
      if (outcome.ok) return;
      throw new DnsProviderError(outcome.kind ?? "rejected", `Agent ${next.hostName} reported: ${outcome.error ?? "the operation failed"}`);
    }
  }

  return {
    async assignments(db, organizationId) {
      const rows = await db.select().from(dnsProviderRelayAgent).where(eq(dnsProviderRelayAgent.organizationId, organizationId)).orderBy(asc(dnsProviderRelayAgent.agentId));
      const byProvider = new Map<string, string[]>();
      for (const row of rows) byProvider.set(row.dnsProviderId, [...(byProvider.get(row.dnsProviderId) ?? []), row.agentId]);
      return byProvider;
    },

    async assignmentsOf(db, providerId) {
      const rows = await db.select().from(dnsProviderRelayAgent).where(eq(dnsProviderRelayAgent.dnsProviderId, providerId)).orderBy(asc(dnsProviderRelayAgent.agentId));
      return rows.map((row) => row.agentId);
    },

    async assign(tx, organizationId, providerId, agentIds) {
      if (new Set(agentIds).size !== agentIds.length) throw new HttpError(400, "an Agent is listed twice");
      if (agentIds.length > MAX_RELAY_AGENTS) throw new HttpError(400, `at most ${MAX_RELAY_AGENTS} Agents may relay a DNS Provider`);
      if (agentIds.some((id) => !UUID.test(id))) throw new HttpError(400, "relay Agents must be the ids of the Organization's Agents");
      // Shared, so that an Agent being revoked finishes first, or is seen revoked.
      const found = agentIds.length > 0 ? await tx.select().from(agent).where(and(eq(agent.organizationId, organizationId), inArray(agent.id, agentIds))).for("share") : [];
      if (found.length !== agentIds.length) throw new HttpError(400, "relay Agents must be the ids of the Organization's Agents");
      const revoked = found.find((a) => a.revokedAt);
      if (revoked) throw new HttpError(400, `the Agent ${revoked.hostName} is revoked and cannot relay`);
      const previous = (await tx.select().from(dnsProviderRelayAgent).where(eq(dnsProviderRelayAgent.dnsProviderId, providerId)).orderBy(asc(dnsProviderRelayAgent.agentId))).map((r) => r.agentId);
      await tx.delete(dnsProviderRelayAgent).where(eq(dnsProviderRelayAgent.dnsProviderId, providerId));
      if (agentIds.length > 0) await tx.insert(dnsProviderRelayAgent).values(agentIds.map((agentId) => ({ organizationId, dnsProviderId: providerId, agentId })));
      return previous;
    },

    provider({ organizationId, providerId, agentIds }) {
      return {
        presentTxt: (record) => run(organizationId, providerId, agentIds, DNS_WORK_TYPES.present, record),
        cleanUpTxt: (record) => run(organizationId, providerId, agentIds, DNS_WORK_TYPES.cleanUp, record),
        testConnection: () => run(organizationId, providerId, agentIds, DNS_WORK_TYPES.test),
      };
    },
  };
}
