// Work that any one of several assigned Agents may carry out, such as a relayed DNS Provider's operations or an ADCS CA's:
// it goes to an online one, most recently heard from first, and an Agent that takes the item and does not answer in time is
// given up on for the next. One that is offline is passed over. What the Agent reports is the caller's to judge, but for
// a result the caller says another Agent may do better with (`passOn`), which tries the next.
import { and, asc, desc, eq, inArray } from "drizzle-orm";
import type { Db } from "../platform/db/client";
import { agent } from "../platform/db/schema";
import type { WorkItems, WorkResult } from "./work-items";

export interface AgentRelayDeps {
  db: Db;
  workItems: WorkItems;
  clock: () => Date;
  offlineAfterSeconds: number;
  /** How long one Agent has to report before another online one is tried. */
  attemptTimeoutMs: number;
}

/** No assigned Agent carried the work out: none was online, or each that was given it did not answer or passed it on. The message says which. */
export class NoAgentAnswered extends Error {}

function ago(ms: number): string {
  const minutes = Math.round(ms / 60_000);
  if (minutes < 1) return `${Math.max(Math.round(ms / 1000), 0)} seconds`;
  if (minutes < 120) return `${minutes} minutes`;
  return minutes < 48 * 60 ? `${Math.round(minutes / 60)} hours` : `${Math.round(minutes / 1440)} days`;
}

/**
 * Has one of `agentIds` carry out a work item of `type`, and returns which one did and what it reported. `role` is what
 * the Agents are to the work, in words, such as "relays this DNS Provider"; it names them in the `NoAgentAnswered` thrown
 * when none carries it out.
 */
export async function relayToAgents(
  { db, workItems, clock, offlineAfterSeconds, attemptTimeoutMs }: AgentRelayDeps,
  work: { organizationId: string; agentIds: string[]; type: string; payload: Record<string, unknown>; role: string; passOn?: (result: WorkResult) => boolean },
): Promise<{ agent: { id: string; hostName: string }; result: WorkResult }> {
  const tried = new Map<string, string>();
  let answered = false;
  for (;;) {
    const agents = await db
      .select()
      .from(agent)
      .where(and(eq(agent.organizationId, work.organizationId), inArray(agent.id, work.agentIds)))
      .orderBy(desc(agent.lastContactAt), asc(agent.id));
    const now = clock();
    const online = (a: (typeof agents)[number]) => !a.revokedAt && now.getTime() - a.lastContactAt.getTime() <= offlineAfterSeconds * 1000;
    const next = agents.find((a) => online(a) && !tried.has(a.id));
    if (!next) {
      if (tried.size > 0) throw new NoAgentAnswered(`no Agent that ${work.role} ${answered ? "could carry it out" : "answered in time"} (${[...tried.values()].join("; ")})`);
      const states = agents.map((a) => `${a.hostName} (${a.revokedAt ? "revoked" : `last contact ${ago(now.getTime() - a.lastContactAt.getTime())} ago`})`);
      throw new NoAgentAnswered(`no Agent that ${work.role} is online${states.length > 0 ? `: ${states.join(", ")}` : ""}`);
    }
    const id = await workItems.enqueue(work.organizationId, next.id, work.type, work.payload);
    const outcome = await workItems.outcome(id, attemptTimeoutMs);
    if (outcome === "expired") {
      tried.set(next.id, `${next.hostName} did not answer within ${attemptTimeoutMs / 1000} seconds`);
      continue;
    }
    if (work.passOn?.(outcome)) {
      answered = true;
      tried.set(next.id, `${next.hostName} reported: ${outcome.error ?? "it could not carry it out"}`);
      continue;
    }
    return { agent: { id: next.id, hostName: next.hostName }, result: outcome };
  }
}
