// Work items: what the platform asks an Agent to do. The platform puts one in for one Agent; the Agent finds it by
// polling (agent-gateway.ts), carries it out and reports a result, and whoever asked is told. Each type of work item says,
// in `register`, how its payload becomes what the Agent is given: the payload kept here names what to do and never holds a
// secret, so what the Agent needs to do it (such as a DNS Provider's credentials) exists only in the delivery to that Agent.
import { and, asc, eq, inArray, lt, notInArray, or } from "drizzle-orm";
import type { Db, Tx } from "./db/client";
import { agent, workItem } from "./db/schema";
import { HttpError } from "./http";
import type { Change, UnitOfWork } from "./unit-of-work";

export const WORK_ITEM_STATUSES = ["pending", "delivered", "succeeded", "failed", "expired"] as const;
/**
 * `pending` until the Agent is given it, `delivered` until it reports, then `succeeded` or `failed` as it reports, or
 * `expired` when whoever asked stopped waiting: what the Agent reports then is refused.
 */
export type WorkItemStatus = (typeof WORK_ITEM_STATUSES)[number];

type Row = typeof workItem.$inferSelect;

/** How one execution of a Deployment Script went, as the Agent reports it. `exitCode` is none when the script was not started. */
export interface RunReport {
  startedAt: string;
  finishedAt: string;
  exitCode: number | null;
  output: string;
  outputTruncated: boolean;
}

/**
 * What an Agent reports of a work item. `kind` is how a DNS Provider operation failed, when it did; `csr` is the CSR for
 * the key it made, for `deployment.generate_key`; `run` is how the script went, for `deployment.run`.
 */
export interface WorkResult {
  ok: boolean;
  kind?: "rejected" | "unreachable";
  error?: string;
  csr?: string;
  run?: RunReport;
}

/** A work item as an Agent is given it. */
export interface DeliveredWorkItem {
  id: string;
  type: string;
  payload: Record<string, unknown>;
}

/** Thrown by a materializer when what an item asks for cannot be prepared: the message is what the item fails with, so it must hold nothing secret. */
export class PreparationError extends Error {}

export type Materializer = (tx: Tx, item: { organizationId: string; payload: Record<string, unknown> }) => Promise<Record<string, unknown>>;

/** What the platform does with the Agent's report of an item, on the transaction that records it: so that the report and what follows from it commit together. */
export type ResultHandler = (tx: Tx, change: Change, item: { organizationId: string; agentId: string; payload: Record<string, unknown> }, result: WorkResult) => Promise<void>;

export interface WorkItemTypeOptions {
  /** What follows from an Agent's report of an item of this type. */
  onResult?: ResultHandler;
  /**
   * For work that must still be done whenever its Agent next comes, however long that takes (an Agent may be away for days):
   * an item of this type does not expire for waiting, and one the Agent was given and never reported on (it stopped
   * in between) is given to it again.
   */
  durable?: boolean;
}

export interface WorkItems {
  /** Says how items of `type` are given to an Agent: from what is kept to what the Agent is sent. */
  register(type: string, materialize: Materializer, options?: WorkItemTypeOptions): void;
  /** Asks the Agent (which must be of the Organization) to do something; returns the item's id. */
  enqueue(organizationId: string, agentId: string, type: string, payload: Record<string, unknown>): Promise<string>;
  /** The same on the transaction of a change that asks, so the item exists only if that change commits. */
  enqueueIn(tx: Tx, change: Change, organizationId: string, agentId: string, type: string, payload: Record<string, unknown>): Promise<string>;
  /**
   * Waits up to `timeoutMs` for the Agent to report on the item. When it has not by then the item expires, and what the
   * Agent reports later is refused; unless it reported in the instant between, which is the result.
   */
  outcome(id: string, timeoutMs: number): Promise<WorkResult | "expired">;
  /** The Agent's pending items, now delivered to it. One whose payload cannot be made for the Agent fails, saying so. */
  deliver(agent: { id: string; organizationId: string }): Promise<DeliveredWorkItem[]>;
  /** Records an Agent's report. A 404 when the item is not the Agent's; a 409 when it is not waiting for one. */
  report(agent: { id: string; organizationId: string }, itemId: string, result: WorkResult): Promise<void>;
}

export interface WorkItemsDeps {
  db: Db;
  unitOfWork: UnitOfWork;
  /** How often `outcome` looks for the Agent's report. */
  pollMs: number;
  /** How long an item may wait to be given to its Agent: older ones are stale (whoever asked is long gone, perhaps with a platform restart) and expire instead. Not for durable types. */
  maxWaitMs: number;
  /** How long a durable item may be with an Agent that has not reported on it before it is given again. Defaults to 15 minutes. */
  redeliverAfterMs?: number;
  clock: () => Date;
}

const BATCH = 20;

export function createWorkItems({ db, unitOfWork, pollMs, maxWaitMs, redeliverAfterMs = 15 * 60_000, clock }: WorkItemsDeps): WorkItems {
  const materializers = new Map<string, Materializer>();
  const handlers = new Map<string, ResultHandler>();
  const durableTypes: string[] = [];
  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

  async function read(id: string) {
    const [row] = await db.select().from(workItem).where(eq(workItem.id, id));
    return row;
  }
  const resultOf = (row: Row): WorkResult | "expired" | null =>
    row.status === "succeeded" || row.status === "failed" ? (row.result ?? { ok: row.status === "succeeded" }) : row.status === "expired" ? "expired" : null;

  return {
    register(type, materialize, options = {}) {
      materializers.set(type, materialize);
      if (options.onResult) handlers.set(type, options.onResult);
      if (options.durable) durableTypes.push(type);
    },

    async enqueue(organizationId, agentId, type, payload) {
      return unitOfWork.run(null, (tx, change) => this.enqueueIn(tx, change, organizationId, agentId, type, payload));
    },

    async enqueueIn(tx, change, organizationId, agentId, type, payload) {
      const [row] = await tx.insert(workItem).values({ organizationId, agentId, type, payload, createdAt: change.occurredAt }).returning({ id: workItem.id });
      return row!.id;
    },

    async outcome(id, timeoutMs) {
      const deadline = Date.now() + timeoutMs;
      for (;;) {
        const row = await read(id);
        const finished = row && resultOf(row);
        if (finished) return finished;
        if (Date.now() >= deadline) break;
        await sleep(Math.min(pollMs, Math.max(deadline - Date.now(), 1)));
      }
      const expired = await unitOfWork.run(null, (tx, change) =>
        tx
          .update(workItem)
          .set({ status: "expired", finishedAt: change.occurredAt })
          .where(and(eq(workItem.id, id), inArray(workItem.status, ["pending", "delivered"])))
          .returning({ id: workItem.id }),
      );
      if (expired.length > 0) return "expired";
      return resultOf((await read(id))!) ?? "expired";
    },

    async deliver(agentRow) {
      // Most polls find nothing, and are not worth a transaction.
      const lost = durableTypes.length > 0 ? [and(eq(workItem.status, "delivered"), inArray(workItem.type, durableTypes), lt(workItem.deliveredAt, new Date(clock().getTime() - redeliverAfterMs)))] : [];
      const waiting = await db
        .select({ id: workItem.id })
        .from(workItem)
        .where(and(eq(workItem.agentId, agentRow.id), or(eq(workItem.status, "pending"), ...lost)))
        .limit(1);
      if (waiting.length === 0) return [];
      return unitOfWork.run(null, async (tx, change) => {
        // An Agent revoked while it waited for work is given none: it holds no credentials of the Organization's from then on.
        const [current] = await tx.select({ revokedAt: agent.revokedAt }).from(agent).where(and(eq(agent.id, agentRow.id), eq(agent.organizationId, agentRow.organizationId))).for("share");
        if (!current || current.revokedAt) return [];
        // Items that waited too long are not given: what they ask for is no longer wanted. Durable ones are always wanted.
        await tx
          .update(workItem)
          .set({ status: "expired", finishedAt: change.occurredAt })
          .where(
            and(
              eq(workItem.agentId, agentRow.id),
              eq(workItem.status, "pending"),
              lt(workItem.createdAt, new Date(change.occurredAt.getTime() - maxWaitMs)),
              ...(durableTypes.length > 0 ? [notInArray(workItem.type, durableTypes)] : []),
            ),
          );
        // A durable item the Agent was given and never reported on, because it stopped in between, is given again.
        if (durableTypes.length > 0) {
          await tx
            .update(workItem)
            .set({ status: "pending", deliveredAt: null })
            .where(
              and(
                eq(workItem.agentId, agentRow.id),
                eq(workItem.status, "delivered"),
                inArray(workItem.type, durableTypes),
                lt(workItem.deliveredAt, new Date(change.occurredAt.getTime() - redeliverAfterMs)),
              ),
            );
        }
        const rows = await tx
          .select()
          .from(workItem)
          .where(and(eq(workItem.agentId, agentRow.id), eq(workItem.status, "pending")))
          .orderBy(asc(workItem.createdAt), asc(workItem.id))
          .limit(BATCH)
          .for("update", { skipLocked: true });
        const delivered: DeliveredWorkItem[] = [];
        for (const row of rows) {
          try {
            const materialize = materializers.get(row.type);
            if (!materialize) throw new Error(`no such type of work item: ${row.type}`);
            // A savepoint: a payload that cannot be made fails this item, not the delivery of the others.
            const payload = await tx.transaction((inner) => materialize(inner, { organizationId: row.organizationId, payload: row.payload }));
            await tx.update(workItem).set({ status: "delivered", deliveredAt: change.occurredAt }).where(eq(workItem.id, row.id));
            delivered.push({ id: row.id, type: row.type, payload });
          } catch (err) {
            console.error(`work item ${row.id} could not be made for its Agent`, err);
            const why = err instanceof PreparationError ? err.message : "the platform could not prepare the work for the Agent";
            await tx
              .update(workItem)
              .set({ status: "failed", finishedAt: change.occurredAt, result: { ok: false, kind: "rejected", error: why } })
              .where(eq(workItem.id, row.id));
          }
        }
        return delivered;
      });
    },

    async report(agent, itemId, result) {
      await unitOfWork.run(null, async (tx, change) => {
        const found = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(itemId)
          ? await tx.select().from(workItem).where(and(eq(workItem.id, itemId), eq(workItem.agentId, agent.id))).for("update")
          : [];
        const row = found[0];
        if (!row) throw new HttpError(404, "work item not found");
        if (row.status !== "delivered") throw new HttpError(409, `the work item is not waiting for a result: it is ${row.status}`);
        await tx
          .update(workItem)
          .set({ status: result.ok ? "succeeded" : "failed", finishedAt: change.occurredAt, result })
          .where(eq(workItem.id, row.id));
        await handlers.get(row.type)?.(tx, change, { organizationId: row.organizationId, agentId: row.agentId, payload: row.payload }, result);
      });
    },
  };
}
