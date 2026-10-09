// The platform's one way to change state: a database transaction in which the change and the Audit Events that
// record it commit or roll back together, and mail goes out only once the commit has happened. Better Auth's
// endpoints run inside it (organization-changes.ts) and so do the platform's own writes (organizations.ts).
import { recordAudit, type AuditAction } from "./audit";
import type { Db, Tx } from "./db/client";
import type { Mail, Mailer } from "./mailer";

export type Actor = { id: string; email: string };

/** What a change has at hand besides the transaction. */
export interface Change {
  /** When this change happened, as the clock read at its start. */
  readonly occurredAt: Date;
  /** Records an Audit Event, attributed to the actor, on the change's own transaction. */
  audit(event: {
    organizationId: string;
    action: AuditAction;
    target: { type: string; id?: string };
    detail?: Record<string, unknown>;
  }): Promise<void>;
  /** Queues `mail` to be sent after the commit. A rolled-back change sends nothing. */
  mail(mail: Mail): void;
}

export interface UnitOfWork {
  /**
   * Runs `work` on a transaction and returns what it returns. Anything it throws rolls back its writes and its
   * Audit Events, and is rethrown. Queued mail is sent after the commit; a mail failure is logged and never hides
   * the commit from the caller. The actor is none only for a change made by an Organization's API key. The unit of
   * work takes no locks: a change that must serialise with others takes its own, as the first thing it does on the
   * transaction.
   */
  run<T>(actor: Actor | null, work: (tx: Tx, change: Change) => Promise<T>): Promise<T>;
}

export interface UnitOfWorkDeps {
  db: Db;
  mailer: Mailer;
  clock: () => Date;
}

export function createUnitOfWork({ db, mailer, clock }: UnitOfWorkDeps): UnitOfWork {
  return {
    async run(actor, work) {
      const outbox: Mail[] = [];
      const occurredAt = clock();
      const result = await db.transaction((tx) =>
        work(tx, {
          occurredAt,
          audit: (event) => recordAudit(tx, { ...event, occurredAt, actor }),
          mail: (mail) => void outbox.push(mail),
        }),
      );
      for (const mail of outbox) await mailer.send(mail).catch((err) => console.error("mail failed", err));
      return result;
    },
  };
}
