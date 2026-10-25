// Notifications: fans the events a Managed Certificate's Subscribers want to know of (upcoming expiry, Renewal succeeded,
// failed or blocked, Deployment Run failed, Agent offline, Approval decided) out to them by email and webhook. There are no
// default Subscribers (subscribers.ts), so a Managed Certificate nobody subscribed to tells nobody.
//
// A notice is queued on the transaction of the event it tells of, so an event that does not happen sends nothing, and is
// sent afterwards by the delivery pass: a job queue in Postgres, which tries a notice that could not be sent again with
// backoff and gives it up after a few tries. Two events are not changes but conditions the pass finds by looking: an
// Agent that has gone silent, and a Certificate nearing its end; each is noticed once.
import { and, asc, eq, inArray, isNull, lt, lte, sql } from "drizzle-orm";
import type { Db, Tx } from "../platform/db/client";
import { agent, deployment, managedCertificate, managedCertificateSubscriber, notice, notificationChannel, noticedCondition } from "../platform/db/schema";
import type { Mailer } from "../platform/mailer";
import type { NoticeEvent } from "./notification-kinds";
import { currentCertificates } from "../issuance/renewal";
import type { Secrets } from "../platform/crypto/secrets";
import { recipientsOf } from "../certificates/subscribers";
import type { Change, UnitOfWork } from "../platform/unit-of-work";

/** Posts a notice to a webhook channel's URL. */
export interface WebhookSender {
  post(url: string, body: Record<string, unknown>): Promise<void>;
}

/** Captures webhook posts instead of sending them. Used by tests; `failing` makes every post fail. */
export class CapturingWebhooks implements WebhookSender {
  readonly sent: { url: string; body: any }[] = [];
  failing = false;
  async post(url: string, body: Record<string, unknown>) {
    if (this.failing) throw new Error("the webhook answered 503");
    this.sent.push({ url, body });
  }
}

/** Posts JSON with `fetch`; anything but a 2xx answer within the timeout is a failure, tried again later. */
export function createFetchWebhooks(timeoutMs = 10_000): WebhookSender {
  return {
    async post(url, body) {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", "user-agent": "certificate-platform" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
        redirect: "manual",
      });
      if (res.status < 200 || res.status >= 300) throw new Error(`the webhook answered ${res.status}`);
    },
  };
}

/** The version of the JSON a webhook is sent; a change that is not only an addition makes a new one. */
export const NOTICE_SCHEMA = "certificate-platform.notice/1";

/** Days before a Certificate ends at which its Subscribers are told; each is noticed once per Certificate. */
export const EXPIRY_NOTICE_DAYS = [14, 7, 1] as const;

/** A notice that could not be sent is tried again after these waits, then given up. */
const RETRY_DELAYS_MS = [60_000, 5 * 60_000, 30 * 60_000, 2 * 3_600_000, 6 * 3_600_000];
/** How long a notice being sent is left alone by other passes; a pass that stopped while sending it has it sent again after this. */
const LEASE_MS = 5 * 60_000;

const DAY_MS = 86_400_000;

/** What happened, to be told to a Managed Certificate's Subscribers. `detail` is the event's own, as webhooks are sent it. */
export type NoticeOf =
  | { event: "certificate.expiring"; detail: { certificateId: string; fingerprint: string; notAfter: string; daysLeft: number } }
  | { event: "renewal.succeeded"; detail: { issuanceId: string; certificateId: string; fingerprint: string; notAfter: string } }
  | { event: "renewal.failed"; detail: { issuanceId: string; code: string; message: string } }
  | { event: "renewal.blocked"; detail: { certificateProfile: { id: string; name: string }; dueAt: string } }
  | { event: "deployment_run.failed"; detail: { deploymentId: string; runId: string; agentId: string; hostName: string; exitCode: number | null } }
  | { event: "agent.offline"; detail: { agentId: string; hostName: string; lastContactAt: string } }
  | { event: "approval.decided"; detail: { of: "proposal" | "name_change"; decision: "approved" | "rejected"; reason: string | null; decidedBy: string; names: string[] } };

export interface Notifications {
  /** Queues `what` for every Subscriber of the Managed Certificate, on the transaction of the change it tells of. */
  notify(tx: Tx, change: Change, managedCertificate: { id: string; organizationId: string }, what: NoticeOf): Promise<void>;
  /** One pass at the clock's time: notices Agents gone silent and Certificates nearing their end, then sends what is due. Returns how many it sent. */
  tick(): Promise<number>;
}

export interface NotificationsDeps {
  db: Db;
  unitOfWork: UnitOfWork;
  secrets: Secrets;
  mailer: Mailer;
  webhooks: WebhookSender;
  clock: () => Date;
  /** Where users open the web UI, for links in notices. */
  webURL: string;
  /** How long an Agent may be silent before it counts as offline (the Agent Gateway's setting). */
  offlineAfterSeconds: number;
}

/** The subject and text of an email notice. */
function render(names: string[], what: NoticeOf, link: string): { subject: string; text: string } {
  const name = names[0] ?? "a Managed Certificate";
  const all = `Names: ${names.join(", ")}`;
  const lines = (...parts: (string | false)[]) => [...parts.filter(Boolean), all, link].join("\n");
  switch (what.event) {
    case "certificate.expiring": {
      const { daysLeft, notAfter, fingerprint } = what.detail;
      return { subject: `${name}: its Certificate ends in ${daysLeft} day${daysLeft === 1 ? "" : "s"}`, text: lines(`The current Certificate (${fingerprint}) ends at ${notAfter}.`) };
    }
    case "renewal.succeeded":
      return { subject: `${name}: renewed`, text: lines(`A new Certificate (${what.detail.fingerprint}) was issued; it ends at ${what.detail.notAfter}.`) };
    case "renewal.failed":
      return { subject: `${name}: Renewal failed`, text: lines(`The Renewal failed (${what.detail.code}): ${what.detail.message}`) };
    case "renewal.blocked": {
      const { certificateProfile, dueAt } = what.detail;
      return {
        subject: `${name}: Renewal blocked`,
        text: lines(
          `It was due for Renewal at ${dueAt}, but it was made from the Certificate Profile ${certificateProfile.name}, which is disabled, so nothing is issued under it. ` +
            "It will not be renewed until an Organization Administrator enables the profile again, or detaches it from the profile.",
        ),
      };
    }
    case "deployment_run.failed": {
      // Not the script's output, which may hold what only those who may see the Deployment should: a Subscriber may not.
      const { hostName, exitCode } = what.detail;
      return { subject: `${name}: Deployment failed on ${hostName}`, text: lines(`The Deployment Script ${exitCode === null ? "was not run" : `exited with ${exitCode}`} on ${hostName}.`) };
    }
    case "agent.offline":
      return { subject: `${name}: Agent ${what.detail.hostName} is offline`, text: lines(`The Agent on ${what.detail.hostName}, which deploys this Managed Certificate, has not been heard from since ${what.detail.lastContactAt}.`) };
    case "approval.decided": {
      const { of, decision, reason, decidedBy } = what.detail;
      const subjectOf = of === "proposal" ? "the proposal" : "the name change";
      return {
        subject: `${name}: ${subjectOf} was ${decision}`,
        text: lines(`${decidedBy} ${decision} ${subjectOf} for ${what.detail.names.join(", ")}.`, reason !== null && `Reason: ${reason}`),
      };
    }
  }
}

export function createNotifications({ db, unitOfWork, secrets, mailer, webhooks, clock, webURL, offlineAfterSeconds }: NotificationsDeps): Notifications {
  const current = currentCertificates(db);
  const hasSubscribers = sql`exists (select 1 from ${managedCertificateSubscriber} where ${managedCertificateSubscriber.managedCertificateId} = ${managedCertificate.id})`;

  async function notify(tx: Tx, change: Change, { id, organizationId }: { id: string; organizationId: string }, what: NoticeOf) {
    const recipients = (await recipientsOf(tx, organizationId, [id])).get(id)!;
    if (recipients.emails.size === 0 && recipients.webhooks.size === 0) return;
    const [mc] = await tx.select({ names: managedCertificate.names }).from(managedCertificate).where(and(eq(managedCertificate.id, id), eq(managedCertificate.organizationId, organizationId)));
    if (!mc) return;
    const link = `${webURL}/organizations/${organizationId}/certificates/${id}`;
    const { subject, text } = render(mc.names, what, link);
    const payload = {
      schema: NOTICE_SCHEMA,
      event: what.event,
      occurredAt: change.occurredAt.toISOString(),
      organization: { id: organizationId },
      managedCertificate: { id, names: mc.names, url: link },
      detail: what.detail,
      subject,
    };
    const queued = { organizationId, event: what.event as NoticeEvent, subject, text, payload, nextAttemptAt: change.occurredAt, createdAt: change.occurredAt };
    await tx.insert(notice).values([
      ...[...recipients.emails].sort(([a], [b]) => a.localeCompare(b)).map(([email, channelId]) => ({ ...queued, email, channelId })),
      ...[...recipients.webhooks].sort().map((channelId) => ({ ...queued, channelId })),
    ]);
  }

  /** Which of the conditions were noticed already, so that a pass opens no change for them. */
  async function noticedAlready(conditions: { organizationId: string; key: string }[]) {
    if (conditions.length === 0) return new Set<string>();
    const rows = await db
      .select({ organizationId: noticedCondition.organizationId, key: noticedCondition.key })
      .from(noticedCondition)
      .where(inArray(noticedCondition.key, conditions.map((c) => c.key)));
    return new Set(rows.map((r) => `${r.organizationId} ${r.key}`));
  }

  /** Marks the condition noticed, on the change's transaction; false when it already was. */
  async function firstTime(tx: Tx, change: Change, organizationId: string, key: string) {
    const marked = await tx.insert(noticedCondition).values({ organizationId, key, noticedAt: change.occurredAt }).onConflictDoNothing().returning({ key: noticedCondition.key });
    return marked.length > 0;
  }

  /** Agents silent for longer than they may be, once per silence, told to the Subscribers of what they deploy. */
  async function noticeSilentAgents(now: Date) {
    const silentSince = new Date(now.getTime() - offlineAfterSeconds * 1000);
    const silent = await db
      .selectDistinct({ id: agent.id, organizationId: agent.organizationId, hostName: agent.hostName, lastContactAt: agent.lastContactAt })
      .from(agent)
      .innerJoin(deployment, and(eq(deployment.agentId, agent.id), eq(deployment.organizationId, agent.organizationId)))
      .innerJoin(managedCertificate, eq(managedCertificate.id, deployment.managedCertificateId))
      .where(and(isNull(agent.revokedAt), lt(agent.lastContactAt, silentSince), isNull(managedCertificate.archivedAt), hasSubscribers));
    // Keyed by its last contact: an Agent that comes back and goes silent again is noticed again.
    const keyed = silent.map((a) => ({ ...a, key: `agent.offline:${a.id}:${a.lastContactAt.toISOString()}` }));
    const already = await noticedAlready(keyed);
    for (const a of keyed.filter((a) => !already.has(`${a.organizationId} ${a.key}`))) {
      await unitOfWork.run(null, async (tx, change) => {
        if (!(await firstTime(tx, change, a.organizationId, a.key))) return;
        const deployed = await tx
          .select({ id: managedCertificate.id })
          .from(deployment)
          .innerJoin(managedCertificate, eq(managedCertificate.id, deployment.managedCertificateId))
          .where(and(eq(deployment.organizationId, a.organizationId), eq(deployment.agentId, a.id), isNull(managedCertificate.archivedAt)))
          .orderBy(asc(managedCertificate.id));
        for (const mc of deployed) {
          await notify(tx, change, { id: mc.id, organizationId: a.organizationId }, { event: "agent.offline", detail: { agentId: a.id, hostName: a.hostName, lastContactAt: a.lastContactAt.toISOString() } });
        }
      });
    }
  }

  /** Current Certificates of live Managed Certificates that someone subscribed to, as each passes the days before its end. */
  async function noticeExpiring(now: Date) {
    const longest = Math.max(...EXPIRY_NOTICE_DAYS);
    const nearing = await db
      .select({ managedCertificateId: managedCertificate.id, organizationId: managedCertificate.organizationId, certificateId: current.id, fingerprint: current.fingerprint, notAfter: current.notAfter })
      .from(managedCertificate)
      .innerJoin(current, eq(current.managedCertificateId, managedCertificate.id))
      .where(and(isNull(managedCertificate.archivedAt), sql`${current.notAfter} > ${now}`, lte(current.notAfter, new Date(now.getTime() + longest * DAY_MS)), hasSubscribers));
    // The nearest of the days it has passed: a Certificate first looked at with five days left is told of once, for the seventh day, not for the fourteenth too.
    const keyed = nearing.map((c) => ({ ...c, key: `certificate.expiring:${c.certificateId}:${Math.min(...EXPIRY_NOTICE_DAYS.filter((d) => c.notAfter.getTime() - now.getTime() <= d * DAY_MS))}` }));
    const already = await noticedAlready(keyed);
    for (const c of keyed.filter((c) => !already.has(`${c.organizationId} ${c.key}`))) {
      await unitOfWork.run(null, async (tx, change) => {
        if (!(await firstTime(tx, change, c.organizationId, c.key))) return;
        await notify(tx, change, { id: c.managedCertificateId, organizationId: c.organizationId }, {
          event: "certificate.expiring",
          detail: { certificateId: c.certificateId, fingerprint: c.fingerprint, notAfter: c.notAfter.toISOString(), daysLeft: Math.ceil((c.notAfter.getTime() - now.getTime()) / DAY_MS) },
        });
      });
    }
  }

  /**
   * Takes the next notice that is due, if there is one, and leases it: its attempt is counted and it is not due again until
   * the lease ends, so another pass leaves it alone and one that stops while sending has it tried again then. Nothing is
   * sent while a transaction is open.
   */
  async function claimNext(now: Date) {
    return unitOfWork.run(null, async (tx) => {
      const [row] = await tx
        .select()
        .from(notice)
        .where(and(eq(notice.status, "queued"), lte(notice.nextAttemptAt, now)))
        .orderBy(asc(notice.nextAttemptAt), asc(notice.createdAt), asc(notice.id))
        .limit(1)
        .for("update", { skipLocked: true });
      if (!row) return null;
      const attempts = row.attempts + 1;
      await tx.update(notice).set({ attempts, nextAttemptAt: new Date(now.getTime() + LEASE_MS) }).where(eq(notice.id, row.id));
      return { ...row, attempts };
    });
  }

  /** Sends a claimed notice and records how that went; returns whether it was sent. A notice that could not be sent waits to be tried again, or is given up. */
  async function send(row: typeof notice.$inferSelect, now: Date) {
    let error: string | null = null;
    try {
      if (row.email) await mailer.send({ to: row.email, subject: row.subject, text: row.text });
      else {
        const [channel] = await db.select({ secretId: notificationChannel.secretId }).from(notificationChannel).where(eq(notificationChannel.id, row.channelId!));
        if (!channel?.secretId) throw new Error("the channel is gone");
        await webhooks.post(await secrets.open(db, row.organizationId, channel.secretId), row.payload);
      }
    } catch (err) {
      error = (err instanceof Error ? err.message : String(err)).replace(/\u0000/g, "").slice(0, 1000);
    }
    const wait = RETRY_DELAYS_MS[row.attempts - 1];
    await unitOfWork.run(null, (tx) =>
      tx
        .update(notice)
        .set(
          error === null
            ? { status: "sent", sentAt: now, lastError: null }
            : { lastError: error, ...(wait === undefined ? { status: "failed" as const } : { nextAttemptAt: new Date(now.getTime() + wait) }) },
        )
        .where(eq(notice.id, row.id)),
    );
    return error === null;
  }

  return {
    notify,
    async tick() {
      const now = clock();
      await noticeSilentAgents(now).catch((err) => console.error("could not notice silent Agents", err));
      await noticeExpiring(now).catch((err) => console.error("could not notice Certificates nearing their end", err));
      // Read again, so that the notices the passes above just queued are due.
      const sendAt = clock();
      let sent = 0;
      for (let row = await claimNext(sendAt); row; row = await claimNext(sendAt)) {
        if (await send(row, sendAt)) sent++;
      }
      return sent;
    },
  };
}

