// A Managed Certificate's Subscribers: users, Teams or notification channels of its Organization who have opted in to
// its notices. Nobody is one by default, and being one grants no visibility: a Subscriber who is not an Owner is told of
// the Managed Certificate but cannot see it. A user who leaves the Organization, a Team that is deleted and a channel that
// is removed stop being one.
import { z } from "@hono/zod-openapi";
import { and, eq, inArray } from "drizzle-orm";
import type { Tx, Db } from "../platform/db/client";
import { managedCertificateSubscriber, member, notificationChannel, team, teamMember, user } from "../platform/db/schema";
import { HttpError } from "../platform/http";
import type { MemberRemovalHook, TeamRemovalHook } from "../tenancy/member-removal";
import type { NotificationChannelKind } from "../notifications/notification-kinds";
import type { Change } from "../platform/unit-of-work";

export const SUBSCRIBER_TYPES = ["user", "team", "channel"] as const;

/** Who may be made a Subscriber. */
export const SubscriberRef = z.object({ type: z.enum(SUBSCRIBER_TYPES), id: z.string().min(1) });
export type SubscriberRef = z.infer<typeof SubscriberRef>;

/** A Subscriber as the API shows it: a user by their email, a Team by its name, a channel by its name and kind. */
export const Subscriber = z.discriminatedUnion("type", [
  z.object({ type: z.literal("user"), id: z.string(), email: z.string() }),
  z.object({ type: z.literal("team"), id: z.string(), name: z.string() }),
  z.object({ type: z.literal("channel"), id: z.string(), name: z.string(), kind: z.enum(["email", "webhook"]) }),
]);
type SubscriberView = z.infer<typeof Subscriber>;

const subscriber = managedCertificateSubscriber;
const isRef = (ref: SubscriberRef) =>
  ref.type === "user" ? eq(subscriber.userId, ref.id) : ref.type === "team" ? eq(subscriber.teamId, ref.id) : eq(subscriber.channelId, ref.id);

/** The Subscribers of the Managed Certificate, in the order they were added. */
export async function subscribersOf(db: Db | Tx, organizationId: string, managedCertificateId: string): Promise<SubscriberView[]> {
  const rows = await db
    .select({ userId: user.id, email: user.email, teamId: team.id, teamName: team.name, channelId: notificationChannel.id, channelName: notificationChannel.name, channelKind: notificationChannel.kind })
    .from(subscriber)
    .leftJoin(user, eq(user.id, subscriber.userId))
    .leftJoin(team, eq(team.id, subscriber.teamId))
    .leftJoin(notificationChannel, eq(notificationChannel.id, subscriber.channelId))
    .where(and(eq(subscriber.organizationId, organizationId), eq(subscriber.managedCertificateId, managedCertificateId)))
    .orderBy(subscriber.id);
  return rows.map((row) =>
    row.userId
      ? { type: "user" as const, id: row.userId, email: row.email! }
      : row.teamId
        ? { type: "team" as const, id: row.teamId, name: row.teamName! }
        : { type: "channel" as const, id: row.channelId!, name: row.channelName!, kind: row.channelKind! },
  );
}

/**
 * Who `ref` is, once known to be one the Organization has. The row is locked in share mode, so that removing the user,
 * deleting the Team or removing the channel (each of which takes its subscriptions off) waits for this change or finds
 * it done, and a Subscriber cannot outlive what it names.
 */
async function lockSubscriberTarget(tx: Tx, organizationId: string, ref: SubscriberRef): Promise<SubscriberView> {
  const notOurs = (what: string) => new HttpError(422, `${ref.id} is not ${what} of this Organization, so cannot be a Subscriber`);
  if (ref.type === "user") {
    const [row] = await tx
      .select({ id: user.id, email: user.email })
      .from(member)
      .innerJoin(user, eq(user.id, member.userId))
      .where(and(eq(member.organizationId, organizationId), eq(member.userId, ref.id)))
      .for("share", { of: member });
    if (!row) throw notOurs("a member");
    return { type: "user", ...row };
  }
  if (ref.type === "team") {
    const [row] = await tx.select({ id: team.id, name: team.name }).from(team).where(and(eq(team.organizationId, organizationId), eq(team.id, ref.id))).for("share");
    if (!row) throw notOurs("a Team");
    return { type: "team", ...row };
  }
  const [row] = z.uuid().safeParse(ref.id).success
    ? await tx
        .select({ id: notificationChannel.id, name: notificationChannel.name, kind: notificationChannel.kind })
        .from(notificationChannel)
        .where(and(eq(notificationChannel.organizationId, organizationId), eq(notificationChannel.id, ref.id)))
        .for("share")
    : [];
  if (!row) throw notOurs("a notification channel");
  return { type: "channel", ...row };
}

/** Makes `ref` a Subscriber, audited; naming one that already is changes nothing. Refuses (422) one the Organization does not have. */
export async function addSubscriber(tx: Tx, change: Change, organizationId: string, managedCertificateId: string, ref: SubscriberRef) {
  const view = await lockSubscriberTarget(tx, organizationId, ref);
  const added = await tx
    .insert(subscriber)
    .values({
      organizationId,
      managedCertificateId,
      userId: ref.type === "user" ? ref.id : null,
      teamId: ref.type === "team" ? ref.id : null,
      channelId: ref.type === "channel" ? ref.id : null,
    })
    .onConflictDoNothing()
    .returning({ id: subscriber.id });
  if (added.length === 0) return;
  await change.audit({
    organizationId,
    action: "managed_certificate.subscriber_added",
    target: { type: "managed_certificate", id: managedCertificateId },
    detail: { subscriber: view },
  });
}

/** Takes `ref` off the Subscribers, audited. Refuses (404) one that is not a Subscriber. */
export async function removeSubscriber(tx: Tx, change: Change, organizationId: string, managedCertificateId: string, ref: SubscriberRef) {
  const view = (await subscribersOf(tx, organizationId, managedCertificateId)).find((s) => s.type === ref.type && s.id === ref.id);
  if (!view) throw new HttpError(404, "that is not a Subscriber of this Managed Certificate");
  await tx.delete(subscriber).where(and(eq(subscriber.organizationId, organizationId), eq(subscriber.managedCertificateId, managedCertificateId), isRef(ref)));
  await change.audit({
    organizationId,
    action: "managed_certificate.subscriber_removed",
    target: { type: "managed_certificate", id: managedCertificateId },
    detail: { subscriber: view },
  });
}

/** Takes whatever `who` names off every Managed Certificate's Subscribers, each audited with why. */
async function removeFromAll(tx: Tx, change: Change, organizationId: string, who: SubscriberView, because: string) {
  const removed = await tx
    .delete(subscriber)
    .where(and(eq(subscriber.organizationId, organizationId), isRef(who)))
    .returning({ managedCertificateId: subscriber.managedCertificateId });
  for (const { managedCertificateId } of removed.sort((a, b) => a.managedCertificateId.localeCompare(b.managedCertificateId))) {
    await change.audit({
      organizationId,
      action: "managed_certificate.subscriber_removed",
      target: { type: "managed_certificate", id: managedCertificateId },
      detail: { subscriber: who, because },
    });
  }
}

/** Runs when a user is removed from an Organization: they stop being a Subscriber of anything in it. */
export const removeUserFromSubscribers: MemberRemovalHook = async (tx, { organizationId, userId }, change) => {
  const [row] = await tx.select({ id: user.id, email: user.email }).from(user).where(eq(user.id, userId));
  if (row) await removeFromAll(tx, change, organizationId, { type: "user", ...row }, "member_removed");
};

/** Runs before a Team is deleted: it stops being a Subscriber of anything. The Team is locked first, as for its Owners (owners.ts). */
export const removeTeamFromSubscribers: TeamRemovalHook = async (tx, { organizationId, teamId, teamName }, change) => {
  await tx.select({ id: team.id }).from(team).where(eq(team.id, teamId)).for("update");
  await removeFromAll(tx, change, organizationId, { type: "team", id: teamId, name: teamName }, "team_deleted");
};

/** Runs before a notification channel is removed (its row locked by the caller): it stops being a Subscriber of anything. */
export const removeChannelFromSubscribers = (tx: Tx, change: Change, organizationId: string, channel: { id: string; name: string; kind: NotificationChannelKind }) =>
  removeFromAll(tx, change, organizationId, { type: "channel", ...channel }, "channel_deleted");

/**
 * Where a notice about each of the Managed Certificates goes: each email address once (users, Teams' members and email
 * channels), with the channel it is for when it is only a channel's, and the webhook channels.
 */
export async function recipientsOf(db: Db | Tx, organizationId: string, managedCertificateIds: string[]) {
  const out = new Map<string, { emails: Map<string, string | null>; webhooks: Set<string> }>(managedCertificateIds.map((id) => [id, { emails: new Map(), webhooks: new Set() }]));
  if (managedCertificateIds.length === 0) return out;
  const ofThese = and(eq(subscriber.organizationId, organizationId), inArray(subscriber.managedCertificateId, managedCertificateIds));
  const direct = await db
    .select({ managedCertificateId: subscriber.managedCertificateId, email: user.email, channelKind: notificationChannel.kind, channelEmail: notificationChannel.email, channelId: notificationChannel.id })
    .from(subscriber)
    .leftJoin(user, eq(user.id, subscriber.userId))
    .leftJoin(notificationChannel, eq(notificationChannel.id, subscriber.channelId))
    .where(ofThese);
  for (const row of direct) {
    const to = out.get(row.managedCertificateId)!;
    if (row.email) to.emails.set(row.email.toLowerCase(), null);
    if (row.channelKind === "email" && row.channelEmail && !to.emails.has(row.channelEmail.toLowerCase())) to.emails.set(row.channelEmail.toLowerCase(), row.channelId);
    if (row.channelKind === "webhook" && row.channelId) to.webhooks.add(row.channelId);
  }
  // A Team's members as they are now, so whoever joins it later is told and whoever leaves is not.
  const throughTeams = await db
    .select({ managedCertificateId: subscriber.managedCertificateId, email: user.email })
    .from(subscriber)
    .innerJoin(teamMember, eq(teamMember.teamId, subscriber.teamId))
    .innerJoin(user, eq(user.id, teamMember.userId))
    .where(ofThese);
  // A person's own address is theirs, not a channel's, even when a channel sends to it too.
  for (const row of throughTeams) out.get(row.managedCertificateId)!.emails.set(row.email.toLowerCase(), null);
  return out;
}
