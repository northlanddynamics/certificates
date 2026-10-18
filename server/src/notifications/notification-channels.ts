// Notification channels: the email addresses and webhooks an Organization's notices can go to besides its users' own
// email. Organization Administrators add and remove them; anyone in the Organization may list them, to choose one as a
// Subscriber. A webhook's URL is a Secret (it often carries the receiver's credential), so only its host is ever shown.
import { isIP } from "node:net";
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, eq, sql } from "drizzle-orm";
import type { Authorizer } from "../tenancy/authorization";
import type { Db } from "../platform/db/client";
import { notificationChannel, secret } from "../platform/db/schema";
import { HttpError, OrgParam, errors, isUniqueViolation, json } from "../platform/http";
import { removeChannelFromSubscribers } from "../certificates/subscribers";
import type { Secrets } from "../platform/crypto/secrets";
import type { Actor, UnitOfWork } from "../platform/unit-of-work";

const Channel = z.object({
  id: z.string(),
  name: z.string(),
  kind: z.enum(["email", "webhook"]),
  email: z.string().nullable().openapi({ description: "Where an email channel sends; none for a webhook." }),
  webhookHost: z.string().nullable().openapi({ description: "The host a webhook posts to; its URL is a Secret and never shown." }),
  createdAt: z.string(),
});

/**
 * Whether `hostname` names the platform's own host or an internal address, which a webhook must not: the platform posts from
 * inside its network, so such a URL would have it reach what only it can. Only names written as such are known here; a DNS
 * name that resolves to one is not looked up.
 */
export function isInternalHost(hostname: string) {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (isIP(host) === 4) {
    const [a = 0, b = 0] = host.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  if (isIP(host) === 6) return host === "::" || host === "::1" || /^f[cd]/.test(host) || host.startsWith("fe80") || host.startsWith("::ffff:");
  return false;
}

const webhookUrl = z
  .url({ protocol: /^https$/ })
  .max(2048)
  .refine((url) => !URL.canParse(url) || !isInternalHost(new URL(url).hostname), "a webhook cannot post to the platform's own host or an internal address")
  .openapi({ description: "Where notices are posted as JSON, over HTTPS, to a host that is not internal. Write-only: it is never shown again, only its host." });

const NewChannel = z.discriminatedUnion("kind", [
  z.object({ name: z.string().trim().min(1).max(100), kind: z.literal("email"), email: z.email() }),
  z.object({ name: z.string().trim().min(1).max(100), kind: z.literal("webhook"), url: webhookUrl }),
]);

const ChannelParams = OrgParam.extend({ channelId: z.string().openapi({ param: { name: "channelId", in: "path" } }) });

type ChannelRow = typeof notificationChannel.$inferSelect;
const toChannel = (row: ChannelRow) => ({
  id: row.id,
  name: row.name,
  kind: row.kind,
  email: row.email,
  webhookHost: row.webhookHost,
  createdAt: row.createdAt.toISOString(),
});

export function registerNotificationChannels(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  secrets: Secrets;
}) {
  const { app, db, requireUser, authorize, unitOfWork, secrets } = ctx;

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/notification-channels",
      tags: ["Notifications"],
      summary: "The Organization's notification channels, by name",
      description: "Anyone in the Organization may list them, to choose one as a Subscriber. A webhook's URL is never shown.",
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(Channel) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { notificationChannel: ["read"] });
      const rows = await db
        .select()
        .from(notificationChannel)
        .where(eq(notificationChannel.organizationId, orgId))
        .orderBy(sql`lower(${notificationChannel.name})`);
      return c.json({ items: rows.map(toChannel) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/notification-channels",
      tags: ["Notifications"],
      summary: "Add an email or webhook notification channel",
      description: "Only Organization Administrators may. Names are unique in the Organization, whatever their case.",
      request: { params: OrgParam, body: { content: { "application/json": { schema: NewChannel } } } },
      responses: { 201: json(Channel, "Created"), ...errors(400, 401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { notificationChannel: ["create"] });
      try {
        const row = await unitOfWork.run(actor, async (tx, change) => {
          const target =
            body.kind === "email"
              ? { email: body.email, secretId: null, webhookHost: null }
              : { email: null, secretId: await secrets.create(tx, orgId, body.url), webhookHost: new URL(body.url).host };
          const [created] = await tx
            .insert(notificationChannel)
            .values({ organizationId: orgId, name: body.name, kind: body.kind, ...target, createdAt: change.occurredAt })
            .returning();
          await change.audit({
            organizationId: orgId,
            action: "notification_channel.created",
            target: { type: "notification_channel", id: created!.id },
            detail: { name: created!.name, kind: created!.kind, ...(created!.email ? { email: created!.email } : { webhookHost: created!.webhookHost }) },
          });
          return created!;
        });
        return c.json(toChannel(row), 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw new HttpError(409, `the Organization already has a channel named ${body.name}`);
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/api/organizations/{orgId}/notification-channels/{channelId}",
      tags: ["Notifications"],
      summary: "Remove a notification channel",
      description: "Only Organization Administrators may. It stops being a Subscriber of every Managed Certificate, and notices still waiting to be sent to it are dropped.",
      request: { params: ChannelParams },
      responses: { 200: json(z.object({ deleted: z.literal(true) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, channelId } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { notificationChannel: ["delete"] });
      if (!z.uuid().safeParse(channelId).success) throw new HttpError(404, "notification channel not found");
      await unitOfWork.run(actor, async (tx, change) => {
        const [row] = await tx
          .select()
          .from(notificationChannel)
          .where(and(eq(notificationChannel.organizationId, orgId), eq(notificationChannel.id, channelId)))
          .for("update");
        if (!row) throw new HttpError(404, "notification channel not found");
        await removeChannelFromSubscribers(tx, change, orgId, { id: row.id, name: row.name, kind: row.kind });
        await tx.delete(notificationChannel).where(eq(notificationChannel.id, row.id));
        // The webhook's URL goes with it: nothing else could ever use it.
        if (row.secretId) await tx.delete(secret).where(and(eq(secret.organizationId, orgId), eq(secret.id, row.secretId)));
        await change.audit({ organizationId: orgId, action: "notification_channel.deleted", target: { type: "notification_channel", id: row.id }, detail: { name: row.name, kind: row.kind } });
      });
      return c.json({ deleted: true as const }, 200);
    },
  );
}
