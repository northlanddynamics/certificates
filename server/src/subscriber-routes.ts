// The routes that list and change a Managed Certificate's Subscribers (the Subscribers themselves are subscribers.ts).
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import type { Db } from "./db/client";
import { errors, json } from "./http";
import { ManagedCertificateParams, type ManagedCertificateReader } from "./managed-certificate-reader";
import { SUBSCRIBER_TYPES, Subscriber, SubscriberRef, addSubscriber, removeSubscriber, subscribersOf } from "./subscribers";
import type { Actor, UnitOfWork } from "./unit-of-work";

const Subscribers = z.object({ items: z.array(Subscriber) });

export function registerSubscriberRoutes(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  unitOfWork: UnitOfWork;
  reader: ManagedCertificateReader;
}) {
  const { app, db, requireUser, unitOfWork, reader } = ctx;
  /** Organization Administrators, and the Managed Certificate's Owners whatever their role. */
  const findSubscribable = (actor: Actor, orgId: string, id: string) =>
    reader.findAsOwnerOr(actor, orgId, id, { managedCertificate: ["changeSubscribers"] }, "only an Owner or an Organization Administrator may change a Managed Certificate's Subscribers");

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/subscribers",
      tags: ["Notifications"],
      summary: "Who is told of this Managed Certificate's events, in the order they were added",
      description: "Anyone who may see the Managed Certificate may. There are none unless someone adds them.",
      request: { params: ManagedCertificateParams },
      responses: { 200: json(Subscribers), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const mc = await reader.findReadable(await requireUser(c), orgId, id);
      return c.json({ items: await subscribersOf(db, orgId, mc.id) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/subscribers",
      tags: ["Notifications"],
      summary: "Add a Subscriber: a user, a Team or a notification channel of the Organization",
      description:
        "Organization Administrators and the Managed Certificate's own Owners may. A Subscriber is told of its events but sees no more of it than before. " +
        "Naming one who already is a Subscriber changes nothing.",
      request: { params: ManagedCertificateParams, body: { content: { "application/json": { schema: SubscriberRef } } } },
      responses: { 200: json(Subscribers, "Its Subscribers"), ...errors(400, 401, 403, 404, 422) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const ref = c.req.valid("json");
      const actor = await requireUser(c);
      const mc = await findSubscribable(actor, orgId, id);
      await unitOfWork.run(actor, (tx, change) => addSubscriber(tx, change, orgId, mc.id, ref));
      return c.json({ items: await subscribersOf(db, orgId, mc.id) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/subscribers/{type}/{subscriberId}",
      tags: ["Notifications"],
      summary: "Remove a Subscriber",
      description: "Organization Administrators and the Managed Certificate's own Owners may.",
      request: {
        params: ManagedCertificateParams.extend({
          type: z.enum(SUBSCRIBER_TYPES).openapi({ param: { name: "type", in: "path" } }),
          subscriberId: z.string().openapi({ param: { name: "subscriberId", in: "path" } }),
        }),
      },
      responses: { 200: json(Subscribers, "Its Subscribers"), ...errors(400, 401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id, type, subscriberId } = c.req.valid("param");
      const actor = await requireUser(c);
      const mc = await findSubscribable(actor, orgId, id);
      await unitOfWork.run(actor, (tx, change) => removeSubscriber(tx, change, orgId, mc.id, { type, id: subscriberId }));
      return c.json({ items: await subscribersOf(db, orgId, mc.id) }, 200);
    },
  );
}
