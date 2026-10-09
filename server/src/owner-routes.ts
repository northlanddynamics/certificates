// The routes that change a Managed Certificate's Owners (the Owners themselves are owners.ts).
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { errors, json } from "./http";
import { ManagedCertificate, ManagedCertificateParams, type ManagedCertificateReader } from "./managed-certificate-reader";
import { OWNER_TYPES, OwnerRef, addOwner, removeOwner } from "./owners";
import type { Actor, UnitOfWork } from "./unit-of-work";

export function registerOwnerRoutes(ctx: {
  app: OpenAPIHono;
  requireUser(c: any): Promise<Actor>;
  unitOfWork: UnitOfWork;
  reader: ManagedCertificateReader;
}) {
  const { app, requireUser, unitOfWork, reader } = ctx;
  const { findOwnable, withState } = reader;

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/owners",
      tags: ["Owners"],
      summary: "Add an Owner: a user or a Team of the Organization",
      description: "Organization Administrators and the Managed Certificate's own Owners may. Naming one who already is an Owner changes nothing.",
      request: { params: ManagedCertificateParams, body: { content: { "application/json": { schema: OwnerRef } } } },
      responses: { 200: json(ManagedCertificate, "The Managed Certificate with its Owners"), ...errors(400, 401, 403, 404, 422) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const ref = c.req.valid("json");
      const actor = await requireUser(c);
      const mc = await findOwnable(actor, orgId, id);
      await unitOfWork.run(actor, (tx, change) => addOwner(tx, change, orgId, mc.id, ref));
      return c.json((await withState([mc]))[0]!, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/owners/{type}/{ownerId}",
      tags: ["Owners"],
      summary: "Remove an Owner",
      description: "Organization Administrators and the Managed Certificate's own Owners may. It may be left with none.",
      request: {
        params: ManagedCertificateParams.extend({
          type: z.enum(OWNER_TYPES).openapi({ param: { name: "type", in: "path" } }),
          ownerId: z.string().openapi({ param: { name: "ownerId", in: "path" } }),
        }),
      },
      responses: { 200: json(ManagedCertificate, "The Managed Certificate with its Owners"), ...errors(400, 401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id, type, ownerId } = c.req.valid("param");
      const actor = await requireUser(c);
      const mc = await findOwnable(actor, orgId, id);
      await unitOfWork.run(actor, (tx, change) => removeOwner(tx, change, orgId, mc.id, { type, id: ownerId }));
      return c.json((await withState([mc]))[0]!, 200);
    },
  );
}
