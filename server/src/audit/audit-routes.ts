// The audit log as the API serves it: an Organization's Audit Events, searched and filtered. There is no route that
// changes or deletes one, and the table refuses it (migration 0001): the log is kept for ever.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { auditTargetTypes, searchAudit } from "./audit";
import type { Authorizer } from "../tenancy/authorization";
import type { Db } from "../platform/db/client";
import { OrgParam, errors, json } from "../platform/http";
import type { Actor } from "../platform/unit-of-work";

const MAX_LIMIT = 500;

export const AuditEvent = z
  .object({
    id: z.string().openapi({ description: "Rising within the platform: a later event has a greater id. Compare as numbers." }),
    occurredAt: z.string().openapi({ description: "When the change happened, as an ISO 8601 UTC time." }),
    actor: z
      .object({ id: z.string().nullable(), email: z.string().nullable() })
      .openapi({ description: "The user who made the change; both are null when the platform itself or an Organization's API key did (an API key's use names it in `detail`)." }),
    action: z.string().openapi({ description: "What was done, as `<resource>.<verb>` (such as `team.created`)." }),
    target: z.object({ type: z.string(), id: z.string().nullable() }).openapi({ description: "What it was done to." }),
    detail: z.record(z.string(), z.unknown()).openapi({ description: "What the action records besides; its fields depend on the action, and may grow." }),
  });

const AuditQuery = z.object({
  q: z.string().trim().min(1).max(200).optional().openapi({ description: "Part of the actor's email or of the action, in any case." }),
  actor: z.string().optional().openapi({ description: "Who made the change: a user's id or email (in any case)." }),
  action: z
    .string()
    .regex(/^[a-z_]+(\.([a-z_]+|\*))?$/, "an action, such as team.created, or a prefix, such as team.*")
    .optional()
    .openapi({ description: "An action (`team.created`), or every action of a resource (`team.*`)." }),
  targetType: z
    .string()
    .regex(/^[a-z_]+(,[a-z_]+)*$/, "target types, comma-separated, such as team,member")
    .optional()
    .openapi({ description: "Any of these types of target, comma-separated." }),
  targetId: z.string().optional(),
  from: z.iso.datetime({ offset: true }).optional().openapi({ description: "From this time, inclusive." }),
  to: z.iso.datetime({ offset: true }).optional().openapi({ description: "Until this time, exclusive." }),
  order: z.enum(["asc", "desc"]).default("asc").openapi({ description: "Oldest first (the default) or newest first." }),
  cursor: z.string().regex(/^\d{1,15}$/).optional().openapi({ description: "Where the page before ended: its `nextCursor`." }),
  limit: z.coerce.number().int().min(1).max(MAX_LIMIT).default(MAX_LIMIT).openapi({ description: `How many to a page, up to ${MAX_LIMIT}.` }),
});

export function registerAuditRoutes(ctx: { app: OpenAPIHono; db: Db; requireUser(c: any): Promise<Actor>; authorize: Authorizer["authorize"] }) {
  const { app, db, requireUser, authorize } = ctx;

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/audit-events",
      tags: ["Audit"],
      summary: "Search the Organization's audit log",
      description: "Every filter given must match. Pages follow one another by `cursor`; `nextCursor` is null on the last.",
      request: { params: OrgParam, query: AuditQuery },
      responses: {
        200: json(z.object({ items: z.array(AuditEvent), nextCursor: z.string().nullable() })),
        ...errors(400, 401, 403, 404),
      },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const q = c.req.valid("query");
      await authorize(await requireUser(c), orgId, { audit: ["read"] });
      const page = await searchAudit(db, orgId, {
        ...q,
        targetType: q.targetType?.split(","),
        from: q.from ? new Date(q.from) : undefined,
        to: q.to ? new Date(q.to) : undefined,
      });
      return c.json(page, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/audit-events/target-types",
      tags: ["Audit"],
      summary: "List the types of target in the Organization's audit log",
      description: "What `targetType` can narrow the search to: the types of target the Organization's Audit Events have, by name.",
      request: { params: OrgParam },
      responses: {
        200: json(z.object({ items: z.array(z.string()) })),
        ...errors(401, 403, 404),
      },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { audit: ["read"] });
      return c.json({ items: await auditTargetTypes(db, orgId) }, 200);
    },
  );
}
