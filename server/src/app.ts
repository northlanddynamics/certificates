import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import type { Context } from "hono";
import type { Pool } from "pg";
import { ORG_ADMIN_ROLE, PLATFORM_OPERATOR_ROLE, createAuth } from "./auth";
import { listAudit, recordAudit } from "./audit";
import type { Mailer } from "./mailer";

export interface AppDeps {
  pool: Pool;
  mailer: Mailer;
  clock: () => Date;
  baseURL: string;
  secret: string;
}

type ErrorStatus = 401 | 403 | 404 | 409;

class HttpError extends Error {
  constructor(
    readonly status: ErrorStatus,
    message: string,
  ) {
    super(message);
  }
}

const ErrorBody = z.object({ error: z.string() });
const errors = (...codes: ErrorStatus[]) =>
  Object.fromEntries(
    codes.map((c) => [c, { description: "Error", content: { "application/json": { schema: ErrorBody } } }]),
  );

const OrgParam = z.object({ orgId: z.string().openapi({ param: { name: "orgId", in: "path" } }) });
const json = <T extends z.ZodType>(schema: T, description = "OK") => ({
  description,
  content: { "application/json": { schema } },
});

const INVITATION_TTL_MS = 7 * 24 * 3600 * 1000;

export function createApp(deps: AppDeps) {
  const { pool, mailer, clock } = deps;
  const auth = createAuth(deps);
  const app = new OpenAPIHono();

  app.onError((err, c) => {
    if (err instanceof HttpError) return c.json({ error: err.message }, err.status);
    console.error(err);
    return c.json({ error: "internal error" }, 500);
  });

  app.on(["GET", "POST"], "/api/auth/*", (c) => auth.handler(c.req.raw));

  async function requireUser(c: Context) {
    const session = await auth.api.getSession({ headers: c.req.raw.headers });
    if (!session) throw new HttpError(401, "sign in required");
    return session.user as { id: string; email: string; role?: string | null };
  }

  async function requireOperator(c: Context) {
    const user = await requireUser(c);
    if (user.role !== PLATFORM_OPERATOR_ROLE) throw new HttpError(403, "platform operator only");
    return user;
  }

  /**
   * The Organization-scoping rule: every domain route passes through here.
   * A non-member (including a Platform Operator not invited in) gets 404, so existence is not revealed.
   */
  async function requireMember(c: Context, orgId: string) {
    const user = await requireUser(c);
    const { rows } = await pool.query(
      `select role from member where "organizationId" = $1 and "userId" = $2`,
      [orgId, user.id],
    );
    if (!rows[0]) throw new HttpError(404, "organization not found");
    return { user, role: rows[0].role as string };
  }

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/platform/organizations",
      tags: ["Platform"],
      request: {
        body: {
          content: {
            "application/json": {
              schema: z.object({
                name: z.string().min(1),
                slug: z.string().regex(/^[a-z0-9-]+$/),
                adminEmail: z.email(),
              }),
            },
          },
        },
      },
      responses: {
        201: json(z.object({ id: z.string(), invitationId: z.string() }), "Created"),
        ...errors(401, 403, 409),
      },
    }),
    async (c) => {
      const operator = await requireOperator(c);
      const { name, slug, adminEmail } = c.req.valid("json");
      const now = clock();
      const orgId = crypto.randomUUID();
      const invitationId = crypto.randomUUID();
      const client = await pool.connect();
      try {
        await client.query("begin");
        await client.query(
          `insert into organization (id, name, slug, "createdAt") values ($1, $2, $3, $4)`,
          [orgId, name, slug, now],
        );
        await client.query(
          `insert into invitation (id, "organizationId", email, role, status, "expiresAt", "createdAt", "inviterId")
           values ($1, $2, $3, $4, 'pending', $5, $6, $7)`,
          [invitationId, orgId, adminEmail.toLowerCase(), ORG_ADMIN_ROLE, new Date(now.getTime() + INVITATION_TTL_MS), now, operator.id],
        );
        await recordAudit(client, {
          organizationId: orgId,
          occurredAt: now,
          actor: operator,
          action: "organization.created",
          target: { type: "organization", id: orgId },
          detail: { slug, firstAdministrator: adminEmail.toLowerCase() },
        });
        await client.query("commit");
      } catch (err: any) {
        await client.query("rollback").catch(() => {});
        if (err?.code === "23505") throw new HttpError(409, "slug already in use");
        throw err;
      } finally {
        client.release();
      }
      await mailer.send({
        to: adminEmail,
        subject: `You are invited to administer ${name}`,
        text: `Accept your invitation: ${deps.baseURL}/accept-invitation/${invitationId}`,
      });
      return c.json({ id: orgId, invitationId }, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/platform/organizations",
      tags: ["Platform"],
      responses: {
        200: json(z.object({ items: z.array(z.object({ id: z.string(), name: z.string(), slug: z.string() })) })),
        ...errors(401, 403),
      },
    }),
    async (c) => {
      await requireOperator(c);
      const { rows } = await pool.query(`select id, name, slug from organization order by "createdAt", id`);
      return c.json({ items: rows }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/invitations/{id}/accept",
      tags: ["Identity"],
      request: { params: z.object({ id: z.string().openapi({ param: { name: "id", in: "path" } }) }) },
      responses: {
        200: json(z.object({ organizationId: z.string(), role: z.string() })),
        ...errors(401, 403, 404, 409),
      },
    }),
    async (c) => {
      const user = await requireUser(c);
      const { id } = c.req.valid("param");
      const now = clock();
      const client = await pool.connect();
      try {
        await client.query("begin");
        const { rows } = await client.query(`select * from invitation where id = $1 for update`, [id]);
        const inv = rows[0];
        if (!inv) throw new HttpError(404, "invitation not found");
        if (inv.email.toLowerCase() !== user.email.toLowerCase()) throw new HttpError(403, "invitation is for a different email");
        if (inv.status !== "pending") throw new HttpError(409, "invitation already used");
        if (new Date(inv.expiresAt) < now) throw new HttpError(404, "invitation expired");
        await client.query(`update invitation set status = 'accepted' where id = $1`, [id]);
        await client.query(
          `insert into member (id, "organizationId", "userId", role, "createdAt") values ($1, $2, $3, $4, $5)`,
          [crypto.randomUUID(), inv.organizationId, user.id, inv.role, now],
        );
        await recordAudit(client, {
          organizationId: inv.organizationId,
          occurredAt: now,
          actor: user,
          action: "invitation.accepted",
          target: { type: "invitation", id },
          detail: { role: inv.role },
        });
        await client.query("commit");
        return c.json({ organizationId: inv.organizationId as string, role: inv.role as string }, 200);
      } catch (err) {
        await client.query("rollback").catch(() => {});
        throw err;
      } finally {
        client.release();
      }
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/me",
      tags: ["Identity"],
      responses: {
        200: json(
          z.object({
            user: z.object({ id: z.string(), email: z.string(), name: z.string(), isPlatformOperator: z.boolean() }),
            organizations: z.array(z.object({ id: z.string(), name: z.string(), slug: z.string(), role: z.string() })),
          }),
        ),
        ...errors(401),
      },
    }),
    async (c) => {
      const user = await requireUser(c);
      const { rows } = await pool.query(
        `select o.id, o.name, o.slug, m.role from member m join organization o on o.id = m."organizationId"
          where m."userId" = $1 order by o."createdAt", o.id`,
        [user.id],
      );
      const { rows: u } = await pool.query(`select name from "user" where id = $1`, [user.id]);
      return c.json(
        {
          user: { id: user.id, email: user.email, name: u[0].name as string, isPlatformOperator: user.role === PLATFORM_OPERATOR_ROLE },
          organizations: rows,
        },
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates",
      tags: ["Managed Certificates"],
      request: { params: OrgParam },
      responses: {
        200: json(z.object({ items: z.array(z.object({ id: z.string() })) })),
        ...errors(401, 404),
      },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await requireMember(c, orgId);
      const { rows } = await pool.query(
        `select id from managed_certificate where organization_id = $1 order by created_at, id`,
        [orgId],
      );
      return c.json({ items: rows }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/audit-events",
      tags: ["Audit"],
      request: { params: OrgParam },
      responses: {
        200: json(
          z.object({
            items: z.array(
              z.object({
                id: z.string(),
                occurredAt: z.string(),
                actor: z.object({ id: z.string().nullable(), email: z.string().nullable() }),
                action: z.string(),
                target: z.object({ type: z.string(), id: z.string().nullable() }),
                detail: z.record(z.string(), z.unknown()),
              }),
            ),
          }),
        ),
        ...errors(401, 403, 404),
      },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const { role } = await requireMember(c, orgId);
      if (role !== ORG_ADMIN_ROLE) throw new HttpError(403, "organization administrators only");
      return c.json({ items: await listAudit(pool, orgId) }, 200);
    },
  );

  app.doc("/api/openapi.json", {
    openapi: "3.1.0",
    info: { title: "Certificate Platform API", version: "0.1.0" },
  });

  return { app, auth };
}
