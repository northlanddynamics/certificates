import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, eq } from "drizzle-orm";
import type { Context } from "hono";
import type { Pool } from "pg";
import { ORG_ADMIN_ROLE, PLATFORM_OPERATOR_ROLE, createAuth } from "./auth";
import { listAudit, recordAudit } from "./audit";
import { createDb } from "./db/client";
import { invitation, managedCertificate, member, organization } from "./db/schema";
import type { Mailer } from "./mailer";

export interface AppDeps {
  pool: Pool;
  mailer: Mailer;
  clock: () => Date;
  /** Where the API is served; Better Auth builds its URLs from this. */
  baseURL: string;
  /** Where users open the web UI, for links in emails. Defaults to baseURL. */
  webURL?: string;
  trustedOrigins?: string[];
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

const UNIQUE_VIOLATION = "23505";
// Drizzle wraps driver errors; the Postgres error code is on the cause.
const isUniqueViolation = (err: any) => (err?.cause?.code ?? err?.code) === UNIQUE_VIOLATION;

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
  const db = createDb(pool);
  const auth = createAuth({ ...deps, db });
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
    return session.user as { id: string; email: string; name: string; role?: string | null };
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
    const [row] = await db
      .select({ role: member.role })
      .from(member)
      .where(and(eq(member.organizationId, orgId), eq(member.userId, user.id)));
    if (!row) throw new HttpError(404, "organization not found");
    return { user, role: row.role };
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
      try {
        await db.transaction(async (tx) => {
          await tx.insert(organization).values({ id: orgId, name, slug, createdAt: now });
          await tx.insert(invitation).values({
            id: invitationId,
            organizationId: orgId,
            email: adminEmail.toLowerCase(),
            role: ORG_ADMIN_ROLE,
            status: "pending",
            expiresAt: new Date(now.getTime() + INVITATION_TTL_MS),
            createdAt: now,
            inviterId: operator.id,
          });
          await recordAudit(tx, {
            organizationId: orgId,
            occurredAt: now,
            actor: operator,
            action: "organization.created",
            target: { type: "organization", id: orgId },
            detail: { slug, firstAdministrator: adminEmail.toLowerCase() },
          });
        });
      } catch (err) {
        if (isUniqueViolation(err)) throw new HttpError(409, "slug already in use");
        throw err;
      }
      // The Organization and invitation are committed; a mail failure must not hide that from the caller.
      await mailer
        .send({
          to: adminEmail,
          subject: `You are invited to administer ${name}`,
          text: `Accept your invitation: ${deps.webURL ?? deps.baseURL}/accept-invitation/${invitationId}`,
        })
        .catch((err) => console.error("invitation email failed", err));
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
      const items = await db
        .select({ id: organization.id, name: organization.name, slug: organization.slug })
        .from(organization)
        .orderBy(asc(organization.createdAt), asc(organization.id));
      return c.json({ items }, 200);
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
      const result = await db.transaction(async (tx) => {
        const [inv] = await tx.select().from(invitation).where(eq(invitation.id, id)).for("update");
        if (!inv) throw new HttpError(404, "invitation not found");
        if (inv.email.toLowerCase() !== user.email.toLowerCase()) throw new HttpError(403, "invitation is for a different email");
        if (inv.status !== "pending") throw new HttpError(409, "invitation already used");
        if (inv.expiresAt < now) throw new HttpError(404, "invitation expired");
        const role = inv.role ?? "member";
        await tx.update(invitation).set({ status: "accepted" }).where(eq(invitation.id, id));
        await tx
          .insert(member)
          .values({ id: crypto.randomUUID(), organizationId: inv.organizationId, userId: user.id, role, createdAt: now });
        await recordAudit(tx, {
          organizationId: inv.organizationId,
          occurredAt: now,
          actor: user,
          action: "invitation.accepted",
          target: { type: "invitation", id },
          detail: { role },
        });
        return { organizationId: inv.organizationId, role };
      });
      return c.json(result, 200);
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
      const organizations = await db
        .select({ id: organization.id, name: organization.name, slug: organization.slug, role: member.role })
        .from(member)
        .innerJoin(organization, eq(organization.id, member.organizationId))
        .where(eq(member.userId, user.id))
        .orderBy(asc(organization.createdAt), asc(organization.id));
      return c.json(
        {
          user: { id: user.id, email: user.email, name: user.name, isPlatformOperator: user.role === PLATFORM_OPERATOR_ROLE },
          organizations,
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
      const items = await db
        .select({ id: managedCertificate.id })
        .from(managedCertificate)
        .where(eq(managedCertificate.organizationId, orgId))
        .orderBy(asc(managedCertificate.createdAt), asc(managedCertificate.id));
      return c.json({ items }, 200);
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
      return c.json({ items: await listAudit(db, orgId) }, 200);
    },
  );

  app.doc("/api/openapi.json", {
    openapi: "3.1.0",
    info: { title: "Certificate Platform API", version: "0.1.0" },
  });

  return { app, auth, db };
}
