import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { Scalar } from "@scalar/hono-api-reference";
import { and, asc, eq } from "drizzle-orm";
import type { Context } from "hono";
import type { Pool } from "pg";
import { registerAcmeAccounts } from "./acme-accounts";
import { PLATFORM_OPERATOR_ROLE, createAuth } from "./auth";
import type { CertificateAuthority } from "./certificate-authority";
import { listAudit } from "./audit";
import { createDb } from "./db/client";
import { managedCertificate, member, organization } from "./db/schema";
import { createAuthorizer } from "./authorization";
import { HttpError, OrgParam, errors, json } from "./http";
import type { Kms } from "./kms";
import type { Mailer } from "./mailer";
import type { MemberRemovalHook } from "./member-removal";
import { createOrganizationChanges } from "./organization-changes";
import { createOrganizations } from "./organizations";
import { ROLE_NAMES, permissionsOf } from "./permissions";
import { createSecrets } from "./secrets";
import { registerTeamsOverview } from "./teams-overview";
import { createUnitOfWork } from "./unit-of-work";

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
  /** Wraps each Organization's data key; see secrets.ts. */
  kms: Kms;
  certificateAuthority: CertificateAuthority;
  /** See `OrganizationChangesDeps.memberRemovalHooks`. */
  memberRemovalHooks?: MemberRemovalHook[];
}

export function createApp(deps: AppDeps) {
  const { pool, mailer, clock } = deps;
  const db = createDb(pool);
  const authConfig = { baseURL: deps.baseURL, secret: deps.secret, trustedOrigins: deps.trustedOrigins };
  const auth = createAuth({ ...authConfig, db });
  const webURL = deps.webURL ?? deps.baseURL;
  const unitOfWork = createUnitOfWork({ db, mailer, clock });
  const { authorize } = createAuthorizer(db);
  const organizationChanges = createOrganizationChanges({
    unitOfWork,
    auth,
    authConfig,
    authorize,
    webURL,
    memberRemovalHooks: deps.memberRemovalHooks,
  });
  const platformOrganizations = createOrganizations({ unitOfWork, webURL });
  const app = new OpenAPIHono();

  app.onError((err, c) => {
    if (err instanceof HttpError) return c.json({ error: err.message }, err.status);
    console.error(err);
    return c.json({ error: "internal error" }, 500);
  });

  // Better Auth's organization endpoints, served as they are (see organization-changes.ts).
  app.all("/api/auth/organization/*", (c) => organizationChanges.serve(c.req.raw));
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
      const created = await platformOrganizations.create(operator, c.req.valid("json"));
      return c.json(created, 201);
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
      method: "get",
      path: "/api/me",
      tags: ["Identity"],
      responses: {
        200: json(
          z.object({
            user: z.object({ id: z.string(), email: z.string(), name: z.string(), isPlatformOperator: z.boolean() }),
            organizations: z.array(
              z.object({
                id: z.string(),
                name: z.string(),
                slug: z.string(),
                role: z.string(),
                // What the caller may do there, so clients ask "may I?" instead of comparing role names.
                permissions: z.record(z.string(), z.array(z.string())),
              }),
            ),
            // The roles the platform accepts when assigning one.
            roles: z.array(z.string()),
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
          organizations: organizations.map((o) => ({ ...o, permissions: permissionsOf(o.role) })),
          roles: ROLE_NAMES,
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
      await authorize(await requireUser(c), orgId);
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
      await authorize(await requireUser(c), orgId, { audit: ["read"] });
      return c.json({ items: await listAudit(db, orgId) }, 200);
    },
  );

  registerTeamsOverview({ app, db, requireUser, authorize });
  registerAcmeAccounts({
    app,
    db,
    requireUser,
    authorize,
    unitOfWork,
    secrets: createSecrets(deps.kms),
    certificateAuthority: deps.certificateAuthority,
  });

  app.doc("/api/openapi.json", {
    openapi: "3.1.0",
    info: { title: "Certificate Platform API", version: "0.1.0" },
  });

  // One reference page for everything: the platform's routes (generated from the route schemas above)
  // and Better Auth's routes (generated by its OpenAPI plugin).
  app.get(
    "/api/docs",
    Scalar({
      pageTitle: "Certificate Platform API",
      sources: [
        { url: "/api/openapi.json", title: "Platform", default: true },
        { url: "/api/auth/open-api/generate-schema", title: "Auth" },
      ],
    }),
  );

  return { app, auth, db };
}
