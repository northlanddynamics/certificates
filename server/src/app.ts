import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { Scalar } from "@scalar/hono-api-reference";
import { and, asc, eq } from "drizzle-orm";
import type { Context } from "hono";
import type { Pool } from "pg";
import { registerAcmeAccounts } from "./acme-accounts";
import { DEFAULT_AGENT_GATEWAY, registerAgentGateway, type AgentGatewayConfig } from "./agent-gateway";
import { createAgentIdentityCa } from "./agent-identity-ca";
import { registerAgents } from "./agents";
import { registerApiKeys } from "./api-keys";
import { PLATFORM_OPERATOR_ROLE, createAuth } from "./auth";
import { registerCertificateExport } from "./certificate-export";
import type { CertificateAuthority } from "./certificate-authority";
import { registerDeploymentScripts } from "./deployment-scripts";
import { registerDeployments } from "./deployments";
import { registerDcvConfiguration } from "./dcv-configuration";
import { createDcvPlans } from "./dcv-plan";
import { DEFAULT_DCV_CONFIG, createDcv, createTxtResolver, type DcvConfig } from "./dcv";
import { listAudit } from "./audit";
import { createDb } from "./db/client";
import { DEFAULT_DNS_RELAY, createDnsRelay, type DnsRelayConfig } from "./dns-relay";
import { createDnsProviders, registerDnsProviders } from "./dns-providers";
import { member, organization } from "./db/schema";
import { createAuthorizer } from "./authorization";
import { HttpError, OrgParam, errors, json } from "./http";
import { createIssuances } from "./issuance";
import type { Kms } from "./kms";
import { registerApprovals } from "./approvals";
import { registerArchiveRoutes } from "./archive-routes";
import { registerHistory } from "./history";
import { createManagedCertificateReader } from "./managed-certificate-reader";
import { registerManagedCertificates } from "./managed-certificates";
import { discardNameChangesOfRemoved } from "./name-change";
import { registerNameChangeRoutes } from "./name-change-routes";
import { registerOwnerRoutes } from "./owner-routes";
import { createRenewalScheduler } from "./renewal-scheduler";
import { registerRenewalRoutes } from "./renewal-routes";
import { registerRevocationRoutes } from "./revocation-routes";
import type { Mailer } from "./mailer";
import type { MemberRemovalHook } from "./member-removal";
import { removeTeamFromOwners, removeUserFromOwners } from "./owners";
import { createOrganizationChanges } from "./organization-changes";
import { createOrganizations } from "./organizations";
import { ROLE_NAMES, permissionsOf } from "./permissions";
import { createSecrets } from "./secrets";
import { registerTeamsOverview } from "./teams-overview";
import { createUnitOfWork } from "./unit-of-work";
import { createWorkItems } from "./work-items";

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
  /** How DCV checks that a challenge record is visible; the host's DNS resolvers, waiting up to two minutes, unless given. */
  dcv?: Partial<DcvConfig>;
  /** How the Agent protocol is run: see `AgentGatewayConfig` for what each setting is and its default. */
  agentGateway?: Partial<AgentGatewayConfig>;
  /** How DNS Provider operations relayed by Agents wait for them: see `DnsRelayConfig`. */
  dnsRelay?: Partial<DnsRelayConfig>;
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
    memberRemovalHooks: [
      removeUserFromOwners,
      discardNameChangesOfRemoved,
      // The host's own (a test adds one while the app runs), so they are looked at when a member is removed.
      async (tx, removed, change) => {
        for (const hook of deps.memberRemovalHooks ?? []) await hook(tx, removed, change);
      },
    ],
    teamRemovalHooks: [removeTeamFromOwners],
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
  const secrets = createSecrets(deps.kms);
  registerAcmeAccounts({ app, db, requireUser, authorize, unitOfWork, secrets, certificateAuthority: deps.certificateAuthority });
  const agentGateway = { ...DEFAULT_AGENT_GATEWAY, ...deps.agentGateway };
  const dnsRelayConfig = { ...DEFAULT_DNS_RELAY, ...deps.dnsRelay };
  const workItems = createWorkItems({ db, unitOfWork, pollMs: dnsRelayConfig.pollMs, maxWaitMs: dnsRelayConfig.maxWaitMs, clock });
  const dnsRelay = createDnsRelay({ db, workItems, secrets, clock, offlineAfterSeconds: agentGateway.offlineAfterSeconds, config: dnsRelayConfig });
  const dnsProviders = createDnsProviders(secrets, dnsRelay);
  registerDnsProviders({ app, db, requireUser, authorize, unitOfWork, secrets, dnsProviders, relay: dnsRelay });
  const dcvPlans = createDcvPlans(dnsProviders);
  registerDcvConfiguration({ app, db, requireUser, authorize, unitOfWork, dcvPlans });
  const dcv = createDcv(dnsProviders, dcvPlans, { resolver: createTxtResolver(), ...DEFAULT_DCV_CONFIG, ...deps.dcv });
  const issuances = createIssuances({ db, unitOfWork, certificateAuthority: deps.certificateAuthority, dcv, secrets });
  const reader = createManagedCertificateReader({ db, authorize });
  registerManagedCertificates({ app, db, requireUser, authorize, unitOfWork, issuances, reader, clock });
  const apiKeys = registerApiKeys({ app, db, auth, authConfig, requireUser, authorize, unitOfWork });
  registerCertificateExport({ app, apiKeys, unitOfWork, reader, certificateAuthority: deps.certificateAuthority });
  registerOwnerRoutes({ app, requireUser, unitOfWork, reader });
  registerRenewalRoutes({ app, db, requireUser, unitOfWork, issuances, reader });
  const renewals = createRenewalScheduler({ db, unitOfWork, issuances, certificateAuthority: deps.certificateAuthority, clock });
  registerNameChangeRoutes({ app, requireUser, authorize, unitOfWork, issuances, reader });
  registerApprovals({ app, db, requireUser, authorize, unitOfWork, issuances, reader });
  registerArchiveRoutes({ app, requireUser, authorize, unitOfWork, reader });
  registerRevocationRoutes({ app, db, requireUser, unitOfWork, reader, secrets, certificateAuthority: deps.certificateAuthority });
  registerHistory({ app, db, requireUser, reader });
  registerDeploymentScripts({ app, db, requireUser, authorize, unitOfWork });
  registerDeployments({ app, db, requireUser, authorize, unitOfWork, workItems, issuances });
  registerAgents({ app, db, requireUser, authorize, unitOfWork, clock, config: agentGateway });
  registerAgentGateway({ app, db, unitOfWork, identityCa: createAgentIdentityCa({ db, kms: deps.kms, clock }), workItems, clock, config: agentGateway });

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

  return { app, auth, db, unitOfWork, issuances, renewals };
}
