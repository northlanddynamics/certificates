import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { Scalar } from "@scalar/hono-api-reference";
import { and, asc, eq } from "drizzle-orm";
import type { Context } from "hono";
import type { Pool } from "pg";
import { ACCOUNT_SECURITY_PATHS, createAccountSecurity } from "./account-security";
import { registerAcmeAccounts } from "./acme-accounts";
import { DEFAULT_AGENT_GATEWAY, registerAgentGateway, type AgentGatewayConfig } from "./agent-gateway";
import { registerAgents } from "./agents";
import { registerApiKeys } from "./api-keys";
import { PLATFORM_OPERATOR_ROLE, createAuth } from "./auth";
import { registerCertificateExport } from "./certificate-export";
import type { AcmeCertificateAuthority } from "./certificate-authority";
import { registerDeploymentScripts } from "./deployment-scripts";
import { registerDeployments } from "./deployments";
import { registerDcvConfiguration } from "./dcv-configuration";
import { createDcvPlans } from "./dcv-plan";
import { DEFAULT_DCV_CONFIG, createDcv, createTxtResolver, type DcvConfig } from "./dcv";
import { createAuditForwarding, registerAuditForwarders } from "./audit-forwarding";
import { registerAuditRoutes } from "./audit-routes";
import { createAuditTransport, type AuditTransport } from "./audit-transport";
import { createCrls, registerPkiRoutes } from "./crl";
import { createDb } from "./db/client";
import { registerDeviceCertificates } from "./device-certificates";
import { createDeviceCertificatePruning } from "./device-certificate-pruning";
import { createSharedChallengeExpiry } from "./shared-challenge-expiry";
import { registerEnrollmentProfiles } from "./enrollment-profiles";
import type { EnrollmentValidators } from "./enrollment-validator";
import { ENROLLMENT_VALIDATOR_KINDS } from "./enrollment-validator-kinds";
import { createEnrollmentValidatorRuns } from "./enrollment-validators";
import { DEFAULT_DNS_RELAY, createDnsRelay, type DnsRelayConfig } from "./dns-relay";
import { createDnsProviders, registerDnsProviders } from "./dns-providers";
import { member, organization } from "./db/schema";
import { createAuthorizer } from "./authorization";
import { HttpError, errors, json } from "./http";
import { createIssuances } from "./issuance";
import { createIssuers } from "./issuer";
import type { Kms } from "./kms";
import { registerApprovals } from "./approvals";
import { registerArchiveRoutes } from "./archive-routes";
import { registerHistory } from "./history";
import { registerIssuerRoutes } from "./issuer-routes";
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
import { createLoginPolicies, registerLoginPolicy } from "./login-policy";
import { createOrganizationChanges } from "./organization-changes";
import { registerNotificationChannels } from "./notification-channels";
import { createFetchWebhooks, createNotifications, type WebhookSender } from "./notifications";
import { registerSubscriberRoutes } from "./subscriber-routes";
import { removeTeamFromSubscribers, removeUserFromSubscribers } from "./subscribers";
import { createOrganizations } from "./organizations";
import { createPrivateCas, registerPrivateCas } from "./private-ca";
import { ROLE_NAMES, permissionsOf } from "./permissions";
import { registerScep, type ScepConfig } from "./scep";
import { createScepTransactions } from "./scep-transactions";
import { createSecrets } from "./secrets";
import { registerSsoConnections } from "./sso-connections";
import { provisionOnSsoSignIn } from "./sso-sign-in";
import { registerTeamsOverview } from "./teams-overview";
import { createUnitOfWork } from "./unit-of-work";
import { createWorkItems } from "./work-items";

export interface AppDeps {
  pool: Pool;
  mailer: Mailer;
  /** How notices reach webhook notification channels; posts with `fetch` unless given. */
  webhooks?: WebhookSender;
  clock: () => Date;
  /** Where the API is served; Better Auth builds its URLs from this. */
  baseURL: string;
  /**
   * Where relying parties fetch what Private CAs publish (their CRLs and CA certificates, under `/pki`), which the
   * certificates they sign name; it should be a plain-HTTP URL (crl.ts). Defaults to baseURL.
   */
  pkiBaseURL?: string;
  /** Where users open the web UI, for links in emails. Defaults to baseURL. */
  webURL?: string;
  trustedOrigins?: string[];
  secret: string;
  /** Wraps each Organization's data key; see secrets.ts. */
  kms: Kms;
  /** The ACME CA: the CA of a Managed Certificate whose issuer is of the ACME kind (issuer.ts). */
  certificateAuthority: AcmeCertificateAuthority;
  /** How DCV checks that a challenge record is visible; the host's DNS resolvers, waiting up to two minutes, unless given. */
  dcv?: Partial<DcvConfig>;
  /** How the Agent protocol is run: see `AgentGatewayConfig` for what each setting is and its default. */
  agentGateway?: Partial<AgentGatewayConfig>;
  /** How DNS Provider operations relayed by Agents wait for them: see `DnsRelayConfig`. */
  dnsRelay?: Partial<DnsRelayConfig>;
  /** How Audit Events reach the Organizations' SIEMs; posts with `fetch` and writes syslog over TLS unless given. */
  auditTransport?: AuditTransport;
  /** See `OrganizationChangesDeps.memberRemovalHooks`. */
  memberRemovalHooks?: MemberRemovalHook[];
  /** The Enrollment Validator kinds Enrollment Profiles can name, by name (enrollment-validator.ts); ENROLLMENT_VALIDATOR_KINDS unless given. */
  enrollmentValidators?: EnrollmentValidators;
  /** How the SCEP routes are rate limited and tell devices apart: see `ScepConfig`. */
  scep?: Partial<ScepConfig>;
}

export function createApp(deps: AppDeps) {
  const { pool, mailer, clock } = deps;
  const db = createDb(pool);
  const authConfig = { baseURL: deps.baseURL, secret: deps.secret, trustedOrigins: deps.trustedOrigins };
  const webURL = deps.webURL ?? deps.baseURL;
  const unitOfWork = createUnitOfWork({ db, mailer, clock });
  const auth = createAuth({ ...authConfig, db, onSsoSignIn: provisionOnSsoSignIn(unitOfWork) });
  const { authorize } = createAuthorizer(db);
  const loginPolicies = createLoginPolicies(db);
  const organizationChanges = createOrganizationChanges({
    unitOfWork,
    auth,
    authConfig,
    authorize,
    admit: loginPolicies.admit,
    webURL,
    memberRemovalHooks: [
      removeUserFromOwners,
      removeUserFromSubscribers,
      discardNameChangesOfRemoved,
      // The host's own (a test adds one while the app runs), so they are looked at when a member is removed.
      async (tx, removed, change) => {
        for (const hook of deps.memberRemovalHooks ?? []) await hook(tx, removed, change);
      },
    ],
    teamRemovalHooks: [removeTeamFromOwners, removeTeamFromSubscribers],
  });
  const accountSecurity = createAccountSecurity({ unitOfWork, auth, authConfig });
  const platformOrganizations = createOrganizations({ unitOfWork, webURL });
  const app = new OpenAPIHono();

  app.onError((err, c) => {
    if (err instanceof HttpError) return c.json({ error: err.message }, err.status);
    console.error(err);
    return c.json({ error: "internal error" }, 500);
  });

  // Better Auth's organization endpoints, served as they are (see organization-changes.ts).
  app.all("/api/auth/organization/*", (c) => organizationChanges.serve(c.req.raw));
  // Better Auth's two-factor and passkey endpoints, served as they are (see account-security.ts).
  app.on(["GET", "POST"], ACCOUNT_SECURITY_PATHS, (c) => accountSecurity.serve(c.req.raw));
  app.on(["GET", "POST"], "/api/auth/*", (c) => auth.handler(c.req.raw));

  /** The signed-in user, even one who must set up MFA before going on: only for what setting it up needs (login-policy.ts). */
  async function requireSession(c: Context) {
    const session = await auth.api.getSession({ headers: c.req.raw.headers });
    if (!session) throw new HttpError(401, "sign in required");
    return session.user as { id: string; email: string; name: string; role?: string | null };
  }

  /** The signed-in user, held to their Organizations' login policy. */
  async function requireUser(c: Context) {
    const user = await requireSession(c);
    await loginPolicies.admit(user);
    return user;
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
            user: z.object({
              id: z.string(),
              email: z.string(),
              name: z.string(),
              isPlatformOperator: z.boolean(),
              // Whether they have set up TOTP, and whether they must before anything else answers them.
              mfa: z.object({ enabled: z.boolean(), setupRequired: z.boolean() }),
            }),
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
      const user = await requireSession(c);
      const organizations = await db
        .select({ id: organization.id, name: organization.name, slug: organization.slug, role: member.role })
        .from(member)
        .innerJoin(organization, eq(organization.id, member.organizationId))
        .where(eq(member.userId, user.id))
        .orderBy(asc(organization.createdAt), asc(organization.id));
      return c.json(
        {
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            isPlatformOperator: user.role === PLATFORM_OPERATOR_ROLE,
            mfa: await loginPolicies.mfaOf(user),
          },
          organizations: organizations.map((o) => ({ ...o, permissions: permissionsOf(o.role) })),
          roles: ROLE_NAMES,
        },
        200,
      );
    },
  );

  registerAuditRoutes({ app, db, requireUser, authorize });
  registerLoginPolicy({ app, db, requireSession, authorize, unitOfWork });
  registerSsoConnections({
    app,
    db,
    requireUser,
    authorize,
    unitOfWork,
    clock,
    baseURL: deps.baseURL,
    secret: deps.secret,
    // The same resolvers DCV looks records up through.
    resolver: deps.dcv?.resolver ?? createTxtResolver(),
    trustedOrigins: deps.trustedOrigins ?? [],
  });
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
  const pkiBaseURL = deps.pkiBaseURL ?? deps.baseURL;
  const crls = createCrls({ db, unitOfWork, kms: deps.kms, clock });
  registerPrivateCas({ app, db, requireUser, authorize, unitOfWork, kms: deps.kms, clock, crls, pkiBaseURL });
  registerPkiRoutes({ app, db });
  const privateCas = createPrivateCas({ kms: deps.kms, clock, crls, pkiBaseURL });
  const validatorKinds = deps.enrollmentValidators ?? ENROLLMENT_VALIDATOR_KINDS;
  const enrollmentValidators = createEnrollmentValidatorRuns({ db, unitOfWork, secrets, privateCas, kinds: validatorKinds, clock });
  const sharedChallengeExpiry = createSharedChallengeExpiry({ db, unitOfWork, clock });
  registerEnrollmentProfiles({ app, db, requireUser, authorize, unitOfWork, secrets, privateCas, kinds: validatorKinds, validators: enrollmentValidators, sharedChallengeExpiry, baseURL: deps.baseURL, clock });
  registerDeviceCertificates({ app, db, requireUser, authorize, unitOfWork, privateCas, clock });
  const deviceCertificatePruning = createDeviceCertificatePruning({ db, unitOfWork, clock });
  const scep = registerScep({ app, db, unitOfWork, secrets, privateCas, kinds: validatorKinds, validators: enrollmentValidators, transactions: createScepTransactions({ db, clock }), clock, config: deps.scep });
  const issuers = createIssuers({ acme: deps.certificateAuthority, secrets, privateCas });
  const issuances = createIssuances({ db, unitOfWork, issuers, dcv });
  const notifications = createNotifications({
    db,
    unitOfWork,
    secrets,
    mailer,
    webhooks: deps.webhooks ?? createFetchWebhooks(),
    clock,
    webURL,
    offlineAfterSeconds: agentGateway.offlineAfterSeconds,
  });
  registerNotificationChannels({ app, db, requireUser, authorize, unitOfWork, secrets });
  registerAuditForwarders({ app, db, requireUser, authorize, unitOfWork, secrets });
  const auditForwarding = createAuditForwarding({ db, unitOfWork, secrets, transport: deps.auditTransport ?? createAuditTransport(), clock });
  // A Renewal's end is told to the Managed Certificate's Subscribers; a first Issuance is not a Renewal, so is not.
  issuances.onEnded(async (tx, change, ended) => {
    if (!ended.renewal) return;
    const mc = { id: ended.managedCertificateId, organizationId: ended.organizationId };
    const { outcome } = ended;
    await notifications.notify(
      tx,
      change,
      mc,
      outcome.kind === "succeeded"
        ? { event: "renewal.succeeded", detail: { issuanceId: ended.issuanceId, certificateId: outcome.certificateId, fingerprint: outcome.fingerprint, notAfter: outcome.notAfter.toISOString() } }
        : { event: "renewal.failed", detail: { issuanceId: ended.issuanceId, code: outcome.code, message: outcome.message } },
    );
  });
  const reader = createManagedCertificateReader({ db, authorize, clock, agentOfflineAfterSeconds: agentGateway.offlineAfterSeconds });
  registerManagedCertificates({ app, db, requireUser, authorize, unitOfWork, issuances, reader, clock, agentOfflineAfterSeconds: agentGateway.offlineAfterSeconds });
  const apiKeys = registerApiKeys({ app, db, auth, authConfig, requireUser, authorize, admit: loginPolicies.admit, unitOfWork });
  registerCertificateExport({ app, db, apiKeys, unitOfWork, reader, issuers });
  registerOwnerRoutes({ app, requireUser, unitOfWork, reader });
  registerSubscriberRoutes({ app, db, requireUser, unitOfWork, reader });
  registerRenewalRoutes({ app, db, requireUser, unitOfWork, issuances, reader });
  const renewals = createRenewalScheduler({ db, unitOfWork, issuances, issuers, clock });
  registerNameChangeRoutes({ app, requireUser, authorize, unitOfWork, issuances, reader, notifications });
  registerApprovals({ app, db, requireUser, authorize, unitOfWork, issuances, reader, notifications });
  registerArchiveRoutes({ app, requireUser, authorize, unitOfWork, issuances, reader });
  registerIssuerRoutes({ app, requireUser, authorize, unitOfWork, reader });
  registerRevocationRoutes({ app, db, requireUser, unitOfWork, reader, issuers });
  registerHistory({ app, db, requireUser, reader });
  registerDeploymentScripts({ app, db, requireUser, authorize, unitOfWork });
  registerDeployments({ app, db, requireUser, authorize, unitOfWork, workItems, issuances, notifications });
  registerAgents({ app, db, requireUser, authorize, unitOfWork, clock, config: agentGateway, issuances });
  registerAgentGateway({ app, db, unitOfWork, workItems, clock, config: agentGateway });

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

  return { app, auth, db, unitOfWork, issuances, renewals, notifications, auditForwarding, crls, enrollmentValidators, deviceCertificatePruning, sharedChallengeExpiry, scep };
}
