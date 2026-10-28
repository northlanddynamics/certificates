import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { Scalar } from "@scalar/hono-api-reference";
import { and, asc, eq } from "drizzle-orm";
import type { Context } from "hono";
import type { Pool } from "pg";
import { DEFAULT_ADCS_RELAY, registerAdcsCas, type AdcsRelayConfig } from "./adcs/adcs-ca";
import { ACCOUNT_SECURITY_PATHS, createAccountSecurity } from "./tenancy/account-security";
import { registerAcmeAccounts } from "./issuance/acme/acme-accounts";
import { DEFAULT_AGENT_GATEWAY, registerAgentGateway, type AgentGatewayConfig } from "./agents/agent-gateway";
import { registerAgents } from "./agents/agents";
import { registerApiKeys } from "./tenancy/api-keys";
import { PLATFORM_OPERATOR_ROLE, createAuth } from "./tenancy/auth";
import { registerCertificateExport } from "./certificates/certificate-export";
import type { AcmeCertificateAuthority } from "./issuance/acme/certificate-authority";
import { createAcmeCas, type BuiltInAcmeCaId } from "./issuance/acme/acme-cas";
import { registerDeploymentScripts } from "./deployment/deployment-scripts";
import { registerDeployments } from "./deployment/deployments";
import { registerDcvConfiguration } from "./issuance/dcv/dcv-configuration";
import { createDcvPlans } from "./issuance/dcv/dcv-plan";
import { DEFAULT_DCV_CONFIG, createDcv, createTxtResolver, type DcvConfig } from "./issuance/dcv/dcv";
import { createAuditForwarding, registerAuditForwarders } from "./audit/audit-forwarding";
import { registerAuditRoutes } from "./audit/audit-routes";
import { createAuditTransport, type AuditTransport } from "./audit/audit-transport";
import { createCrls, registerPkiRoutes } from "./private-ca/crl";
import { createDb } from "./platform/db/client";
import { createDeviceCertificateRevocations } from "./enrollment/device-certificate-revocation";
import { registerDeviceCertificates } from "./enrollment/device-certificates";
import { createDeviceCertificatePruning } from "./enrollment/device-certificate-pruning";
import { createDeviceEnrollment } from "./enrollment/device-enrollment";
import { createEnrollmentIssuers } from "./enrollment/enrollment-issuer";
import { createSharedChallenges } from "./enrollment/shared-challenge";
import { registerEnrollmentProfiles } from "./enrollment/enrollment-profiles";
import type { EnrollmentValidators } from "./enrollment/enrollment-validator";
import { ENROLLMENT_VALIDATOR_KINDS } from "./enrollment/enrollment-validator-kinds";
import { createEnrollmentValidatorRuns } from "./enrollment/enrollment-validators";
import { DEFAULT_DNS_RELAY, createDnsRelay, type DnsRelayConfig } from "./issuance/dcv/dns-relay";
import { createDnsProviders, registerDnsProviders } from "./issuance/dcv/dns-providers";
import { certificateProfileSettings, member, organization } from "./platform/db/schema";
import { createAuthorizer } from "./tenancy/authorization";
import { HttpError, errors, json } from "./platform/http";
import { createIssuances } from "./issuance/issuance";
import { createIssuers, type Issuers } from "./issuance/issuer";
import type { Kms } from "./platform/crypto/kms";
import { registerApprovals } from "./certificates/approvals";
import { registerArchiveRoutes } from "./certificates/archive-routes";
import { registerHistory } from "./certificates/history";
import { registerIssuerRoutes } from "./issuance/issuer-routes";
import { createManagedCertificateReader } from "./certificates/managed-certificate-reader";
import { registerManagedCertificates } from "./certificates/managed-certificates";
import { registerCertificateProfiles } from "./certificates/certificate-profiles";
import { registerCertificateProfileSettings, requestsWithoutProfile } from "./certificates/certificate-profile-settings";
import { registerProfileDetachRoutes } from "./certificates/profile-detach-routes";
import { discardNameChangesOfRemoved } from "./certificates/name-change";
import { registerNameChangeRoutes } from "./certificates/name-change-routes";
import { registerOwnerRoutes } from "./certificates/owner-routes";
import { createRenewalScheduler } from "./issuance/renewal-scheduler";
import { registerRenewalRoutes } from "./issuance/renewal-routes";
import { registerRevocationRoutes } from "./issuance/revocation-routes";
import { createRevocations } from "./issuance/revocations";
import type { Mailer } from "./platform/mailer";
import type { MemberRemovalHook } from "./tenancy/member-removal";
import { removeTeamFromOwners, removeUserFromOwners } from "./certificates/owners";
import { createLoginPolicies, registerLoginPolicy } from "./tenancy/login-policy";
import { createOrganizationChanges } from "./tenancy/organization-changes";
import { registerNotificationChannels } from "./notifications/notification-channels";
import { createFetchWebhooks, createNotifications, type WebhookSender } from "./notifications/notifications";
import { registerSubscriberRoutes } from "./certificates/subscriber-routes";
import { removeTeamFromSubscribers, removeUserFromSubscribers } from "./certificates/subscribers";
import { createOrganizations } from "./tenancy/organizations";
import { createPrivateCas, registerPrivateCas } from "./private-ca/private-ca";
import { ROLE_NAMES, permissionsOf, roleCan } from "./tenancy/permissions";
import { registerScep, type ScepConfig } from "./enrollment/scep";
import { createScepTransactions } from "./enrollment/scep-transactions";
import { createSecrets } from "./platform/crypto/secrets";
import { registerSsoConnections } from "./tenancy/sso-connections";
import { provisionOnSsoSignIn } from "./tenancy/sso-sign-in";
import { registerTeamsOverview } from "./tenancy/teams-overview";
import { createUnitOfWork } from "./platform/unit-of-work";
import { createWorkItems } from "./agents/work-items";

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
  /** How the platform talks to an ACME CA: the CA of a Managed Certificate whose issuer is of the ACME kind (issuer.ts). */
  certificateAuthority: AcmeCertificateAuthority;
  /** Where the built-in ACME CAs' directories are served, by id; Let's Encrypt's own unless given (tests point them at Pebble). Read each time it is needed. */
  builtInAcmeDirectories?: Partial<Record<BuiltInAcmeCaId, string>>;
  /** How DCV checks that a challenge record is visible; the host's DNS resolvers, waiting up to two minutes, unless given. */
  dcv?: Partial<DcvConfig>;
  /** How the Agent protocol is run: see `AgentGatewayConfig` for what each setting is and its default. */
  agentGateway?: Partial<AgentGatewayConfig>;
  /** How DNS Provider operations relayed by Agents wait for them: see `DnsRelayConfig`. */
  dnsRelay?: Partial<DnsRelayConfig>;
  /** How ADCS CA operations wait for the Agents that carry them out: see `AdcsRelayConfig`. */
  adcsRelay?: Partial<AdcsRelayConfig>;
  /** How Audit Events reach the Organizations' SIEMs; posts with `fetch` and writes syslog over TLS unless given. */
  auditTransport?: AuditTransport;
  /** See `OrganizationChangesDeps.memberRemovalHooks`. */
  memberRemovalHooks?: MemberRemovalHook[];
  /** The Enrollment Validator kinds Enrollment Profiles can name, by name (enrollment-validator.ts); ENROLLMENT_VALIDATOR_KINDS unless given. */
  enrollmentValidators?: EnrollmentValidators;
  /** How the SCEP routes are rate limited and tell devices apart: see `ScepConfig`. */
  scep?: Partial<ScepConfig>;
  /** Certificates' issuers (issuer.ts) as the platform reaches them: its own, unless a test wraps them in a test-only kind. */
  issuers?: (platform: Issuers) => Issuers;
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
    if (err instanceof HttpError) return c.json({ ...err.detail, error: err.message }, err.status);
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
                // Whether they may request a Managed Certificate without a Certificate Profile: not while one is required of those who may not create one outright.
                requestsWithoutProfile: z.boolean(),
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
        .select({ id: organization.id, name: organization.name, slug: organization.slug, role: member.role, requireProfile: certificateProfileSettings.requireProfile })
        .from(member)
        .innerJoin(organization, eq(organization.id, member.organizationId))
        .leftJoin(certificateProfileSettings, eq(certificateProfileSettings.organizationId, member.organizationId))
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
          organizations: organizations.map(({ requireProfile, ...o }) => ({
            ...o,
            permissions: permissionsOf(o.role),
            requestsWithoutProfile: requestsWithoutProfile({ requireProfile: requireProfile ?? false }, roleCan(o.role, { managedCertificate: ["create"] })),
          })),
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
  const acmeCas = createAcmeCas({ db, directoryUrls: deps.builtInAcmeDirectories });
  registerAcmeAccounts({ app, db, requireUser, authorize, unitOfWork, secrets, certificateAuthority: deps.certificateAuthority, acmeCas });
  const agentGateway = { ...DEFAULT_AGENT_GATEWAY, ...deps.agentGateway };
  const dnsRelayConfig = { ...DEFAULT_DNS_RELAY, ...deps.dnsRelay };
  const workItems = createWorkItems({ db, unitOfWork, pollMs: dnsRelayConfig.pollMs, maxWaitMs: dnsRelayConfig.maxWaitMs, clock });
  const dnsRelay = createDnsRelay({ db, workItems, secrets, clock, offlineAfterSeconds: agentGateway.offlineAfterSeconds, config: dnsRelayConfig });
  const dnsProviders = createDnsProviders(secrets, dnsRelay);
  registerDnsProviders({ app, db, requireUser, authorize, unitOfWork, secrets, dnsProviders, relay: dnsRelay });
  const dcvPlans = createDcvPlans(dnsProviders);
  const dcvConfig = { resolver: createTxtResolver(), ...DEFAULT_DCV_CONFIG, ...deps.dcv };
  registerDcvConfiguration({ app, db, requireUser, authorize, unitOfWork, dcvPlans, resolver: dcvConfig.resolver });
  const dcv = createDcv(dnsProviders, dcvPlans, dcvConfig);
  const pkiBaseURL = deps.pkiBaseURL ?? deps.baseURL;
  const crls = createCrls({ db, unitOfWork, kms: deps.kms, clock });
  registerPrivateCas({ app, db, requireUser, authorize, unitOfWork, kms: deps.kms, clock, crls, pkiBaseURL, pkiBaseURLConfigured: deps.pkiBaseURL !== undefined });
  registerPkiRoutes({ app, db });
  const adcsDiscovery = registerAdcsCas({ app, db, requireUser, authorize, unitOfWork, workItems, clock, offlineAfterSeconds: agentGateway.offlineAfterSeconds, config: { ...DEFAULT_ADCS_RELAY, ...deps.adcsRelay } });
  const privateCas = createPrivateCas({ kms: deps.kms, clock, crls, pkiBaseURL });
  const validatorKinds = deps.enrollmentValidators ?? ENROLLMENT_VALIDATOR_KINDS;
  const platformIssuers = createIssuers({ acme: deps.certificateAuthority, acmeCas, secrets, privateCas });
  const issuers = deps.issuers?.(platformIssuers) ?? platformIssuers;
  const certificateRevocations = createRevocations({ db, unitOfWork, issuers, clock });
  const revocations = createDeviceCertificateRevocations({ revocations: certificateRevocations });
  const enrollmentValidators = createEnrollmentValidatorRuns({ db, unitOfWork, secrets, revocations, kinds: validatorKinds, clock });
  const sharedChallenges = createSharedChallenges({ db, unitOfWork, clock });
  const enrollmentIssuers = createEnrollmentIssuers({ privateCas });
  registerEnrollmentProfiles({ app, db, requireUser, authorize, unitOfWork, secrets, issuers: enrollmentIssuers, kinds: validatorKinds, validators: enrollmentValidators, sharedChallenges, baseURL: deps.baseURL, clock });
  registerDeviceCertificates({ app, db, requireUser, authorize, unitOfWork, revocations, clock });
  const deviceCertificatePruning = createDeviceCertificatePruning({ db, unitOfWork, clock });
  const deviceEnrollment = createDeviceEnrollment({ db, unitOfWork, issuers: enrollmentIssuers, revocations, sharedChallenges, kinds: validatorKinds, validators: enrollmentValidators, transactions: createScepTransactions({ db, clock }), clock });
  const scep = registerScep({ app, db, secrets, issuers: enrollmentIssuers, enrollment: deviceEnrollment, kinds: validatorKinds, clock, config: deps.scep });
  const issuances = createIssuances({ db, unitOfWork, issuers, dcv, clock });
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
  const apiKeys = registerApiKeys({ app, db, auth, authConfig, requireUser, authorize, admit: loginPolicies.admit, unitOfWork });
  registerManagedCertificates({ app, db, requireUser, authorize, apiKeys, unitOfWork, issuances, reader, acmeCas, clock, agentOfflineAfterSeconds: agentGateway.offlineAfterSeconds });
  registerCertificateProfiles({ app, db, requireUser, authorize, unitOfWork, acmeCas });
  registerCertificateProfileSettings({ app, db, requireUser, authorize, unitOfWork });
  registerCertificateExport({ app, db, apiKeys, unitOfWork, reader, issuers });
  registerOwnerRoutes({ app, requireUser, unitOfWork, reader });
  registerSubscriberRoutes({ app, db, requireUser, unitOfWork, reader });
  registerRenewalRoutes({ app, db, requireUser, unitOfWork, issuances, reader });
  const renewals = createRenewalScheduler({ db, unitOfWork, issuances, issuers, notifications, clock });
  registerNameChangeRoutes({ app, requireUser, authorize, unitOfWork, issuances, reader, notifications });
  registerApprovals({ app, db, requireUser, authorize, unitOfWork, issuances, reader, notifications });
  registerArchiveRoutes({ app, requireUser, authorize, unitOfWork, issuances, reader });
  registerIssuerRoutes({ app, requireUser, authorize, unitOfWork, reader });
  registerProfileDetachRoutes({ app, requireUser, authorize, unitOfWork, reader });
  registerRevocationRoutes({ app, db, requireUser, unitOfWork, reader, revocations: certificateRevocations });
  registerHistory({ app, db, requireUser, reader });
  registerDeploymentScripts({ app, db, requireUser, authorize, unitOfWork });
  registerDeployments({ app, db, requireUser, authorize, unitOfWork, workItems, issuances, notifications, acmeCas });
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

  return { app, auth, db, unitOfWork, issuances, renewals, adcsDiscovery, notifications, auditForwarding, crls, enrollmentValidators, deviceCertificatePruning, sharedChallenges, deviceCertificateRevocations: revocations, revocations: certificateRevocations, deviceEnrollment, scep };
}
