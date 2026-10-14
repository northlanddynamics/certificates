// An Organization's SSO connections: the SAML or OIDC identity providers its users sign in through. Each is a row of
// Better Auth's SSO plugin (`sso_provider`), which signs users in through it (sso-sign-in.ts); the platform writes those
// rows itself, here, because the plugin's own endpoints ask for its built-in "owner" and "admin" roles and audit nothing.
//
// A connection belongs to exactly one Organization, and to one email domain, which no other connection may have: a
// user signing in by email is sent to the connection of their address's domain. The OIDC client secret is stored where
// the plugin reads it and is never returned, nor put in an Audit Event.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { computeDiscoveryUrl, DiscoveryError, fetchDiscoveryDocument, normalizeDiscoveryUrls, selectTokenEndpointAuthMethod, validateDiscoveryDocument } from "@better-auth/sso";
import { X509Certificate } from "@peculiar/x509";
import { and, asc, eq, sql } from "drizzle-orm";
import type { Authorizer } from "./authorization";
import type { Db, Tx } from "./db/client";
import { account, loginPolicy, ssoProvider } from "./db/schema";
import { HttpError, OrgParam, errors, json } from "./http";
import type { Actor, UnitOfWork } from "./unit-of-work";

type Row = typeof ssoProvider.$inferSelect;

/** What the plugin reads from `oidc_config`; the fields it finds there at sign-in. */
interface StoredOidc {
  issuer: string;
  clientId: string;
  clientSecret: string;
  discoveryEndpoint: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  tokenEndpointAuthentication: "client_secret_basic" | "client_secret_post";
  jwksEndpoint: string;
  userInfoEndpoint?: string;
  scopes?: string[];
  pkce: true;
  overrideUserInfo: false;
}

/** What the plugin reads from `saml_config`. Its `issuer` is the platform's own entity ID for the connection; the IdP's is `idpMetadata.entityID`. */
interface StoredSaml {
  issuer: string;
  entryPoint: string;
  cert: string;
  idpMetadata: { entityID: string };
  wantAssertionsSigned: true;
}

const Name = z.string().trim().min(1).max(100);
const Domain = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/, "a domain name, such as example.com")
  .openapi({ description: "The email domain the connection signs in: addresses in it and its subdomains, and no others." });
const Scopes = z.array(z.string().regex(/^[\x21\x23-\x5b\x5d-\x7e]+$/)).max(20);
const OidcInput = z.object({
  issuer: z.url({ protocol: /^https?$/ }).openapi({ description: "The provider's issuer; its discovery document is at <issuer>/.well-known/openid-configuration." }),
  clientId: z.string().min(1).max(500),
  clientSecret: z.string().min(1).max(2000).openapi({ description: "Write-only." }),
  scopes: Scopes.optional().openapi({ description: "Scopes to ask for; openid, email and profile unless given." }),
});
const SamlInput = z.object({
  entityId: z.string().trim().min(1).max(500).openapi({ description: "The identity provider's entity ID." }),
  ssoUrl: z.url({ protocol: /^https?$/ }).openapi({ description: "The identity provider's single sign-on URL (HTTP-Redirect binding)." }),
  certificate: z.string().min(1).max(20_000).openapi({ description: "The identity provider's signing certificate, PEM." }),
});
const Create = z
  .object({ name: Name, domain: Domain, oidc: OidcInput.optional(), saml: SamlInput.optional() })
  .refine((c) => Boolean(c.oidc) !== Boolean(c.saml), "exactly one of oidc and saml");

const Change = z.object({
  name: Name.optional(),
  domain: Domain.optional(),
  oidc: OidcInput.partial().optional(),
  saml: SamlInput.partial().optional(),
});

const Connection = z.object({
  id: z.string(),
  name: z.string(),
  type: z.enum(["oidc", "saml"]),
  domain: z.string(),
  oidc: z.object({ issuer: z.string(), clientId: z.string(), scopes: z.array(z.string()).optional() }).optional(),
  saml: z.object({ entityId: z.string(), ssoUrl: z.string(), certificate: z.object({ subject: z.string(), notAfter: z.string() }) }).optional(),
  serviceProvider: z
    .object({
      redirectUri: z.string().optional().openapi({ description: "OIDC: the redirect URI to register with the provider." }),
      entityId: z.string().optional().openapi({ description: "SAML: the platform's entity ID (audience) for this connection." }),
      acsUrl: z.string().optional().openapi({ description: "SAML: the assertion consumer service URL (HTTP-POST)." }),
      metadataUrl: z.string().optional().openapi({ description: "SAML: the platform's metadata for this connection." }),
    })
    .openapi({ description: "What the identity provider must be told about the platform." }),
});
type Connection = z.infer<typeof Connection>;

const ConnectionParams = OrgParam.extend({ connectionId: z.string().openapi({ param: { name: "connectionId", in: "path" } }) });

const certificateOf = (pem: string) => {
  try {
    const cert = new X509Certificate(pem.trim());
    return { subject: cert.subject, notBefore: cert.notBefore, notAfter: cert.notAfter, pem: cert.toString("pem") };
  } catch {
    throw new HttpError(400, "certificate: not a PEM X.509 certificate");
  }
};

export function registerSsoConnections(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  /** Where the API is served; Better Auth's endpoints are under /api/auth. */
  baseURL: string;
  clock: () => Date;
  /** Origins the platform may fetch from although they are not public (an IdP on a private network), as Better Auth's own. */
  trustedOrigins: string[];
}) {
  const { app, db, requireUser, authorize, unitOfWork } = ctx;
  const authBase = `${ctx.baseURL}/api/auth`;
  const trusted = new Set([ctx.baseURL, ...ctx.trustedOrigins].map((o) => new URL(o).origin));
  const isTrustedOrigin = (url: string) => {
    try {
      return trusted.has(new URL(url).origin);
    } catch {
      return false;
    }
  };

  const serviceProviderOf = (row: Row, type: "oidc" | "saml") =>
    type === "oidc"
      ? { redirectUri: `${authBase}/sso/callback/${row.providerId}` }
      : { entityId: spEntityId(row.providerId), acsUrl: `${authBase}/sso/saml2/sp/acs/${row.providerId}`, metadataUrl: spEntityId(row.providerId) };
  const spEntityId = (providerId: string) => `${authBase}/sso/saml2/sp/metadata?providerId=${encodeURIComponent(providerId)}`;

  function toConnection(row: Row): Connection {
    const base = { id: row.providerId, name: row.name, domain: row.domain };
    if (row.oidcConfig) {
      const oidc = JSON.parse(row.oidcConfig) as StoredOidc;
      return { ...base, type: "oidc", oidc: { issuer: oidc.issuer, clientId: oidc.clientId, ...(oidc.scopes && { scopes: oidc.scopes }) }, serviceProvider: serviceProviderOf(row, "oidc") };
    }
    const saml = JSON.parse(row.samlConfig ?? "{}") as StoredSaml;
    const cert = certificateOf(saml.cert);
    return {
      ...base,
      type: "saml",
      saml: { entityId: saml.idpMetadata.entityID, ssoUrl: saml.entryPoint, certificate: { subject: cert.subject, notAfter: cert.notAfter.toISOString() } },
      serviceProvider: serviceProviderOf(row, "saml"),
    };
  }

  /** The provider's endpoints, from its discovery document; a 400 that says what is wrong when they cannot be had. */
  async function discover(input: z.infer<typeof OidcInput>): Promise<Omit<StoredOidc, "clientId" | "clientSecret" | "scopes" | "pkce" | "overrideUserInfo">> {
    const discoveryEndpoint = computeDiscoveryUrl(input.issuer);
    try {
      const doc = await fetchDiscoveryDocument(discoveryEndpoint, 10_000, isTrustedOrigin);
      validateDiscoveryDocument(doc, input.issuer);
      const normalized = normalizeDiscoveryUrls(doc, input.issuer, isTrustedOrigin);
      const auth = selectTokenEndpointAuthMethod(normalized);
      return {
        issuer: normalized.issuer,
        discoveryEndpoint,
        authorizationEndpoint: normalized.authorization_endpoint,
        tokenEndpoint: normalized.token_endpoint,
        tokenEndpointAuthentication: auth === "client_secret_post" ? "client_secret_post" : "client_secret_basic",
        jwksEndpoint: normalized.jwks_uri,
        ...(normalized.userinfo_endpoint && { userInfoEndpoint: normalized.userinfo_endpoint }),
      };
    } catch (err) {
      if (err instanceof DiscoveryError) throw new HttpError(400, `oidc: ${err.message}`);
      throw err;
    }
  }

  /** Serialises changes to the connections of `domain`, so that two cannot take the same one. */
  const lockDomain = (tx: Tx, domain: string) => tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`sso-domain:${domain}`}))`);
  async function refuseTakenDomain(tx: Tx, domain: string, except?: string) {
    await lockDomain(tx, domain);
    const [taken] = await tx.select({ providerId: ssoProvider.providerId }).from(ssoProvider).where(eq(ssoProvider.domain, domain));
    if (taken && taken.providerId !== except) throw new HttpError(409, `an SSO connection for ${domain} already exists`);
  }

  async function findConnection(db: Db | Tx, orgId: string, connectionId: string, lock = false) {
    const query = db.select().from(ssoProvider).where(and(eq(ssoProvider.organizationId, orgId), eq(ssoProvider.providerId, connectionId)));
    const [row] = await (lock ? query.for("update") : query);
    if (!row) throw new HttpError(404, "SSO connection not found");
    return row;
  }

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/sso-connections",
      tags: ["Identity"],
      summary: "The Organization's SSO connections",
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(Connection) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { ssoConnection: ["read"] });
      const rows = await db.select().from(ssoProvider).where(eq(ssoProvider.organizationId, orgId)).orderBy(asc(ssoProvider.name), asc(ssoProvider.id));
      return c.json({ items: rows.map(toConnection) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/sso-connections",
      tags: ["Identity"],
      summary: "Add an SSO connection",
      description:
        "An OIDC connection is checked against its provider's discovery document before it is saved. Users whose email is in the domain then sign in through it, and are made Members of the Organization the first time. A change is an Audit Event.",
      request: { params: OrgParam, body: { content: { "application/json": { schema: Create } } } },
      responses: { 201: json(Connection, "Created"), ...errors(400, 401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const input = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { ssoConnection: ["create"] });
      const providerId = crypto.randomUUID();
      let config: { issuer: string; oidcConfig: string | null; samlConfig: string | null };
      if (input.oidc) {
        // The provider is asked outside any transaction.
        const discovered = await discover(input.oidc);
        const stored: StoredOidc = {
          ...discovered,
          clientId: input.oidc.clientId,
          clientSecret: input.oidc.clientSecret,
          scopes: input.oidc.scopes ?? ["openid", "email", "profile"],
          pkce: true,
          overrideUserInfo: false,
        };
        config = { issuer: discovered.issuer, oidcConfig: JSON.stringify(stored), samlConfig: null };
      } else {
        const saml = input.saml!;
        const stored: StoredSaml = {
          issuer: spEntityId(providerId),
          entryPoint: saml.ssoUrl,
          cert: certificateOf(saml.certificate).pem,
          idpMetadata: { entityID: saml.entityId },
          wantAssertionsSigned: true,
        };
        config = { issuer: stored.issuer, oidcConfig: null, samlConfig: JSON.stringify(stored) };
      }
      const created = await unitOfWork.run(actor, async (tx, change) => {
        await refuseTakenDomain(tx, input.domain);
        const [row] = await tx
          .insert(ssoProvider)
          .values({ id: crypto.randomUUID(), providerId, organizationId: orgId, userId: actor.id, name: input.name, domain: input.domain, domainVerified: true, ...config })
          .returning();
        const connection = toConnection(row!);
        await change.audit({ organizationId: orgId, action: "sso_connection.created", target: { type: "sso_connection", id: providerId }, detail: auditDetail(connection) });
        return connection;
      });
      return c.json(created, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/api/organizations/{orgId}/sso-connections/{connectionId}",
      tags: ["Identity"],
      summary: "Change an SSO connection",
      description:
        "Only what is given changes. Which identity provider the connection trusts (an OIDC issuer or client ID, a SAML entity ID) cannot change once anyone has signed in through it; a new client secret or signing certificate can. A change is an Audit Event.",
      request: { params: ConnectionParams, body: { content: { "application/json": { schema: Change } } } },
      responses: { 200: json(Connection), ...errors(400, 401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, connectionId } = c.req.valid("param");
      const input = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { ssoConnection: ["update"] });
      const existing = await findConnection(db, orgId, connectionId);
      if (input.oidc && !existing.oidcConfig) throw new HttpError(400, "oidc: this is a SAML connection");
      if (input.saml && !existing.samlConfig) throw new HttpError(400, "saml: this is an OIDC connection");
      const before = JSON.parse(existing.oidcConfig ?? "{}") as StoredOidc;
      // A new issuer is asked for its endpoints outside any transaction.
      const rediscovered =
        input.oidc?.issuer && input.oidc.issuer !== before.issuer
          ? await discover({ issuer: input.oidc.issuer, clientId: "", clientSecret: "" })
          : undefined;
      const changed = await unitOfWork.run(actor, async (tx, change) => {
        const row = await findConnection(tx, orgId, connectionId, true);
        const current = toConnection(row);
        const detail: Record<string, unknown> = {};
        const note = (field: string, from: unknown, to: unknown) => {
          if (to !== undefined && from !== to) detail[field] = { from, to };
        };
        const values: Partial<typeof ssoProvider.$inferInsert> = {};
        let identityChanged = false;
        if (input.name !== undefined && input.name !== row.name) {
          note("name", row.name, input.name);
          values.name = input.name;
        }
        if (input.domain !== undefined && input.domain !== row.domain) {
          await refuseTakenDomain(tx, input.domain, connectionId);
          note("domain", row.domain, input.domain);
          values.domain = input.domain;
        }
        if (input.oidc && row.oidcConfig) {
          const stored = JSON.parse(row.oidcConfig) as StoredOidc;
          // A change of issuer between asking it and now is lost to the later change; ask again.
          if (rediscovered && stored.issuer !== before.issuer) throw new HttpError(409, "the connection changed meanwhile; try again");
          const next: StoredOidc = {
            ...stored,
            ...rediscovered,
            ...(input.oidc.clientId !== undefined && { clientId: input.oidc.clientId }),
            ...(input.oidc.clientSecret !== undefined && { clientSecret: input.oidc.clientSecret }),
            ...(input.oidc.scopes !== undefined && { scopes: input.oidc.scopes }),
          };
          note("issuer", stored.issuer, next.issuer);
          note("clientId", stored.clientId, next.clientId);
          if (input.oidc.scopes !== undefined && JSON.stringify(stored.scopes) !== JSON.stringify(next.scopes)) detail.scopes = { from: stored.scopes, to: next.scopes };
          if (input.oidc.clientSecret !== undefined && next.clientSecret !== stored.clientSecret) detail.clientSecret = "replaced";
          identityChanged = next.issuer !== stored.issuer || next.clientId !== stored.clientId;
          values.oidcConfig = JSON.stringify(next);
          values.issuer = next.issuer;
        }
        if (input.saml && row.samlConfig) {
          const stored = JSON.parse(row.samlConfig) as StoredSaml;
          const cert = input.saml.certificate !== undefined ? certificateOf(input.saml.certificate) : undefined;
          const next: StoredSaml = {
            ...stored,
            ...(input.saml.ssoUrl !== undefined && { entryPoint: input.saml.ssoUrl }),
            ...(cert && { cert: cert.pem }),
            ...(input.saml.entityId !== undefined && { idpMetadata: { ...stored.idpMetadata, entityID: input.saml.entityId } }),
          };
          note("entityId", stored.idpMetadata.entityID, next.idpMetadata.entityID);
          note("ssoUrl", stored.entryPoint, next.entryPoint);
          if (cert && cert.pem !== stored.cert) detail.certificate = { from: current.saml!.certificate, to: { subject: cert.subject, notAfter: cert.notAfter.toISOString() } };
          identityChanged = next.idpMetadata.entityID !== stored.idpMetadata.entityID;
          values.samlConfig = JSON.stringify(next);
        }
        if (identityChanged) {
          const [linked] = await tx.select({ id: account.id }).from(account).where(eq(account.providerId, connectionId)).limit(1);
          if (linked) throw new HttpError(409, "users have signed in through this connection, so it cannot be pointed at another identity provider; add a new connection instead");
        }
        if (Object.keys(detail).length === 0) return current;
        const [updated] = await tx.update(ssoProvider).set(values).where(eq(ssoProvider.id, row.id)).returning();
        await change.audit({ organizationId: orgId, action: "sso_connection.changed", target: { type: "sso_connection", id: connectionId }, detail: { ...detail } });
        return toConnection(updated!);
      });
      return c.json(changed, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/api/organizations/{orgId}/sso-connections/{connectionId}",
      tags: ["Identity"],
      summary: "Delete an SSO connection",
      description:
        "Those who signed in through it can no longer; their accounts stay, as do their memberships. The Organization's last connection cannot be deleted while its login policy requires SSO. A deletion is an Audit Event.",
      request: { params: ConnectionParams },
      responses: { 204: { description: "Deleted" }, ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, connectionId } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { ssoConnection: ["delete"] });
      await unitOfWork.run(actor, async (tx, change) => {
        // Serialises with changes to the login policy (login-policy.ts), which take the same lock.
        await tx.insert(loginPolicy).values({ organizationId: orgId, updatedAt: change.occurredAt }).onConflictDoNothing();
        const [policy] = await tx.select({ requireSso: loginPolicy.requireSso }).from(loginPolicy).where(eq(loginPolicy.organizationId, orgId)).for("update");
        const row = await findConnection(tx, orgId, connectionId, true);
        if (policy?.requireSso) {
          const others = await tx.select({ id: ssoProvider.id }).from(ssoProvider).where(eq(ssoProvider.organizationId, orgId));
          if (others.length <= 1) throw new HttpError(409, "the Organization requires SSO, and this is its last connection; stop requiring SSO first");
        }
        await tx.delete(account).where(eq(account.providerId, connectionId));
        await tx.delete(ssoProvider).where(eq(ssoProvider.id, row.id));
        await change.audit({ organizationId: orgId, action: "sso_connection.deleted", target: { type: "sso_connection", id: connectionId }, detail: auditDetail(toConnection(row)) });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/sso-connections/{connectionId}/test",
      tags: ["Identity"],
      summary: "Test an SSO connection",
      description:
        "Checks the connection against its identity provider without signing anyone in: an OIDC provider's discovery document must still name its issuer and endpoints, a SAML signing certificate must be valid now. Always 200; `ok` says whether it passed and `error` why not. A test is an Audit Event.",
      request: { params: ConnectionParams },
      responses: { 200: json(z.object({ ok: z.boolean(), error: z.string().optional() }), "Whether the connection passed"), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, connectionId } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { ssoConnection: ["test"] });
      const row = await findConnection(db, orgId, connectionId);
      // The identity provider is asked outside any transaction: only the record of the test is written in one.
      const outcome: { ok: true } | { ok: false; error: string } = await check(row).then(
        () => ({ ok: true as const }),
        (err) => {
          if (!(err instanceof HttpError)) throw err;
          return { ok: false as const, error: err.message };
        },
      );
      await unitOfWork.run(actor, (_tx, change) =>
        change.audit({ organizationId: orgId, action: "sso_connection.tested", target: { type: "sso_connection", id: connectionId }, detail: outcome }),
      );
      return c.json(outcome, 200);
    },
  );

  async function check(row: Row) {
    if (row.oidcConfig) {
      const stored = JSON.parse(row.oidcConfig) as StoredOidc;
      const found = await discover({ issuer: stored.issuer, clientId: stored.clientId, clientSecret: "" });
      for (const field of ["authorizationEndpoint", "tokenEndpoint", "jwksEndpoint"] as const) {
        if (found[field] !== stored[field]) throw new HttpError(400, `oidc: the provider's ${field} is now ${found[field]}; change the issuer to fetch it again`);
      }
      return;
    }
    const stored = JSON.parse(row.samlConfig ?? "{}") as StoredSaml;
    const cert = certificateOf(stored.cert);
    const now = ctx.clock();
    if (now < cert.notBefore) throw new HttpError(400, `saml: the signing certificate is not valid until ${cert.notBefore.toISOString()}`);
    if (now > cert.notAfter) throw new HttpError(400, `saml: the signing certificate expired on ${cert.notAfter.toISOString()}`);
  }
}

/** A connection as its Audit Events record it: what identifies it, never its secret. */
function auditDetail(connection: Connection) {
  return {
    name: connection.name,
    type: connection.type,
    domain: connection.domain,
    issuer: connection.oidc?.issuer ?? connection.saml?.entityId,
    ...(connection.oidc && { clientId: connection.oidc.clientId }),
    ...(connection.saml && { ssoUrl: connection.saml.ssoUrl, certificateNotAfter: connection.saml.certificate.notAfter }),
  };
}
