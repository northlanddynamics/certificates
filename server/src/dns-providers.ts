// An Organization's DNS Providers: its connections to the DNS services that publish Domain Control Validation
// records. What each kind of service needs is in dns-provider.ts and its own module; this is what they share:
// storing the settings, keeping the secret write-only (secrets.ts), auditing, and handing a ready DnsProvider to
// whoever needs one (`open`).
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, eq } from "drizzle-orm";
import type { Authorizer } from "./authorization";
import type { Db, Tx } from "./db/client";
import { dnsProvider } from "./db/schema";
import { DnsProviderError, type DnsProvider } from "./dns-provider";
import { DNS_PROVIDER_KINDS, DNS_PROVIDER_TYPES } from "./dns-provider-kinds";
import { HttpError, OrgParam, errors, isUniqueViolation, json } from "./http";
import type { Secrets } from "./secrets";
import type { Actor, UnitOfWork } from "./unit-of-work";

type Row = typeof dnsProvider.$inferSelect;

export interface DnsProviders {
  /** The Organization's DNS Provider `providerId`, ready to use: the one way anything else gets at a provider and its secret. Throws when there is no such provider. */
  open(db: Db | Tx, organizationId: string, providerId: string): Promise<DnsProvider>;
  /**
   * The Organization's DNS Provider that publishes records at `name`, ready to use: of those whose zone contains the
   * name, the one with the most specific zone (earliest added when two have the same). Null when none does.
   */
  findFor(db: Db | Tx, organizationId: string, name: string): Promise<{ id: string; name: string; zone: string; provider: DnsProvider } | null>;
}

export function createDnsProviders(secrets: Secrets): DnsProviders {
  async function build(db: Db | Tx, row: Row) {
    const kind = DNS_PROVIDER_KINDS[row.type];
    return kind.create(kind.settings.parse(row.settings), await secrets.open(db, row.organizationId, row.secretId));
  }

  return {
    async open(db, organizationId, providerId) {
      const [row] = await db
        .select()
        .from(dnsProvider)
        .where(and(eq(dnsProvider.organizationId, organizationId), eq(dnsProvider.id, providerId)));
      if (!row) throw new Error("no such DNS Provider");
      return build(db, row);
    },
    async findFor(db, organizationId, name) {
      const rows = await db
        .select()
        .from(dnsProvider)
        .where(eq(dnsProvider.organizationId, organizationId))
        .orderBy(asc(dnsProvider.createdAt), asc(dnsProvider.id));
      let best: { row: Row; zone: string } | undefined;
      for (const row of rows) {
        const kind = DNS_PROVIDER_KINDS[row.type];
        // A provider whose stored settings can no longer be read covers nothing.
        const settings = kind.settings.safeParse(row.settings);
        const zone = settings.success ? kind.zoneOf(settings.data, name) : null;
        if (zone !== null && (!best || zone.length > best.zone.length)) best = { row, zone };
      }
      return best ? { id: best.row.id, name: best.row.name, zone: best.zone, provider: await build(db, best.row) } : null;
    },
  };
}

const ProviderParams = OrgParam.extend({ providerId: z.string().openapi({ param: { name: "providerId", in: "path" } }) });
const Name = z.string().trim().min(1).max(100);
// Deliberately without the secret: this is every shape a provider is ever returned in.
const Provider = z.object({
  id: z.string(),
  name: Name,
  type: z.enum(DNS_PROVIDER_TYPES),
  settings: z.record(z.string(), z.unknown()).openapi({ description: "The type's non-secret configuration." }),
});
const toProvider = (row: Row) => ({ id: row.id, name: row.name, type: row.type, settings: row.settings });

const nameTaken = (name: string) => new HttpError(409, `the Organization already has a DNS Provider named "${name}"`);

/** What is wrong with `input` as seen by `schema`, as a message that quotes none of it. */
function refuse<T>(what: string, schema: z.ZodType<T>, input: unknown): T {
  const parsed = schema.safeParse(input);
  if (parsed.success) return parsed.data;
  throw new HttpError(400, `${what}: ${parsed.error.issues.map((i) => [...i.path, i.message].join(": ")).join("; ")}`);
}

export function registerDnsProviders(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  secrets: Secrets;
  dnsProviders: DnsProviders;
}) {
  const { app, db, requireUser, authorize, unitOfWork, secrets, dnsProviders } = ctx;

  async function findProvider(orgId: string, providerId: string) {
    // Not a UUID can't be a provider; asking Postgres would only raise a type error.
    const [row] = z.uuid().safeParse(providerId).success
      ? await db.select().from(dnsProvider).where(and(eq(dnsProvider.organizationId, orgId), eq(dnsProvider.id, providerId)))
      : [];
    if (!row) throw new HttpError(404, "DNS Provider not found");
    return row;
  }

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/dns-providers",
      tags: ["DNS Providers"],
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(Provider) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { dnsProvider: ["read"] });
      const rows = await db
        .select()
        .from(dnsProvider)
        .where(eq(dnsProvider.organizationId, orgId))
        .orderBy(asc(dnsProvider.createdAt), asc(dnsProvider.id));
      return c.json({ items: rows.map(toProvider) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/dns-providers",
      tags: ["DNS Providers"],
      summary: "Connect a DNS Provider",
      description:
        "`settings` and `secret` are those of the `type`. For `rfc2136`: settings `server`, `port` (53), `zone`, `keyName` and " +
        "`algorithm` (hmac-sha256), and the TSIG key's secret, base64, as `secret`. The secret is write-only: nothing returns it.",
      request: {
        params: OrgParam,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                name: Name,
                type: z.enum(DNS_PROVIDER_TYPES),
                settings: z.record(z.string(), z.unknown()),
                secret: z.string().min(1),
              }),
            },
          },
        },
      },
      responses: { 201: json(Provider, "Created"), ...errors(400, 401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { dnsProvider: ["create"] });
      const kind = DNS_PROVIDER_KINDS[body.type];
      const settings = refuse("settings", kind.settings, body.settings);
      const secret = refuse("secret", kind.secret, body.secret);
      try {
        const row = await unitOfWork.run(actor, async (tx, change) => {
          const secretId = await secrets.create(tx, orgId, secret);
          const [row] = await tx
            .insert(dnsProvider)
            .values({ organizationId: orgId, name: body.name, type: body.type, settings, secretId })
            .returning();
          await change.audit({
            organizationId: orgId,
            action: "dns_provider.created",
            target: { type: "dns_provider", id: row!.id },
            detail: { name: body.name, type: body.type, settings },
          });
          return row!;
        });
        return c.json(toProvider(row), 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw nameTaken(body.name);
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/api/organizations/{orgId}/dns-providers/{providerId}",
      tags: ["DNS Providers"],
      summary: "Change a DNS Provider's name and settings",
      description: "Replaces the name and all the settings; the type and the secret stay. Replace the secret with its own call.",
      request: {
        params: ProviderParams,
        body: { content: { "application/json": { schema: z.object({ name: Name, settings: z.record(z.string(), z.unknown()) }) } } },
      },
      responses: { 200: json(Provider), ...errors(400, 401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, providerId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { dnsProvider: ["update"] });
      const existing = await findProvider(orgId, providerId);
      const settings = refuse("settings", DNS_PROVIDER_KINDS[existing.type].settings, body.settings);
      try {
        const row = await unitOfWork.run(actor, async (tx, change) => {
          const [before] = await tx.select().from(dnsProvider).where(eq(dnsProvider.id, existing.id)).for("update");
          const [row] = await tx.update(dnsProvider).set({ name: body.name, settings }).where(eq(dnsProvider.id, existing.id)).returning();
          await change.audit({
            organizationId: orgId,
            action: "dns_provider.changed",
            target: { type: "dns_provider", id: existing.id },
            detail: { name: body.name, type: existing.type, settings, previous: { name: before!.name, settings: before!.settings } },
          });
          return row!;
        });
        return c.json(toProvider(row), 200);
      } catch (err) {
        if (isUniqueViolation(err)) throw nameTaken(body.name);
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/api/organizations/{orgId}/dns-providers/{providerId}/secret",
      tags: ["DNS Providers"],
      summary: "Replace the DNS Provider's secret",
      description: "Secrets are write-only: nothing returns the stored one. Test the connection afterwards to see that it works.",
      request: {
        params: ProviderParams,
        body: { content: { "application/json": { schema: z.object({ secret: z.string().min(1) }) } } },
      },
      responses: { 200: json(Provider), ...errors(400, 401, 403, 404) },
    }),
    async (c) => {
      const { orgId, providerId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { dnsProvider: ["update"] });
      const existing = await findProvider(orgId, providerId);
      const secret = refuse("secret", DNS_PROVIDER_KINDS[existing.type].secret, body.secret);
      await unitOfWork.run(actor, async (tx, change) => {
        await secrets.replace(tx, orgId, existing.secretId, secret);
        await change.audit({
          organizationId: orgId,
          action: "dns_provider.secret_replaced",
          target: { type: "dns_provider", id: existing.id },
        });
      });
      return c.json(toProvider(existing), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/dns-providers/{providerId}/test",
      tags: ["DNS Providers"],
      summary: "Test the connection",
      description: "Publishes a TXT record in the zone and removes it again. Always 200; `ok` says whether it worked and `error` why not.",
      request: { params: ProviderParams },
      responses: {
        200: json(z.object({ ok: z.boolean(), error: z.string().optional() }), "Whether the provider could publish and remove a record"),
        ...errors(401, 403, 404),
      },
    }),
    async (c) => {
      const { orgId, providerId } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { dnsProvider: ["test"] });
      const existing = await findProvider(orgId, providerId);
      // The DNS server is asked outside any transaction: only the record of the test is written in one.
      const outcome: { ok: true } | { ok: false; error: string } = await dnsProviders
        .open(db, orgId, existing.id)
        .then(
          (provider) => provider.testConnection(),
          // Stored settings or a secret that can no longer be used are as much a failed test as a server that says no.
          () => Promise.reject(new DnsProviderError("rejected", "the stored settings or secret cannot be used; change the settings or replace the secret")),
        )
        .then(
          () => ({ ok: true as const }),
          (err) => {
            if (!(err instanceof DnsProviderError)) throw err;
            return { ok: false as const, error: err.message };
          },
        );
      await unitOfWork.run(actor, (_tx, change) =>
        change.audit({ organizationId: orgId, action: "dns_provider.tested", target: { type: "dns_provider", id: existing.id }, detail: outcome }),
      );
      return c.json(outcome, 200);
    },
  );
}
