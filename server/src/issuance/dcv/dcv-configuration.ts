// How an Organization sets up Delegated DCV and chooses the method per name: its Validation Zones, on its own DNS
// Providers, and its DCV Rules, which say for a name or a zone whether DCV is Direct or Delegated and through what.
// Every change is audited. What a rule means for a name, including the CNAME record a Delegated name needs, is in
// dcv-plan.ts, and is shown here as the platform will carry it out. There is no platform-wide Validation Zone: every
// zone is one Organization's own (ADR 0003).
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, eq } from "drizzle-orm";
import type { Authorizer } from "../../tenancy/authorization";
import type { Db } from "../../platform/db/client";
import { dcvRule, dnsProvider, validationZone } from "../../platform/db/schema";
import { DNS_PROVIDER_KINDS } from "./dns-provider-kinds";
import type { TxtResolver } from "./dcv";
import { HttpError, OrgParam, errors, isForeignKeyViolation, isUniqueViolation, json } from "../../platform/http";
import { normalizeDomain, normalizeName } from "../../pki/names";
import { DCV_METHODS, DCV_SCOPES, type DcvPlans, type DcvRule } from "./dcv-plan";
import type { Actor, UnitOfWork } from "../../platform/unit-of-work";

const ZoneParams = OrgParam.extend({ zoneId: z.string().openapi({ param: { name: "zoneId", in: "path" } }) });
const RuleParams = OrgParam.extend({ ruleId: z.string().openapi({ param: { name: "ruleId", in: "path" } }) });

const Zone = z.object({ id: z.string(), name: z.string(), dnsProviderId: z.string() });
const toZone = (row: typeof validationZone.$inferSelect) => ({ id: row.id, name: row.name, dnsProviderId: row.dnsProviderId });

const Rule = z.object({
  id: z.string(),
  scope: z.enum(DCV_SCOPES),
  domain: z.string(),
  method: z.enum(DCV_METHODS),
  dnsProviderId: z.string().nullable(),
  validationZoneId: z.string().nullable(),
});
const toRule = (row: DcvRule) => ({
  id: row.id,
  scope: row.scope,
  domain: row.domain,
  method: row.method,
  dnsProviderId: row.dnsProviderId,
  validationZoneId: row.validationZoneId,
});
/** A rule as an Audit Event records it: what it says, not which row. */
const ruleDetail = (row: DcvRule) => ({ scope: row.scope, domain: row.domain, method: row.method, validationZoneId: row.validationZoneId, dnsProviderId: row.dnsProviderId });

const RuleBody = z.object({
  scope: z.enum(DCV_SCOPES).openapi({ description: "`name`: that name only (and its wildcard). `zone`: the name and everything beneath it; the longest zone, and a name's own rule, win." }),
  domain: z.string().openapi({ description: "A host name, never a wildcard: a rule for `example.com` covers `*.example.com` too." }),
  method: z.enum(DCV_METHODS),
  dnsProviderId: z.string().nullish().openapi({ description: "Direct only: the DNS Provider to publish through. Without it, whichever publishes the name does." }),
  validationZoneId: z.string().nullish().openapi({ description: "Delegated only, and required then: the Validation Zone the challenge records are written in." }),
});

const notFound = (what: string) => new HttpError(404, `${what} not found`);
const isUuid = (id: string) => z.uuid().safeParse(id).success;

export function registerDcvConfiguration(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  dcvPlans: DcvPlans;
  /** The resolvers DCV looks records up through, for the preview to say whether a Delegated name's CNAME is in DNS yet. */
  resolver: Pick<TxtResolver, "lookupCname">;
}) {
  const { app, db, requireUser, authorize, unitOfWork, dcvPlans, resolver } = ctx;

  async function zoneOf(orgId: string, zoneId: string) {
    const [row] = isUuid(zoneId) ? await db.select().from(validationZone).where(and(eq(validationZone.organizationId, orgId), eq(validationZone.id, zoneId))) : [];
    if (!row) throw notFound("Validation Zone");
    return row;
  }

  async function ruleOf(orgId: string, ruleId: string) {
    const [row] = isUuid(ruleId) ? await db.select().from(dcvRule).where(and(eq(dcvRule.organizationId, orgId), eq(dcvRule.id, ruleId))) : [];
    if (!row) throw notFound("DCV Rule");
    return row;
  }

  /** A rule's body made into what is stored, or the reason it cannot be one. */
  async function checkedRule(orgId: string, body: z.infer<typeof RuleBody>) {
    const domain = normalizeDomain(body.domain);
    if (domain === null) throw new HttpError(400, "domain: must be a host name, not a wildcard (a rule for a name covers its wildcard too)");
    if (body.method === "delegated") {
      if (!body.validationZoneId) throw new HttpError(400, "validationZoneId: Delegated DCV needs a Validation Zone");
      if (body.dnsProviderId) throw new HttpError(400, "dnsProviderId: Delegated DCV writes through the Validation Zone's DNS Provider; leave it out");
    } else if (body.validationZoneId) {
      throw new HttpError(400, "validationZoneId: only Delegated DCV has a Validation Zone");
    }
    // Both must be the Organization's own.
    if (body.validationZoneId) await zoneOf(orgId, body.validationZoneId);
    if (body.dnsProviderId) {
      const [provider] = isUuid(body.dnsProviderId)
        ? await db.select({ id: dnsProvider.id }).from(dnsProvider).where(and(eq(dnsProvider.organizationId, orgId), eq(dnsProvider.id, body.dnsProviderId)))
        : [];
      if (!provider) throw notFound("DNS Provider");
    }
    return { scope: body.scope, domain, method: body.method, dnsProviderId: body.dnsProviderId ?? null, validationZoneId: body.validationZoneId ?? null };
  }

  /** What the CNAME `cname` names points to now, and whether that is where it should. */
  async function cnameInDns(cname: { name: string; value: string }) {
    const pointsTo = await resolver.lookupCname(cname.name);
    return { pointsTo, matches: pointsTo.includes(cname.value.toLowerCase()) };
  }

  const ruleTaken = (rule: { scope: string; domain: string }) => new HttpError(409, `the Organization already has a DCV Rule for the ${rule.scope} ${rule.domain}`);

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/validation-zones",
      tags: ["DCV"],
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(Zone) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { validationZone: ["read"] });
      const rows = await db.select().from(validationZone).where(eq(validationZone.organizationId, orgId)).orderBy(asc(validationZone.createdAt), asc(validationZone.id));
      return c.json({ items: rows.map(toZone) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/validation-zones",
      tags: ["DCV"],
      summary: "Define a Validation Zone",
      description:
        "A DNS zone, inside the zone of one of the Organization's DNS Providers, that `_acme-challenge` names are delegated into by CNAME. " +
        "The platform writes the challenge records of Delegated DCV there, so it needs no write access to the domains' own zones.",
      request: { params: OrgParam, body: { content: { "application/json": { schema: z.object({ name: z.string(), dnsProviderId: z.string() }) } } } },
      responses: { 201: json(Zone, "Created"), ...errors(400, 401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { validationZone: ["create"] });
      const [provider] = isUuid(body.dnsProviderId)
        ? await db.select().from(dnsProvider).where(and(eq(dnsProvider.organizationId, orgId), eq(dnsProvider.id, body.dnsProviderId)))
        : [];
      if (!provider) throw notFound("DNS Provider");
      const name = normalizeDomain(body.name);
      if (name === null) throw new HttpError(400, "name: must be a DNS zone name");
      const kind = DNS_PROVIDER_KINDS[provider.type];
      const settings = kind.settings.safeParse(provider.settings);
      if (!settings.success || kind.zoneOf(settings.data, name) === null) {
        throw new HttpError(400, `name: DNS Provider "${provider.name}" cannot publish records in ${name}; the zone must be inside the provider's own`);
      }
      try {
        const row = await unitOfWork.run(actor, async (tx, change) => {
          const [row] = await tx.insert(validationZone).values({ organizationId: orgId, name, dnsProviderId: provider.id }).returning();
          await change.audit({
            organizationId: orgId,
            action: "validation_zone.created",
            target: { type: "validation_zone", id: row!.id },
            detail: { name, dnsProviderId: provider.id },
          });
          return row!;
        });
        return c.json(toZone(row), 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw new HttpError(409, `the Organization already has a Validation Zone ${name}`);
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/api/organizations/{orgId}/validation-zones/{zoneId}",
      tags: ["DCV"],
      summary: "Remove a Validation Zone",
      description: "Refused while a DCV Rule delegates through it. The records the CNAMEs point into are not touched.",
      request: { params: ZoneParams },
      responses: { 200: json(z.object({ deleted: z.literal(true) })), ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, zoneId } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { validationZone: ["delete"] });
      const existing = await zoneOf(orgId, zoneId);
      try {
        await unitOfWork.run(actor, async (tx, change) => {
          const removed = await tx.delete(validationZone).where(eq(validationZone.id, existing.id)).returning({ id: validationZone.id });
          if (removed.length === 0) throw notFound("Validation Zone");
          await change.audit({
            organizationId: orgId,
            action: "validation_zone.deleted",
            target: { type: "validation_zone", id: existing.id },
            detail: { name: existing.name, dnsProviderId: existing.dnsProviderId },
          });
        });
      } catch (err) {
        // The rules reference it, and the database says so even if one was made just now.
        if (isForeignKeyViolation(err)) throw new HttpError(409, `a DCV Rule still delegates through the Validation Zone ${existing.name}; change or remove it first`);
        throw err;
      }
      return c.json({ deleted: true as const }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/dcv-rules",
      tags: ["DCV"],
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(Rule) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { dcvRule: ["read"] });
      const rows = await db.select().from(dcvRule).where(eq(dcvRule.organizationId, orgId)).orderBy(asc(dcvRule.createdAt), asc(dcvRule.id));
      return c.json({ items: rows.map(toRule) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/dcv-rules",
      tags: ["DCV"],
      summary: "Choose how DCV is done for a name or a zone",
      description:
        "Direct publishes the challenge record in the domain's own zone through a DNS Provider; Delegated publishes it in a Validation Zone that " +
        "`_acme-challenge.<name>` is a CNAME into (see `dcv/preview` for the record). Names under no rule are Direct, through whichever DNS Provider publishes them.",
      request: { params: OrgParam, body: { content: { "application/json": { schema: RuleBody } } } },
      responses: { 201: json(Rule, "Created"), ...errors(400, 401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { dcvRule: ["create"] });
      const values = await checkedRule(orgId, c.req.valid("json"));
      try {
        const row = await unitOfWork.run(actor, async (tx, change) => {
          const [row] = await tx.insert(dcvRule).values({ organizationId: orgId, ...values }).returning();
          await change.audit({ organizationId: orgId, action: "dcv_rule.created", target: { type: "dcv_rule", id: row!.id }, detail: ruleDetail(row!) });
          return row!;
        });
        return c.json(toRule(row), 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw ruleTaken(values);
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/api/organizations/{orgId}/dcv-rules/{ruleId}",
      tags: ["DCV"],
      summary: "Change a DCV Rule",
      description: "Replaces the whole rule.",
      request: { params: RuleParams, body: { content: { "application/json": { schema: RuleBody } } } },
      responses: { 200: json(Rule), ...errors(400, 401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, ruleId } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { dcvRule: ["update"] });
      const existing = await ruleOf(orgId, ruleId);
      const values = await checkedRule(orgId, c.req.valid("json"));
      try {
        const row = await unitOfWork.run(actor, async (tx, change) => {
          const [before] = await tx.select().from(dcvRule).where(eq(dcvRule.id, existing.id)).for("update");
          if (!before) throw notFound("DCV Rule");
          const [row] = await tx.update(dcvRule).set(values).where(eq(dcvRule.id, existing.id)).returning();
          await change.audit({
            organizationId: orgId,
            action: "dcv_rule.changed",
            target: { type: "dcv_rule", id: existing.id },
            detail: { ...ruleDetail(row!), previous: ruleDetail(before) },
          });
          return row!;
        });
        return c.json(toRule(row), 200);
      } catch (err) {
        if (isUniqueViolation(err)) throw ruleTaken(values);
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/api/organizations/{orgId}/dcv-rules/{ruleId}",
      tags: ["DCV"],
      summary: "Remove a DCV Rule",
      description: "Names it covered fall back to the rule above it, or to Direct DCV through whichever DNS Provider publishes them.",
      request: { params: RuleParams },
      responses: { 200: json(z.object({ deleted: z.literal(true) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, ruleId } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { dcvRule: ["delete"] });
      const existing = await ruleOf(orgId, ruleId);
      await unitOfWork.run(actor, async (tx, change) => {
        const removed = await tx.delete(dcvRule).where(eq(dcvRule.id, existing.id)).returning({ id: dcvRule.id });
        if (removed.length === 0) throw notFound("DCV Rule");
        await change.audit({ organizationId: orgId, action: "dcv_rule.deleted", target: { type: "dcv_rule", id: existing.id }, detail: ruleDetail(existing) });
      });
      return c.json({ deleted: true as const }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/dcv/preview",
      tags: ["DCV"],
      summary: "How DCV is done for a name, and the CNAME a Delegated name needs",
      description:
        "What DCV will do for `name` under the Organization's rules now. For a Delegated name, `cname` is the exact record the Organization " +
        "must create in the DNS of the name's own domain: `_acme-challenge.<name>` pointing into the Validation Zone. A wildcard shows its base name's record. " +
        "With `lookup=true`, `dns` also says what that name is a CNAME to now, as the platform's resolvers see it.",
      request: {
        params: OrgParam,
        query: z.object({
          name: z.string().openapi({ param: { name: "name", in: "query" } }),
          lookup: z.literal("true").optional().openapi({ param: { name: "lookup", in: "query" }, description: "Look the CNAME up in DNS." }),
        }),
      },
      responses: {
        200: json(
          z.object({
            name: z.string(),
            challengeName: z.string().openapi({ description: "Where the CA looks the challenge up." }),
            method: z.enum(DCV_METHODS),
            rule: z.object({ id: z.string(), scope: z.enum(DCV_SCOPES), domain: z.string() }).nullable().openapi({ description: "The rule that decides; null when none does." }),
            dnsProvider: z.object({ id: z.string(), name: z.string() }).nullable().openapi({ description: "The DNS Provider the record is written through; null when none can, which fails DCV." }),
            validationZone: z.object({ id: z.string(), name: z.string() }).nullable(),
            cname: z.object({ name: z.string(), type: z.literal("CNAME"), value: z.string() }).nullable(),
            dns: z
              .object({
                pointsTo: z.array(z.string()).openapi({ description: "What the CNAME at `cname.name` points to now; none when it is not there." }),
                matches: z.boolean().openapi({ description: "Whether it points to `cname.value`, as DCV needs." }),
              })
              .nullable()
              .optional()
              .openapi({ description: "Only with `lookup=true`: what DNS holds for `cname`; null when the name needs no CNAME." }),
          }),
        ),
        ...errors(400, 401, 403, 404),
      },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const { name: asked, lookup } = c.req.valid("query");
      await authorize(await requireUser(c), orgId, { dcvRule: ["read"] });
      const name = normalizeName(asked);
      if (name === null) throw new HttpError(400, "name: must be a DNS name, or a wildcard of one");
      const plan = await dcvPlans.plan(db, orgId, name);
      return c.json(
        {
          name: plan.name,
          challengeName: plan.challengeName,
          method: plan.method,
          rule: plan.rule && { id: plan.rule.id, scope: plan.rule.scope, domain: plan.rule.domain },
          dnsProvider: plan.dnsProvider,
          validationZone: plan.validationZone,
          cname: plan.cname,
          ...(lookup && { dns: plan.cname && (await cnameInDns(plan.cname)) }),
        },
        200,
      );
    },
  );
}
