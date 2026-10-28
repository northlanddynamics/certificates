// An Organization's ADCS CAs: its Active Directory Certificate Services CAs, which the platform reaches only through the
// Agents assigned to each (ADR 0013). An Organization Administrator adds one by its name and config string (`host\CA Name`)
// and assigns it Windows Agents of the Organization; adding it has an online assigned Agent discover it (`adcs.discover`):
// fetch its CA certificate and chain and list its Certificate Templates with their facts, and nothing is saved unless one
// does. Discovery runs again on Refresh and once a day, and refreshes the chain and the templates' facts each time: a
// template no longer reported is kept, as unavailable, since what names it must keep its issuer, and a discovery that
// fails is recorded and changes nothing else. An Organization Administrator may hide a template from being offered.
// Everyone in the Organization may see them, their templates and their chains. The platform holds no AD credential and
// no ADCS key: each Agent acts as its own account.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import * as x509 from "@peculiar/x509";
import { and, asc, eq, inArray, sql } from "drizzle-orm";
import type { Context } from "hono";
import { CONFIG_STRING, TEMPLATE_PURPOSES, isAvailable, offeredFor, unavailableReason, type TemplateFacts } from "./adcs-kinds";
import { ADCS_WORK_TYPES, DiscoveryResult } from "./adcs-work";
import { NoAgentAnswered, relayToAgents } from "../agents/agent-relay";
import type { WorkItems } from "../agents/work-items";
import type { Authorizer } from "../tenancy/authorization";
import type { Db, Tx } from "../platform/db/client";
import { adcsCa, adcsCaAgent, adcsTemplate, agent } from "../platform/db/schema";
import { HttpError, OrgParam, PemResponse, errors, fileNameOf, isForeignKeyViolation, isUniqueViolation, json, pemFile } from "../platform/http";
import { fingerprintOf } from "../pki/fingerprint";
import type { Actor, Change, UnitOfWork } from "../platform/unit-of-work";

type AdcsCaRow = typeof adcsCa.$inferSelect;
type TemplateRow = typeof adcsTemplate.$inferSelect;

export interface AdcsRelayConfig {
  /** How long one Agent has to report on an ADCS operation before another online one is tried. */
  attemptTimeoutMs: number;
}

export const DEFAULT_ADCS_RELAY: AdcsRelayConfig = { attemptTimeoutMs: 60_000 };

/** How long after its last discovery the scheduler discovers an ADCS CA again, whether that one succeeded or failed. */
export const DISCOVERY_INTERVAL_MS = 24 * 3600_000;

/** The most Agents one ADCS CA may be assigned. */
export const MAX_ADCS_AGENTS = 20;

const AdcsCaParams = OrgParam.extend({ id: z.string().openapi({ param: { name: "id", in: "path" } }) });
const TemplateParams = AdcsCaParams.extend({ templateId: z.string().openapi({ param: { name: "templateId", in: "path" } }) });
const Name = z.string().trim().min(1).max(100);
const ConfigString = z
  .string()
  .trim()
  .max(255)
  .regex(CONFIG_STRING, "a config string is the CA's host, a backslash and its name: host\\CA Name")
  .openapi({ description: "How ADCS names the CA: its host, a backslash and the CA's name, such as `ca01.corp.example\\Corp Issuing CA`." });
const AgentIds = z
  .array(z.string())
  .min(1)
  .max(MAX_ADCS_AGENTS)
  .openapi({ description: "Agents of the Organization, on domain-joined Windows hosts, that carry out the CA's operations: any one that is online does." });

const CertificateShown = z.object({
  subject: z.string(),
  issuer: z.string(),
  notBefore: z.string(),
  notAfter: z.string(),
  fingerprint: z.string().openapi({ description: "SHA-256 of its DER, lower-case hex." }),
});

const Template = z.object({
  id: z.string(),
  name: z.string().openapi({ description: "Its ADCS name, which requests name it by." }),
  oid: z.string(),
  displayName: z.string(),
  extendedKeyUsages: z.array(z.string()).openapi({ description: "Its EKUs, as OIDs." }),
  validityDays: z.number().int().openapi({ description: "How long what it issues is valid for, in days: the template decides, not the platform." }),
  minimumKeySize: z.number().int(),
  keyAlgorithms: z.array(z.string()),
  managerApproval: z.boolean().openapi({ description: "Whether a request under it waits for a CA manager's approval at ADCS." }),
  subjectFromRequest: z.boolean().openapi({ description: "Whether it is set to \"Supply in the request\"." }),
  enrollable: z.boolean().openapi({ description: "Whether the Agents' account may enroll on it." }),
  published: z.boolean().openapi({ description: "Whether the CA publishes it." }),
  reported: z.boolean().openapi({ description: "Whether the CA's last discovery reported it. One no longer reported is kept, as unavailable, and is available again when it comes back." }),
  available: z.boolean().openapi({ description: "Whether the platform can issue under it: it is reported, published, enrollable and supplies the subject from the request." }),
  unavailableReason: z.string().nullable().openapi({ description: "Why the platform cannot issue under it; none while it is available." }),
  hidden: z.boolean().openapi({ description: "Hidden by an Organization Administrator: offered for nothing, whatever ADCS allows." }),
  offeredFor: z
    .array(z.enum(TEMPLATE_PURPOSES))
    .openapi({ description: "What it is offered for while it is available and not hidden: `tls` with Server Authentication, `devices` with Client Authentication, both with both." }),
});

const AdcsCa = z.object({
  id: z.string(),
  name: z.string(),
  configString: z.string(),
  agentIds: z.array(z.string()).openapi({ description: "The Agents that carry out its operations." }),
  caCertificate: CertificateShown.openapi({ description: "The CA's own certificate, as its last discovery fetched it." }),
  chain: z.array(CertificateShown).openapi({ description: "The CA certificate, then each certificate above it up to its root." }),
  cdpUrls: z.array(z.string()).openapi({ description: "The CRL Distribution Point URLs in the CA certificate. ADCS publishes its own CRL; the platform serves none for it." }),
  templates: z.array(Template).openapi({ description: "Its Certificate Templates, as discovery last found them, by name." }),
  offered: z
    .object({ tls: z.array(z.string()), devices: z.array(z.string()) })
    .openapi({ description: "The ids of the templates offered for TLS and for devices, by name: those available, not hidden, and with Server Authentication or Client Authentication." }),
  discoveredAt: z.string().openapi({ description: "When a discovery last succeeded: what the chain and the templates are from." }),
  discoveryFailure: z
    .object({ at: z.string(), error: z.string() })
    .nullable()
    .openapi({ description: "When the latest discovery failed, and why; none once one succeeds. A failed discovery leaves the chain and the templates as they were." }),
  createdAt: z.string(),
});

const shownCertificate = (pem: string): z.infer<typeof CertificateShown> => {
  const certificate = new x509.X509Certificate(pem);
  return {
    subject: certificate.subject,
    issuer: certificate.issuer,
    notBefore: certificate.notBefore.toISOString(),
    notAfter: certificate.notAfter.toISOString(),
    fingerprint: fingerprintOf(certificate.rawData),
  };
};

const toTemplate = (row: TemplateRow): z.infer<typeof Template> => ({
  id: row.id,
  name: row.name,
  oid: row.oid,
  displayName: row.displayName,
  extendedKeyUsages: row.extendedKeyUsages,
  validityDays: row.validityDays,
  minimumKeySize: row.minimumKeySize,
  keyAlgorithms: row.keyAlgorithms,
  managerApproval: row.managerApproval,
  subjectFromRequest: row.subjectFromRequest,
  enrollable: row.enrollable,
  published: row.published,
  reported: row.reported,
  available: isAvailable(row),
  unavailableReason: unavailableReason(row),
  hidden: row.hidden,
  offeredFor: offeredFor(row),
});

const toAdcsCa = (row: AdcsCaRow, agentIds: string[], allTemplates: TemplateRow[]): z.infer<typeof AdcsCa> => {
  const templates = allTemplates.filter((t) => t.adcsCaId === row.id).map(toTemplate);
  const offeredForPurpose = (purpose: (typeof TEMPLATE_PURPOSES)[number]) => templates.filter((t) => t.offeredFor.includes(purpose)).map((t) => t.id);
  return {
    id: row.id,
    name: row.name,
    configString: row.configString,
    agentIds,
    caCertificate: shownCertificate(row.caCertificatePem),
    chain: [row.caCertificatePem, ...row.chainPem].map(shownCertificate),
    cdpUrls: row.cdpUrls,
    templates,
    offered: { tls: offeredForPurpose("tls"), devices: offeredForPurpose("devices") },
    discoveredAt: row.discoveredAt.toISOString(),
    discoveryFailure: row.discoveryFailedAt ? { at: row.discoveryFailedAt.toISOString(), error: row.discoveryError ?? "" } : null,
    createdAt: row.createdAt.toISOString(),
  };
};

/** The CRL Distribution Point URLs in a certificate. */
function cdpUrlsOf(certificate: x509.X509Certificate): string[] {
  const extension = certificate.getExtension(x509.CRLDistributionPointsExtension);
  return (extension?.distributionPoints ?? []).flatMap((point) => point.distributionPoint?.fullName?.flatMap((name) => (name.uniformResourceIdentifier ? [name.uniformResourceIdentifier] : [])) ?? []);
}

/** A discovery as the platform keeps it: the CA certificate, the certificates above it, its CDP URLs and the templates. */
interface Discovered {
  caCertificatePem: string;
  chainPem: string[];
  cdpUrls: string[];
  templates: TemplateFacts[];
  by: { id: string; hostName: string };
}

/**
 * What an Agent reported of a discovery, checked; a 422 that says what is wrong with it when it cannot be what the CA is:
 * the CA certificate, then each certificate above it, each signed by the next, up to a root that signs itself.
 */
async function discoveredFrom(by: { id: string; hostName: string }, reported: DiscoveryResult): Promise<Discovered> {
  const refuse = (why: string) => new HttpError(422, `the Agent ${by.hostName} reported a discovery the platform cannot use: ${why}`);
  let chain: x509.X509Certificate[];
  try {
    chain = reported.chain.map((pem) => new x509.X509Certificate(pem));
  } catch {
    throw refuse("a certificate of the chain cannot be read");
  }
  if (chain.some((certificate) => !certificate.getExtension(x509.BasicConstraintsExtension)?.ca)) throw refuse("a certificate of the chain is not a CA certificate");
  for (const [i, certificate] of chain.entries()) {
    const signer = chain[i + 1] ?? certificate;
    const signed = certificate.issuer === signer.subject && (await certificate.verify({ publicKey: signer.publicKey, signatureOnly: true }).catch(() => false));
    if (!signed) throw refuse(chain[i + 1] ? `${certificate.subject} is not signed by ${signer.subject}, which follows it` : `the chain ends at ${certificate.subject}, which is not a root`);
  }
  const names = reported.templates.map((t) => t.name.toLowerCase());
  if (new Set(names).size !== names.length) throw refuse("a template is listed twice");
  const pems = chain.map((certificate) => certificate.toString("pem"));
  return { caCertificatePem: pems[0]!, chainPem: pems.slice(1), cdpUrls: cdpUrlsOf(chain[0]!), templates: reported.templates, by };
}

const isId = (id: string) => z.uuid().safeParse(id).success;
const nameTaken = (name: string) => new HttpError(409, `the Organization already has an ADCS CA named "${name}"`);
const configStringTaken = (configString: string) => new HttpError(409, `the Organization already has an ADCS CA at ${configString}`);

export function registerAdcsCas(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: Context): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  workItems: WorkItems;
  clock: () => Date;
  offlineAfterSeconds: number;
  config: AdcsRelayConfig;
}) {
  const { app, db, requireUser, authorize, unitOfWork, workItems, clock, offlineAfterSeconds, config } = ctx;

  // The payload is all the Agent needs: it reaches ADCS as its own account.
  workItems.register(ADCS_WORK_TYPES.discover, async (_tx, item) => ({ configString: item.payload.configString }));

  /**
   * The Agents, checked: each must be one of the Organization's, not revoked, on Windows, and listed once; a 400 says which
   * is not. Read under a shared lock on a transaction, so that an Agent being revoked finishes first, or is seen revoked.
   */
  async function checkAgents(dbOrTx: Db | Tx, organizationId: string, agentIds: string[]) {
    if (new Set(agentIds).size !== agentIds.length) throw new HttpError(400, "an Agent is listed twice");
    const notOurs = new HttpError(400, "the Agents must be the ids of the Organization's Agents");
    if (agentIds.some((id) => !isId(id))) throw notOurs;
    const query = dbOrTx.select().from(agent).where(and(eq(agent.organizationId, organizationId), inArray(agent.id, agentIds)));
    const found = "rollback" in dbOrTx ? await query.for("share") : await query;
    if (found.length !== agentIds.length) throw notOurs;
    const revoked = found.find((a) => a.revokedAt);
    if (revoked) throw new HttpError(400, `the Agent ${revoked.hostName} is revoked`);
    const notWindows = found.find((a) => a.os !== "windows");
    if (notWindows) throw new HttpError(400, `the Agent ${notWindows.hostName} runs on ${notWindows.os}, not Windows, so it cannot reach ADCS`);
  }

  /** Has an online one of the Agents discover the CA. A 502 when none could reach it, a 422 when ADCS or the Agent refused, with the Agent's reason. */
  async function discover(organizationId: string, agentIds: string[], configString: string): Promise<Discovered> {
    const relayed = await relayToAgents(
      { db, workItems, clock, offlineAfterSeconds, attemptTimeoutMs: config.attemptTimeoutMs },
      {
        organizationId,
        agentIds,
        type: ADCS_WORK_TYPES.discover,
        payload: { configString },
        role: "is assigned to this ADCS CA",
        // Another Agent may reach the CA from where it is.
        passOn: (result) => !result.ok && result.kind === "unreachable",
      },
    ).catch((err) => {
      if (err instanceof NoAgentAnswered) throw new HttpError(502, `${configString} could not be reached: ${err.message}`);
      throw err;
    });
    const { agent: by, result } = relayed;
    if (!result.ok) throw new HttpError(422, `the Agent ${by.hostName} reported: ${result.error ?? "the discovery failed"}`);
    if (!result.discovery) throw new HttpError(422, `the Agent ${by.hostName} reported no discovery`);
    return discoveredFrom(by, result.discovery);
  }

  /** The ADCS CA's Agents, in a stable order. */
  const agentsOf = async (dbOrTx: Db | Tx, adcsCaIds: string[]) =>
    adcsCaIds.length === 0 ? [] : dbOrTx.select().from(adcsCaAgent).where(inArray(adcsCaAgent.adcsCaId, adcsCaIds)).orderBy(asc(adcsCaAgent.agentId));
  const templatesOf = async (dbOrTx: Db | Tx, adcsCaIds: string[]) =>
    adcsCaIds.length === 0 ? [] : dbOrTx.select().from(adcsTemplate).where(inArray(adcsTemplate.adcsCaId, adcsCaIds)).orderBy(asc(adcsTemplate.name));

  async function shown(dbOrTx: Db | Tx, rows: AdcsCaRow[]) {
    const ids = rows.map((r) => r.id);
    const [agents, templates] = await Promise.all([agentsOf(dbOrTx, ids), templatesOf(dbOrTx, ids)]);
    return rows.map((row) =>
      toAdcsCa(
        row,
        agents.filter((a) => a.adcsCaId === row.id).map((a) => a.agentId),
        templates,
      ),
    );
  }

  async function find(dbOrTx: Db | Tx, organizationId: string, id: string, lock = false) {
    if (!isId(id)) return undefined;
    const query = dbOrTx.select().from(adcsCa).where(and(eq(adcsCa.organizationId, organizationId), eq(adcsCa.id, id)));
    const [row] = lock ? await query.for("update") : await query;
    return row;
  }

  async function findReadable(actor: Actor, orgId: string, id: string) {
    await authorize(actor, orgId, { adcsCa: ["read"] });
    const row = await find(db, orgId, id);
    if (!row) throw new HttpError(404, "ADCS CA not found");
    return row;
  }

  /**
   * Records what discovery found, on the CA locked by the caller: the chain, and the templates' facts. A template keeps its
   * id from one discovery to the next (matched by name, as ADCS matches them), and one no longer reported is kept, as not
   * reported. The Audit Event names the templates whose availability changed. Returns the CA as it is now.
   */
  async function recordDiscovery(tx: Tx, change: Change, row: AdcsCaRow, discovered: Discovered): Promise<AdcsCaRow> {
    const keyOf = (name: string) => name.toLowerCase();
    const kept = await templatesOf(tx, [row.id]);
    const wasAvailable = new Map(kept.map((t) => [keyOf(t.name), isAvailable(t)]));
    const reported = new Map(discovered.templates.map((t) => [keyOf(t.name), t]));
    for (const t of kept) {
      const facts = reported.get(keyOf(t.name));
      if (facts) await tx.update(adcsTemplate).set({ ...facts, reported: true }).where(eq(adcsTemplate.id, t.id));
      else if (t.reported) await tx.update(adcsTemplate).set({ reported: false }).where(eq(adcsTemplate.id, t.id));
    }
    const added = discovered.templates.filter((t) => !wasAvailable.has(keyOf(t.name)));
    if (added.length > 0) {
      await tx.insert(adcsTemplate).values(added.map((t) => ({ ...t, organizationId: row.organizationId, adcsCaId: row.id })));
    }
    const [updated] = (await tx
      .update(adcsCa)
      .set({
        caCertificatePem: discovered.caCertificatePem,
        chainPem: discovered.chainPem,
        cdpUrls: discovered.cdpUrls,
        discoveredAt: change.occurredAt,
        discoveryFailedAt: null,
        discoveryError: null,
      })
      .where(eq(adcsCa.id, row.id))
      .returning()) as [AdcsCaRow];

    const now = await templatesOf(tx, [row.id]);
    const names = (keep: (t: TemplateRow) => boolean) => now.filter(keep).map((t) => t.name);
    const { subject, fingerprint } = shownCertificate(discovered.caCertificatePem);
    await change.audit({
      organizationId: row.organizationId,
      action: "adcs_ca.discovered",
      target: { type: "adcs_ca", id: row.id },
      detail: {
        name: row.name,
        agent: discovered.by,
        caCertificate: { subject, fingerprint },
        cdpUrls: discovered.cdpUrls,
        templates: {
          available: names(isAvailable),
          unavailable: names((t) => !isAvailable(t)),
          // A template new to the platform was not available before.
          becameAvailable: names((t) => isAvailable(t) && !wasAvailable.get(keyOf(t.name))),
          becameUnavailable: names((t) => !isAvailable(t) && wasAvailable.get(keyOf(t.name)) === true),
        },
      },
    });
    return updated;
  }

  /**
   * Discovers an ADCS CA again, through its Agents, and records what was found; `actor` is null for the scheduler's. A
   * discovery that fails is recorded on the CA, and audited, and leaves its chain and templates as they were; its
   * HttpError is thrown again. The Agents are asked outside any transaction.
   */
  async function rediscover(actor: Actor | null, row: AdcsCaRow): Promise<AdcsCaRow> {
    const agentIds = (await agentsOf(db, [row.id])).map((a) => a.agentId);
    let discovered: Discovered;
    try {
      discovered = await discover(row.organizationId, agentIds, row.configString);
    } catch (err) {
      if (!(err instanceof HttpError)) throw err;
      await unitOfWork.run(actor, async (tx, change) => {
        const current = await find(tx, row.organizationId, row.id, true);
        // Removed meanwhile: nothing to record it on.
        if (!current) return;
        await tx.update(adcsCa).set({ discoveryFailedAt: change.occurredAt, discoveryError: err.message }).where(eq(adcsCa.id, row.id));
        await change.audit({
          organizationId: row.organizationId,
          action: "adcs_ca.discovery_failed",
          target: { type: "adcs_ca", id: row.id },
          detail: { name: current.name, error: err.message },
        });
      });
      throw err;
    }
    return unitOfWork.run(actor, async (tx, change) => {
      const current = await find(tx, row.organizationId, row.id, true);
      if (!current) throw new HttpError(404, "ADCS CA not found");
      return recordDiscovery(tx, change, current, discovered);
    });
  }

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/adcs-cas",
      tags: ["ADCS CAs"],
      summary: "The Organization's ADCS CAs, oldest first",
      description: "Everyone in the Organization may list them, with their templates and chains.",
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(AdcsCa) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { adcsCa: ["read"] });
      const rows = await db.select().from(adcsCa).where(eq(adcsCa.organizationId, orgId)).orderBy(asc(adcsCa.createdAt), asc(adcsCa.id));
      return c.json({ items: await shown(db, rows) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/adcs-cas",
      tags: ["ADCS CAs"],
      summary: "Add an ADCS CA",
      description:
        "Organization Administrators only. An online assigned Agent discovers the CA as it is added: it fetches the CA's certificate and chain and lists its Certificate Templates. " +
        "When no assigned Agent can reach the CA it is 502, and when ADCS or the Agent refuses it is 422, each with the Agent's reason; either way nothing is saved. " +
        "Each Agent must be one of the Organization's, not revoked, and on Windows (400). Names and config strings are unique within the Organization (409).",
      request: { params: OrgParam, body: { content: { "application/json": { schema: z.object({ name: Name, configString: ConfigString, agentIds: AgentIds }) } } } },
      responses: { 201: json(AdcsCa, "Added"), ...errors(400, 401, 403, 404, 409, 422, 502) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { adcsCa: ["create"] });
      await checkAgents(db, orgId, body.agentIds);
      // Refused before an Agent is asked anything, as far as can be told yet.
      const [taken] = await db.select().from(adcsCa).where(and(eq(adcsCa.organizationId, orgId), eq(adcsCa.name, body.name)));
      if (taken) throw nameTaken(body.name);
      const [sameCa] = await db.select().from(adcsCa).where(and(eq(adcsCa.organizationId, orgId), eq(adcsCa.configString, body.configString)));
      if (sameCa) throw configStringTaken(body.configString);
      // The Agent is asked outside any transaction: only what it found is written in one.
      const discovered = await discover(orgId, body.agentIds, body.configString);
      try {
        const row = await unitOfWork.run(actor, async (tx, change) => {
          await checkAgents(tx, orgId, body.agentIds);
          const [row] = await tx
            .insert(adcsCa)
            .values({
              organizationId: orgId,
              name: body.name,
              configString: body.configString,
              caCertificatePem: discovered.caCertificatePem,
              chainPem: discovered.chainPem,
              cdpUrls: discovered.cdpUrls,
              discoveredAt: change.occurredAt,
              createdAt: change.occurredAt,
            })
            .returning();
          await tx.insert(adcsCaAgent).values(body.agentIds.map((agentId) => ({ organizationId: orgId, adcsCaId: row!.id, agentId })));
          await change.audit({
            organizationId: orgId,
            action: "adcs_ca.created",
            target: { type: "adcs_ca", id: row!.id },
            detail: { name: body.name, configString: body.configString, agentIds: body.agentIds },
          });
          return recordDiscovery(tx, change, row!, discovered);
        });
        return c.json((await shown(db, [row]))[0]!, 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw (err as any)?.cause?.constraint === "adcs_ca_organization_config_string_unique" ? configStringTaken(body.configString) : nameTaken(body.name);
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/adcs-cas/{id}",
      tags: ["ADCS CAs"],
      summary: "An ADCS CA, with its templates and chain",
      request: { params: AdcsCaParams },
      responses: { 200: json(AdcsCa), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const row = await findReadable(await requireUser(c), orgId, id);
      return c.json((await shown(db, [row]))[0]!, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/api/organizations/{orgId}/adcs-cas/{id}",
      tags: ["ADCS CAs"],
      summary: "Rename an ADCS CA or change its Agents",
      description:
        "Organization Administrators only. What is given replaces what it had; its config string is fixed. Each Agent must be one of the Organization's, not revoked, and on Windows (400).",
      request: {
        params: AdcsCaParams,
        body: { content: { "application/json": { schema: z.object({ name: Name.optional(), agentIds: AgentIds.optional() }) } } },
      },
      responses: { 200: json(AdcsCa, "Changed"), ...errors(400, 401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { adcsCa: ["update"] });
      try {
        const row = await unitOfWork.run(actor, async (tx, change) => {
          const before = await find(tx, orgId, id, true);
          if (!before) throw new HttpError(404, "ADCS CA not found");
          const previousAgentIds = (await agentsOf(tx, [id])).map((a) => a.agentId);
          const changes: Record<string, { from: unknown; to: unknown }> = {};
          let row = before;
          if (body.name !== undefined && body.name !== before.name) {
            [row] = (await tx.update(adcsCa).set({ name: body.name }).where(eq(adcsCa.id, id)).returning()) as [AdcsCaRow];
            changes.name = { from: before.name, to: body.name };
          }
          const sorted = body.agentIds && [...body.agentIds].sort();
          // The Agents it has are not checked again: one revoked since does not stop a rename.
          if (sorted && sorted.join() !== previousAgentIds.join()) {
            await checkAgents(tx, orgId, sorted);
            await tx.delete(adcsCaAgent).where(eq(adcsCaAgent.adcsCaId, id));
            await tx.insert(adcsCaAgent).values(sorted.map((agentId) => ({ organizationId: orgId, adcsCaId: id, agentId })));
            changes.agentIds = { from: previousAgentIds, to: sorted };
          }
          if (Object.keys(changes).length > 0) {
            await change.audit({ organizationId: orgId, action: "adcs_ca.updated", target: { type: "adcs_ca", id }, detail: { name: row.name, changes } });
          }
          return row;
        });
        return c.json((await shown(db, [row]))[0]!, 200);
      } catch (err) {
        if (isUniqueViolation(err)) throw nameTaken(body.name!);
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/api/organizations/{orgId}/adcs-cas/{id}",
      tags: ["ADCS CAs"],
      summary: "Remove an ADCS CA",
      description: "Organization Administrators only, and only while nothing refers to it (409): no history may lose its issuer.",
      request: { params: AdcsCaParams },
      responses: { 204: { description: "Removed" }, ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { adcsCa: ["delete"] });
      let name = "the ADCS CA";
      try {
        await unitOfWork.run(actor, async (tx, change) => {
          const row = await find(tx, orgId, id, true);
          if (!row) throw new HttpError(404, "ADCS CA not found");
          name = row.name;
          await tx.delete(adcsCa).where(eq(adcsCa.id, id));
          await change.audit({ organizationId: orgId, action: "adcs_ca.deleted", target: { type: "adcs_ca", id }, detail: { name: row.name, configString: row.configString } });
        });
      } catch (err) {
        // Whatever names an ADCS CA references it, so the database refuses to remove one something still names.
        if (isForeignKeyViolation(err)) throw new HttpError(409, `${name} is the issuer of something the platform keeps, so it cannot be removed`);
        throw err;
      }
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/adcs-cas/{id}/refresh",
      tags: ["ADCS CAs"],
      summary: "Discover an ADCS CA again",
      description:
        "Organization Administrators only. An online assigned Agent discovers the CA again, as the platform does once a day: its CA certificate and chain are refreshed, and its templates' facts. " +
        "A template no longer reported is kept, as unavailable, and is available again when it comes back. " +
        "When no assigned Agent can reach the CA it is 502, and when ADCS or the Agent refuses it is 422, each with the Agent's reason; the failure is recorded on the CA, which otherwise stays as it was.",
      request: { params: AdcsCaParams },
      responses: { 200: json(AdcsCa, "Discovered"), ...errors(401, 403, 404, 422, 502) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { adcsCa: ["update"] });
      const row = await find(db, orgId, id);
      if (!row) throw new HttpError(404, "ADCS CA not found");
      const discovered = await rediscover(actor, row);
      return c.json((await shown(db, [discovered]))[0]!, 200);
    },
  );

  /** Hides a template from being offered, or shows it again; 409 when it already is. */
  async function setHidden(c: Context, { orgId, id, templateId }: z.infer<typeof TemplateParams>, hidden: boolean) {
    const actor = await requireUser(c);
    await authorize(actor, orgId, { adcsCa: ["update"] });
    const row = await unitOfWork.run(actor, async (tx, change) => {
      const row = await find(tx, orgId, id, true);
      if (!row) throw new HttpError(404, "ADCS CA not found");
      const [template] = isId(templateId) ? await tx.select().from(adcsTemplate).where(and(eq(adcsTemplate.adcsCaId, id), eq(adcsTemplate.id, templateId))) : [];
      if (!template) throw new HttpError(404, "Certificate Template not found");
      if (template.hidden === hidden) throw new HttpError(409, `${template.name} is already ${hidden ? "hidden" : "shown"}`);
      await tx.update(adcsTemplate).set({ hidden }).where(eq(adcsTemplate.id, template.id));
      await change.audit({
        organizationId: orgId,
        action: hidden ? "adcs_ca.template_hidden" : "adcs_ca.template_shown",
        target: { type: "adcs_ca", id },
        detail: { name: row.name, template: { id: template.id, name: template.name } },
      });
      return row;
    });
    return (await shown(db, [row]))[0]!;
  }

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/adcs-cas/{id}/templates/{templateId}/hide",
      tags: ["ADCS CAs"],
      summary: "Hide a Certificate Template",
      description: "Organization Administrators only. Nobody in the Organization can pick it, whatever ADCS allows; discovery keeps it hidden. 409 when it is hidden already.",
      request: { params: TemplateParams },
      responses: { 200: json(AdcsCa, "Hidden"), ...errors(401, 403, 404, 409) },
    }),
    async (c) => c.json(await setHidden(c, c.req.valid("param"), true), 200),
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/adcs-cas/{id}/templates/{templateId}/show",
      tags: ["ADCS CAs"],
      summary: "Show a hidden Certificate Template again",
      description: "Organization Administrators only. It is offered again while it is available. 409 when it is not hidden.",
      request: { params: TemplateParams },
      responses: { 200: json(AdcsCa, "Shown"), ...errors(401, 403, 404, 409) },
    }),
    async (c) => c.json(await setHidden(c, c.req.valid("param"), false), 200),
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/adcs-cas/{id}/chain",
      tags: ["ADCS CAs"],
      summary: "Download an ADCS CA's chain: its CA certificate, then each certificate above it up to its root",
      description: "PEM. Install the root wherever the Certificates it issues must be trusted and it is not already.",
      request: { params: AdcsCaParams },
      responses: PemResponse("The chain, PEM"),
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const row = await findReadable(await requireUser(c), orgId, id);
      return pemFile(c, [row.caCertificatePem, ...row.chainPem].join("\n"), `${fileNameOf(row.name, "adcs-ca")}.chain.pem`);
    },
  );

  return {
    /**
     * One pass of the daily discovery at the clock's time: discovers again each ADCS CA whose last discovery, whether it
     * succeeded or failed, was a day ago or more, and returns how many it tried. One CA's failure is recorded on it, and
     * stops no other.
     */
    async discoverDue(): Promise<number> {
      const dayAgo = new Date(clock().getTime() - DISCOVERY_INTERVAL_MS);
      const due = await db
        .select()
        .from(adcsCa)
        .where(sql`greatest(${adcsCa.discoveredAt}, ${adcsCa.discoveryFailedAt}) <= ${dayAgo}`)
        .orderBy(asc(adcsCa.discoveredAt));
      for (const row of due) {
        await rediscover(null, row).catch((err) => {
          if (!(err instanceof HttpError)) console.error("could not discover the ADCS CA", row.id, err);
        });
      }
      return due.length;
    },
  };
}
