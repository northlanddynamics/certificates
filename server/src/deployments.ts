// Deployments: an Organization Administrator's arrangement for one Agent to make the key for a Managed Certificate, obtain
// its Certificates and put them into use by running a Deployment Script. It is set up in one call: the Agent, the Managed
// Certificate's names and key algorithm, the script version and the Renewal Policy. The rest is done through work items
// (work-items.ts) and what follows from them, never by the platform holding a key (ADR 0002):
//   1. `deployment.generate_key`: the Agent makes the key in a store only its service account reads and reports a CSR for
//      it. The platform checks the CSR as it does an Owner's, keeps it and begins the Issuance.
//   2. When the Issuance stores the Certificate, `deployment.run`: the Agent is given the Certificate and the script
//      (with its hash, which it checks before running it, ADR 0004), runs it, and reports how it went.
//   3. That report is the Deployment Run. An Organization Administrator can have the Agent run it again for the current
//      Certificate without renewing.
// Each Renewal is for a new key: its Issuance waits (issuance.ts) while the Agent is asked again, through
// `deployment.generate_key` naming the Issuance, and runs once the CSR is stored; it then goes on through steps 2 and 3. An
// Agent that is away holds the Renewal up until it is back, when it is given the request it missed.
// Each step and each Deployment Run is an Audit Event, written with the change it records.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, desc, eq, inArray, sql } from "drizzle-orm";
import type { Authorizer } from "./authorization";
import { ACME_ENVIRONMENTS } from "./certificate-authority";
import { KEY_ALGORITHMS } from "./csr";
import type { Db, Tx } from "./db/client";
import { agent, certificate, deployment, deploymentRun, deploymentScript, deploymentScriptVersion, issuance, managedCertificate, workItem } from "./db/schema";
import { SCRIPT_INTERPRETERS } from "./deployment-script-kinds";
import { HttpError, OrgParam, PageQuery, errors, json, pageOf } from "./http";
import type { Issuances } from "./issuance";
import { RenewalPolicy } from "./managed-certificate-reader";
import { MAX_NAMES, normalizeNames } from "./names";
import { checkNamesAndCsr, namesField } from "./names-and-csr";
import { lockManagedCertificate } from "./name-change";
import type { Actor, UnitOfWork } from "./unit-of-work";
import { PreparationError, type RunReport, type WorkItems } from "./work-items";

export const DEPLOYMENT_WORK_TYPES = { generateKey: "deployment.generate_key", run: "deployment.run" } as const;

/** How much of a script's output a Deployment Run keeps. The Agent sends no more than this, and the platform keeps no more than this whatever it is sent. */
export const OUTPUT_LIMIT_BYTES = 32 * 1024;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** `text` cut to at most `limit` bytes of UTF-8, at a character. */
function truncate(text: string, limit: number): { text: string; truncated: boolean } {
  const bytes = Buffer.from(text, "utf8");
  if (bytes.length <= limit) return { text, truncated: false };
  return { text: bytes.subarray(0, limit).toString("utf8").replace(/�+$/, ""), truncated: true };
}

const Run = z.object({
  id: z.string(),
  deploymentId: z.string(),
  status: z.enum(["succeeded", "failed"]).openapi({ description: "`succeeded` when the script exited with 0. `failed` when it did not, or was not started (it did not match its hash)." }),
  trigger: z.enum(["issuance", "rerun"]).openapi({ description: "What asked for it: the Issuance of the Certificate, or an Organization Administrator running the Deployment again." }),
  startedAt: z.string(),
  finishedAt: z.string(),
  exitCode: z.number().int().nullable().openapi({ description: "None when the script was not started." }),
  output: z.string().openapi({ description: `What the script wrote to its standard output and error, up to ${OUTPUT_LIMIT_BYTES / 1024} KiB; when it was not started, why.` }),
  outputTruncated: z.boolean(),
  certificate: z.object({ id: z.string(), fingerprint: z.string() }).openapi({ description: "The Certificate it delivered." }),
  script: z.object({ version: z.number().int(), hash: z.string() }).openapi({ description: "The script content it was given, which the Agent ran only because it matched this hash." }),
});

const DEPLOYMENT_STATES = ["awaiting_key", "key_failed", "issuing", "issuance_failed", "awaiting_deployment", "deployed", "deployment_failed"] as const;

const Deployment = z.object({
  id: z.string(),
  managedCertificateId: z.string(),
  names: z.array(z.string()),
  keyAlgorithm: z.enum(KEY_ALGORITHMS),
  agent: z.object({ id: z.string(), hostName: z.string() }),
  script: z.object({ id: z.string(), name: z.string(), interpreter: z.enum(SCRIPT_INTERPRETERS), version: z.number().int(), hash: z.string() }),
  createdAt: z.string(),
  createdBy: z.string(),
  state: z.enum(DEPLOYMENT_STATES).openapi({
    description:
      "`awaiting_key`: the Agent has not yet made the key. `key_failed`: it could not, or its CSR was refused (see `keyFailure`). `issuing`: the Certificate is being issued. `issuance_failed`: it could not be; try issuing again on the Managed Certificate. " +
      "`awaiting_deployment`: the Certificate is issued and the Agent has not run the script for it. `deployed`/`deployment_failed`: how the script went for the current Certificate.",
  }),
  keyFailure: z.string().nullable(),
  runPending: z.boolean().openapi({ description: "Whether the Agent has been asked to run the script and has not yet reported." }),
  lastRun: Run.nullable(),
});

type DeploymentRow = typeof deployment.$inferSelect;
type RunRow = typeof deploymentRun.$inferSelect;

const toRun = (row: RunRow, fingerprint: string) => ({
  id: row.id,
  deploymentId: row.deploymentId,
  status: row.status,
  trigger: row.trigger,
  startedAt: row.startedAt.toISOString(),
  finishedAt: row.finishedAt.toISOString(),
  exitCode: row.exitCode,
  output: row.output,
  outputTruncated: row.outputTruncated,
  certificate: { id: row.certificateId, fingerprint },
  script: { version: row.scriptVersion, hash: row.scriptHash },
});

const DeploymentParams = OrgParam.extend({ id: z.string().openapi({ param: { name: "id", in: "path" } }) });

export function registerDeployments(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  workItems: WorkItems;
  issuances: Issuances;
}) {
  const { app, db, requireUser, authorize, unitOfWork, workItems, issuances } = ctx;

  async function findDeployment(orgId: string, id: string) {
    // Not a UUID can't be a Deployment; asking Postgres would only raise a type error.
    const [row] = UUID.test(id) ? await db.select().from(deployment).where(and(eq(deployment.organizationId, orgId), eq(deployment.id, id))) : [];
    if (!row) throw new HttpError(404, "Deployment not found");
    return row;
  }

  /** The Deployments as the API shows them: each with its Agent, script, Managed Certificate, where it has got to and its latest run. */
  async function withState(rows: DeploymentRow[]) {
    if (rows.length === 0) return [];
    const ids = rows.map((r) => r.id);
    const mcIds = rows.map((r) => r.managedCertificateId);
    const [agents, scripts, versions, mcs, issuances_, certificates, runs, pending] = await Promise.all([
      db.select({ id: agent.id, hostName: agent.hostName }).from(agent).where(inArray(agent.id, rows.map((r) => r.agentId))),
      db.select().from(deploymentScript).where(inArray(deploymentScript.id, rows.map((r) => r.scriptId))),
      db.select({ scriptId: deploymentScriptVersion.scriptId, version: deploymentScriptVersion.version, hash: deploymentScriptVersion.hash }).from(deploymentScriptVersion).where(inArray(deploymentScriptVersion.scriptId, rows.map((r) => r.scriptId))),
      db.select().from(managedCertificate).where(inArray(managedCertificate.id, mcIds)),
      db.selectDistinctOn([issuance.managedCertificateId]).from(issuance).where(inArray(issuance.managedCertificateId, mcIds)).orderBy(issuance.managedCertificateId, desc(issuance.createdAt), desc(issuance.id)),
      db.selectDistinctOn([certificate.managedCertificateId]).from(certificate).where(inArray(certificate.managedCertificateId, mcIds)).orderBy(certificate.managedCertificateId, desc(certificate.createdAt), desc(certificate.id)),
      db.selectDistinctOn([deploymentRun.deploymentId]).from(deploymentRun).where(inArray(deploymentRun.deploymentId, ids)).orderBy(deploymentRun.deploymentId, desc(deploymentRun.createdAt), desc(deploymentRun.id)),
      db
        .select({ deploymentId: sql<string>`${workItem.payload}->>'deploymentId'` })
        .from(workItem)
        .where(and(eq(workItem.type, DEPLOYMENT_WORK_TYPES.run), inArray(workItem.status, ["pending", "delivered"]), inArray(sql`${workItem.payload}->>'deploymentId'`, ids))),
    ]);
    const fingerprints = new Map(
      (await db.select({ id: certificate.id, fingerprint: certificate.fingerprint }).from(certificate).where(inArray(certificate.id, runs.map((r) => r.certificateId)))).map((c) => [c.id, c.fingerprint]),
    );
    return rows.map((row) => {
      const mc = mcs.find((m) => m.id === row.managedCertificateId)!;
      const script = scripts.find((s) => s.id === row.scriptId)!;
      const latestIssuance = issuances_.find((i) => i.managedCertificateId === mc.id);
      const current = certificates.find((c) => c.managedCertificateId === mc.id);
      const last = runs.find((r) => r.deploymentId === row.id);
      let state: (typeof DEPLOYMENT_STATES)[number];
      if (row.keyFailure) state = "key_failed";
      else if (mc.csr === null) state = "awaiting_key";
      else if (last && current && last.certificateId === current.id) state = last.status === "succeeded" ? "deployed" : "deployment_failed";
      else if (latestIssuance?.status === "running") state = "issuing";
      else if (!current) state = latestIssuance?.status === "failed" ? "issuance_failed" : "issuing";
      else state = "awaiting_deployment";
      return {
        id: row.id,
        managedCertificateId: row.managedCertificateId,
        names: mc.names,
        keyAlgorithm: mc.keyAlgorithm,
        agent: { id: row.agentId, hostName: agents.find((a) => a.id === row.agentId)?.hostName ?? "" },
        script: {
          id: script.id,
          name: script.name,
          interpreter: script.interpreter,
          version: row.scriptVersion,
          hash: versions.find((v) => v.scriptId === row.scriptId && v.version === row.scriptVersion)!.hash,
        },
        createdAt: row.createdAt.toISOString(),
        createdBy: row.createdByEmail,
        state,
        keyFailure: row.keyFailure,
        runPending: pending.some((p) => p.deploymentId === row.id),
        lastRun: last ? toRun(last, fingerprints.get(last.certificateId) ?? "") : null,
      };
    });
  }

  async function lockDeployment(tx: Tx, organizationId: string, id: string) {
    const [row] = await tx.select().from(deployment).where(and(eq(deployment.id, id), eq(deployment.organizationId, organizationId))).for("update");
    return row;
  }

  // ---- What the Agent is given -------------------------------------------------------------------------------------

  workItems.register(
    DEPLOYMENT_WORK_TYPES.generateKey,
    async (tx, item) => {
      const { deploymentId, issuanceId } = item.payload as { deploymentId: string; issuanceId?: string };
      const [row] = await tx.select().from(deployment).where(and(eq(deployment.id, deploymentId), eq(deployment.organizationId, item.organizationId)));
      if (!row) throw new PreparationError("the Deployment is gone");
      const [mc] = await tx.select().from(managedCertificate).where(eq(managedCertificate.id, row.managedCertificateId));
      if (!mc || mc.archivedAt) throw new PreparationError("the Managed Certificate is archived, so no key is wanted");
      if (issuanceId) {
        const [waiting] = await tx.select({ awaitingKey: issuance.awaitingKey }).from(issuance).where(eq(issuance.id, issuanceId));
        if (!waiting?.awaitingKey) throw new PreparationError("the Renewal that wanted the key has ended");
      }
      return { deploymentId, managedCertificateId: mc.id, names: mc.names, keyAlgorithm: mc.keyAlgorithm };
    },
    {
      durable: true,
      // The Agent's report of the key: a CSR the platform checks as it would an Owner's, and issues from. For the first key
      // that is the first Issuance; for a Renewal's, the Issuance that waits for it, which fails instead when no usable key
      // came, and is tried again as any failed Renewal is.
      async onResult(tx, change, item, result) {
        const { deploymentId, issuanceId } = item.payload as { deploymentId: string; issuanceId?: string };
        const row = await lockDeployment(tx, item.organizationId, deploymentId);
        if (!row) return;
        const mc = await lockManagedCertificate(tx, item.organizationId, row.managedCertificateId);
        // A stale report changes nothing: for a Renewal that has ended meanwhile, or for a first key already made (a second
        // request for it, answered late).
        if (issuanceId) {
          const [waiting] = await tx.select({ awaitingKey: issuance.awaitingKey }).from(issuance).where(and(eq(issuance.id, issuanceId), eq(issuance.managedCertificateId, mc.id)));
          if (!waiting?.awaitingKey) return;
        } else if (mc.csr !== null) return;
        const fail = async (message: string) => {
          await change.audit({ organizationId: item.organizationId, action: "deployment.key_failed", target: { type: "deployment", id: row.id }, detail: { agentId: row.agentId, ...(issuanceId && { issuanceId }), message } });
          if (issuanceId) await issuances.abandon(tx, change, issuanceId, { code: "agent_key_failed", message });
          else await tx.update(deployment).set({ keyFailure: message }).where(eq(deployment.id, row.id));
        };
        if (!result.ok || !result.csr) return fail(result.error ?? "the Agent could not make the key");
        let csr;
        try {
          ({ csr } = await checkNamesAndCsr({ names: mc.names, csr: result.csr, keyAlgorithm: mc.keyAlgorithm }));
        } catch (err) {
          if (err instanceof HttpError) return fail(`the CSR the Agent sent is not usable: ${err.message}`);
          throw err;
        }
        await tx.update(managedCertificate).set({ csr: result.csr }).where(and(eq(managedCertificate.id, mc.id), eq(managedCertificate.organizationId, mc.organizationId)));
        await change.audit({
          organizationId: item.organizationId,
          action: "deployment.key_generated",
          target: { type: "deployment", id: row.id },
          detail: { agentId: row.agentId, managedCertificateId: mc.id, keyAlgorithm: mc.keyAlgorithm, csrFingerprint: csr.fingerprint, ...(issuanceId && { issuanceId }) },
        });
        if (issuanceId) {
          await issuances.keyMade(tx, change, issuanceId);
          return;
        }
        await tx.update(deployment).set({ keyFailure: null }).where(eq(deployment.id, row.id));
        // The first Issuance, as of whoever set the Deployment up. It is refused only if the Managed Certificate was archived meanwhile.
        await issuances.begin(tx, change, { id: row.createdById, email: row.createdByEmail }, mc, "issue");
      },
    },
  );

  workItems.register(
    DEPLOYMENT_WORK_TYPES.run,
    async (tx, item) => {
      const { deploymentId, certificateId, trigger } = item.payload as { deploymentId: string; certificateId: string; trigger: string };
      const [row] = await tx.select().from(deployment).where(and(eq(deployment.id, deploymentId), eq(deployment.organizationId, item.organizationId)));
      if (!row) throw new PreparationError("the Deployment is gone");
      const [mc] = await tx.select().from(managedCertificate).where(eq(managedCertificate.id, row.managedCertificateId));
      // Archiving stops deploying: what was asked before is not done after.
      if (!mc || mc.archivedAt) throw new PreparationError("the Managed Certificate is archived, so it is not deployed");
      const [cert] = await tx.select().from(certificate).where(and(eq(certificate.id, certificateId), eq(certificate.organizationId, item.organizationId)));
      const [script] = await tx.select().from(deploymentScript).where(eq(deploymentScript.id, row.scriptId));
      const [version] = await tx
        .select()
        .from(deploymentScriptVersion)
        .where(and(eq(deploymentScriptVersion.scriptId, row.scriptId), eq(deploymentScriptVersion.version, row.scriptVersion)));
      if (!cert || !script || !version) throw new PreparationError("the Certificate or the script is gone");
      return {
        deploymentId,
        managedCertificateId: mc.id,
        trigger,
        names: cert.names,
        certificate: { id: cert.id, fingerprint: cert.fingerprint, notAfter: cert.notAfter.toISOString(), chainPem: cert.chainPem },
        script: { name: script.name, interpreter: script.interpreter, version: version.version, hash: version.hash, content: version.content },
      };
    },
    {
      durable: true,
      // The Agent's report of the run: the Deployment Run, written with its Audit Event.
      async onResult(tx, change, item, result) {
        const { deploymentId, certificateId, trigger } = item.payload as { deploymentId: string; certificateId: string; trigger: "issuance" | "rerun" };
        const row = await lockDeployment(tx, item.organizationId, deploymentId);
        if (!row) return;
        const [version] = await tx
          .select({ hash: deploymentScriptVersion.hash })
          .from(deploymentScriptVersion)
          .where(and(eq(deploymentScriptVersion.scriptId, row.scriptId), eq(deploymentScriptVersion.version, row.scriptVersion)));
        const [cert] = await tx.select({ fingerprint: certificate.fingerprint }).from(certificate).where(eq(certificate.id, certificateId));
        const reported: Partial<RunReport> = result.run ?? {};
        const output = truncate(reported.output ?? result.error ?? "the Agent reported no output", OUTPUT_LIMIT_BYTES);
        const at = (value: string | undefined) => {
          const date = value ? new Date(value) : change.occurredAt;
          return Number.isNaN(date.getTime()) ? change.occurredAt : date;
        };
        const status = result.ok && (reported.exitCode ?? 0) === 0 ? "succeeded" : "failed";
        const [run] = await tx
          .insert(deploymentRun)
          .values({
            organizationId: item.organizationId,
            deploymentId: row.id,
            certificateId,
            trigger,
            status,
            scriptVersion: row.scriptVersion,
            scriptHash: version!.hash,
            startedAt: at(reported.startedAt),
            finishedAt: at(reported.finishedAt),
            exitCode: reported.exitCode ?? null,
            output: output.text,
            outputTruncated: output.truncated || reported.outputTruncated === true,
            createdAt: change.occurredAt,
          })
          .returning({ id: deploymentRun.id });
        await change.audit({
          organizationId: item.organizationId,
          action: `deployment_run.${status}`,
          target: { type: "deployment", id: row.id },
          detail: {
            runId: run!.id,
            agentId: row.agentId,
            managedCertificateId: row.managedCertificateId,
            certificateId,
            fingerprint: cert!.fingerprint,
            trigger,
            scriptVersion: row.scriptVersion,
            scriptHash: version!.hash,
            exitCode: reported.exitCode ?? null,
          },
        });
      },
    },
  );

  // A Renewal asks the Deployment's Agent for a new key. The request waits for the Agent however long it is away; a
  // revoked Agent is never given work, so it is not asked.
  issuances.askForKeyWith(async (tx, change, waiting) => {
    const [row] = await tx.select().from(deployment).where(and(eq(deployment.organizationId, waiting.organizationId), eq(deployment.managedCertificateId, waiting.managedCertificateId)));
    if (!row) throw new Error("a Managed Certificate whose key an Agent holds has no Deployment");
    // Shared, so that the Agent being revoked finishes first, and ends this Renewal, or is seen revoked.
    const [holder] = await tx.select({ revokedAt: agent.revokedAt }).from(agent).where(eq(agent.id, row.agentId)).for("share");
    if (!holder || holder.revokedAt) return "agent_revoked";
    await workItems.enqueueIn(tx, change, waiting.organizationId, row.agentId, DEPLOYMENT_WORK_TYPES.generateKey, { deploymentId: row.id, issuanceId: waiting.issuanceId });
  });

  // A Certificate for a Managed Certificate with a Deployment is given to its Agent to deploy, as it is stored.
  issuances.onIssued(async (tx, change, issued) => {
    const [row] = await tx.select().from(deployment).where(and(eq(deployment.organizationId, issued.organizationId), eq(deployment.managedCertificateId, issued.managedCertificateId)));
    if (!row) return;
    const [mc] = await tx.select({ archivedAt: managedCertificate.archivedAt }).from(managedCertificate).where(eq(managedCertificate.id, issued.managedCertificateId));
    if (mc?.archivedAt) return;
    await workItems.enqueueIn(tx, change, issued.organizationId, row.agentId, DEPLOYMENT_WORK_TYPES.run, { deploymentId: row.id, certificateId: issued.certificateId, trigger: "issuance" });
  });

  // ---- Routes ------------------------------------------------------------------------------------------------------

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/deployments",
      tags: ["Deployments"],
      summary: "Set up a Deployment: an Agent makes the key for a new Managed Certificate and runs a Deployment Script with each Certificate",
      description:
        "Organization Administrators only, and no Approval is needed. It creates the Managed Certificate (Key Custody: Agent, bound to this one Agent and this Deployment) with the names, key algorithm and Renewal Policy given, " +
        "and asks the Agent to make the key and send a CSR for it: the private key never reaches the platform. Once the Agent has, Issuance begins; when the Certificate is stored the Agent is given it and the script, " +
        "and its report of running it is the first Deployment Run. One Agent can serve many Deployments. The script version is pinned: the latest unless `scriptVersion` says. " +
        "An Agent that is offline does the work when it next polls.",
      request: {
        params: OrgParam,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                agentId: z.string().openapi({ description: "One of the Organization's Agents, not revoked." }),
                scriptId: z.string().openapi({ description: "A Deployment Script of the Organization." }),
                scriptVersion: z.number().int().min(1).optional().openapi({ description: "Which version of the script to run; the latest by default." }),
                names: namesField("The DNS names to issue for."),
                keyAlgorithm: z.enum(KEY_ALGORITHMS),
                environment: z.enum(ACME_ENVIRONMENTS).default("staging").openapi({ description: "Which of the Organization's ACME accounts to issue through." }),
                renewalPolicy: RenewalPolicy.default({ mode: "automatic", daysBeforeExpiry: 30 }),
              }),
            },
          },
        },
      },
      responses: { 201: json(Deployment, "Set up, and the Agent asked to make the key"), ...errors(400, 401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { deployment: ["create"] });
      const normalized = normalizeNames(body.names);
      if ("invalid" in normalized) throw new HttpError(400, `"${normalized.invalid}" cannot be a name to issue for`);
      if (normalized.names.length > MAX_NAMES) throw new HttpError(400, `at most ${MAX_NAMES} names`);
      if (!UUID.test(body.agentId)) throw new HttpError(400, "the Agent must be the id of one of the Organization's Agents");
      if (!UUID.test(body.scriptId)) throw new HttpError(400, "the script must be the id of one of the Organization's Deployment Scripts");

      const created = await unitOfWork.run(actor, async (tx, change) => {
        // Shared, so that the Agent being revoked finishes first, or is seen revoked.
        const [chosen] = await tx.select().from(agent).where(and(eq(agent.id, body.agentId), eq(agent.organizationId, orgId))).for("share");
        if (!chosen) throw new HttpError(400, "the Agent must be the id of one of the Organization's Agents");
        if (chosen.revokedAt) throw new HttpError(400, `the Agent ${chosen.hostName} is revoked and cannot run Deployments`);
        const [script] = await tx.select().from(deploymentScript).where(and(eq(deploymentScript.id, body.scriptId), eq(deploymentScript.organizationId, orgId)));
        if (!script) throw new HttpError(400, "the script must be the id of one of the Organization's Deployment Scripts");
        const [version] = await tx
          .select()
          .from(deploymentScriptVersion)
          .where(and(eq(deploymentScriptVersion.scriptId, script.id), ...(body.scriptVersion ? [eq(deploymentScriptVersion.version, body.scriptVersion)] : [])))
          .orderBy(desc(deploymentScriptVersion.version))
          .limit(1);
        if (!version) throw new HttpError(400, `the script has no version ${body.scriptVersion}`);

        const [mc] = await tx
          .insert(managedCertificate)
          .values({
            organizationId: orgId,
            names: normalized.names,
            keyAlgorithm: body.keyAlgorithm,
            keyCustody: "agent",
            environment: body.environment,
            csr: null,
            renewalMode: body.renewalPolicy.mode,
            renewalDaysBeforeExpiry: body.renewalPolicy.daysBeforeExpiry,
          })
          .returning();
        const [row] = await tx
          .insert(deployment)
          .values({
            organizationId: orgId,
            managedCertificateId: mc!.id,
            agentId: chosen.id,
            scriptId: script.id,
            scriptVersion: version.version,
            createdById: actor.id,
            createdByEmail: actor.email,
            createdAt: change.occurredAt,
          })
          .returning();
        await change.audit({
          organizationId: orgId,
          action: "managed_certificate.created",
          target: { type: "managed_certificate", id: mc!.id },
          detail: { names: mc!.names, keyAlgorithm: mc!.keyAlgorithm, keyCustody: "agent", environment: mc!.environment, deploymentId: row!.id },
        });
        await change.audit({
          organizationId: orgId,
          action: "deployment.created",
          target: { type: "deployment", id: row!.id },
          detail: {
            managedCertificateId: mc!.id,
            names: mc!.names,
            keyAlgorithm: mc!.keyAlgorithm,
            agentId: chosen.id,
            agentHostName: chosen.hostName,
            scriptId: script.id,
            scriptName: script.name,
            scriptVersion: version.version,
            scriptHash: version.hash,
            renewalPolicy: body.renewalPolicy,
          },
        });
        await workItems.enqueueIn(tx, change, orgId, chosen.id, DEPLOYMENT_WORK_TYPES.generateKey, { deploymentId: row!.id });
        return row!;
      });
      return c.json((await withState([created]))[0]!, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/deployments",
      tags: ["Deployments"],
      summary: "List the Deployments, newest first, a page at a time",
      description: "Each with its Agent, script version, where it has got to and its latest Deployment Run. Organization Administrators only.",
      request: { params: OrgParam, query: PageQuery },
      responses: { 200: json(pageOf(Deployment)), ...errors(400, 401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { deployment: ["read"] });
      const { page, pageSize } = c.req.valid("query");
      const where = eq(deployment.organizationId, orgId);
      const [total, rows] = await Promise.all([
        db.$count(deployment, where),
        db.select().from(deployment).where(where).orderBy(desc(deployment.createdAt), desc(deployment.id)).limit(pageSize).offset((page - 1) * pageSize),
      ]);
      return c.json({ items: await withState(rows), total, page, pageSize }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/deployments/{id}",
      tags: ["Deployments"],
      summary: "One Deployment, with its latest Deployment Run",
      request: { params: DeploymentParams },
      responses: { 200: json(Deployment), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { deployment: ["read"] });
      return c.json((await withState([await findDeployment(orgId, id)]))[0]!, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/deployments/{id}/runs",
      tags: ["Deployments"],
      summary: "The Deployment's runs, newest first, a page at a time",
      request: { params: DeploymentParams, query: PageQuery },
      responses: { 200: json(pageOf(Run)), ...errors(400, 401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { deployment: ["read"] });
      const row = await findDeployment(orgId, id);
      const { page, pageSize } = c.req.valid("query");
      const where = eq(deploymentRun.deploymentId, row.id);
      const [total, runs] = await Promise.all([
        db.$count(deploymentRun, where),
        db
          .select({ run: deploymentRun, fingerprint: certificate.fingerprint })
          .from(deploymentRun)
          .innerJoin(certificate, eq(certificate.id, deploymentRun.certificateId))
          .where(where)
          .orderBy(desc(deploymentRun.createdAt), desc(deploymentRun.id))
          .limit(pageSize)
          .offset((page - 1) * pageSize),
      ]);
      return c.json({ items: runs.map((r) => toRun(r.run, r.fingerprint)), total, page, pageSize }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/deployments/{id}/runs",
      tags: ["Deployments"],
      summary: "Run the Deployment again for its current Certificate, without renewing",
      description:
        "Has the Agent run the script once more for the Managed Certificate's current Certificate, for recovering after a broken script or target has been fixed. Nothing is issued. " +
        "The script version is the one the Deployment is pinned to. When the Agent could not make the key, it asks for the key again instead. Refused while there is no Certificate yet, while the Managed Certificate is archived or the Agent revoked, and while a run is already waiting for the Agent. " +
        "The run is recorded when the Agent reports it.",
      request: { params: DeploymentParams },
      responses: { 202: json(Deployment, "The Agent is asked; `runPending` is true until it reports"), ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { deployment: ["run"] });
      await findDeployment(orgId, id);
      await unitOfWork.run(actor, async (tx, change) => {
        // Under the Managed Certificate's lock, so an archive or an Issuance racing this has finished.
        const row = await lockDeployment(tx, orgId, id);
        if (!row) throw new HttpError(404, "Deployment not found");
        const mc = await lockManagedCertificate(tx, orgId, row.managedCertificateId);
        if (mc.archivedAt) throw new HttpError(409, "the Managed Certificate is archived, so it is not deployed");
        const [chosen] = await tx.select().from(agent).where(eq(agent.id, row.agentId));
        if (chosen?.revokedAt) throw new HttpError(409, `the Agent ${chosen.hostName} is revoked and cannot run Deployments`);
        const [current] = await tx
          .select({ id: certificate.id, fingerprint: certificate.fingerprint })
          .from(certificate)
          .where(and(eq(certificate.organizationId, orgId), eq(certificate.managedCertificateId, mc.id)))
          .orderBy(desc(certificate.createdAt), desc(certificate.id))
          .limit(1);
        if (mc.csr === null) {
          // No key yet. When the Agent could not make it, running the Deployment again asks for it again.
          if (!row.keyFailure) throw new HttpError(409, "the Agent has not yet made the key for this Deployment");
          await tx.update(deployment).set({ keyFailure: null }).where(eq(deployment.id, row.id));
          await workItems.enqueueIn(tx, change, orgId, row.agentId, DEPLOYMENT_WORK_TYPES.generateKey, { deploymentId: row.id });
          await change.audit({ organizationId: orgId, action: "deployment.key_requested", target: { type: "deployment", id: row.id }, detail: { agentId: row.agentId, managedCertificateId: mc.id, previousFailure: row.keyFailure } });
          return;
        }
        if (!current) throw new HttpError(409, "the Managed Certificate has no Certificate yet to deploy");
        const [waiting] = await tx
          .select({ id: workItem.id })
          .from(workItem)
          .where(and(eq(workItem.type, DEPLOYMENT_WORK_TYPES.run), inArray(workItem.status, ["pending", "delivered"]), sql`${workItem.payload}->>'deploymentId' = ${row.id}`))
          .limit(1);
        if (waiting) throw new HttpError(409, "a run of this Deployment is already waiting for its Agent");
        await workItems.enqueueIn(tx, change, orgId, row.agentId, DEPLOYMENT_WORK_TYPES.run, { deploymentId: row.id, certificateId: current.id, trigger: "rerun" });
        await change.audit({
          organizationId: orgId,
          action: "deployment.run_requested",
          target: { type: "deployment", id: row.id },
          detail: { agentId: row.agentId, managedCertificateId: mc.id, certificateId: current.id, fingerprint: current.fingerprint },
        });
      });
      return c.json((await withState([await findDeployment(orgId, id)]))[0]!, 202);
    },
  );
}
