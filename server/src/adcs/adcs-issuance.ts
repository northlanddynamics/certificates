// Issuing from an ADCS CA: the ADCS kind of issuer (issuer.ts). The platform never reaches ADCS itself (ADR 0013): an
// Issuance's CSR becomes a request (`adcs_request`) that one online Agent assigned to the CA submits under the
// Certificate Template, as `adcs.submit`, and the Issuance waits, pending, until that Agent reports. An Agent that cannot
// reach the CA has it given to another online one; while none is online it waits, and after 7 days it fails as "no Agent
// available". An Agent given it that does not report in time is given up on for another. Before anything is submitted the
// platform checks what ADCS would not: the template is still available, the names keep to the CA's Permitted Name Rules,
// and the key to the template's key requirements. The template decides validity.
import * as x509 from "@peculiar/x509";
import { and, asc, desc, eq, inArray } from "drizzle-orm";
import { offeredFor, templateKeyRefusal, unavailableReason } from "./adcs-kinds";
import { ADCS_WORK_TYPES } from "./adcs-work";
import { CertificateAuthorityError } from "../issuance/acme/certificate-authority";
import type { Issuances } from "../issuance/issuance";
import { IssuanceFailure } from "../issuance/issuance-failure";
import type { Issued, IssueRequest, Pending } from "../issuance/issuer";
import type { WorkItems, WorkResult } from "../agents/work-items";
import type { Db, Tx } from "../platform/db/client";
import { adcsCa, adcsCaAgent, adcsRequest, adcsTemplate, agent, issuance, workItem } from "../platform/db/schema";
import { parseCsr, type KeyAlgorithm } from "../pki/csr";
import { namesOutside, type PermittedNames } from "../private-ca/permitted-names";
import type { Change, UnitOfWork } from "../platform/unit-of-work";

type AdcsCaRow = typeof adcsCa.$inferSelect;
type TemplateRow = typeof adcsTemplate.$inferSelect;
type RequestRow = typeof adcsRequest.$inferSelect;
type AdcsIssuer = { adcsCaId: string; templateId: string };

/** How long a request may wait for an Agent to submit it before its Issuance fails as "no Agent available". */
export const NO_AGENT_TIMEOUT_MS = 7 * 24 * 3600_000;
/**
 * How much later than that the Issuance's own deadline is: a backstop, for a request this module could not end itself
 * (it ends them with a cause of its own, which the generic `timed_out` would hide).
 */
const DEADLINE_BACKSTOP_MS = 3600_000;

export interface AdcsSubmitConfig {
  /** How long an Agent given a request to submit has to report on it before it is given to another online one. */
  submitTimeoutMs: number;
}

export const DEFAULT_ADCS_SUBMIT: AdcsSubmitConfig = { submitTimeoutMs: 10 * 60_000 };

/** An ADCS CA's Permitted Name Rules, from its row; none while it has none. */
export const adcsPermittedNamesOf = (row: Pick<AdcsCaRow, "permittedExactNames" | "permittedZones">): PermittedNames | null =>
  row.permittedExactNames && row.permittedZones ? { exact: row.permittedExactNames, zones: row.permittedZones } : null;

/** The template in words, by its display name and its CA's name. */
export const templateLabel = (ca: Pick<AdcsCaRow, "name">, template: Pick<TemplateRow, "displayName" | "name">) =>
  `the Certificate Template ${template.displayName || template.name} of the ADCS CA ${ca.name}`;

/** Why the ADCS CA may not issue for the names (normalised): those its Permitted Name Rules do not permit. None when it has none, or they do. */
export function adcsNamesRefusal(ca: AdcsCaRow, names: string[]) {
  const rules = adcsPermittedNamesOf(ca);
  const outside = rules ? namesOutside(rules, names) : [];
  return outside.length === 0 ? undefined : `${outside.join(", ")} ${outside.length === 1 ? "is" : "are"} outside the Permitted Name Rules of the ADCS CA ${ca.name}`;
}

/** The Organization's ADCS CA and the template of it, each none when it has none such. */
async function findIssuer(db: Db | Tx, organizationId: string, issuer: AdcsIssuer) {
  const isId = (id: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
  const [ca] = isId(issuer.adcsCaId) ? await db.select().from(adcsCa).where(and(eq(adcsCa.organizationId, organizationId), eq(adcsCa.id, issuer.adcsCaId))) : [];
  const [template] =
    ca && isId(issuer.templateId) ? await db.select().from(adcsTemplate).where(and(eq(adcsTemplate.adcsCaId, ca.id), eq(adcsTemplate.id, issuer.templateId))) : [];
  return { ca, template };
}

/**
 * Why a Managed Certificate may not ask the ADCS CA and template for the names (normalised), the validity and, when
 * given, the key algorithm: a 400 for any validity, which the template decides; a 422 for a CA or template that is not
 * the Organization's, a template not offered for TLS (unavailable, hidden, or without Server Authentication), names
 * outside the CA's Permitted Name Rules, or a key the template does not take. None when it may.
 */
export async function adcsIssuerRefusal(db: Db | Tx, organizationId: string, issuer: AdcsIssuer, asked: { names: string[]; validityDays: number | null; keyAlgorithm?: KeyAlgorithm }) {
  const refused = (status: 400 | 422, message: string) => ({ status, message });
  if (asked.validityDays !== null) return refused(400, "a validity can be chosen only for a Managed Certificate issued from a Private CA: an ADCS CA's Certificate Template decides it");
  const { ca, template } = await findIssuer(db, organizationId, issuer);
  if (!ca) return refused(422, "the Organization has no such ADCS CA");
  if (!template) return refused(422, `the ADCS CA ${ca.name} has no such Certificate Template`);
  if (!offeredFor(template).includes("tls")) {
    const why = unavailableReason(template) ?? (template.hidden ? "an Organization Administrator hid it." : "It has no Server Authentication EKU.");
    return refused(422, `${templateLabel(ca, template)} is not offered for TLS: ${why}`);
  }
  const refusal = adcsNamesRefusal(ca, asked.names) ?? (asked.keyAlgorithm && templateKeyRefusal(template, asked.keyAlgorithm));
  return refusal ? refused(422, refusal) : undefined;
}

/** Where an ADCS request stands, as an Issuance shows it. */
export interface AdcsRequestShown {
  status: RequestRow["status"];
  agent: { id: string; hostName: string } | null;
  requestId: string | null;
}

/** The ADCS requests of the Issuances, by Issuance. */
export async function adcsRequestsOf(db: Db, issuanceIds: string[]): Promise<Map<string, AdcsRequestShown>> {
  if (issuanceIds.length === 0) return new Map();
  const rows = await db
    .select({ request: adcsRequest, hostName: agent.hostName })
    .from(adcsRequest)
    .leftJoin(agent, eq(agent.id, adcsRequest.agentId))
    .where(inArray(adcsRequest.issuanceId, issuanceIds));
  return new Map(
    rows.map(({ request, hostName }) => [
      request.issuanceId,
      { status: request.status, agent: request.agentId && hostName !== null ? { id: request.agentId, hostName } : null, requestId: request.adcsRequestId },
    ]),
  );
}

export interface AdcsIssuance {
  /**
   * Checks what can be checked before ADCS sees the request, then records it and gives it to an online assigned Agent
   * (or has it wait for one), and answers Pending. Throws an IssuanceFailure when the template is no longer available,
   * a name is outside the CA's Permitted Name Rules, or the key does not meet the template's requirements.
   */
  issue(db: Db | Tx, organizationId: string, issuer: AdcsIssuer, request: IssueRequest): Promise<Pending>;
  /** The root (PEM) the ADCS CA's chain ends in. */
  roots(db: Db | Tx, organizationId: string, adcsCaId: string): Promise<string[]>;
  /** Where the outcome of each request is reported. */
  reportTo(issuances: Issuances): void;
  /**
   * One pass at the clock's time: gives each request waiting for an Agent to an online one; gives up on an Agent that has
   * not reported in time for another; fails requests that waited 7 days as "no Agent available"; and reports again an
   * outcome that was recorded but not yet reported. Returns how many requests it looked at.
   */
  tick(): Promise<number>;
}

export function createAdcsIssuance({
  db,
  unitOfWork,
  workItems,
  clock,
  offlineAfterSeconds,
  config,
}: {
  db: Db;
  unitOfWork: UnitOfWork;
  workItems: WorkItems;
  clock: () => Date;
  offlineAfterSeconds: number;
  config: AdcsSubmitConfig;
}): AdcsIssuance {
  let issuances: Issuances | undefined;

  /** Has the Issuance told what came of its request, once the change that recorded it has committed. */
  const report = (change: Change, issuanceId: string, result: Issued | { failed: unknown }) =>
    change.afterCommit(async () => {
      if (!issuances) throw new Error("nothing takes the outcome of ADCS requests");
      await issuances.report(issuanceId, result);
    });

  /** The ADCS CA's chain above a Certificate it issued: its CA certificate and each certificate up to, but not, its root. */
  const above = (ca: AdcsCaRow) => [ca.caCertificatePem, ...ca.chainPem];
  const pemOf = (pem: string) => `${pem.trim()}\n`;

  /** What ADCS issued for a request, as the Issuance stores it: the Certificate then the CA's chain short of its root. */
  function issuedOf(ca: AdcsCaRow, row: RequestRow): Issued {
    const chain = [row.certificatePem!, ...above(ca).slice(0, -1)];
    return { chainPem: chain.map(pemOf).join(""), ca: ca.name, issuedBy: { kind: "adcs", adcsCaId: ca.id, templateId: row.templateId, requestId: row.adcsRequestId! } };
  }

  /** The Agents assigned to the CA, most recently heard from first, with whether each is online now. */
  async function assignedAgents(tx: Tx, adcsCaId: string, now: Date) {
    const rows = await tx
      .select({ id: agent.id, hostName: agent.hostName, revokedAt: agent.revokedAt, lastContactAt: agent.lastContactAt })
      .from(adcsCaAgent)
      .innerJoin(agent, eq(agent.id, adcsCaAgent.agentId))
      .where(eq(adcsCaAgent.adcsCaId, adcsCaId))
      .orderBy(desc(agent.lastContactAt), asc(agent.id));
    return rows.map((a) => ({ ...a, online: !a.revokedAt && now.getTime() - a.lastContactAt.getTime() <= offlineAfterSeconds * 1000 }));
  }

  /**
   * Gives the request (locked by the caller) to an online assigned Agent it has not been tried on, as `adcs.submit`; or,
   * when there is none, has it wait. Returns the Agent given it, if one was.
   */
  async function dispatch(tx: Tx, change: Change, row: RequestRow, tried: string[]) {
    const [ca] = await tx.select().from(adcsCa).where(eq(adcsCa.id, row.adcsCaId));
    const [template] = await tx.select().from(adcsTemplate).where(eq(adcsTemplate.id, row.templateId));
    const next = (await assignedAgents(tx, row.adcsCaId, change.occurredAt)).find((a) => a.online && !tried.includes(a.id));
    if (!next) {
      await tx.update(adcsRequest).set({ status: "waiting", triedAgentIds: tried, agentId: null, workItemId: null, submittedAt: null }).where(eq(adcsRequest.id, row.id));
      return undefined;
    }
    const itemId = await workItems.enqueueIn(tx, change, row.organizationId, next.id, ADCS_WORK_TYPES.submit, {
      requestId: row.id,
      configString: ca!.configString,
      template: template!.name,
      csr: row.csr,
    });
    await tx
      .update(adcsRequest)
      .set({ status: "submitted", triedAgentIds: tried, agentId: next.id, workItemId: itemId, submittedAt: change.occurredAt })
      .where(eq(adcsRequest.id, row.id));
    return next;
  }

  /** Ends the request (locked by the caller) as failed, and has its Issuance fail with `failure`. */
  async function fail(tx: Tx, change: Change, row: RequestRow, failure: unknown) {
    await tx.update(adcsRequest).set({ status: "failed", finishedAt: change.occurredAt }).where(eq(adcsRequest.id, row.id));
    report(change, row.issuanceId, { failed: failure });
  }

  /** Stops the Agent being given the request's work item, or reporting on it: it was given up on. */
  const expireItem = (tx: Tx, change: Change, row: RequestRow) =>
    row.workItemId
      ? tx
          .update(workItem)
          .set({ status: "expired", finishedAt: change.occurredAt })
          .where(and(eq(workItem.id, row.workItemId), inArray(workItem.status, ["pending", "delivered"])))
      : Promise.resolve();

  /** What follows from an Agent's report of `adcs.submit`, on the transaction that records the report. */
  async function submitted(tx: Tx, change: Change, item: { organizationId: string; agentId: string; payload: Record<string, unknown> }, result: WorkResult) {
    const [row] = await tx
      .select()
      .from(adcsRequest)
      .where(and(eq(adcsRequest.id, String(item.payload.requestId)), eq(adcsRequest.organizationId, item.organizationId)))
      .for("update");
    // Given to another Agent since, or ended: what this one says is no longer asked.
    if (!row || row.status !== "submitted" || row.agentId !== item.agentId) return;
    const [ca] = await tx.select().from(adcsCa).where(eq(adcsCa.id, row.adcsCaId));
    const [template] = await tx.select().from(adcsTemplate).where(eq(adcsTemplate.id, row.templateId));
    const [by] = await tx.select({ id: agent.id, hostName: agent.hostName }).from(agent).where(eq(agent.id, item.agentId));
    const [of] = await tx.select({ managedCertificateId: issuance.managedCertificateId }).from(issuance).where(eq(issuance.id, row.issuanceId));

    if (result.ok && result.submission?.status === "issued") {
      const { requestId, certificate } = result.submission;
      try {
        new x509.X509Certificate(certificate);
      } catch {
        return fail(tx, change, row, new CertificateAuthorityError("rejected", `the Agent ${by!.hostName} reported a Certificate from ADCS that cannot be read`));
      }
      const [issued] = await tx
        .update(adcsRequest)
        .set({ status: "issued", adcsRequestId: requestId, certificatePem: certificate, finishedAt: change.occurredAt })
        .where(eq(adcsRequest.id, row.id))
        .returning();
      await change.audit({
        organizationId: row.organizationId,
        action: "adcs_ca.request_submitted",
        target: { type: "managed_certificate", id: of!.managedCertificateId },
        detail: {
          issuanceId: row.issuanceId,
          adcsCa: { id: ca!.id, name: ca!.name },
          template: { id: template!.id, name: template!.name },
          agent: by,
          adcsRequestId: requestId,
          disposition: "issued",
        },
      });
      report(change, row.issuanceId, issuedOf(ca!, issued!));
      return;
    }
    if (!result.ok && result.kind === "unreachable") {
      // Another Agent may reach the CA from where it is; when every one has been tried, none can.
      const tried = [...row.triedAgentIds, item.agentId];
      if (await dispatch(tx, change, row, tried)) return;
      const assigned = (await assignedAgents(tx, row.adcsCaId, change.occurredAt)).filter((a) => !a.revokedAt);
      if (assigned.every((a) => tried.includes(a.id))) {
        await fail(tx, change, row, new CertificateAuthorityError("unreachable", `no Agent assigned to the ADCS CA ${ca!.name} could reach it; the last, ${by!.hostName}, reported: ${result.error ?? "it could not reach it"}`));
      }
      return;
    }
    const why = result.ok ? "it reported no Certificate" : (result.error ?? "it reported no reason");
    await fail(tx, change, row, new CertificateAuthorityError("rejected", `the ADCS CA ${ca!.name} refused the request, through the Agent ${by!.hostName}: ${why}`));
  }

  // The payload is all the Agent needs: it reaches ADCS as its own account. Our own id of the request stays with the platform.
  workItems.register(ADCS_WORK_TYPES.submit, async (_tx, item) => ({ configString: item.payload.configString, template: item.payload.template, csr: item.payload.csr }), {
    onResult: submitted,
  });

  /** One open request's turn in a pass, under the locks a report takes, in the order it takes them: the work item's, then the request's. */
  async function attend(id: string, workItemId: string | null) {
    await unitOfWork.run(null, async (tx, change) => {
      if (workItemId) await tx.select({ id: workItem.id }).from(workItem).where(eq(workItem.id, workItemId)).for("update");
      const [row] = await tx.select().from(adcsRequest).where(eq(adcsRequest.id, id)).for("update");
      if (!row || (row.status !== "waiting" && row.status !== "submitted") || row.workItemId !== workItemId) return;
      const [of] = await tx.select({ status: issuance.status }).from(issuance).where(eq(issuance.id, row.issuanceId));
      if (of?.status !== "running") {
        // Its Issuance ended without it (the platform stopped before it was recorded, or it timed out): nothing to submit for.
        await expireItem(tx, change, row);
        await tx.update(adcsRequest).set({ status: "failed", finishedAt: change.occurredAt }).where(eq(adcsRequest.id, row.id));
        return;
      }
      const [ca] = await tx.select().from(adcsCa).where(eq(adcsCa.id, row.adcsCaId));
      if (change.occurredAt.getTime() - row.createdAt.getTime() >= NO_AGENT_TIMEOUT_MS) {
        await expireItem(tx, change, row);
        await fail(tx, change, row, new IssuanceFailure("no_agent_available", `no Agent assigned to the ADCS CA ${ca!.name} submitted the request within 7 days; ask for it again once one is online`));
        return;
      }
      if (row.status === "submitted") {
        if (change.occurredAt.getTime() - row.submittedAt!.getTime() < config.submitTimeoutMs) return;
        // The Agent did not report in time: another is given it, or, when there is none, any that comes online again.
        await expireItem(tx, change, row);
        const tried = [...row.triedAgentIds, row.agentId!];
        if (!(await dispatch(tx, change, row, tried))) await dispatch(tx, change, row, []);
        return;
      }
      await dispatch(tx, change, row, row.triedAgentIds);
    });
  }

  return {
    async issue(dbOrTx, organizationId, issuer, request) {
      const { ca, template } = await findIssuer(dbOrTx, organizationId, issuer);
      if (!ca || !template) throw new IssuanceFailure("internal", "the ADCS CA or its Certificate Template is gone");
      const unavailable = unavailableReason(template);
      if (unavailable) throw new IssuanceFailure("template_unavailable", `${templateLabel(ca, template)} is unavailable: ${unavailable}`);
      const outside = adcsNamesRefusal(ca, request.names);
      if (outside) throw new IssuanceFailure("name_not_permitted", outside);
      const keyRefusal = templateKeyRefusal(template, (await parseCsr(request.csr)).keyAlgorithm);
      if (keyRefusal) throw new IssuanceFailure("ca_rejected", keyRefusal);
      return unitOfWork.run(null, async (tx, change) => {
        const [row] = await tx
          .insert(adcsRequest)
          .values({ organizationId, adcsCaId: ca.id, templateId: template.id, issuanceId: request.issuanceId, csr: request.csr, status: "waiting", createdAt: change.occurredAt })
          .returning();
        await dispatch(tx, change, row!, []);
        return { pending: { handle: row!.id, deadline: new Date(change.occurredAt.getTime() + NO_AGENT_TIMEOUT_MS + DEADLINE_BACKSTOP_MS) } };
      });
    },
    async roots(dbOrTx, organizationId, adcsCaId) {
      const [ca] = await dbOrTx.select().from(adcsCa).where(and(eq(adcsCa.organizationId, organizationId), eq(adcsCa.id, adcsCaId)));
      return ca ? [above(ca).at(-1)!] : [];
    },
    reportTo(to) {
      issuances = to;
    },
    async tick() {
      const open = await db
        .select({ id: adcsRequest.id, workItemId: adcsRequest.workItemId })
        .from(adcsRequest)
        .where(inArray(adcsRequest.status, ["waiting", "submitted"]))
        .orderBy(asc(adcsRequest.createdAt));
      for (const { id, workItemId } of open) await attend(id, workItemId).catch((err) => console.error("could not attend to the ADCS request", id, err));
      // An outcome recorded whose report did not reach its Issuance (the platform stopped in between) is reported again.
      const unreported = await db
        .select({ request: adcsRequest, ca: adcsCa })
        .from(adcsRequest)
        .innerJoin(issuance, eq(issuance.id, adcsRequest.issuanceId))
        .innerJoin(adcsCa, eq(adcsCa.id, adcsRequest.adcsCaId))
        .where(and(eq(adcsRequest.status, "issued"), eq(issuance.status, "running")));
      for (const { request, ca } of unreported) await issuances?.report(request.issuanceId, issuedOf(ca, request));
      return open.length;
    },
  };
}
