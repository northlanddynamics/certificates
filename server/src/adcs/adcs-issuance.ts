// Issuing from an ADCS CA: the ADCS kind of issuer (issuer.ts). The platform never reaches ADCS itself (ADR 0013): an
// Issuance's CSR becomes a request (`adcs_request`) that one online Agent assigned to the CA submits under the
// Certificate Template, as `adcs.submit`, and the Issuance waits, pending, until that Agent reports. An Agent that cannot
// reach the CA has it given to another online one; while none is online it waits, and after 7 days it fails as "no Agent
// available". An Agent that has not taken the work item in time is given up on for another; one that has taken it is not,
// since ADCS may be issuing for it, and a second submission would issue twice. Before anything is submitted the
// platform checks what ADCS would not: the template is still available, the names keep to the CA's Permitted Name Rules,
// and the key to the template's key requirements. The template decides validity.
//
// ADCS may hold a request for a CA manager's approval (the template says so). The request is then pending at ADCS, with
// ADCS's ID of it, and an online assigned Agent is asked again where it stands, as `adcs.check`, on a backoff that grows to
// once every 15 minutes, until ADCS issues or denies it, or until 7 days after it was submitted, when it is pending too
// long. A check is only a question, so one that is not answered in time is asked of another Agent, or again later.
//
// An Enrollment Profile on an ADCS CA has its requests go the same way (`request`): a device's CSR, which its SCEP
// transaction waits for, and the profile's RA certificate. What comes of those is handed to whoever registered for
// their purpose (`handle`), on the transaction that learned it, rather than to an Issuance.
import * as x509 from "@peculiar/x509";
import { and, asc, desc, eq, inArray, isNotNull, lte, or } from "drizzle-orm";
import { offeredFor, templateKeyRefusal, unavailableReason } from "./adcs-kinds";
import { ADCS_WORK_TYPES, type SubmissionResult } from "./adcs-work";
import { CertificateAuthorityError } from "../issuance/acme/certificate-authority";
import type { Failed, Issuances } from "../issuance/issuance";
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
export type AdcsRequestRow = typeof adcsRequest.$inferSelect;
type RequestRow = AdcsRequestRow;
type AdcsIssuer = { adcsCaId: string; templateId: string };

/** What a request not for an Issuance is for: a device's Device Certificate, or an Enrollment Profile's RA certificate. */
export type AdcsRequestPurpose = Exclude<RequestRow["purpose"], "issuance">;

/**
 * Who takes what comes of the requests of one purpose, on the transaction that learned it, with the request locked: the
 * Certificate (PEM) ADCS issued for it, or why it failed (an IssuanceFailure or a CertificateAuthorityError, whose
 * message says why). Neither is told twice.
 */
export interface AdcsOutcomes {
  issued(tx: Tx, change: Change, request: RequestRow, certificatePem: string): Promise<void>;
  failed(tx: Tx, change: Change, request: RequestRow, failure: Error): Promise<void>;
}

/** The statuses of a request that has not ended. */
const OPEN: RequestRow["status"][] = ["waiting", "submitted", "pending"];

/** How long a request may wait for an Agent to submit it before its Issuance fails as "no Agent available". */
export const NO_AGENT_TIMEOUT_MS = 7 * 24 * 3600_000;
/**
 * How much later than that the Issuance's own deadline is: a backstop, for a request this module could not end itself
 * (it ends them with a cause of its own, which the generic `timed_out` would hide).
 */
const DEADLINE_BACKSTOP_MS = 3600_000;
/** How long after its submission a request ADCS holds pending may stay so before its Issuance fails as "pending too long". */
export const PENDING_TIMEOUT_MS = 7 * 24 * 3600_000;
/** How long after ADCS said it holds a request it is first checked; each check after waits twice as long as the one before, up to the longest wait. */
export const FIRST_CHECK_AFTER_MS = 60_000;
export const LONGEST_CHECK_WAIT_MS = 15 * 60_000;

/** How long to wait before checking a pending request again, after `checks` checks. */
export const checkWaitMs = (checks: number) => Math.min(FIRST_CHECK_AFTER_MS * 2 ** Math.min(checks, 20), LONGEST_CHECK_WAIT_MS);

export interface AdcsSubmitConfig {
  /**
   * How long an Agent given a request to submit has to take it before it is given to another online one; and how long one
   * given a pending request to check has to report before the check is asked of another.
   */
  submitTimeoutMs: number;
}

export const DEFAULT_ADCS_SUBMIT: AdcsSubmitConfig = { submitTimeoutMs: 10 * 60_000 };

/** An ADCS CA's Permitted Name Rules, from its row; none while it has none. */
export const adcsPermittedNamesOf = (row: Pick<AdcsCaRow, "permittedExactNames" | "permittedZones">): PermittedNames | null =>
  row.permittedExactNames && row.permittedZones ? { exact: row.permittedExactNames, zones: row.permittedZones } : null;

/** The template in words, by its display name and its CA's name. */
export const templateLabel = (ca: Pick<AdcsCaRow, "name">, template: Pick<TemplateRow, "displayName" | "name">) =>
  `the Certificate Template ${template.displayName || template.name} of the ADCS CA ${ca.name}`;

/** Why nothing is issued under the template now, naming it and its CA; none while it is available. */
export function templateUnavailableRefusal(ca: Pick<AdcsCaRow, "name">, template: TemplateRow) {
  const unavailable = unavailableReason(template);
  return unavailable ? `${templateLabel(ca, template)} is unavailable: ${unavailable}` : undefined;
}

/** Why the ADCS CA may not issue for the names (normalised): those its Permitted Name Rules do not permit. None when it has none, or they do. */
export function adcsNamesRefusal(ca: AdcsCaRow, names: string[]) {
  const rules = adcsPermittedNamesOf(ca);
  const outside = rules ? namesOutside(rules, names) : [];
  return outside.length === 0 ? undefined : `${outside.join(", ")} ${outside.length === 1 ? "is" : "are"} outside the Permitted Name Rules of the ADCS CA ${ca.name}`;
}

/** The Organization's ADCS CA and the template of it, each none when it has none such. */
export async function findAdcsIssuer(db: Db | Tx, organizationId: string, issuer: AdcsIssuer) {
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
  const { ca, template } = await findAdcsIssuer(db, organizationId, issuer);
  if (!ca) return refused(422, "the Organization has no such ADCS CA");
  if (!template) return refused(422, `the ADCS CA ${ca.name} has no such Certificate Template`);
  if (!offeredFor(template).includes("tls")) {
    const why = unavailableReason(template) ?? (template.hidden ? "an Organization Administrator hid it." : "It has no Server Authentication EKU.");
    return refused(422, `${templateLabel(ca, template)} is not offered for TLS: ${why}`);
  }
  const refusal = adcsNamesRefusal(ca, asked.names) ?? (asked.keyAlgorithm && templateKeyRefusal(template, asked.keyAlgorithm));
  return refusal ? refused(422, refusal) : undefined;
}

/** Where an ADCS request stands, as an Issuance shows it; while ADCS holds it pending, when it will be pending too long. */
export interface AdcsRequestShown {
  status: RequestRow["status"];
  agent: { id: string; hostName: string } | null;
  requestId: string | null;
  pendingUntil: string | null;
}

/** When a request submitted at `submittedAt` that ADCS holds pending is pending too long. */
const pendingUntilOf = (submittedAt: Date) => new Date(submittedAt.getTime() + PENDING_TIMEOUT_MS);

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
      request.issuanceId!,
      {
        status: request.status,
        agent: request.agentId && hostName !== null ? { id: request.agentId, hostName } : null,
        requestId: request.adcsRequestId,
        pendingUntil: request.status === "pending" ? pendingUntilOf(request.submittedAt!).toISOString() : null,
      },
    ]),
  );
}

/** The Agents assigned to the CA, most recently heard from first, with whether each is online now. */
export async function assignedAgentsOf(tx: Tx, adcsCaId: string, now: Date, offlineAfterSeconds: number) {
  const rows = await tx
    .select({ id: agent.id, hostName: agent.hostName, revokedAt: agent.revokedAt, lastContactAt: agent.lastContactAt })
    .from(adcsCaAgent)
    .innerJoin(agent, eq(agent.id, adcsCaAgent.agentId))
    .where(eq(adcsCaAgent.adcsCaId, adcsCaId))
    .orderBy(desc(agent.lastContactAt), asc(agent.id));
  return rows.map((a) => ({ ...a, online: !a.revokedAt && now.getTime() - a.lastContactAt.getTime() <= offlineAfterSeconds * 1000 }));
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
  /** Where the outcome of each request for an Issuance is reported. */
  reportTo(issuances: Issuances): void;
  /**
   * Records a request for an Enrollment Profile (`purpose`) on the change, and gives it to an online assigned Agent, or
   * has it wait for one; its outcome goes to whoever handles its purpose. The caller has checked what ADCS would not.
   * Returns the request's id.
   */
  request(
    tx: Tx,
    change: Change,
    request: { organizationId: string; adcsCaId: string; templateId: string; csrPem: string; purpose: AdcsRequestPurpose; enrollmentProfileId: string },
  ): Promise<string>;
  /** Has `outcomes` take what comes of the requests of the purpose. */
  handle(purpose: AdcsRequestPurpose, outcomes: AdcsOutcomes): void;
  /**
   * One pass at the clock's time: gives each request waiting for an Agent to an online one; gives up on an Agent that has
   * not reported in time for another; fails requests that waited 7 days as "no Agent available"; has an Agent check each
   * request ADCS holds pending whose check is due, and fails those pending 7 days as "pending too long"; and reports again
   * an outcome that was recorded but not yet reported. Returns how many requests it looked at.
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
  const handlers = new Map<AdcsRequestPurpose, AdcsOutcomes>();
  const handlerOf = (row: RequestRow) => {
    const handler = row.purpose === "issuance" ? undefined : handlers.get(row.purpose);
    if (!handler) throw new Error(`nothing takes the outcome of ADCS requests for ${row.purpose}`);
    return handler;
  };

  /** Has the Issuance told what came of its request, once the change that recorded it has committed. */
  const report = (change: Change, issuanceId: string, result: Issued | Pending | Failed) =>
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

  const assignedAgents = (tx: Tx, adcsCaId: string, now: Date) => assignedAgentsOf(tx, adcsCaId, now, offlineAfterSeconds);

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

  /** Ends the request (locked by the caller) as failed, and has its Issuance, or whoever handles its purpose, fail with `failure`. */
  async function fail(tx: Tx, change: Change, row: RequestRow, failure: Error) {
    const [failed] = await tx.update(adcsRequest).set({ status: "failed", finishedAt: change.occurredAt }).where(eq(adcsRequest.id, row.id)).returning();
    if (row.purpose === "issuance") report(change, row.issuanceId!, { failed: failure });
    else await handlerOf(row).failed(tx, change, failed!, failure);
  }

  /** What the Issuance waits for while ADCS holds its request: its deadline moves to when the request is pending too long, and an hour after. */
  const pendingOf = (row: Pick<RequestRow, "id" | "submittedAt">): Pending => ({
    pending: { handle: row.id, deadline: new Date(pendingUntilOf(row.submittedAt!).getTime() + DEADLINE_BACKSTOP_MS) },
  });

  /**
   * Gives the pending request (locked by the caller) to an online assigned Agent it has not been tried on for this check,
   * as `adcs.check`; or, when there is none, has the check wait until one is. Returns the Agent given it, if one was.
   */
  async function dispatchCheck(tx: Tx, change: Change, row: RequestRow, tried: string[]) {
    const [ca] = await tx.select().from(adcsCa).where(eq(adcsCa.id, row.adcsCaId));
    const next = (await assignedAgents(tx, row.adcsCaId, change.occurredAt)).find((a) => a.online && !tried.includes(a.id));
    if (!next) {
      await tx.update(adcsRequest).set({ triedAgentIds: tried, workItemId: null, checkGivenAt: null }).where(eq(adcsRequest.id, row.id));
      return undefined;
    }
    const itemId = await workItems.enqueueIn(tx, change, row.organizationId, next.id, ADCS_WORK_TYPES.check, {
      requestId: row.id,
      configString: ca!.configString,
      adcsRequestId: row.adcsRequestId,
    });
    await tx
      .update(adcsRequest)
      .set({ triedAgentIds: tried, agentId: next.id, workItemId: itemId, checkGivenAt: change.occurredAt })
      .where(eq(adcsRequest.id, row.id));
    return next;
  }

  /** The audit detail of what ADCS answered the request with, through the Agent. */
  const answerDetail = (row: RequestRow, ca: AdcsCaRow, template: TemplateRow, by: { id: string; hostName: string } | undefined, adcsRequestId: string) => ({
    ...(row.purpose === "issuance" ? { issuanceId: row.issuanceId } : { enrollmentProfileId: row.enrollmentProfileId, purpose: row.purpose }),
    adcsCa: { id: ca.id, name: ca.name },
    template: { id: template.id, name: template.name },
    agent: by ?? null,
    adcsRequestId,
  });

  /**
   * What follows from what ADCS answered a request with, or holds it as now, as an Agent reported it (for the request
   * locked by the caller): the Certificate when it issued it; pending, to be checked again; or failed when it denied it.
   */
  async function answered(tx: Tx, change: Change, row: RequestRow, by: { id: string; hostName: string }, answer: SubmissionResult, { submission }: { submission: boolean }) {
    const [ca] = await tx.select().from(adcsCa).where(eq(adcsCa.id, row.adcsCaId));
    const [template] = await tx.select().from(adcsTemplate).where(eq(adcsTemplate.id, row.templateId));
    const target = await auditTargetOf(tx, row);
    const detail = answerDetail(row, ca!, template!, by, answer.requestId);
    // A request is ADCS's own once submitted: a check reporting another is not about it.
    if (!submission && answer.requestId !== row.adcsRequestId) {
      return fail(tx, change, row, new CertificateAuthorityError("rejected", `the Agent ${by.hostName} reported the ADCS request ${answer.requestId} when asked about ${row.adcsRequestId}`));
    }
    if (submission) await change.audit({ organizationId: row.organizationId, action: "adcs_ca.request_submitted", target, detail: { ...detail, disposition: answer.status } });

    if (answer.status === "issued") {
      try {
        new x509.X509Certificate(answer.certificate);
      } catch {
        return fail(tx, change, row, new CertificateAuthorityError("rejected", `the Agent ${by.hostName} reported a Certificate from ADCS that cannot be read`));
      }
      const [issued] = await tx
        .update(adcsRequest)
        .set({ status: "issued", adcsRequestId: answer.requestId, certificatePem: answer.certificate, workItemId: null, finishedAt: change.occurredAt })
        .where(eq(adcsRequest.id, row.id))
        .returning();
      if (row.purpose === "issuance") report(change, row.issuanceId!, issuedOf(ca!, issued!));
      else await handlerOf(row).issued(tx, change, issued!, answer.certificate);
      return;
    }
    if (answer.status === "denied") {
      await tx.update(adcsRequest).set({ adcsRequestId: answer.requestId }).where(eq(adcsRequest.id, row.id));
      await change.audit({ organizationId: row.organizationId, action: "adcs_ca.request_denied", target, detail: { ...detail, message: answer.message } });
      return fail(tx, change, row, new IssuanceFailure("request_denied", `the ADCS CA ${ca!.name} denied the request (ADCS request ${answer.requestId}): ${answer.message || "it gave no reason"}`));
    }
    // Pending: held for a CA manager's approval, and checked again on the backoff.
    const [pending] = await tx
      .update(adcsRequest)
      .set({
        status: "pending",
        adcsRequestId: answer.requestId,
        workItemId: null,
        checkGivenAt: null,
        triedAgentIds: [],
        // Each answer that it is still pending makes the wait for the next check longer.
        checks: submission ? 0 : row.checks + 1,
        nextCheckAt: new Date(change.occurredAt.getTime() + checkWaitMs(submission ? 0 : row.checks + 1)),
      })
      .where(eq(adcsRequest.id, row.id))
      .returning();
    if (submission) {
      await change.audit({ organizationId: row.organizationId, action: "adcs_ca.request_pending", target, detail: { ...detail, pendingUntil: pendingUntilOf(row.submittedAt!).toISOString() } });
      if (row.purpose === "issuance") report(change, row.issuanceId!, pendingOf(pending!));
    }
  }

  /** What the Audit Events of the request are about: an Issuance's Managed Certificate, or the Enrollment Profile. */
  async function auditTargetOf(tx: Tx, row: RequestRow) {
    if (row.purpose !== "issuance") return { type: "enrollment_profile", id: row.enrollmentProfileId! };
    const [of] = await tx.select({ managedCertificateId: issuance.managedCertificateId }).from(issuance).where(eq(issuance.id, row.issuanceId!));
    return { type: "managed_certificate", id: of!.managedCertificateId };
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
    const [by] = await tx.select({ id: agent.id, hostName: agent.hostName }).from(agent).where(eq(agent.id, item.agentId));

    if (result.ok && result.submission) return answered(tx, change, row, by!, result.submission, { submission: true });
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
    const why = result.ok ? "it reported no answer from ADCS" : (result.error ?? "it reported no reason");
    await fail(tx, change, row, new CertificateAuthorityError("rejected", `the ADCS CA ${ca!.name} refused the request, through the Agent ${by!.hostName}: ${why}`));
  }

  /** What follows from an Agent's report of `adcs.check`, on the transaction that records the report. */
  async function checked(tx: Tx, change: Change, item: { organizationId: string; agentId: string; payload: Record<string, unknown> }, result: WorkResult) {
    const [row] = await tx
      .select()
      .from(adcsRequest)
      .where(and(eq(adcsRequest.id, String(item.payload.requestId)), eq(adcsRequest.organizationId, item.organizationId)))
      .for("update");
    // Asked of another Agent since, or ended: what this one says is no longer asked.
    if (!row || row.status !== "pending" || !row.workItemId || row.agentId !== item.agentId) return;
    const [ca] = await tx.select().from(adcsCa).where(eq(adcsCa.id, row.adcsCaId));
    const [by] = await tx.select({ id: agent.id, hostName: agent.hostName }).from(agent).where(eq(agent.id, item.agentId));

    if (result.ok && result.submission) return answered(tx, change, row, by!, result.submission, { submission: false });
    if (!result.ok && result.kind === "unreachable") {
      // Another Agent may reach the CA; when none can now, it is checked again later, while it may still be pending.
      const tried = [...row.triedAgentIds, item.agentId];
      if (await dispatchCheck(tx, change, row, tried)) return;
      await tx.update(adcsRequest).set({ triedAgentIds: [], nextCheckAt: new Date(change.occurredAt.getTime() + checkWaitMs(row.checks)) }).where(eq(adcsRequest.id, row.id));
      return;
    }
    const why = result.ok ? "it reported no answer from ADCS" : (result.error ?? "it reported no reason");
    await fail(tx, change, row, new CertificateAuthorityError("rejected", `the ADCS CA ${ca!.name} refused to say where the request ${row.adcsRequestId} stands, through the Agent ${by!.hostName}: ${why}`));
  }

  // The payload is all the Agent needs: it reaches ADCS as its own account. Our own id of the request stays with the platform.
  workItems.register(ADCS_WORK_TYPES.submit, async (_tx, item) => ({ configString: item.payload.configString, template: item.payload.template, csr: item.payload.csr }), {
    onResult: submitted,
  });
  workItems.register(ADCS_WORK_TYPES.check, async (_tx, item) => ({ configString: item.payload.configString, requestId: item.payload.adcsRequestId }), { onResult: checked });

  /** One open request's turn in a pass, under the locks a report takes, in the order it takes them: the work item's, then the request's. */
  async function attend(id: string, workItemId: string | null) {
    await unitOfWork.run(null, async (tx, change) => {
      if (workItemId) await tx.select({ id: workItem.id }).from(workItem).where(eq(workItem.id, workItemId)).for("update");
      const [row] = await tx.select().from(adcsRequest).where(eq(adcsRequest.id, id)).for("update");
      if (!row || !OPEN.includes(row.status) || row.workItemId !== workItemId) return;
      const [of] = row.purpose === "issuance" ? await tx.select({ status: issuance.status }).from(issuance).where(eq(issuance.id, row.issuanceId!)) : [{ status: "running" }];
      if (of?.status !== "running") {
        // Its Issuance ended without it (the platform stopped before it was recorded, or it timed out): nothing to submit for.
        await expireItem(tx, change, row);
        await tx.update(adcsRequest).set({ status: "failed", finishedAt: change.occurredAt }).where(eq(adcsRequest.id, row.id));
        return;
      }
      const [ca] = await tx.select().from(adcsCa).where(eq(adcsCa.id, row.adcsCaId));
      if (row.status === "pending") return attendPending(tx, change, row, ca!);
      if (change.occurredAt.getTime() - row.createdAt.getTime() >= NO_AGENT_TIMEOUT_MS) {
        await expireItem(tx, change, row);
        await fail(tx, change, row, new IssuanceFailure("no_agent_available", `no Agent assigned to the ADCS CA ${ca!.name} submitted the request within 7 days; ask for it again once one is online`));
        return;
      }
      if (row.status === "submitted") {
        if (change.occurredAt.getTime() - row.submittedAt!.getTime() < config.submitTimeoutMs) return;
        // An Agent that took the item may be submitting it now: it is waited for, never given up on for a second submission.
        const [item] = await tx.select({ status: workItem.status }).from(workItem).where(eq(workItem.id, row.workItemId!));
        if (item?.status !== "pending") return;
        // The Agent did not take it in time: another is given it, or, when there is none, any that comes online again.
        await expireItem(tx, change, row);
        const tried = [...row.triedAgentIds, row.agentId!];
        if (!(await dispatch(tx, change, row, tried))) await dispatch(tx, change, row, []);
        return;
      }
      // What waits is submitted under the template only while the platform can still issue under it.
      const [template] = await tx.select().from(adcsTemplate).where(eq(adcsTemplate.id, row.templateId));
      const unavailable = templateUnavailableRefusal(ca!, template!);
      if (unavailable) {
        await fail(tx, change, row, new IssuanceFailure("template_unavailable", unavailable));
        return;
      }
      // An Agent that could not reach the CA before is tried again once no other is online: the CA may be back.
      if (!(await dispatch(tx, change, row, row.triedAgentIds)) && row.triedAgentIds.length > 0) await dispatch(tx, change, row, []);
    });
  }

  /** A pending request's turn: pending too long after 7 days; otherwise its check, given up on when not answered in time, or due. */
  async function attendPending(tx: Tx, change: Change, row: RequestRow, ca: AdcsCaRow) {
    const now = change.occurredAt.getTime();
    if (now >= pendingUntilOf(row.submittedAt!).getTime()) {
      await expireItem(tx, change, row);
      await fail(
        tx,
        change,
        row,
        new IssuanceFailure("pending_too_long", `the ADCS CA ${ca.name} held the request (ADCS request ${row.adcsRequestId}) for a CA manager's approval for 7 days, and neither issued nor denied it; ask for it again`),
      );
      return;
    }
    if (row.workItemId) {
      if (now - row.checkGivenAt!.getTime() < config.submitTimeoutMs) return;
      // Not answered in time: a check is only a question, so it is asked of another Agent, or of any once none other is online.
      await expireItem(tx, change, row);
      const tried = [...row.triedAgentIds, row.agentId!];
      if (!(await dispatchCheck(tx, change, row, tried))) await dispatchCheck(tx, change, row, []);
      return;
    }
    if (now < row.nextCheckAt!.getTime()) return;
    if (!(await dispatchCheck(tx, change, row, row.triedAgentIds)) && row.triedAgentIds.length > 0) await dispatchCheck(tx, change, row, []);
  }

  return {
    async issue(dbOrTx, organizationId, issuer, request) {
      const { ca, template } = await findAdcsIssuer(dbOrTx, organizationId, issuer);
      if (!ca || !template) throw new IssuanceFailure("internal", "the ADCS CA or its Certificate Template is gone");
      const unavailable = templateUnavailableRefusal(ca, template);
      if (unavailable) throw new IssuanceFailure("template_unavailable", unavailable);
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
    async request(tx, change, { organizationId, adcsCaId, templateId, csrPem, purpose, enrollmentProfileId }) {
      const [row] = await tx
        .insert(adcsRequest)
        .values({ organizationId, adcsCaId, templateId, purpose, enrollmentProfileId, csr: csrPem, status: "waiting", createdAt: change.occurredAt })
        .returning();
      await dispatch(tx, change, row!, []);
      return row!.id;
    },
    handle(purpose, outcomes) {
      handlers.set(purpose, outcomes);
    },
    async tick() {
      const now = clock();
      // A pending request is looked at only when there is something to do: its check is due or out, or it is pending too long.
      const open = await db
        .select({ id: adcsRequest.id, workItemId: adcsRequest.workItemId })
        .from(adcsRequest)
        .where(
          or(
            inArray(adcsRequest.status, ["waiting", "submitted"]),
            and(
              eq(adcsRequest.status, "pending"),
              or(lte(adcsRequest.nextCheckAt, now), isNotNull(adcsRequest.workItemId), lte(adcsRequest.submittedAt, new Date(now.getTime() - PENDING_TIMEOUT_MS))),
            ),
          ),
        )
        .orderBy(asc(adcsRequest.createdAt));
      for (const { id, workItemId } of open) await attend(id, workItemId).catch((err) => console.error("could not attend to the ADCS request", id, err));
      // An outcome recorded whose report did not reach its Issuance (the platform stopped in between) is reported again.
      const unreported = await db
        .select({ request: adcsRequest, ca: adcsCa })
        .from(adcsRequest)
        .innerJoin(issuance, eq(issuance.id, adcsRequest.issuanceId))
        .innerJoin(adcsCa, eq(adcsCa.id, adcsRequest.adcsCaId))
        .where(and(eq(adcsRequest.status, "issued"), eq(issuance.status, "running")));
      for (const { request, ca } of unreported) await issuances?.report(request.issuanceId!, issuedOf(ca, request));
      // So is that a request is pending at ADCS, which moves its Issuance's deadline; reporting it again changes nothing.
      const stillPending = await db
        .select({ request: adcsRequest, pendingUntil: issuance.pendingUntil })
        .from(adcsRequest)
        .innerJoin(issuance, eq(issuance.id, adcsRequest.issuanceId))
        .where(and(eq(adcsRequest.status, "pending"), eq(issuance.status, "running")));
      for (const { request, pendingUntil } of stillPending) {
        const wanted = pendingOf(request);
        if (!pendingUntil || pendingUntil.getTime() < wanted.pending.deadline.getTime()) await issuances?.report(request.issuanceId!, wanted);
      }
      return open.length;
    },
  };
}
