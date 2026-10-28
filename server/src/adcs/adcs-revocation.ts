// Revoking at an ADCS CA: the ADCS kind's revocation (issuer.ts). The platform never reaches ADCS itself (ADR 0013): each
// Certificate becomes `adcs.revoke` for an online Agent assigned to its CA, with its serial number and the RFC 5280 reason
// code, which ADCS takes as its own, and the Revocation Request (revocations.ts) waits for that Agent's report. Revoked, the
// Revocation is recorded; refused, it fails as rejected. An Agent that cannot reach the CA has it given to another online
// one, and when none is left it fails as unreachable, as it does at once when no assigned Agent is online to ask. An Agent
// that does not report by the deadline leaves it to time out; revoking again is safe, since ADCS keeps what it revoked.
import * as x509 from "@peculiar/x509";
import { and, eq } from "drizzle-orm";
import { assignedAgentsOf } from "./adcs-issuance";
import { ADCS_WORK_TYPES } from "./adcs-work";
import { CertificateAuthorityError } from "../issuance/acme/certificate-authority";
import type { RevocationAnswer, RevocationRequest } from "../issuance/issuer";
import type { Revocations } from "../issuance/revocations";
import type { WorkItems, WorkResult } from "../agents/work-items";
import type { Tx } from "../platform/db/client";
import { adcsCa, agent, revocationRequest } from "../platform/db/schema";
import { REVOCATION_REASONS } from "../pki/revocation-reasons";
import type { Change } from "../platform/unit-of-work";

/** How long an Agent has to report a revocation before its Revocation Request fails as timed out. */
export const REVOCATION_DEADLINE_MS = 3600_000;

/** The first certificate of a PEM chain: the Certificate itself. */
const leafOf = (pem: string) => pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/)?.[0] ?? pem;

export interface AdcsRevocation {
  /**
   * Gives each Certificate's revocation to an online Agent assigned to the ADCS CA, on the change, and answers pending
   * for each. Throws a CertificateAuthorityError when no assigned Agent is online, or the CA is not the Organization's.
   */
  revoke(tx: Tx, change: Change, organizationId: string, adcsCaId: string, requests: RevocationRequest[]): Promise<RevocationAnswer[]>;
  /** Where the outcome of each revocation is reported. */
  reportTo(revocations: Pick<Revocations, "report">): void;
}

/** What an `adcs.revoke` work item keeps: what the Agent is given, the Revocation Request it is for, and the Agents tried for it. */
type Payload = { configString: string; serialNumber: string; reason: number; adcsCaId: string; revocationRequestId: string; tried: string[] };

export function createAdcsRevocation({ workItems, offlineAfterSeconds }: { workItems: WorkItems; offlineAfterSeconds: number }): AdcsRevocation {
  let revocations: Pick<Revocations, "report"> | undefined;

  /** Has the Revocation Request told what came of it, once the change that learned it has committed. */
  const report = (change: Change, revocationRequestId: string, result: "revoked" | { failed: unknown }) =>
    change.afterCommit(async () => {
      if (!revocations) throw new Error("nothing takes the outcome of ADCS revocations");
      await revocations.report(revocationRequestId, result);
    });

  /** Gives the revocation to an online assigned Agent not yet tried for it; the work item's id, or none when there is no such Agent. */
  async function dispatch(tx: Tx, change: Change, organizationId: string, payload: Payload) {
    const next = (await assignedAgentsOf(tx, payload.adcsCaId, change.occurredAt, offlineAfterSeconds)).find((a) => a.online && !payload.tried.includes(a.id));
    if (!next) return undefined;
    return workItems.enqueueIn(tx, change, organizationId, next.id, ADCS_WORK_TYPES.revoke, { ...payload, tried: [...payload.tried, next.id] });
  }

  /** What follows from an Agent's report of `adcs.revoke`, on the transaction that records the report. */
  async function revoked(tx: Tx, change: Change, item: { organizationId: string; agentId: string; payload: Record<string, unknown> }, result: WorkResult) {
    const payload = item.payload as Payload;
    const [request] = await tx
      .select({ status: revocationRequest.status })
      .from(revocationRequest)
      .where(and(eq(revocationRequest.id, payload.revocationRequestId), eq(revocationRequest.organizationId, item.organizationId)));
    const [ca] = await tx.select({ name: adcsCa.name }).from(adcsCa).where(eq(adcsCa.id, payload.adcsCaId));
    const [by] = await tx.select({ hostName: agent.hostName }).from(agent).where(eq(agent.id, item.agentId));
    // ADCS confirming is recorded however late (Revocations decides); anything else only while the request still waits.
    if (result.ok && result.revocation?.status === "revoked") return report(change, payload.revocationRequestId, "revoked");
    if (request?.status !== "pending") return;
    if (!result.ok && result.kind === "unreachable") {
      // Another Agent may reach the CA from where it is; when every online one has been tried, none can now.
      if (await dispatch(tx, change, item.organizationId, payload)) return;
      const failure = new CertificateAuthorityError("unreachable", `no Agent assigned to the ADCS CA ${ca?.name} could reach it to revoke the Certificate; the last, ${by?.hostName}, reported: ${result.error ?? "it could not reach it"}`);
      return report(change, payload.revocationRequestId, { failed: failure });
    }
    const why = result.ok ? "it reported no answer from ADCS" : (result.error ?? "it reported no reason");
    const failure = new CertificateAuthorityError("rejected", `the ADCS CA ${ca?.name} refused to revoke the Certificate, through the Agent ${by?.hostName}: ${why}`);
    return report(change, payload.revocationRequestId, { failed: failure });
  }

  // The Agent is given what ADCS needs, and nothing of the platform's own.
  workItems.register(
    ADCS_WORK_TYPES.revoke,
    async (_tx, item) => ({ configString: item.payload.configString, serialNumber: item.payload.serialNumber, reason: item.payload.reason }),
    { onResult: revoked },
  );

  return {
    async revoke(tx, change, organizationId, adcsCaId, requests) {
      const [ca] = await tx.select().from(adcsCa).where(and(eq(adcsCa.organizationId, organizationId), eq(adcsCa.id, adcsCaId)));
      if (!ca) throw new CertificateAuthorityError("rejected", "the ADCS CA the Certificate came from is gone");
      const answers: RevocationAnswer[] = [];
      for (const { requestId, certificate, reason } of requests) {
        const serialNumber = new x509.X509Certificate(leafOf(certificate)).serialNumber.toLowerCase();
        const payload: Payload = { configString: ca.configString, serialNumber, reason: REVOCATION_REASONS[reason], adcsCaId: ca.id, revocationRequestId: requestId, tried: [] };
        const itemId = await dispatch(tx, change, organizationId, payload);
        if (!itemId) throw new CertificateAuthorityError("unreachable", `no Agent assigned to the ADCS CA ${ca.name} is online to revoke the Certificate; ask again once one is`);
        answers.push({ pending: { handle: itemId, deadline: new Date(change.occurredAt.getTime() + REVOCATION_DEADLINE_MS) } });
      }
      return answers;
    },
    reportTo(to) {
      revocations = to;
    },
  };
}
