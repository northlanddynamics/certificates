// Issuance: turns "issue these names for this Managed Certificate with its CSR" into a Certificate. An Issuance is
// recorded when it is asked for and runs in the background (a CA with DNS propagation can take minutes, longer than a
// request should wait): it does DCV through the Organization's DNS Provider, has the CA finalize the order with the
// CSR, and ends by storing the Certificate, or with the cause of its failure. Either end is one audited change.
import { X509Certificate, createHash } from "node:crypto";
import { and, desc, eq, inArray, isNull } from "drizzle-orm";
import { CertificateAuthorityError, type CertificateAuthority } from "./certificate-authority";
import { parseCsr } from "./csr";
import type { Dcv } from "./dcv";
import type { Db, Tx } from "./db/client";
import { acmeAccount, certificate, issuance, managedCertificate } from "./db/schema";
import { IssuanceFailure, type IssuanceFailureCode } from "./issuance-failure";
import type { Secrets } from "./secrets";
import type { Actor, Change, UnitOfWork } from "./unit-of-work";

/**
 * What an Issuance is asked for as: `issue` is for a Managed Certificate's Issuance by creation, Approval or a person
 * trying again, whether or not it has a Certificate; `renewNow` is a person's Renewal, which needs one; `scheduled` is
 * the scheduler's, which needs one and an automatic Renewal Policy.
 */
export type IssuanceIntent = "issue" | "renewNow" | "scheduled";

/** Why a Managed Certificate may not have an Issuance begin now. */
export type Refusal = "awaiting_approval" | "rejected" | "archived" | "already_running" | "no_certificate" | "not_automatic";

export type Begun = { issuanceId: string } | { refused: Refusal };

/**
 * The Managed Certificates whose Certificates are renewed by the platform on its own: automatic, not archived and
 * approved. What the scheduler and the asking of the CA about renewal windows select by; the same three things `begin`
 * refuses a scheduled Issuance for (it checks them again under a lock).
 */
export const renewsAutomatically = and(
  eq(managedCertificate.renewalMode, "automatic"),
  isNull(managedCertificate.archivedAt),
  inArray(managedCertificate.approvalStatus, ["not_required", "approved"]),
)!;

/** What to tell whoever asked for an Issuance that was refused. */
export function refusalMessage(refusal: Refusal, intent: IssuanceIntent): string {
  const verb = intent === "issue" ? "issued" : "renewed";
  switch (refusal) {
    case "awaiting_approval":
      return `the Managed Certificate is awaiting Approval, so it cannot be ${verb}`;
    case "rejected":
      return `the Managed Certificate is rejected, so it cannot be ${verb}`;
    case "archived":
      return `the Managed Certificate is archived, so it cannot be ${verb}`;
    case "already_running":
      return "an Issuance of this Managed Certificate is already running";
    case "no_certificate":
      return "the Managed Certificate has no Certificate yet to renew; try issuing it again instead";
    case "not_automatic":
      return "the Managed Certificate is not renewed automatically";
  }
}

export interface Issuances {
  /**
   * Begins an Issuance of the Managed Certificate if it may have one now, as the intent says, on the transaction of the
   * change that asks (so it exists only if that change commits), and runs it in the background once that change has
   * committed. It decides from the Managed Certificate as the transaction sees it, under a lock on it, so changes that
   * race (an archive, a rejection, another Issuance) are not overridden by a decision made earlier. A refusal writes
   * nothing. An Issuance of a Managed Certificate that has a Certificate is its Renewal, whatever the intent.
   */
  begin(
    tx: Tx,
    change: Change,
    actor: Actor | null,
    managedCertificate: { id: string; organizationId: string },
    intent: IssuanceIntent,
  ): Promise<Begun>;
  /** Resolves once every Issuance started so far has recorded its outcome. */
  idle(): Promise<void>;
  /** Ends the Issuances a stopped platform left running, as failed. Call it once, before serving. */
  failInterrupted(): Promise<void>;
}

export interface IssuancesDeps {
  db: Db;
  unitOfWork: UnitOfWork;
  certificateAuthority: CertificateAuthority;
  dcv: Dcv;
  secrets: Secrets;
}

/** What the leaf of the chain the CA served says about itself. */
function readLeaf(chainPem: string) {
  const leafPem = chainPem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/)?.[0];
  if (!leafPem) throw new IssuanceFailure("ca_rejected", "the CA served no certificate");
  const leaf = new X509Certificate(leafPem);
  return {
    fingerprint: createHash("sha256").update(leaf.raw).digest("hex"),
    serial: leaf.serialNumber,
    notBefore: new Date(leaf.validFrom),
    notAfter: new Date(leaf.validTo),
    names: (leaf.subjectAltName ?? "")
      .split(", ")
      .filter((entry) => entry.startsWith("DNS:"))
      .map((entry) => entry.slice(4).toLowerCase()),
    publicKey: leaf.publicKey.export({ type: "spki", format: "der" }),
  };
}

type Failure = { code: IssuanceFailureCode; message: string };
type Outcome = { kind: "succeeded"; certificateId: string } | ({ kind: "failed" } & Failure);

/** A failure to complete an Issuance, as the code and message that are recorded. */
function failureOf(err: unknown): Failure {
  if (err instanceof IssuanceFailure) return { code: err.code, message: err.message };
  if (err instanceof CertificateAuthorityError) return { code: err.kind === "unreachable" ? "ca_unreachable" : "ca_rejected", message: err.message };
  console.error("issuance failed", err);
  return { code: "internal", message: "the platform failed while issuing; see its log" };
}

export function createIssuances({ db, unitOfWork, certificateAuthority: ca, dcv, secrets }: IssuancesDeps): Issuances {
  const running = new Set<Promise<void>>();
  const actorOf = (row: typeof issuance.$inferSelect) => (row.requestedById && row.requestedByEmail ? { id: row.requestedById, email: row.requestedByEmail } : null);
  const targetOf = (row: typeof issuance.$inferSelect) => ({ type: "managed_certificate", id: row.managedCertificateId });
  const leftoverDetail = (leftovers: string[]) => (leftovers.length > 0 ? { challengeRecordsNotRemoved: leftovers } : {});

  /**
   * Records how the Issuance ended, on the change's transaction. A failure ends only an Issuance that is still running
   * (one a restart's sweep already ended stays as it was); a Certificate that was issued always ends it as succeeded.
   * Returns whether the Issuance's row changed.
   */
  async function end(tx: Tx, change: Change, row: typeof issuance.$inferSelect, outcome: Outcome) {
    const failed = outcome.kind === "failed";
    const ended = await tx
      .update(issuance)
      .set({
        status: outcome.kind,
        certificateId: failed ? null : outcome.certificateId,
        failureCode: failed ? outcome.code : null,
        failureMessage: failed ? outcome.message : null,
        finishedAt: change.occurredAt,
      })
      .where(failed ? and(eq(issuance.id, row.id), eq(issuance.status, "running")) : eq(issuance.id, row.id))
      .returning({ id: issuance.id });
    return ended.length > 0;
  }

  const fail = (row: typeof issuance.$inferSelect, failure: Failure, leftovers: string[] = []) =>
    unitOfWork.run(actorOf(row), async (tx, change) => {
      if (!(await end(tx, change, row, { kind: "failed", ...failure }))) return;
      await change.audit({
        organizationId: row.organizationId,
        action: "issuance.failed",
        target: targetOf(row),
        detail: { issuanceId: row.id, code: failure.code, message: failure.message, ...leftoverDetail(leftovers) },
      });
    });

  async function run(issuanceId: string) {
    const [row] = await db.select().from(issuance).where(eq(issuance.id, issuanceId));
    if (!row || row.status !== "running") return;
    const responder = dcv.directFor(db, row.organizationId);
    let chainPem: string;
    let mc: typeof managedCertificate.$inferSelect;
    let accountId: string;
    try {
      const [found] = await db
        .select()
        .from(managedCertificate)
        .where(and(eq(managedCertificate.id, row.managedCertificateId), eq(managedCertificate.organizationId, row.organizationId)));
      if (!found) throw new Error("the Managed Certificate is gone");
      mc = found;
      const [account] = await db
        .select()
        .from(acmeAccount)
        .where(and(eq(acmeAccount.organizationId, row.organizationId), eq(acmeAccount.environment, mc.environment)));
      if (!account) throw new IssuanceFailure("no_acme_account", `the Organization has no ${mc.environment} ACME account; register one first`);
      accountId = account.id;

      const accountKey = await secrets.open(db, row.organizationId, account.secretId);
      // An Issuance of a Managed Certificate that has a Certificate is its Renewal, and names the Certificate it replaces so a CA with ARI can tell.
      const [replaced] = await db
        .select({ chainPem: certificate.chainPem })
        .from(certificate)
        .where(and(eq(certificate.organizationId, row.organizationId), eq(certificate.managedCertificateId, mc.id)))
        .orderBy(desc(certificate.createdAt), desc(certificate.id))
        .limit(1);
      chainPem = await ca.issue(mc.environment, { accountUrl: account.accountUrl, accountKey }, { csr: mc.csr, responder, replaces: replaced?.chainPem });
    } catch (err) {
      return fail(row, failureOf(err), responder.leftovers());
    }

    // The CA has issued: from here on the Certificate is kept whatever else happens to the Issuance.
    try {
      const issued = readLeaf(chainPem);
      const csr = await parseCsr(mc.csr);
      if (!issued.publicKey.equals(csr.publicKey)) throw new IssuanceFailure("ca_rejected", "the CA issued a Certificate for a different key than the CSR's");
      if (issued.names.length !== mc.names.length || !mc.names.every((name) => issued.names.includes(name))) {
        throw new IssuanceFailure("ca_rejected", `the CA issued a Certificate for ${issued.names.join(", ")}, not for the names asked (${mc.names.join(", ")})`);
      }
      const { publicKey: _publicKey, ...stored } = issued;
      const certificateId = crypto.randomUUID();
      await unitOfWork.run(actorOf(row), async (tx, change) => {
        await tx.insert(certificate).values({
          id: certificateId,
          organizationId: row.organizationId,
          managedCertificateId: mc.id,
          ...stored,
          chainPem,
          ca: ca.name,
          environment: mc.environment,
          acmeAccountId: accountId,
          issuedAt: change.occurredAt,
        });
        await end(tx, change, row, { kind: "succeeded", certificateId });
        await change.audit({
          organizationId: row.organizationId,
          action: "issuance.succeeded",
          target: targetOf(row),
          detail: {
            issuanceId: row.id,
            certificateId,
            fingerprint: stored.fingerprint,
            serial: stored.serial,
            names: stored.names,
            notAfter: stored.notAfter.toISOString(),
            ...leftoverDetail(responder.leftovers()),
          },
        });
      });
    } catch (err) {
      await fail(row, failureOf(err), responder.leftovers());
    }
  }

  /** Runs the Issuance in the background; it records its own outcome and never throws. */
  function start(issuanceId: string) {
    const task = run(issuanceId)
      // Recording the outcome failed too (the database is gone): nothing more can be done but say so.
      .catch((err) => console.error("could not record the outcome of issuance", issuanceId, err))
      .finally(() => running.delete(task));
    running.add(task);
  }

  return {
    async begin(tx, change, actor, { id, organizationId }, intent) {
      const [mc] = await tx
        .select()
        .from(managedCertificate)
        .where(and(eq(managedCertificate.id, id), eq(managedCertificate.organizationId, organizationId)))
        .for("update");
      if (!mc) throw new Error("the Managed Certificate is gone");
      const [certificateOf] = await tx
        .select({ id: certificate.id })
        .from(certificate)
        .where(and(eq(certificate.organizationId, organizationId), eq(certificate.managedCertificateId, id)))
        .limit(1);
      const hasCertificate = certificateOf !== undefined;

      if (mc.archivedAt) return { refused: "archived" };
      if (mc.approvalStatus === "pending") return { refused: "awaiting_approval" };
      if (mc.approvalStatus === "rejected") return { refused: "rejected" };
      if (intent === "scheduled" && mc.renewalMode !== "automatic") return { refused: "not_automatic" };
      if (intent !== "issue" && !hasCertificate) return { refused: "no_certificate" };
      // The lock on the Managed Certificate makes this the only Issuance that can begin now; the index that allows one running is a backstop.
      const [runningOne] = await tx
        .select({ id: issuance.id })
        .from(issuance)
        .where(and(eq(issuance.managedCertificateId, id), eq(issuance.status, "running")))
        .limit(1);
      if (runningOne) return { refused: "already_running" };

      const [row] = await tx
        .insert(issuance)
        .values({
          organizationId,
          managedCertificateId: id,
          status: "running",
          requestedById: actor?.id ?? null,
          requestedByEmail: actor?.email ?? null,
          startedAt: change.occurredAt,
        })
        .returning({ id: issuance.id });
      const renewal = hasCertificate ? (intent === "scheduled" ? "scheduled" : "requested") : undefined;
      await change.audit({
        organizationId,
        action: "issuance.started",
        target: { type: "managed_certificate", id },
        detail: { issuanceId: row!.id, ...(renewal && { renewal }) },
      });
      change.afterCommit(() => start(row!.id));
      return { issuanceId: row!.id };
    },
    async idle() {
      while (running.size > 0) await Promise.all(running);
    },
    async failInterrupted() {
      const rows = await db.select().from(issuance).where(eq(issuance.status, "running"));
      for (const row of rows) await fail(row, { code: "interrupted", message: "the platform stopped while this was running; ask for it again" });
    },
  };
}
