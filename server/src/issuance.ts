// Issuance: turns "issue these names for this Managed Certificate with its CSR" into a Certificate. An Issuance is
// recorded when it is asked for and runs in the background (a CA with DNS propagation can take minutes, longer than a
// request should wait): it does DCV through the Organization's DNS Provider, has the CA finalize the order with the
// CSR, and ends by storing the Certificate, or with the cause of its failure. Either end is one audited change.
import { X509Certificate, createHash } from "node:crypto";
import { and, desc, eq } from "drizzle-orm";
import { CertificateAuthorityError, type CertificateAuthority } from "./certificate-authority";
import { parseCsr } from "./csr";
import type { Dcv } from "./dcv";
import type { Db, Tx } from "./db/client";
import { acmeAccount, certificate, issuance, managedCertificate } from "./db/schema";
import { IssuanceFailure, type IssuanceFailureCode } from "./issuance-failure";
import type { Secrets } from "./secrets";
import type { Actor, Change, UnitOfWork } from "./unit-of-work";

/** Who started an Issuance that renews a Managed Certificate that has a Certificate: the scheduler, or a person who asked for it. */
export type RenewalTrigger = "scheduled" | "requested";

export interface Issuances {
  /**
   * Records that an Issuance of the Managed Certificate has been asked for, on the transaction of the change that asks
   * (so it exists only if that change commits), and returns its id. Call `start` with it once that change has committed.
   */
  begin(
    tx: Tx,
    change: Change,
    actor: Actor | null,
    managedCertificate: { id: string; organizationId: string },
    renewal?: RenewalTrigger,
  ): Promise<string>;
  /** Runs the Issuance in the background; it records its own outcome and never throws. */
  start(issuanceId: string): void;
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

  return {
    async begin(tx, change, actor, mc, renewal) {
      const [row] = await tx
        .insert(issuance)
        .values({
          organizationId: mc.organizationId,
          managedCertificateId: mc.id,
          status: "running",
          requestedById: actor?.id ?? null,
          requestedByEmail: actor?.email ?? null,
          startedAt: change.occurredAt,
        })
        .returning({ id: issuance.id });
      await change.audit({
        organizationId: mc.organizationId,
        action: "issuance.started",
        target: { type: "managed_certificate", id: mc.id },
        detail: { issuanceId: row!.id, ...(renewal && { renewal }) },
      });
      return row!.id;
    },
    start(issuanceId) {
      const task = run(issuanceId)
        // Recording the outcome failed too (the database is gone): nothing more can be done but say so.
        .catch((err) => console.error("could not record the outcome of issuance", issuanceId, err))
        .finally(() => running.delete(task));
      running.add(task);
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
