// How the platform reads Managed Certificates for the routes that serve them: the shapes the API gives, which ones a
// caller may see (an Approver or an Organization Administrator sees them all, a Member only what they own, directly or
// through a Team, or proposed), and each with its latest Issuance, current Certificate and Owners.
import { z } from "@hono/zod-openapi";
import { and, desc, eq, inArray, or, type SQL } from "drizzle-orm";
import { APPROVAL_STATUSES } from "./approval";
import type { Authorizer } from "./authorization";
import { ACME_ENVIRONMENTS } from "./certificate-authority";
import { KEY_ALGORITHMS } from "./csr";
import type { Db } from "./db/client";
import { certificate, issuance, managedCertificate } from "./db/schema";
import { HttpError, OrgParam } from "./http";
import { ISSUANCE_FAILURE_CODES } from "./issuance-failure";
import { isOwner, ownedByUser, ownersOf } from "./owners";
import { roleCan, type Permissions } from "./permissions";
import { MAX_RENEWAL_DAYS, RENEWAL_MODES, dueAt, failuresOf, nextAttemptAt } from "./renewal";
import type { Actor } from "./unit-of-work";

export const ManagedCertificateParams = OrgParam.extend({ id: z.string().openapi({ param: { name: "id", in: "path" } }) });

export const Issuance = z.object({
  id: z.string(),
  status: z.enum(["running", "succeeded", "failed"]),
  startedAt: z.string(),
  finishedAt: z.string().nullable(),
  failure: z
    .object({ code: z.enum(ISSUANCE_FAILURE_CODES), message: z.string() })
    .nullable()
    .openapi({ description: "Why it failed: which step, and what the DNS Provider or the CA said." }),
  certificateId: z.string().nullable(),
});

export const Certificate = z.object({
  id: z.string(),
  fingerprint: z.string().openapi({ description: "SHA-256 of the certificate, lower-case hex." }),
  serial: z.string(),
  notBefore: z.string(),
  notAfter: z.string(),
  names: z.array(z.string()),
  ca: z.string(),
  environment: z.enum(ACME_ENVIRONMENTS),
  acmeAccountId: z.string(),
  issuedAt: z.string(),
});

export const RenewalPolicy = z.object({
  mode: z.enum(RENEWAL_MODES).openapi({ description: "`automatic`: the scheduler renews it when due. `manual`: only an Owner or an Organization Administrator does." }),
  daysBeforeExpiry: z.number().int().min(1).max(MAX_RENEWAL_DAYS).openapi({ description: "How many days before its current Certificate ends it is due for Renewal." }),
});

export const Renewal = z.object({
  policy: RenewalPolicy,
  dueAt: z.string().nullable().openapi({ description: "When the scheduler will renew it; none for a manual one or one with no Certificate yet." }),
  failing: z
    .object({
      failures: z.number().int().openapi({ description: "How many Renewals have failed since the current Certificate was issued." }),
      lastFailure: z.object({ code: z.enum(ISSUANCE_FAILURE_CODES), message: z.string(), at: z.string() }),
      nextAttemptAt: z.string().nullable().openapi({ description: "When the scheduler will try again; none for a manual one, which only a person renews." }),
    })
    .nullable()
    .openapi({ description: "Set while the latest Renewal of a Managed Certificate that has a Certificate has failed." }),
});

export const Person = z.object({ id: z.string(), email: z.string() });

export const Approval = z.object({
  status: z.enum(APPROVAL_STATUSES).openapi({ description: "`not_required` for one an Organization Administrator created." }),
  proposedBy: Person.nullable(),
  decidedBy: Person.nullable(),
  decidedAt: z.string().nullable(),
  reason: z.string().nullable().openapi({ description: "What the Approver said; always present for a rejection." }),
});

export const Owner = z.discriminatedUnion("type", [
  z.object({ type: z.literal("user"), id: z.string(), email: z.string() }),
  z.object({ type: z.literal("team"), id: z.string(), name: z.string() }),
]);

export const ManagedCertificate = z.object({
  id: z.string(),
  names: z.array(z.string()),
  keyAlgorithm: z.enum(KEY_ALGORITHMS),
  keyCustody: z.enum(["owner"]),
  environment: z.enum(ACME_ENVIRONMENTS),
  createdAt: z.string(),
  owners: z.array(Owner).openapi({ description: "Users and Teams accountable for it, in the order they were added; none is allowed." }),
  approval: Approval,
  renewal: Renewal,
  issuance: Issuance.nullable().openapi({ description: "The latest attempt to issue a Certificate." }),
  currentCertificate: Certificate.nullable().openapi({ description: "The most recently issued Certificate." }),
});

type ManagedCertificateRow = typeof managedCertificate.$inferSelect;
export const toIssuance = (row: typeof issuance.$inferSelect) => ({
  id: row.id,
  status: row.status,
  startedAt: row.startedAt.toISOString(),
  finishedAt: row.finishedAt?.toISOString() ?? null,
  failure: row.failureCode && row.failureMessage ? { code: row.failureCode, message: row.failureMessage } : null,
  certificateId: row.certificateId,
});
export const toCertificate = (row: typeof certificate.$inferSelect) => ({
  id: row.id,
  fingerprint: row.fingerprint,
  serial: row.serial,
  notBefore: row.notBefore.toISOString(),
  notAfter: row.notAfter.toISOString(),
  names: row.names,
  ca: row.ca,
  environment: row.environment,
  acmeAccountId: row.acmeAccountId,
  issuedAt: row.issuedAt.toISOString(),
});

export function createManagedCertificateReader({ db, authorize }: { db: Db; authorize: Authorizer["authorize"] }) {
  async function findManagedCertificate(orgId: string, id: string) {
    // Not a UUID can't be a Managed Certificate; asking Postgres would only raise a type error.
    const [row] = z.uuid().safeParse(id).success
      ? await db.select().from(managedCertificate).where(and(eq(managedCertificate.organizationId, orgId), eq(managedCertificate.id, id)))
      : [];
    if (!row) throw new HttpError(404, "Managed Certificate not found");
    return row;
  }

  /**
   * Which Managed Certificates of the Organization the caller sees: all of them for those who may read them, and for
   * the rest what they own (directly or through a Team) and what they proposed themselves (a proposer follows their
   * proposal through Approval and Issuance).
   */
  const visibleTo = (role: string, actor: Actor, orgId: string): SQL => {
    const ofOrganization = eq(managedCertificate.organizationId, orgId);
    if (roleCan(role, { managedCertificate: ["read"] })) return ofOrganization;
    return and(ofOrganization, or(eq(managedCertificate.proposedById, actor.id), ownedByUser(orgId, actor.id)))!;
  };

  /** The Managed Certificate the caller may see. One they may not is refused (403) whether or not it exists. */
  async function findReadable(actor: Actor, orgId: string, id: string) {
    const { role } = await authorize(actor, orgId);
    if (roleCan(role, { managedCertificate: ["read"] })) return findManagedCertificate(orgId, id);
    const [row] = z.uuid().safeParse(id).success
      ? await db.select().from(managedCertificate).where(and(eq(managedCertificate.id, id), visibleTo(role, actor, orgId)))
      : [];
    if (!row) throw new HttpError(403, "not permitted");
    return row;
  }

  /**
   * The Managed Certificate the caller may see and may do `permissions` to: those whose role holds them, and its Owners
   * whatever their role. Anyone else is refused (403) with `refusal`.
   */
  async function findAsOwnerOr(actor: Actor, orgId: string, id: string, permissions: Permissions, refusal: string) {
    const mc = await findReadable(actor, orgId, id);
    const { role } = await authorize(actor, orgId);
    if (!roleCan(role, permissions) && !(await isOwner(db, orgId, mc.id, actor.id))) throw new HttpError(403, refusal);
    return mc;
  }

  /** The Managed Certificate the caller may change the Owners of: Organization Administrators, and its Owners. */
  const findOwnable = (actor: Actor, orgId: string, id: string) =>
    findAsOwnerOr(actor, orgId, id, { managedCertificate: ["changeOwners"] }, "only an Owner or an Organization Administrator may change a Managed Certificate's Owners");

  /** The Managed Certificate's Certificates, the most recently stored first: the first is the current one. */
  const certificatesOf = (orgId: string, managedCertificateId: string) =>
    db
      .select()
      .from(certificate)
      .where(and(eq(certificate.organizationId, orgId), eq(certificate.managedCertificateId, managedCertificateId)))
      .orderBy(desc(certificate.createdAt), desc(certificate.id));

  /** The Managed Certificates as the API shows them: each with its latest Issuance and its current Certificate. */
  async function withState(rows: ManagedCertificateRow[]) {
    if (rows.length === 0) return [];
    const ids = rows.map((r) => r.id);
    const latestIssuances = await db
      .selectDistinctOn([issuance.managedCertificateId])
      .from(issuance)
      .where(inArray(issuance.managedCertificateId, ids))
      .orderBy(issuance.managedCertificateId, desc(issuance.createdAt), desc(issuance.id));
    const currentCertificates = await db
      .selectDistinctOn([certificate.managedCertificateId])
      .from(certificate)
      .where(inArray(certificate.managedCertificateId, ids))
      .orderBy(certificate.managedCertificateId, desc(certificate.createdAt), desc(certificate.id));
    const owners = await ownersOf(db, ids);
    const failures = await failuresOf(db, ids);
    return rows.map((row) => {
      const latest = latestIssuances.find((i) => i.managedCertificateId === row.id);
      const current = currentCertificates.find((c) => c.managedCertificateId === row.id);
      const policy = { mode: row.renewalMode, daysBeforeExpiry: row.renewalDaysBeforeExpiry };
      // A failed first Issuance is not a failing Renewal: there is no Certificate yet to renew.
      const failed = current ? failures.get(row.id) : undefined;
      return {
        id: row.id,
        names: row.names,
        keyAlgorithm: row.keyAlgorithm,
        keyCustody: row.keyCustody,
        environment: row.environment,
        createdAt: row.createdAt.toISOString(),
        owners: owners.get(row.id) ?? [],
        approval: {
          status: row.approvalStatus,
          proposedBy: row.proposedById && row.proposedByEmail ? { id: row.proposedById, email: row.proposedByEmail } : null,
          decidedBy: row.decidedById && row.decidedByEmail ? { id: row.decidedById, email: row.decidedByEmail } : null,
          decidedAt: row.decidedAt?.toISOString() ?? null,
          reason: row.decisionReason,
        },
        renewal: {
          policy,
          dueAt: policy.mode === "automatic" && current ? dueAt(current, policy.daysBeforeExpiry).toISOString() : null,
          failing: failed
            ? {
                failures: failed.failures,
                lastFailure: { code: failed.last.code, message: failed.last.message, at: failed.last.at.toISOString() },
                nextAttemptAt: nextAttemptAt(policy, current!, failed)?.toISOString() ?? null,
              }
            : null,
        },
        issuance: latest ? toIssuance(latest) : null,
        currentCertificate: current ? toCertificate(current) : null,
      };
    });
  }

  return { findManagedCertificate, visibleTo, findReadable, findOwnable, findAsOwnerOr, certificatesOf, withState };
}

export type ManagedCertificateReader = ReturnType<typeof createManagedCertificateReader>;
