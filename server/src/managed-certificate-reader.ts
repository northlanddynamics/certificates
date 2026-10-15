// How the platform reads Managed Certificates for the routes that serve them: the shapes the API gives, which ones a
// caller may see (an Approver or an Organization Administrator sees them all, a Member only what they own, directly or
// through a Team, or proposed), and each with its latest Issuance, current Certificate and Owners.
import { z } from "@hono/zod-openapi";
import { and, desc, eq, inArray, or, type SQL } from "drizzle-orm";
import { APPROVAL_STATUSES } from "./approval";
import { AGENT_STATUSES, agentStatus } from "./agents";
import type { Authorizer } from "./authorization";
import { ACME_ENVIRONMENTS } from "./certificate-authority";
import { KEY_ALGORITHMS, KEY_CUSTODIES } from "./csr";
import type { Db } from "./db/client";
import { agent, certificate, deployment, issuance, managedCertificate, privateCa } from "./db/schema";
import { HttpError, OrgParam } from "./http";
import { issuerOf, type Issuer as IssuerOfRow } from "./issuer";
import { ISSUANCE_FAILURE_CODES } from "./issuance-failure";
import { ISSUANCE_KINDS } from "./issuance-kinds";
import { PendingNameChange, pendingNameChanges, toPendingNameChange } from "./name-change";
import { isOwner, ownedByUser, ownersOf } from "./owners";
import { roleCan, type Permissions } from "./permissions";
import { MAX_RENEWAL_DAYS, RENEWAL_MODES, failuresOf, nextAttemptAt, renewalDue } from "./renewal";
import { informationOf } from "./renewal-information";
import { Revocation, revocationsOf, toRevocation, type RevocationRow } from "./revocation";
import type { Actor } from "./unit-of-work";

export const ManagedCertificateParams = OrgParam.extend({ id: z.string().openapi({ param: { name: "id", in: "path" } }) });

export const Person = z.object({ id: z.string(), email: z.string() });

export const Issuance = z.object({
  id: z.string(),
  kind: z.enum(ISSUANCE_KINDS).openapi({ description: "`first_issue`: it had no Certificate yet. `renewal`: it had one for its names. `name_change`: it had one for other names, which a Name Change replaced." }),
  status: z.enum(["running", "succeeded", "failed"]),
  requestedBy: Person.nullable().openapi({ description: "Who asked for it; none when the Renewal scheduler did." }),
  startedAt: z.string(),
  finishedAt: z.string().nullable(),
  failure: z
    .object({ code: z.enum(ISSUANCE_FAILURE_CODES), message: z.string() })
    .nullable()
    .openapi({ description: "Why it failed: which step, and what the DNS Provider or the CA said." }),
  certificateId: z.string().nullable(),
  awaitingKey: z.boolean().openapi({ description: "Whether it waits for the Agent that holds the key to make a new one and send its CSR, as a Renewal of a key an Agent holds begins: it waits as long as the Agent is away." }),
});

export const Certificate = z.object({
  id: z.string(),
  fingerprint: z.string().openapi({ description: "SHA-256 of the certificate, lower-case hex." }),
  serial: z.string(),
  notBefore: z.string(),
  notAfter: z.string(),
  names: z.array(z.string()),
  ca: z.string(),
  environment: z.enum(ACME_ENVIRONMENTS).nullable().openapi({ description: "The ACME environment it was issued through; none for a Certificate from a Private CA." }),
  acmeAccountId: z.string().nullable().openapi({ description: "The ACME account it was issued through; none for a Certificate from a Private CA." }),
  privateCaId: z.string().nullable().openapi({ description: "The Private CA that issued it; none for a Certificate from an ACME CA." }),
  issuedAt: z.string(),
  revocation: Revocation.nullable().openapi({ description: "Set once the CA has been told to revoke it, by whom and why." }),
});

const ChainCertificate = z.object({
  subject: z.string(),
  issuer: z.string(),
  serial: z.string().openapi({ description: "Upper-case hex." }),
  fingerprint: z.string().openapi({ description: "SHA-256 of the certificate, lower-case hex." }),
  notBefore: z.string(),
  notAfter: z.string(),
});

export const CertificateFacts = Certificate.extend({
  subject: z.string().openapi({ description: "The leaf's subject, as a distinguished name; `names` are its subject alternative names." }),
  issuer: z.string().openapi({ description: "The distinguished name of the CA certificate that signed it." }),
  signatureAlgorithm: z.string().openapi({ description: "How the CA signed it, such as `ECDSA with SHA-256`." }),
  chain: z.array(ChainCertificate).openapi({ description: "The leaf and the intermediates the CA served, leaf first." }),
  acmeAccount: z
    .object({ id: z.string(), environment: z.enum(ACME_ENVIRONMENTS) })
    .nullable()
    .openapi({ description: "The Organization's ACME account it was issued through; none for a Certificate from a Private CA." }),
});

export const RenewalPolicy = z.object({
  mode: z.enum(RENEWAL_MODES).openapi({ description: "`automatic`: the scheduler renews it when due. `manual`: only an Owner or an Organization Administrator does." }),
  daysBeforeExpiry: z.number().int().min(1).max(MAX_RENEWAL_DAYS).openapi({ description: "How many days before its current Certificate ends it is due for Renewal." }),
});

export const Renewal = z.object({
  policy: RenewalPolicy,
  dueAt: z.string().nullable().openapi({ description: "When the scheduler will renew it, the earlier of its days before expiry and a time within the CA's ARI window; none for a manual one or one with no Certificate yet." }),
  dueBecause: z.enum(["policy", "ari"]).nullable().openapi({ description: "What makes it due then: `policy`, its days before expiry, or `ari`, the CA's suggested window." }),
  ari: z
    .object({
      window: z.object({ start: z.string(), end: z.string() }).nullable().openapi({ description: "The window the CA suggests renewing in; none if it offers no ARI, or has not said." }),
      checkedAt: z.string().nullable().openapi({ description: "When the CA last answered; none if it has not." }),
      nextCheckAt: z.string().openapi({ description: "When the CA will be asked again (its Retry-After)." }),
    })
    .nullable()
    .openapi({ description: "What the CA's ACME Renewal Information last said about the current Certificate; none for a manual one, or until the scheduler has asked." }),
  failing: z
    .object({
      failures: z.number().int().openapi({ description: "How many Renewals have failed since the current Certificate was issued." }),
      lastFailure: z.object({ code: z.enum(ISSUANCE_FAILURE_CODES), message: z.string(), at: z.string() }),
      nextAttemptAt: z.string().nullable().openapi({ description: "When the scheduler will try again; none for a manual one, which only a person renews." }),
    })
    .nullable()
    .openapi({ description: "Set while the latest Renewal of a Managed Certificate that has a Certificate has failed." }),
});

const Issuer = z
  .discriminatedUnion("kind", [
    z.object({ kind: z.literal("acme"), environment: z.enum(ACME_ENVIRONMENTS) }),
    z.object({ kind: z.literal("private_ca"), privateCa: z.object({ id: z.string(), name: z.string() }) }),
  ])
  .openapi({ description: "Where its Certificates come from: `acme`, through the Organization's ACME account in `environment`; `private_ca`, from one of the Organization's Private CAs, with no DCV." });

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
  keyCustody: z.enum(KEY_CUSTODIES).openapi({ description: "`owner`: the Owner holds the private key and submitted a CSR. `agent`: one Agent made the key and holds it, through its one Deployment." }),
  environment: z.enum(ACME_ENVIRONMENTS).nullable().openapi({ description: "The ACME environment, as in `issuer`; none for one issued from a Private CA." }),
  issuer: Issuer,
  validityDays: z
    .number()
    .nullable()
    .openapi({ description: "For one issued from a Private CA, how many days its Certificates are valid for, never past the Private CA's maximum or its Issuing CA's end; none for the Private CA's default, and always none for an ACME CA, which decides." }),
  createdAt: z.string(),
  archivedAt: z.string().nullable().openapi({ description: "When it was archived: it then neither issues, renews nor deploys, and is listed only when archived ones are asked for." }),
  owners: z.array(Owner).openapi({ description: "Users and Teams accountable for it, in the order they were added; none is allowed." }),
  approval: Approval,
  pendingNameChange: PendingNameChange.nullable().openapi({ description: "A change of its names waiting for Approval; until it is approved, Renewal uses the names above." }),
  renewal: Renewal,
  issuance: Issuance.nullable().openapi({ description: "The latest attempt to issue a Certificate." }),
  currentCertificate: Certificate.nullable().openapi({ description: "The most recently issued Certificate." }),
  agent: z
    .object({ id: z.string(), hostName: z.string(), status: z.enum(AGENT_STATUSES) })
    .nullable()
    .openapi({ description: "For Key Custody `agent`, the Agent that holds the key, and whether it is online: one that is offline holds up the Renewal, which waits for it to make the new key. None for a key the Owner holds." }),
});

type ManagedCertificateRow = typeof managedCertificate.$inferSelect;

/** The issuer as the API shows it: a Private CA by its id and name, so that whoever decides on it sees which CA it is. */
const issuerShown = (issuer: IssuerOfRow, privateCaNames: Map<string, string>): z.infer<typeof Issuer> =>
  issuer.kind === "acme" ? issuer : { kind: "private_ca", privateCa: { id: issuer.privateCaId, name: privateCaNames.get(issuer.privateCaId) ?? "" } };
export const toIssuance = (row: typeof issuance.$inferSelect) => ({
  id: row.id,
  kind: row.kind,
  status: row.status,
  requestedBy: row.requestedById && row.requestedByEmail ? { id: row.requestedById, email: row.requestedByEmail } : null,
  startedAt: row.startedAt.toISOString(),
  finishedAt: row.finishedAt?.toISOString() ?? null,
  failure: row.failureCode && row.failureMessage ? { code: row.failureCode, message: row.failureMessage } : null,
  certificateId: row.certificateId,
  awaitingKey: row.awaitingKey,
});
export const toCertificate = (row: typeof certificate.$inferSelect, revocation: RevocationRow | undefined) => ({
  id: row.id,
  fingerprint: row.fingerprint,
  serial: row.serial,
  notBefore: row.notBefore.toISOString(),
  notAfter: row.notAfter.toISOString(),
  names: row.names,
  ca: row.ca,
  environment: row.environment,
  acmeAccountId: row.acmeAccountId,
  privateCaId: row.privateCaId,
  issuedAt: row.issuedAt.toISOString(),
  revocation: revocation ? toRevocation(revocation) : null,
});

export function createManagedCertificateReader({ db, authorize, clock, agentOfflineAfterSeconds }: { db: Db; authorize: Authorizer["authorize"]; clock: () => Date; agentOfflineAfterSeconds: number }) {
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
    const privateCaIds = [...new Set(rows.flatMap((r) => (r.privateCaId ? [r.privateCaId] : [])))];
    const privateCaNames = new Map(
      privateCaIds.length === 0 ? [] : (await db.select({ id: privateCa.id, name: privateCa.name }).from(privateCa).where(inArray(privateCa.id, privateCaIds))).map((ca) => [ca.id, ca.name]),
    );
    const failures = await failuresOf(db, ids);
    const nameChanges = await pendingNameChanges(db, ids);
    const information = await informationOf(db, currentCertificates.map((c) => c.id));
    const revocations = await revocationsOf(db, currentCertificates.map((c) => c.id));
    const holders = new Map(
      (
        await db
          .select({ managedCertificateId: deployment.managedCertificateId, id: agent.id, hostName: agent.hostName, revokedAt: agent.revokedAt, lastContactAt: agent.lastContactAt })
          .from(deployment)
          .innerJoin(agent, eq(agent.id, deployment.agentId))
          .where(inArray(deployment.managedCertificateId, ids))
      ).map((h) => [h.managedCertificateId, h]),
    );
    const now = clock();
    return rows.map((row) => {
      const holder = holders.get(row.id);
      const latest = latestIssuances.find((i) => i.managedCertificateId === row.id);
      const current = currentCertificates.find((c) => c.managedCertificateId === row.id);
      const policy = { mode: row.renewalMode, daysBeforeExpiry: row.renewalDaysBeforeExpiry };
      // A failed first Issuance is not a failing Renewal: there is no Certificate yet to renew.
      const failed = current ? failures.get(row.id) : undefined;
      const ari = current ? information.get(current.id) : undefined;
      const pending = nameChanges.get(row.id);
      const due = policy.mode === "automatic" && current ? renewalDue(current, policy.daysBeforeExpiry, ari?.window ?? null) : null;
      return {
        id: row.id,
        names: row.names,
        keyAlgorithm: row.keyAlgorithm,
        keyCustody: row.keyCustody,
        environment: row.environment,
        issuer: issuerShown(issuerOf(row), privateCaNames),
        validityDays: row.validityDays,
        createdAt: row.createdAt.toISOString(),
        archivedAt: row.archivedAt?.toISOString() ?? null,
        owners: owners.get(row.id) ?? [],
        approval: {
          status: row.approvalStatus,
          proposedBy: row.proposedById && row.proposedByEmail ? { id: row.proposedById, email: row.proposedByEmail } : null,
          decidedBy: row.decidedById && row.decidedByEmail ? { id: row.decidedById, email: row.decidedByEmail } : null,
          decidedAt: row.decidedAt?.toISOString() ?? null,
          reason: row.decisionReason,
        },
        pendingNameChange: pending ? toPendingNameChange(pending) : null,
        renewal: {
          policy,
          dueAt: due?.at.toISOString() ?? null,
          dueBecause: due?.because ?? null,
          ari:
            policy.mode === "automatic" && ari
              ? {
                  window: ari.window && { start: ari.window.start.toISOString(), end: ari.window.end.toISOString() },
                  checkedAt: ari.checkedAt?.toISOString() ?? null,
                  nextCheckAt: ari.nextCheckAt.toISOString(),
                }
              : null,
          failing: failed
            ? {
                failures: failed.failures,
                lastFailure: { code: failed.last.code, message: failed.last.message, at: failed.last.at.toISOString() },
                nextAttemptAt: nextAttemptAt(policy, current!, failed, ari?.window ?? null)?.toISOString() ?? null,
              }
            : null,
        },
        issuance: latest ? toIssuance(latest) : null,
        currentCertificate: current ? toCertificate(current, revocations.get(current.id)) : null,
        agent: holder ? { id: holder.id, hostName: holder.hostName, status: agentStatus(holder, now, agentOfflineAfterSeconds) } : null,
      };
    });
  }

  return { findManagedCertificate, visibleTo, findReadable, findOwnable, findAsOwnerOr, certificatesOf, withState };
}

export type ManagedCertificateReader = ReturnType<typeof createManagedCertificateReader>;
