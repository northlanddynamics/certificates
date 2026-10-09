// An Organization's Managed Certificates: created by an Organization Administrator with names, a key algorithm and a
// CSR (Key Custody: Owner), issued in the background (issuance.ts), and downloaded once a Certificate exists. The
// platform never sees the private key (ADR 0002): the CSR proves the Owner holds it. Anyone else proposes one instead;
// it waits in the Approval queue (approval.ts) and its Issuance starts when an Approver approves it. It may have
// Owners (owners.ts), who with Approvers and Organization Administrators are the ones who see it: an Approver or an
// Administrator sees them all, a Member only what they own or proposed.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import type { Context } from "hono";
import { and, asc, desc, eq, inArray, ne, or, type SQL } from "drizzle-orm";
import { APPROVAL_STATUSES } from "./approval";
import type { Authorizer } from "./authorization";
import { ACME_ENVIRONMENTS } from "./certificate-authority";
import { CsrError, KEY_ALGORITHMS, parseCsr } from "./csr";
import type { Db } from "./db/client";
import { certificate, issuance, managedCertificate } from "./db/schema";
import { HISTORY_KINDS, historyOf } from "./history";
import { HttpError, OrgParam, errors, isUniqueViolation, json } from "./http";
import { InventoryQuery, inventoryCondition } from "./inventory-filters";
import { ISSUANCE_FAILURE_CODES } from "./issuance-failure";
import type { Issuances } from "./issuance";
import { MAX_NAMES, normalizeNames, sameNames } from "./names";
import { OwnerRef, OWNER_TYPES, addOwner, isOwner, ownedByUser, ownersOf, removeOwner } from "./owners";
import { roleCan } from "./permissions";
import type { Actor, UnitOfWork } from "./unit-of-work";

const MAX_OWNERS = 50;

const ManagedCertificateParams = OrgParam.extend({ id: z.string().openapi({ param: { name: "id", in: "path" } }) });

const Issuance = z.object({
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

const Certificate = z.object({
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

const Person = z.object({ id: z.string(), email: z.string() });

const Approval = z.object({
  status: z.enum(APPROVAL_STATUSES).openapi({ description: "`not_required` for one an Organization Administrator created." }),
  proposedBy: Person.nullable(),
  decidedBy: Person.nullable(),
  decidedAt: z.string().nullable(),
  reason: z.string().nullable().openapi({ description: "What the Approver said; always present for a rejection." }),
});

const Owner = z.discriminatedUnion("type", [
  z.object({ type: z.literal("user"), id: z.string(), email: z.string() }),
  z.object({ type: z.literal("team"), id: z.string(), name: z.string() }),
]);

const ManagedCertificate = z.object({
  id: z.string(),
  names: z.array(z.string()),
  keyAlgorithm: z.enum(KEY_ALGORITHMS),
  keyCustody: z.enum(["owner"]),
  environment: z.enum(ACME_ENVIRONMENTS),
  createdAt: z.string(),
  owners: z.array(Owner).openapi({ description: "Users and Teams accountable for it, in the order they were added; none is allowed." }),
  approval: Approval,
  issuance: Issuance.nullable().openapi({ description: "The latest attempt to issue a Certificate." }),
  currentCertificate: Certificate.nullable().openapi({ description: "The most recently issued Certificate." }),
});

const HistoryEntry = z.discriminatedUnion("kind", [
  z.object({
    kind: z.enum(Object.values(HISTORY_KINDS) as [string, ...string[]]),
    at: z.string(),
    actor: Person.nullable(),
    reason: z.string().nullable().openapi({ description: "What the Approver said, for a decision." }),
  }),
  z.object({ kind: z.literal("certificate_issued"), at: z.string(), certificate: Certificate }),
]);

type ManagedCertificateRow = typeof managedCertificate.$inferSelect;
const toIssuance = (row: typeof issuance.$inferSelect) => ({
  id: row.id,
  status: row.status,
  startedAt: row.startedAt.toISOString(),
  finishedAt: row.finishedAt?.toISOString() ?? null,
  failure: row.failureCode && row.failureMessage ? { code: row.failureCode, message: row.failureMessage } : null,
  certificateId: row.certificateId,
});
const toCertificate = (row: typeof certificate.$inferSelect) => ({
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

export function registerManagedCertificates(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  issuances: Issuances;
  clock: () => Date;
}) {
  const { app, db, requireUser, authorize, unitOfWork, issuances, clock } = ctx;

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

  /** The Managed Certificate the caller may change the Owners of: Organization Administrators, and its Owners. */
  async function findOwnable(actor: Actor, orgId: string, id: string) {
    const mc = await findReadable(actor, orgId, id);
    const { role } = await authorize(actor, orgId);
    if (!roleCan(role, { managedCertificate: ["changeOwners"] }) && !(await isOwner(db, orgId, mc.id, actor.id))) {
      throw new HttpError(403, "only an Owner or an Organization Administrator may change a Managed Certificate's Owners");
    }
    return mc;
  }

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
    return rows.map((row) => {
      const latest = latestIssuances.find((i) => i.managedCertificateId === row.id);
      const current = currentCertificates.find((c) => c.managedCertificateId === row.id);
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
        issuance: latest ? toIssuance(latest) : null,
        currentCertificate: current ? toCertificate(current) : null,
      };
    });
  }

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates",
      tags: ["Managed Certificates"],
      summary: "The inventory: the Managed Certificates the caller may see",
      description:
        "Everyone in the Organization may ask. Organization Administrators and Approvers see every Managed Certificate; anyone else sees those they own, directly or through a Team, and those they proposed. " +
        "Archived ones are left out unless `archived` is given. The filters combine, and narrow what the caller sees.",
      request: { params: OrgParam, query: InventoryQuery },
      responses: { 200: json(z.object({ items: z.array(ManagedCertificate) })), ...errors(400, 401, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const actor = await requireUser(c);
      const { role } = await authorize(actor, orgId);
      const rows = await db
        .select()
        .from(managedCertificate)
        .where(and(visibleTo(role, actor, orgId), inventoryCondition(c.req.valid("query"), clock())))
        .orderBy(asc(managedCertificate.createdAt), asc(managedCertificate.id));
      return c.json({ items: await withState(rows) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates",
      tags: ["Managed Certificates"],
      summary: "Create a Managed Certificate and start issuing its first Certificate, or propose one for Approval",
      description:
        "The Owner keeps the private key and submits a CSR for it. The CSR must be for the key algorithm given and ask for exactly the names given. " +
        "An Organization Administrator creates it outright and Issuance starts at once; anyone else proposes it, and it waits for an Approver to approve it, which starts Issuance. " +
        "Issuance runs in the background: the response shows it running, and the Managed Certificate shows the Certificate or the cause of the failure when it ends. " +
        "Staging is the default environment.",
      request: {
        params: OrgParam,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                names: z.array(z.string()).min(1).max(MAX_NAMES).openapi({ description: "DNS names; a wildcard is `*.` and a name." }),
                keyAlgorithm: z.enum(KEY_ALGORITHMS),
                csr: z.string().min(1).openapi({ description: "PEM." }),
                environment: z.enum(ACME_ENVIRONMENTS).default("staging").openapi({ description: "Which of the Organization's ACME accounts to issue through." }),
                owners: z.array(OwnerRef).max(MAX_OWNERS).default([]).openapi({ description: "Users and Teams of the Organization accountable for it; none is allowed." }),
              }),
            },
          },
        },
      },
      responses: { 201: json(ManagedCertificate, "Created with its first Issuance running, or proposed and awaiting Approval"), ...errors(400, 401, 403, 404, 422) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      const { role } = await authorize(actor, orgId);
      // Who may create outright needs no Approval; everyone else must be allowed to propose.
      const needsApproval = !roleCan(role, { managedCertificate: ["create"] });
      if (needsApproval) await authorize(actor, orgId, { managedCertificate: ["propose"] });

      const normalized = normalizeNames(body.names);
      if ("invalid" in normalized) throw new HttpError(400, `"${normalized.invalid}" cannot be a name to issue for`);
      const csr = await parseCsr(body.csr).catch((err) => {
        if (err instanceof CsrError) throw new HttpError(400, err.message);
        throw err;
      });
      if (csr.keyAlgorithm !== body.keyAlgorithm) {
        throw new HttpError(422, `the CSR's key is ${csr.keyAlgorithm}, but the Managed Certificate's key algorithm is ${body.keyAlgorithm}`);
      }
      if (!sameNames(csr.names, normalized.names)) {
        throw new HttpError(422, `the CSR must ask for exactly the names being issued (${normalized.names.join(", ")}), but asks for ${csr.names.join(", ")}`);
      }

      const created = await unitOfWork.run(actor, async (tx, change) => {
        const [row] = await tx
          .insert(managedCertificate)
          .values({
            organizationId: orgId,
            names: normalized.names,
            keyAlgorithm: body.keyAlgorithm,
            keyCustody: "owner",
            environment: body.environment,
            csr: body.csr,
            ...(needsApproval && { approvalStatus: "pending", proposedById: actor.id, proposedByEmail: actor.email }),
          })
          .returning();
        await change.audit({
          organizationId: orgId,
          action: needsApproval ? "managed_certificate.proposed" : "managed_certificate.created",
          target: { type: "managed_certificate", id: row!.id },
          detail: { names: normalized.names, keyAlgorithm: body.keyAlgorithm, keyCustody: "owner", environment: body.environment, csrFingerprint: csr.fingerprint },
        });
        // Whoever creates or proposes may name the Owners at the same time; each is audited as added (naming one twice adds it once).
        for (const ref of body.owners) await addOwner(tx, change, orgId, row!.id, ref);
        // A proposal is issued only once approved.
        return { row: row!, issuanceId: needsApproval ? null : await issuances.begin(tx, change, actor, row!) };
      });
      if (created.issuanceId) issuances.start(created.issuanceId);
      return c.json((await withState([created.row]))[0]!, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates/{id}",
      tags: ["Managed Certificates"],
      request: { params: ManagedCertificateParams },
      responses: { 200: json(ManagedCertificate), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      return c.json((await withState([await findReadable(await requireUser(c), orgId, id)]))[0]!, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/issuances",
      tags: ["Managed Certificates"],
      summary: "Try issuing a Certificate again",
      description: "For when the last Issuance failed. It reuses the Managed Certificate's CSR. Only one runs at a time.",
      request: { params: ManagedCertificateParams },
      responses: { 202: json(Issuance, "Started"), ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { managedCertificate: ["issue"] });
      const mc = await findManagedCertificate(orgId, id);
      if (mc.approvalStatus === "pending" || mc.approvalStatus === "rejected") {
        throw new HttpError(409, `the Managed Certificate is ${mc.approvalStatus === "pending" ? "awaiting Approval" : "rejected"}, so it cannot be issued`);
      }
      let issuanceId: string;
      try {
        issuanceId = await unitOfWork.run(actor, (tx, change) => issuances.begin(tx, change, actor, mc));
      } catch (err) {
        if (isUniqueViolation(err)) throw new HttpError(409, "an Issuance of this Managed Certificate is already running");
        throw err;
      }
      issuances.start(issuanceId);
      const [row] = await db.select().from(issuance).where(eq(issuance.id, issuanceId));
      return c.json(toIssuance(row!), 202);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/owners",
      tags: ["Owners"],
      summary: "Add an Owner: a user or a Team of the Organization",
      description: "Organization Administrators and the Managed Certificate's own Owners may. Naming one who already is an Owner changes nothing.",
      request: { params: ManagedCertificateParams, body: { content: { "application/json": { schema: OwnerRef } } } },
      responses: { 200: json(ManagedCertificate, "The Managed Certificate with its Owners"), ...errors(400, 401, 403, 404, 422) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const ref = c.req.valid("json");
      const actor = await requireUser(c);
      const mc = await findOwnable(actor, orgId, id);
      await unitOfWork.run(actor, (tx, change) => addOwner(tx, change, orgId, mc.id, ref));
      return c.json((await withState([mc]))[0]!, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/owners/{type}/{ownerId}",
      tags: ["Owners"],
      summary: "Remove an Owner",
      description: "Organization Administrators and the Managed Certificate's own Owners may. It may be left with none.",
      request: {
        params: ManagedCertificateParams.extend({
          type: z.enum(OWNER_TYPES).openapi({ param: { name: "type", in: "path" } }),
          ownerId: z.string().openapi({ param: { name: "ownerId", in: "path" } }),
        }),
      },
      responses: { 200: json(ManagedCertificate, "The Managed Certificate with its Owners"), ...errors(400, 401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id, type, ownerId } = c.req.valid("param");
      const actor = await requireUser(c);
      const mc = await findOwnable(actor, orgId, id);
      await unitOfWork.run(actor, (tx, change) => removeOwner(tx, change, orgId, mc.id, { type, id: ownerId }));
      return c.json((await withState([mc]))[0]!, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/history",
      tags: ["Managed Certificates"],
      summary: "How the Managed Certificate got to its current state, oldest first",
      description: "Its creation or proposal, its Approvals and the Certificates issued for it.",
      request: { params: ManagedCertificateParams },
      responses: { 200: json(z.object({ items: z.array(HistoryEntry) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const mc = await findReadable(await requireUser(c), orgId, id);
      const entries = await historyOf(db, orgId, mc.id);
      return c.json({ items: entries.map((e) => (e.kind === "certificate_issued" ? { ...e, certificate: toCertificate(e.certificate) } : e)) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/approvals",
      tags: ["Approval"],
      summary: "The Approval queue: proposed Managed Certificates the caller may decide, the oldest first",
      description: "A proposal is decided by someone other than who proposed it, so the caller's own proposals are not in their queue.",
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(ManagedCertificate) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { approval: ["read"] });
      const rows = await db
        .select()
        .from(managedCertificate)
        .where(
          and(
            eq(managedCertificate.organizationId, orgId),
            eq(managedCertificate.approvalStatus, "pending"),
            ne(managedCertificate.proposedById, actor.id),
          ),
        )
        .orderBy(asc(managedCertificate.createdAt), asc(managedCertificate.id));
      return c.json({ items: await withState(rows) }, 200);
    },
  );

  /**
   * Records an Approver's decision on a pending proposal. Whoever proposed cannot decide it, and a decision is final:
   * the update takes only a proposal still pending, so of two decisions made at once, one wins and the other is refused.
   * Approving starts the Issuance on the same transaction.
   */
  async function decide(c: Context, orgId: string, id: string, decision: "approved" | "rejected", reason: string | null) {
    const actor = await requireUser(c);
    await authorize(actor, orgId, { approval: ["decide"] });
    const mc = await findManagedCertificate(orgId, id);
    if (mc.proposedById === actor.id) throw new HttpError(403, "a proposal must be decided by someone other than who proposed it");
    if (mc.approvalStatus !== "pending") throw new HttpError(409, "this Managed Certificate is not awaiting Approval");

    const issuanceId = await unitOfWork.run(actor, async (tx, change) => {
      const decided = await tx
        .update(managedCertificate)
        .set({ approvalStatus: decision, decidedById: actor.id, decidedByEmail: actor.email, decidedAt: change.occurredAt, decisionReason: reason })
        .where(and(eq(managedCertificate.id, mc.id), eq(managedCertificate.organizationId, orgId), eq(managedCertificate.approvalStatus, "pending")))
        .returning({ id: managedCertificate.id });
      if (decided.length === 0) throw new HttpError(409, "this Managed Certificate is not awaiting Approval");
      await change.audit({
        organizationId: orgId,
        action: decision === "approved" ? "managed_certificate.approved" : "managed_certificate.rejected",
        target: { type: "managed_certificate", id: mc.id },
        detail: { names: mc.names, reason, proposedBy: mc.proposedByEmail },
      });
      return decision === "approved" ? issuances.begin(tx, change, actor, mc) : null;
    });
    if (issuanceId) issuances.start(issuanceId);
    return (await withState([await findManagedCertificate(orgId, id)]))[0]!;
  }

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/approve",
      tags: ["Approval"],
      summary: "Approve a proposed Managed Certificate, which starts its Issuance",
      description: "The proposer need do nothing more. Nobody decides their own proposal, and a decision is final.",
      request: {
        params: ManagedCertificateParams,
        body: { content: { "application/json": { schema: z.object({ reason: z.string().trim().max(1000).optional() }) } } },
      },
      responses: { 200: json(ManagedCertificate, "Approved, with its first Issuance running"), ...errors(400, 401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      return c.json(await decide(c, orgId, id, "approved", c.req.valid("json").reason || null), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/reject",
      tags: ["Approval"],
      summary: "Reject a proposed Managed Certificate, with the reason the proposer will see",
      request: {
        params: ManagedCertificateParams,
        body: { content: { "application/json": { schema: z.object({ reason: z.string().trim().min(1).max(1000) }) } } },
      },
      responses: { 200: json(ManagedCertificate, "Rejected"), ...errors(400, 401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      return c.json(await decide(c, orgId, id, "rejected", c.req.valid("json").reason), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/certificates",
      tags: ["Managed Certificates"],
      summary: "Every Certificate issued for the Managed Certificate, the newest first",
      request: { params: ManagedCertificateParams },
      responses: { 200: json(z.object({ items: z.array(Certificate) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const mc = await findReadable(await requireUser(c), orgId, id);
      return c.json({ items: (await certificatesOf(orgId, mc.id)).map(toCertificate) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/certificate.pem",
      tags: ["Managed Certificates"],
      summary: "Download the current Certificate as PEM, with its chain",
      description: "The Certificate followed by the intermediates the CA served. There is no private key in it: the platform never has one.",
      request: { params: ManagedCertificateParams },
      responses: {
        200: { description: "PEM", content: { "application/x-pem-file": { schema: z.string() } } },
        ...errors(401, 403, 404),
      },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const mc = await findReadable(await requireUser(c), orgId, id);
      const [current] = await certificatesOf(orgId, mc.id);
      if (!current) throw new HttpError(404, "no Certificate has been issued for this Managed Certificate yet");
      const filename = `${mc.names[0]!.replace(/^\*\./, "wildcard.")}.pem`;
      return c.body(current.chainPem, 200, {
        "content-type": "application/x-pem-file",
        "content-disposition": `attachment; filename="${filename}"`,
      });
    },
  );
}
