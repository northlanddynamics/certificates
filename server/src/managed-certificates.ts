// An Organization's Managed Certificates: created by an Organization Administrator with names, a key algorithm and a
// CSR (Key Custody: Owner), issued in the background (issuance.ts) and downloaded once a Certificate exists
// (certificate-export.ts). The platform never sees the private key (ADR 0002): the CSR proves the Owner holds it.
// Anyone else proposes one instead; it waits in the Approval queue (approval.ts) and its Issuance starts when an
// Approver approves it. It may have Owners (owners.ts), who with Approvers and Organization Administrators are the
// ones who see it (see managed-certificate-reader.ts). This module serves the inventory and the Managed Certificate itself.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, eq } from "drizzle-orm";
import { silentSince } from "./agents";
import type { Authorizer } from "./authorization";
import { ACME_ENVIRONMENTS } from "./certificate-authority";
import { KEY_ALGORITHMS } from "./csr";
import type { Db } from "./db/client";
import { issuance, managedCertificate } from "./db/schema";
import { HttpError, OrgParam, PageQuery, errors, json, pageOf } from "./http";
import { InventoryQuery, inventoryCondition } from "./inventory-filters";
import { refusalMessage, type Issuances } from "./issuance";
import { Certificate, Issuance, ManagedCertificate, ManagedCertificateParams, toCertificate, toIssuance, type ManagedCertificateReader } from "./managed-certificate-reader";
import { checkNamesAndCsr, csrField, namesField } from "./names-and-csr";
import { OwnerRef, addOwner } from "./owners";
import { roleCan } from "./permissions";
import { revocationsOf } from "./revocation";
import type { Actor, UnitOfWork } from "./unit-of-work";

const MAX_OWNERS = 50;
export function registerManagedCertificates(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  issuances: Issuances;
  reader: ManagedCertificateReader;
  clock: () => Date;
  /** How long an Agent may be silent before it counts as offline, for the inventory's `agentOffline` filter. */
  agentOfflineAfterSeconds: number;
}) {
  const { app, db, requireUser, authorize, unitOfWork, issuances, reader, clock, agentOfflineAfterSeconds } = ctx;
  const { findManagedCertificate, findReadable, visibleTo, certificatesOf, withState } = reader;

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates",
      tags: ["Managed Certificates"],
      summary: "The inventory: the Managed Certificates the caller may see",
      description:
        "Everyone in the Organization may ask. Organization Administrators and Approvers see every Managed Certificate; anyone else sees those they own, directly or through a Team, and those they proposed. " +
        "Archived ones are left out unless `archived` is given. The filters combine, and narrow what the caller sees. " +
        "It is listed oldest first, a page at a time; `total` is how many match the filters, whatever the page.",
      request: { params: OrgParam, query: InventoryQuery.extend(PageQuery.shape) },
      responses: { 200: json(pageOf(ManagedCertificate)), ...errors(400, 401, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const actor = await requireUser(c);
      const { role } = await authorize(actor, orgId);
      const query = c.req.valid("query");
      const now = clock();
      const where = and(visibleTo(role, actor, orgId), inventoryCondition(query, { now, agentsSilentSince: silentSince(now, agentOfflineAfterSeconds) }));
      const [total, rows] = await Promise.all([
        db.$count(managedCertificate, where),
        db
          .select()
          .from(managedCertificate)
          .where(where)
          .orderBy(asc(managedCertificate.createdAt), asc(managedCertificate.id))
          .limit(query.pageSize)
          .offset((query.page - 1) * query.pageSize),
      ]);
      return c.json({ items: await withState(rows), total, page: query.page, pageSize: query.pageSize }, 200);
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
                names: namesField("The DNS names to issue for."),
                keyAlgorithm: z.enum(KEY_ALGORITHMS),
                csr: csrField,
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

      const { names, csr } = await checkNamesAndCsr(body);

      const created = await unitOfWork.run(actor, async (tx, change) => {
        const [row] = await tx
          .insert(managedCertificate)
          .values({
            organizationId: orgId,
            names,
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
          detail: { names, keyAlgorithm: body.keyAlgorithm, keyCustody: "owner", environment: body.environment, csrFingerprint: csr.fingerprint },
        });
        // Whoever creates or proposes may name the Owners at the same time; each is audited as added (naming one twice adds it once).
        for (const ref of body.owners) await addOwner(tx, change, orgId, row!.id, ref);
        // A proposal is issued only once approved.
        if (!needsApproval) {
          const begun = await issuances.begin(tx, change, actor, row!, "issue");
          if ("refused" in begun) throw new Error(`the Issuance of a Managed Certificate just created was refused: ${begun.refused}`);
        }
        return row!;
      });
      return c.json((await withState([created]))[0]!, 201);
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
      const begun = await unitOfWork.run(actor, (tx, change) => issuances.begin(tx, change, actor, mc, "issue"));
      if ("refused" in begun) throw new HttpError(409, refusalMessage(begun.refused, "issue"));
      const [row] = await db.select().from(issuance).where(eq(issuance.id, begun.issuanceId));
      return c.json(toIssuance(row!), 202);
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
      const rows = await certificatesOf(orgId, mc.id);
      const revocations = await revocationsOf(db, rows.map((row) => row.id));
      return c.json({ items: rows.map((row) => toCertificate(row, revocations.get(row.id))) }, 200);
    },
  );
}
