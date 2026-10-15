// An Organization's Managed Certificates: created by an Organization Administrator with names, a key algorithm and a
// CSR (Key Custody: Owner), issued in the background (issuance.ts) and downloaded once a Certificate exists
// (certificate-export.ts). The platform never sees the private key (ADR 0002): the CSR proves the Owner holds it.
// Anyone else proposes one instead; it waits in the Approval queue (approval.ts) and its Issuance starts when an
// Approver approves it. It may have Owners (owners.ts), who with Approvers and Organization Administrators are the
// ones who see it (see managed-certificate-reader.ts). This module serves the inventory and the Managed Certificate itself.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, desc, eq } from "drizzle-orm";
import { silentSince } from "./agents";
import type { Authorizer } from "./authorization";
import { ACME_ENVIRONMENTS, type AcmeEnvironment } from "./certificate-authority";
import { certificateFacts } from "./certificate-facts";
import { KEY_ALGORITHMS } from "./csr";
import type { Db } from "./db/client";
import { issuance, managedCertificate } from "./db/schema";
import { HttpError, OrgParam, PageQuery, errors, json, pageOf } from "./http";
import { issuerColumns, issuerDetail, type Issuer } from "./issuer";
import { InventoryQuery, inventoryCondition } from "./inventory-filters";
import { refusalMessage, type Issuances } from "./issuance";
import { Certificate, CertificateFacts, Issuance, ManagedCertificate, ManagedCertificateParams, toCertificate, toIssuance, type ManagedCertificateReader } from "./managed-certificate-reader";
import { checkNamesAndCsr, csrField, namesField } from "./names-and-csr";
import { OwnerRef, addOwner } from "./owners";
import { roleCan } from "./permissions";
import { findPrivateCa } from "./private-ca";
import { revocationsOf } from "./revocation";
import type { Actor, UnitOfWork } from "./unit-of-work";

const MAX_OWNERS = 50;

/** The issuer a Managed Certificate is created or proposed with. */
const IssuerField = z
  .discriminatedUnion("kind", [
    z.object({ kind: z.literal("acme"), environment: z.enum(ACME_ENVIRONMENTS).default("staging") }),
    z.object({ kind: z.literal("private_ca"), privateCaId: z.string() }),
  ])
  .openapi({ description: "`acme`: through the Organization's ACME account in `environment`. `private_ca`: from one of the Organization's active Private CAs, with no DCV." });
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

  /** The issuer asked for: `issuer`, or the ACME kind in `environment`. A Private CA must be one of the Organization's, and active. */
  async function issuerAsked(orgId: string, body: { environment?: AcmeEnvironment; issuer?: z.infer<typeof IssuerField> }): Promise<Issuer> {
    if (body.issuer && body.environment) throw new HttpError(400, "give either `issuer` or `environment`, not both");
    const issuer = body.issuer ?? { kind: "acme", environment: body.environment ?? "staging" };
    if (issuer.kind === "private_ca") {
      const ca = await findPrivateCa(db, orgId, issuer.privateCaId);
      if (!ca) throw new HttpError(422, "the Organization has no such Private CA");
      if (ca.status !== "active") throw new HttpError(422, `the Private CA ${ca.name} is ${ca.status}, so it issues nothing`);
    }
    return issuer;
  }

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
        "Its issuer is an ACME CA (staging unless `environment` says otherwise) or, given `issuer`, one of the Organization's active Private CAs, which issues with no DCV.",
      request: {
        params: OrgParam,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                names: namesField("The DNS names to issue for."),
                keyAlgorithm: z.enum(KEY_ALGORITHMS),
                csr: csrField,
                environment: z.enum(ACME_ENVIRONMENTS).optional().openapi({ description: "Which of the Organization's ACME accounts to issue through, when `issuer` is not given; staging unless given." }),
                issuer: IssuerField.optional(),
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
      const issuer = await issuerAsked(orgId, body);

      const created = await unitOfWork.run(actor, async (tx, change) => {
        const [row] = await tx
          .insert(managedCertificate)
          .values({
            organizationId: orgId,
            names,
            keyAlgorithm: body.keyAlgorithm,
            keyCustody: "owner",
            ...issuerColumns(issuer),
            csr: body.csr,
            ...(needsApproval && { approvalStatus: "pending", proposedById: actor.id, proposedByEmail: actor.email }),
          })
          .returning();
        await change.audit({
          organizationId: orgId,
          action: needsApproval ? "managed_certificate.proposed" : "managed_certificate.created",
          target: { type: "managed_certificate", id: row!.id },
          detail: {
            names,
            keyAlgorithm: body.keyAlgorithm,
            keyCustody: "owner",
            ...(issuer.kind === "acme" && { environment: issuer.environment }),
            ...issuerDetail(issuer),
            csrFingerprint: csr.fingerprint,
          },
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
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/issuances",
      tags: ["Managed Certificates"],
      summary: "Every attempt to issue a Certificate for the Managed Certificate, the newest first",
      description: "Each with its kind (first issue, Renewal, Name Change), status and failure, so a failure a later attempt cleared can still be explained.",
      request: { params: ManagedCertificateParams },
      responses: { 200: json(z.object({ items: z.array(Issuance) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const mc = await findReadable(await requireUser(c), orgId, id);
      const rows = await db
        .select()
        .from(issuance)
        .where(and(eq(issuance.organizationId, orgId), eq(issuance.managedCertificateId, mc.id)))
        .orderBy(desc(issuance.startedAt), desc(issuance.createdAt));
      return c.json({ items: rows.map(toIssuance) }, 200);
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

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/certificates/{certificateId}",
      tags: ["Managed Certificates"],
      summary: "One Certificate of the Managed Certificate, with everything it says about itself",
      description:
        "Its subject and names, issuer, serial, signature algorithm, the chain the CA served (leaf first), the CA and ACME Account it was issued through, and its revocation if any. " +
        "Whoever may see the Managed Certificate may see its Certificates; a Certificate of another Managed Certificate is not found.",
      request: { params: ManagedCertificateParams.extend({ certificateId: z.string().openapi({ param: { name: "certificateId", in: "path" } }) }) },
      responses: { 200: json(CertificateFacts), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id, certificateId } = c.req.valid("param");
      const mc = await findReadable(await requireUser(c), orgId, id);
      const row = (await certificatesOf(orgId, mc.id)).find((r) => r.id === certificateId);
      if (!row) throw new HttpError(404, "Certificate not found");
      const revocations = await revocationsOf(db, [row.id]);
      return c.json({ ...toCertificate(row, revocations.get(row.id)), ...certificateFacts(row.chainPem), acmeAccount: row.acmeAccountId && row.environment ? { id: row.acmeAccountId, environment: row.environment } : null }, 200);
    },
  );
}
