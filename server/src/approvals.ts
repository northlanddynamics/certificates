// The Approval queue and the decisions on proposed Managed Certificates (what Approval is: approval.ts); the decisions
// on name changes are in name-change-routes.ts.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import type { Context } from "hono";
import { and, asc, eq, isNull, ne } from "drizzle-orm";
import type { Authorizer } from "./authorization";
import type { Db } from "./db/client";
import { managedCertificate } from "./db/schema";
import { OrgParam, HttpError, errors, json } from "./http";
import { refusalMessage, type Issuances } from "./issuance";
import { ManagedCertificate, ManagedCertificateParams, type ManagedCertificateReader } from "./managed-certificate-reader";
import { PendingNameChange, pendingNameChangesOf, toPendingNameChange } from "./name-change";
import type { Actor, UnitOfWork } from "./unit-of-work";

const QueuedNameChange = PendingNameChange.extend({ managedCertificateId: z.string(), currentNames: z.array(z.string()) });

export function registerApprovals(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  issuances: Issuances;
  reader: ManagedCertificateReader;
}) {
  const { app, db, requireUser, authorize, unitOfWork, issuances, reader } = ctx;
  const { findManagedCertificate, withState } = reader;

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/approvals",
      tags: ["Approval"],
      summary: "The Approval queue: proposed Managed Certificates and name changes the caller may decide, the oldest first",
      description: "A proposal is decided by someone other than who proposed it, so the caller's own proposals are not in their queue.",
      request: { params: OrgParam },
      responses: {
        200: json(
          z.object({
            items: z.array(ManagedCertificate).openapi({ description: "Proposed Managed Certificates." }),
            nameChanges: z.array(QueuedNameChange).openapi({ description: "Name changes of existing Managed Certificates; each is decided at `.../managed-certificates/{managedCertificateId}/name-change`." }),
          }),
        ),
        ...errors(401, 403, 404),
      },
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
            // An archived proposal cannot be approved, so is not asked for.
            isNull(managedCertificate.archivedAt),
            ne(managedCertificate.proposedById, actor.id),
          ),
        )
        .orderBy(asc(managedCertificate.createdAt), asc(managedCertificate.id));
      const changes = await pendingNameChangesOf(db, orgId);
      const nameChanges = changes
        .filter(({ change }) => change.proposedById !== actor.id)
        .map(({ change, currentNames }) => ({ managedCertificateId: change.managedCertificateId, currentNames, ...toPendingNameChange(change) }));
      return c.json({ items: await withState(rows), nameChanges }, 200);
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

    await unitOfWork.run(actor, async (tx, change) => {
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
      if (decision === "approved") {
        const begun = await issuances.begin(tx, change, actor, mc, "issue");
        // Only an archive can refuse it now (archived since the proposal was made); the approval is rolled back with it.
        if ("refused" in begun) throw new HttpError(409, refusalMessage(begun.refused, "issue"));
      }
    });
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
}
