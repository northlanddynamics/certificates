// The routes that change a Managed Certificate's names (what a name change is: name-change.ts). An Owner proposes the
// new names with a CSR for them and an Approver decides; an Organization Administrator's change applies as it is made.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import type { Context } from "hono";
import { and, eq } from "drizzle-orm";
import type { Authorizer } from "../tenancy/authorization";
import { managedCertificate, nameChange } from "../platform/db/schema";
import { HttpError, errors, json } from "../platform/http";
import type { Notifications } from "../notifications/notifications";
import type { Issuances } from "../issuance/issuance";
import { ManagedCertificate, ManagedCertificateParams, type ManagedCertificateReader } from "./managed-certificate-reader";
import { sameNames } from "../pki/names";
import { checkNamesAndCsr, csrField, namesField } from "./names-and-csr";
import { applyNames, endPendingNameChange, lockManagedCertificate, pendingNameChanges, refusalToChangeNames, validityChangeDetail } from "./name-change";
import { issuerOf } from "../issuance/issuer";
import { roleCan } from "../tenancy/permissions";
import { issuerRefusal, validityDaysField } from "../private-ca/private-ca";
import type { Actor, UnitOfWork } from "../platform/unit-of-work";

export function registerNameChangeRoutes(ctx: {
  app: OpenAPIHono;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  issuances: Issuances;
  reader: ManagedCertificateReader;
  notifications: Notifications;
}) {
  const { app, requireUser, authorize, unitOfWork, issuances, reader, notifications } = ctx;
  const { findAsOwnerOr, findManagedCertificate, findReadable, withState } = reader;

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/name-change",
      tags: ["Name changes"],
      summary: "Change the Managed Certificate's names, with a CSR for the new names",
      description:
        "For a Managed Certificate issued from a Private CA, the new names must be within its Issuing CA's permitted name rules, and the change may give it another `validityDays` " +
        "(null for the Issuing CA's default; when not given, it keeps its own), at most the Issuing CA's maximum (422 above it, and 400 for one from an ACME CA). " +
        "An Organization Administrator's change applies at once and an Issuance of the new names begins. An Owner's waits for an Approver to approve it, " +
        "and until then Renewal continues with the last approved names and CSR; at most one is pending at a time. The CSR must be for the key algorithm of the Managed Certificate and ask for exactly the new names.",
      request: {
        params: ManagedCertificateParams,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                names: namesField("All the names the Managed Certificate is to have."),
                csr: csrField,
                validityDays: validityDaysField.nullable().optional().openapi({ description: "For a Private CA issuer only: the validity it is to have, in days; null for the default. It keeps its own when not given." }),
              }),
            },
          },
        },
      },
      responses: { 201: json(ManagedCertificate, "Applied, or proposed and awaiting Approval"), ...errors(400, 401, 403, 404, 409, 422) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      const found = await findAsOwnerOr(actor, orgId, id, { managedCertificate: ["proposeNameChange"] }, "only an Owner or an Organization Administrator may change a Managed Certificate's names");
      const { role } = await authorize(actor, orgId);
      // Who may change names outright needs no Approval; an Owner who may not proposes the change instead.
      const needsApproval = !roleCan(role, { managedCertificate: ["changeNames"] });

      const { names, csr } = await checkNamesAndCsr({ ...body, keyAlgorithm: found.keyAlgorithm });

      await unitOfWork.run(actor, async (tx, change) => {
        // Under the lock, so what is decided here is what is there: a change, an archive or an Approval racing this one has finished.
        const mc = await lockManagedCertificate(tx, orgId, id);
        const refusal = refusalToChangeNames(mc);
        if (refusal) throw new HttpError(409, refusal);
        if ((await pendingNameChanges(tx, [mc.id])).size > 0) throw new HttpError(409, "a name change of this Managed Certificate is already pending Approval; wait for it to be decided");
        if (sameNames(names, mc.names)) {
          throw new HttpError(422, "the Managed Certificate already has the same names; to replace only its CSR, upload a new one");
        }
        // Only a validity asked for is checked: one it keeps is clipped at Issuance to a maximum lowered since.
        const refused = await issuerRefusal(tx, orgId, issuerOf(mc), { names, validityDays: body.validityDays ?? null, keyAlgorithm: csr.keyAlgorithm });
        if (refused) throw new HttpError(refused.status, refused.message);
        const validityDays = body.validityDays === undefined ? mc.validityDays : body.validityDays;
        const detail = { from: mc.names, to: names, ...validityChangeDetail(mc.validityDays, validityDays), csrFingerprint: csr.fingerprint };
        if (needsApproval) {
          await tx.insert(nameChange).values({
            organizationId: orgId,
            managedCertificateId: mc.id,
            status: "pending",
            names: names,
            csr: body.csr,
            validityDays,
            proposedById: actor.id,
            proposedByEmail: actor.email,
          });
          await change.audit({ organizationId: orgId, action: "name_change.proposed", target: { type: "managed_certificate", id: mc.id }, detail });
        } else {
          await change.audit({ organizationId: orgId, action: "managed_certificate.names_changed", target: { type: "managed_certificate", id: mc.id }, detail });
          await applyNames(tx, change, actor, issuances, mc, { names: names, csr: body.csr, validityDays });
        }
      });
      return c.json((await withState([await findManagedCertificate(orgId, id)]))[0]!, 201);
    },
  );

  /**
   * Records an Approver's decision on the pending name change. Whoever proposed it cannot decide it, and a decision is
   * final: it is made under the Managed Certificate's lock on a change still pending, so of two decisions made at once
   * one wins and the other finds nothing to decide. Approving gives the Managed Certificate the new names and CSR and
   * begins an Issuance of them on the same transaction.
   */
  async function decide(c: Context, orgId: string, id: string, decision: "approved" | "rejected", reason: string | null) {
    const actor = await requireUser(c);
    await authorize(actor, orgId, { approval: ["decide"] });
    await findManagedCertificate(orgId, id);
    await unitOfWork.run(actor, async (tx, change) => {
      const mc = await lockManagedCertificate(tx, orgId, id);
      const pending = (await pendingNameChanges(tx, [mc.id])).get(mc.id);
      if (!pending) throw new HttpError(409, "this Managed Certificate has no name change awaiting Approval");
      if (pending.proposedById === actor.id) throw new HttpError(403, "a name change must be decided by someone other than who proposed it");
      if (decision === "approved") {
        const refusal = refusalToChangeNames(mc);
        if (refusal) throw new HttpError(409, refusal);
      }
      const decided = await tx
        .update(nameChange)
        .set({ status: decision, decidedById: actor.id, decidedByEmail: actor.email, decidedAt: change.occurredAt, decisionReason: reason })
        .where(and(eq(nameChange.id, pending.id), eq(nameChange.status, "pending")))
        .returning({ id: nameChange.id });
      // Ended by someone else after it was read (a discard by the platform does not take the Managed Certificate's lock).
      if (decided.length === 0) throw new HttpError(409, "this Managed Certificate has no name change awaiting Approval");
      await change.audit({
        organizationId: orgId,
        action: decision === "approved" ? "name_change.approved" : "name_change.rejected",
        target: { type: "managed_certificate", id: mc.id },
        detail: { from: mc.names, to: pending.names, ...validityChangeDetail(mc.validityDays, pending.validityDays), reason, proposedBy: pending.proposedByEmail },
      });
      await notifications.notify(tx, change, mc, { event: "approval.decided", detail: { of: "name_change", decision, reason, decidedBy: actor.email, names: pending.names } });
      if (decision === "approved") await applyNames(tx, change, actor, issuances, mc, { names: pending.names, csr: pending.csr, validityDays: pending.validityDays });
    });
    return (await withState([await findManagedCertificate(orgId, id)]))[0]!;
  }

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/name-change/withdraw",
      tags: ["Name changes"],
      summary: "Withdraw the pending name change you proposed; the Managed Certificate is otherwise unaffected",
      description:
        "Only whoever proposed it may; anyone else who should not see it go ahead asks an Approver to reject it. " +
        "A change is also discarded, with the reason in its history, when its proposer leaves the Organization or its Managed Certificate is archived.",
      request: { params: ManagedCertificateParams },
      responses: { 200: json(ManagedCertificate, "Withdrawn"), ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const actor = await requireUser(c);
      await findReadable(actor, orgId, id);
      await unitOfWork.run(actor, async (tx, change) => {
        const mc = await lockManagedCertificate(tx, orgId, id);
        const pending = (await pendingNameChanges(tx, [mc.id])).get(mc.id);
        if (!pending) throw new HttpError(409, "this Managed Certificate has no name change awaiting Approval");
        if (pending.proposedById !== actor.id) throw new HttpError(403, "only whoever proposed a name change may withdraw it");
        if (!(await endPendingNameChange(tx, change, pending, mc.names, { status: "withdrawn", actor }))) {
          throw new HttpError(409, "this Managed Certificate has no name change awaiting Approval");
        }
      });
      return c.json((await withState([await findManagedCertificate(orgId, id)]))[0]!, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/name-change/approve",
      tags: ["Name changes"],
      summary: "Approve the pending name change: the Managed Certificate takes the new names and CSR, and an Issuance of them begins",
      description: "Nobody decides their own proposal, and a decision is final.",
      request: {
        params: ManagedCertificateParams,
        body: { content: { "application/json": { schema: z.object({ reason: z.string().trim().max(1000).optional() }) } } },
      },
      responses: { 200: json(ManagedCertificate, "Approved, with the Issuance of the new names running"), ...errors(400, 401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      return c.json(await decide(c, orgId, id, "approved", c.req.valid("json").reason || null), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/name-change/reject",
      tags: ["Name changes"],
      summary: "Reject the pending name change, with the reason the proposer will see; the Managed Certificate is otherwise unaffected",
      request: {
        params: ManagedCertificateParams,
        body: { content: { "application/json": { schema: z.object({ reason: z.string().trim().min(1).max(1000) }) } } },
      },
      responses: { 200: json(ManagedCertificate, "Rejected and discarded"), ...errors(400, 401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      return c.json(await decide(c, orgId, id, "rejected", c.req.valid("json").reason), 200);
    },
  );
}
