// The Archive of a Managed Certificate: soft deletion by an Organization Administrator. It stops issuing, renewing and
// deploying, discards the name change waiting for Approval and ends a Renewal waiting for an Agent's key, but the Managed Certificate, its Certificates and its
// history stay, and nothing is revoked (revocation is its own act: revocation-routes.ts).
import { OpenAPIHono, createRoute } from "@hono/zod-openapi";
import { and, eq } from "drizzle-orm";
import type { Authorizer } from "./authorization";
import { issuance, managedCertificate } from "./db/schema";
import { HttpError, errors, json } from "./http";
import type { Issuances } from "./issuance";
import { ManagedCertificate, ManagedCertificateParams, type ManagedCertificateReader } from "./managed-certificate-reader";
import { discardPendingNameChange, lockManagedCertificate } from "./name-change";
import type { Actor, UnitOfWork } from "./unit-of-work";

export function registerArchiveRoutes(ctx: {
  app: OpenAPIHono;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  issuances: Issuances;
  reader: ManagedCertificateReader;
}) {
  const { app, requireUser, authorize, unitOfWork, issuances, reader } = ctx;
  const { findManagedCertificate, withState } = reader;

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/archive",
      tags: ["Archive"],
      summary: "Archive the Managed Certificate: it stops issuing, renewing and deploying, and is kept with its Certificates and history",
      description:
        "Organization Administrators only, not even the Managed Certificate's Owners. Archiving revokes nothing: its Certificates stay valid until they end or are revoked. " +
        "A name change waiting for Approval is discarded, and a Renewal waiting for its Agent to make the key is ended. Archived Managed Certificates are listed only under the inventory's `archived` filter, and are never deleted.",
      request: { params: ManagedCertificateParams },
      responses: { 200: json(ManagedCertificate, "Archived"), ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { managedCertificate: ["archive"] });
      await findManagedCertificate(orgId, id);
      await unitOfWork.run(actor, async (tx, change) => {
        // Under the lock, so an Issuance, a name change or a decision racing this one has finished, and none begins after.
        const mc = await lockManagedCertificate(tx, orgId, id);
        if (mc.archivedAt) throw new HttpError(409, "the Managed Certificate is already archived");
        await tx
          .update(managedCertificate)
          .set({ archivedAt: change.occurredAt })
          .where(and(eq(managedCertificate.id, mc.id), eq(managedCertificate.organizationId, orgId)));
        await change.audit({ organizationId: orgId, action: "managed_certificate.archived", target: { type: "managed_certificate", id: mc.id }, detail: { names: mc.names } });
        await discardPendingNameChange(tx, change, mc, "the Managed Certificate was archived");
        // A Renewal that has its key runs to its end; one still waiting for the key (abandon ends only such) would wait for nothing.
        const [running] = await tx.select({ id: issuance.id }).from(issuance).where(and(eq(issuance.managedCertificateId, mc.id), eq(issuance.status, "running")));
        if (running) await issuances.abandon(tx, change, running.id, { code: "archived", message: "the Managed Certificate was archived before its Agent made the new key" });
      });
      return c.json((await withState([await findManagedCertificate(orgId, id)]))[0]!, 200);
    },
  );
}
