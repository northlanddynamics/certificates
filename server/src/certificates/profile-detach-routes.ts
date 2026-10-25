// Detaching a Managed Certificate from the Certificate Profile it was made from: an Organization Administrator makes it
// an ordinary Managed Certificate. Its issuance settings were copied from the profile (ADR 0012) and stay as they are,
// as do its Owners; what it loses is what is checked live, so its Name Changes no longer keep to the profile's name
// rules, and the profile being disabled no longer stops it being issued: one whose Renewal was blocked is due again at
// once. There is no attaching one back (moving a Managed Certificate onto a profile is not something the platform does).
import { OpenAPIHono, createRoute } from "@hono/zod-openapi";
import { and, eq } from "drizzle-orm";
import type { Authorizer } from "../tenancy/authorization";
import { certificateProfile, managedCertificate } from "../platform/db/schema";
import { HttpError, errors, json } from "../platform/http";
import { ManagedCertificate, ManagedCertificateParams, type ManagedCertificateReader } from "./managed-certificate-reader";
import { lockManagedCertificate } from "./name-change";
import type { Actor, UnitOfWork } from "../platform/unit-of-work";

export function registerProfileDetachRoutes(ctx: { app: OpenAPIHono; requireUser(c: any): Promise<Actor>; authorize: Authorizer["authorize"]; unitOfWork: UnitOfWork; reader: ManagedCertificateReader }) {
  const { app, requireUser, authorize, unitOfWork, reader } = ctx;
  const { findManagedCertificate, withState } = reader;

  app.openapi(
    createRoute({
      method: "delete",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/profile",
      tags: ["Managed Certificates"],
      summary: "Detach the Managed Certificate from its Certificate Profile",
      description:
        "It becomes an ordinary Managed Certificate: its issuer, validity, key algorithm, Renewal Policy, names, Owners and Subscribers stay as they are, and only its link to the profile is cleared. " +
        "Its Name Changes are then no longer checked against the profile's name rules, and the profile being disabled no longer stops its Issuance: one whose Renewal was blocked renews on the scheduler's next pass. " +
        "It cannot be attached again. Refused with 409 for one made without a profile or already detached, for a Proposal (pending or rejected), which stays linked to its profile, and for one archived. Only Organization Administrators may.",
      request: { params: ManagedCertificateParams },
      responses: { 200: json(ManagedCertificate, "Detached"), ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { managedCertificate: ["detachProfile"] });
      await findManagedCertificate(orgId, id);
      await unitOfWork.run(actor, async (tx, change) => {
        // Under the lock, so an Issuance beginning (which reads its profile under the same lock) sees it detached or not at all.
        const mc = await lockManagedCertificate(tx, orgId, id);
        if (mc.certificateProfileId === null) throw new HttpError(409, "the Managed Certificate is not linked to a Certificate Profile");
        if (mc.archivedAt) throw new HttpError(409, "the Managed Certificate is archived, so it cannot be detached");
        if (mc.approvalStatus === "pending" || mc.approvalStatus === "rejected") throw new HttpError(409, "a Proposal stays linked to the Certificate Profile it came through, so it cannot be detached");
        const [profile] = await tx.select({ id: certificateProfile.id, name: certificateProfile.name }).from(certificateProfile).where(eq(certificateProfile.id, mc.certificateProfileId));
        // Its renewal-blocked mark goes with the link: without a profile, nothing blocks it.
        await tx
          .update(managedCertificate)
          .set({ certificateProfileId: null, renewalBlockedAt: null })
          .where(and(eq(managedCertificate.id, mc.id), eq(managedCertificate.organizationId, orgId)));
        await change.audit({ organizationId: orgId, action: "managed_certificate.profile_detached", target: { type: "managed_certificate", id: mc.id }, detail: { names: mc.names, certificateProfile: profile! } });
      });
      return c.json((await withState([await findManagedCertificate(orgId, id)]))[0]!, 200);
    },
  );
}
