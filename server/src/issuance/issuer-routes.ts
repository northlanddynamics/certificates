// Repointing a Managed Certificate: an Organization Administrator moves it to another Issuing CA, under the same root or
// another, which is how an Issuing CA is rolled over (private-ca.ts). It needs no Approval: the names it is issued for
// stay as they were approved, and must be within the new Issuing CA's permitted name rules. It never moves a Managed
// Certificate between kinds of issuer. Its next Issuance, by Renewal or asked for, comes from the new Issuing CA; the
// Certificates it has stay as they were, on the CRL of the Issuing CA that signed them. Also here: which key algorithms
// each kind of CA takes, so that no client need hold a copy of the rule.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, eq } from "drizzle-orm";
import type { Authorizer } from "../tenancy/authorization";
import { managedCertificate } from "../platform/db/schema";
import { HttpError, errors, json } from "../platform/http";
import { issuerColumns, issuerOf } from "./issuer";
import { ManagedCertificate, ManagedCertificateParams, type ManagedCertificateReader } from "../certificates/managed-certificate-reader";
import { lockManagedCertificate, pendingNameChanges } from "../certificates/name-change";
import { IssuerField, issuerRefusal } from "../private-ca/private-ca";
import { KEY_ALGORITHMS, SIGNING_KEY_ALGORITHMS, certificateKeyAlgorithmsOn } from "../pki/csr";
import type { Actor, UnitOfWork } from "../platform/unit-of-work";

export function registerIssuerRoutes(ctx: { app: OpenAPIHono; requireUser(c: any): Promise<Actor>; authorize: Authorizer["authorize"]; unitOfWork: UnitOfWork; reader: ManagedCertificateReader }) {
  const { app, requireUser, authorize, unitOfWork, reader } = ctx;
  const { findManagedCertificate, withState } = reader;

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/key-algorithms",
      tags: ["Managed Certificates"],
      summary: "The key algorithms, and which ones each kind of CA takes",
      description:
        "`keyAlgorithms`: every key algorithm a Managed Certificate may have. `privateCaKeyAlgorithms`: what a Private CA's own keys may be under each kind of root (never ML-DSA-44, too weak for a CA key). " +
        "`acmeKeyAlgorithms`: what a Managed Certificate on an ACME CA may have. On a Private CA, it is its `certificateKeyAlgorithms`: a chain is all ML-DSA or none of it. Anyone signed in may ask.",
      responses: {
        200: json(
          z.object({
            keyAlgorithms: z.array(z.enum(KEY_ALGORITHMS)),
            privateCaKeyAlgorithms: z.object({ platform_root: z.array(z.enum(KEY_ALGORITHMS)), organization_root: z.array(z.enum(KEY_ALGORITHMS)) }),
            acmeKeyAlgorithms: z.array(z.enum(KEY_ALGORITHMS)),
          }),
        ),
        ...errors(401),
      },
    }),
    async (c) => {
      await requireUser(c);
      return c.json(
        {
          keyAlgorithms: [...KEY_ALGORITHMS],
          privateCaKeyAlgorithms: { platform_root: [...SIGNING_KEY_ALGORITHMS], organization_root: [...SIGNING_KEY_ALGORITHMS] },
          acmeKeyAlgorithms: [...certificateKeyAlgorithmsOn()],
        },
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/issuer",
      tags: ["Managed Certificates"],
      summary: "Repoint the Managed Certificate to another Issuing CA",
      description:
        "Only for a Managed Certificate issued from a Private CA, and only to another Issuing CA (422 for a move between kinds of issuer, such as to or from an ACME CA). " +
        "The Issuing CA, of any of the Organization's Private CAs, must issue (active, under an active root), permit its names (and those of a name change pending Approval), allow the validity it chose, and take its key algorithm (ML-DSA keys only on an ML-DSA Private CA, and only those there); 422 otherwise. " +
        "No Approval is needed, and nothing is issued: its next Issuance, a Renewal or one asked for, comes from the new Issuing CA, and the Certificates it has are unchanged. " +
        "Repointing it to the Issuing CA it is on already changes nothing. Refused with 409 for one archived or rejected. Only Organization Administrators may.",
      request: { params: ManagedCertificateParams, body: { content: { "application/json": { schema: z.object({ issuer: IssuerField }) } } } },
      responses: { 200: json(ManagedCertificate, "Repointed"), ...errors(400, 401, 403, 404, 409, 422) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const { issuer: to } = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { managedCertificate: ["changeIssuer"] });
      await findManagedCertificate(orgId, id);
      await unitOfWork.run(actor, async (tx, change) => {
        // Under the lock, so an Issuance, a name change or an archive racing this one has finished, and none begins after on the old issuer.
        const mc = await lockManagedCertificate(tx, orgId, id);
        if (mc.archivedAt) throw new HttpError(409, "the Managed Certificate is archived, so it cannot be repointed");
        if (mc.approvalStatus === "rejected") throw new HttpError(409, "the Managed Certificate is rejected, so it cannot be repointed");
        const from = issuerOf(mc);
        if (from.kind !== "private_ca" || to.kind !== "private_ca") throw new HttpError(422, "only a Managed Certificate issued from a Private CA can be repointed, and only to another Issuing CA");
        if (from.issuingCaId === to.issuingCaId) return;
        const pending = (await pendingNameChanges(tx, [mc.id])).get(mc.id);
        for (const asked of [{ names: mc.names, validityDays: mc.validityDays }, ...(pending ? [{ names: pending.names, validityDays: pending.validityDays }] : [])]) {
          const refused = await issuerRefusal(tx, orgId, to, { ...asked, keyAlgorithm: mc.keyAlgorithm });
          if (refused) throw new HttpError(refused.status, refused.message);
        }
        await tx
          .update(managedCertificate)
          .set(issuerColumns(to))
          .where(and(eq(managedCertificate.id, mc.id), eq(managedCertificate.organizationId, orgId)));
        await change.audit({ organizationId: orgId, action: "managed_certificate.issuer_changed", target: { type: "managed_certificate", id: mc.id }, detail: { names: mc.names, from, to } });
      });
      return c.json((await withState([await findManagedCertificate(orgId, id)]))[0]!, 200);
    },
  );
}
