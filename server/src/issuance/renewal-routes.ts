// The routes that act on a Managed Certificate's Renewal: its policy, a new CSR for the next Renewal, and renewing it now.
// An Owner may do each whatever their role, and so may an Organization Administrator; the scheduler's part is in
// renewal-scheduler.ts and what is due and when in renewal.ts.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, eq } from "drizzle-orm";
import { parseCsr } from "../pki/csr";
import type { Db } from "../platform/db/client";
import { issuance, managedCertificate } from "../platform/db/schema";
import { HttpError, errors, json } from "../platform/http";
import { refusalError, type Issuances } from "./issuance";
import { Issuance, ManagedCertificate, ManagedCertificateParams, RenewalPolicy, toIssuance, type ManagedCertificateReader } from "../certificates/managed-certificate-reader";
import { checkNamesAndCsr, csrField } from "../certificates/names-and-csr";
import type { Actor, UnitOfWork } from "../platform/unit-of-work";

export function registerRenewalRoutes(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  unitOfWork: UnitOfWork;
  issuances: Issuances;
  reader: ManagedCertificateReader;
}) {
  const { app, db, requireUser, unitOfWork, issuances, reader } = ctx;
  const { findAsOwnerOr, findManagedCertificate, withState } = reader;

  app.openapi(
    createRoute({
      method: "put",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/renewal-policy",
      tags: ["Renewal"],
      summary: "Set the Renewal Policy: automatic or manual, and the days before expiry it is due",
      description: "Organization Administrators and the Managed Certificate's own Owners may. A manual Managed Certificate is renewed only when one of them starts it.",
      request: { params: ManagedCertificateParams, body: { content: { "application/json": { schema: RenewalPolicy } } } },
      responses: { 200: json(ManagedCertificate, "The Managed Certificate with its new policy"), ...errors(400, 401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const policy = c.req.valid("json");
      const actor = await requireUser(c);
      const mc = await findAsOwnerOr(actor, orgId, id, { managedCertificate: ["setRenewalPolicy"] }, "only an Owner or an Organization Administrator may set a Managed Certificate's Renewal Policy");
      await unitOfWork.run(actor, async (tx, change) => {
        await tx
          .update(managedCertificate)
          .set({ renewalMode: policy.mode, renewalDaysBeforeExpiry: policy.daysBeforeExpiry })
          .where(and(eq(managedCertificate.id, mc.id), eq(managedCertificate.organizationId, orgId)));
        await change.audit({
          organizationId: orgId,
          action: "managed_certificate.renewal_policy_changed",
          target: { type: "managed_certificate", id: mc.id },
          detail: { from: { mode: mc.renewalMode, daysBeforeExpiry: mc.renewalDaysBeforeExpiry }, to: policy },
        });
      });
      return c.json((await withState([await findManagedCertificate(orgId, mc.id)]))[0]!, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/csr",
      tags: ["Renewal"],
      summary: "Upload a new CSR, which the next Renewal uses",
      description:
        "For a key the Owner holds: a new CSR for the same key algorithm and exactly the same names. Nothing is issued now; every Renewal from the next on uses it. " +
        "Organization Administrators and the Managed Certificate's own Owners may.",
      request: { params: ManagedCertificateParams, body: { content: { "application/json": { schema: z.object({ csr: csrField }) } } } },
      responses: { 200: json(ManagedCertificate, "Stored"), ...errors(400, 401, 403, 404, 409, 422) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const { csr: pem } = c.req.valid("json");
      const actor = await requireUser(c);
      const mc = await findAsOwnerOr(actor, orgId, id, { managedCertificate: ["replaceCsr"] }, "only an Owner or an Organization Administrator may upload a new CSR for a Managed Certificate");
      if (mc.keyCustody === "agent" || mc.csr === null) throw new HttpError(409, "the key of this Managed Certificate is held by an Agent, which makes its CSR; one cannot be uploaded");
      const { csr } = await checkNamesAndCsr({ names: mc.names, csr: pem, keyAlgorithm: mc.keyAlgorithm });
      await unitOfWork.run(actor, async (tx, change) => {
        await tx
          .update(managedCertificate)
          .set({ csr: pem })
          .where(and(eq(managedCertificate.id, mc.id), eq(managedCertificate.organizationId, orgId)));
        await change.audit({
          organizationId: orgId,
          action: "managed_certificate.csr_uploaded",
          target: { type: "managed_certificate", id: mc.id },
          detail: { csrFingerprint: csr.fingerprint, previousCsrFingerprint: (await parseCsr(mc.csr!)).fingerprint },
        });
      });
      return c.json((await withState([await findManagedCertificate(orgId, mc.id)]))[0]!, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/renewals",
      tags: ["Renewal"],
      summary: "Renew now: start a Renewal at once, whatever the Renewal Policy",
      description:
        "Issues a new Certificate with the Managed Certificate's CSR, in the background. Only for one that has a Certificate, is approved and is not archived, and only one Issuance runs at a time. " +
        "Refused (422) while the Certificate Profile it was made from is disabled. Organization Administrators and the Managed Certificate's own Owners may.",
      request: { params: ManagedCertificateParams },
      responses: { 202: json(Issuance, "Started"), ...errors(401, 403, 404, 409, 422) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const actor = await requireUser(c);
      const mc = await findAsOwnerOr(actor, orgId, id, { managedCertificate: ["renew"] }, "only an Owner or an Organization Administrator may renew a Managed Certificate");
      const begun = await unitOfWork.run(actor, (tx, change) => issuances.begin(tx, change, actor, mc, "renewNow"));
      if ("refused" in begun) throw refusalError(begun, "renewNow");
      const [row] = await db.select().from(issuance).where(eq(issuance.id, begun.issuanceId));
      return c.json(toIssuance(row!), 202);
    },
  );
}
