// The routes that act on a Managed Certificate's Renewal: its policy, a new CSR for the next Renewal, and renewing it now.
// An Owner may do each whatever their role, and so may an Organization Administrator; the scheduler's part is in
// renewal-scheduler.ts and what is due and when in renewal.ts.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, eq } from "drizzle-orm";
import { CsrError, parseCsr } from "./csr";
import type { Db } from "./db/client";
import { issuance, managedCertificate } from "./db/schema";
import { HttpError, errors, json } from "./http";
import { refusalMessage, type Issuances } from "./issuance";
import { Issuance, ManagedCertificate, ManagedCertificateParams, RenewalPolicy, toIssuance, type ManagedCertificateReader } from "./managed-certificate-reader";
import { sameNames } from "./names";
import type { Actor, UnitOfWork } from "./unit-of-work";

/** Far more than any CSR for the names a Managed Certificate may have (MAX_NAMES), so a larger body is refused before it is parsed. */
const MAX_CSR_LENGTH = 64_000;

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
      request: { params: ManagedCertificateParams, body: { content: { "application/json": { schema: z.object({ csr: z.string().min(1).max(MAX_CSR_LENGTH).openapi({ description: "PEM." }) }) } } } },
      responses: { 200: json(ManagedCertificate, "Stored"), ...errors(400, 401, 403, 404, 422) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const { csr: pem } = c.req.valid("json");
      const actor = await requireUser(c);
      const mc = await findAsOwnerOr(actor, orgId, id, { managedCertificate: ["replaceCsr"] }, "only an Owner or an Organization Administrator may upload a new CSR for a Managed Certificate");
      const csr = await parseCsr(pem).catch((err) => {
        if (err instanceof CsrError) throw new HttpError(400, err.message);
        throw err;
      });
      if (csr.keyAlgorithm !== mc.keyAlgorithm) {
        throw new HttpError(422, `the CSR's key is ${csr.keyAlgorithm}, but the Managed Certificate's key algorithm is ${mc.keyAlgorithm}`);
      }
      if (!sameNames(csr.names, mc.names)) {
        throw new HttpError(422, `the CSR must ask for exactly the names of the Managed Certificate (${mc.names.join(", ")}), but asks for ${csr.names.join(", ")}`);
      }
      await unitOfWork.run(actor, async (tx, change) => {
        await tx
          .update(managedCertificate)
          .set({ csr: pem })
          .where(and(eq(managedCertificate.id, mc.id), eq(managedCertificate.organizationId, orgId)));
        await change.audit({
          organizationId: orgId,
          action: "managed_certificate.csr_uploaded",
          target: { type: "managed_certificate", id: mc.id },
          detail: { csrFingerprint: csr.fingerprint, previousCsrFingerprint: (await parseCsr(mc.csr)).fingerprint },
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
        "Organization Administrators and the Managed Certificate's own Owners may.",
      request: { params: ManagedCertificateParams },
      responses: { 202: json(Issuance, "Started"), ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const actor = await requireUser(c);
      const mc = await findAsOwnerOr(actor, orgId, id, { managedCertificate: ["renew"] }, "only an Owner or an Organization Administrator may renew a Managed Certificate");
      const begun = await unitOfWork.run(actor, (tx, change) => issuances.begin(tx, change, actor, mc, "renewNow"));
      if ("refused" in begun) throw new HttpError(409, refusalMessage(begun.refused, "renewNow"));
      const [row] = await db.select().from(issuance).where(eq(issuance.id, begun.issuanceId));
      return c.json(toIssuance(row!), 202);
    },
  );
}
