// Revoking a Certificate: an Owner of its Managed Certificate or an Organization Administrator tells the CA to distrust
// it, with an RFC 5280 reason. Only a person's request does: archiving, name changes and removing users revoke nothing,
// and nothing else is done to the Managed Certificate (a replacement is issued by Renewal, when asked for).
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, eq } from "drizzle-orm";
import { CertificateAuthorityError } from "./certificate-authority";
import type { Db } from "./db/client";
import { certificate, certificateRevocation } from "./db/schema";
import { HttpError, errors, json } from "./http";
import { certificateIssuerOf, type Issuers } from "./issuer";
import { Certificate, ManagedCertificateParams, toCertificate, type ManagedCertificateReader } from "./managed-certificate-reader";
import { lockManagedCertificate } from "./name-change";
import { RevocationReasonName, revocationsOf } from "./revocation";
import type { Actor, UnitOfWork } from "./unit-of-work";

const CertificateParams = ManagedCertificateParams.extend({ certificateId: z.string().openapi({ param: { name: "certificateId", in: "path" } }) });

export function registerRevocationRoutes(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  unitOfWork: UnitOfWork;
  reader: ManagedCertificateReader;
  issuers: Issuers;
}) {
  const { app, db, requireUser, unitOfWork, reader, issuers } = ctx;
  const { findAsOwnerOr } = reader;

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/certificates/{certificateId}/revocation",
      tags: ["Revocation"],
      summary: "Revoke a Certificate with an RFC 5280 reason: the CA is told, and the Certificate shows as revoked",
      description:
        "Organization Administrators and the Managed Certificate's own Owners may, even once it is archived. The CA is told first, and the revocation is recorded and audited only once it has revoked the Certificate; " +
        "if it refuses or cannot be reached nothing is recorded and the request may be made again. A revoked Certificate cannot be revoked again. Revoking does not issue a replacement: renew the Managed Certificate (with a new CSR, if the key is compromised) when one is needed.",
      request: {
        params: CertificateParams,
        body: { content: { "application/json": { schema: z.object({ reason: RevocationReasonName }) } } },
      },
      responses: { 200: json(Certificate, "Revoked"), ...errors(400, 401, 403, 404, 409, 422, 502) },
    }),
    async (c) => {
      const { orgId, id, certificateId } = c.req.valid("param");
      const { reason } = c.req.valid("json");
      const actor = await requireUser(c);
      const mc = await findAsOwnerOr(actor, orgId, id, { managedCertificate: ["revoke"] }, "only an Owner or an Organization Administrator may revoke a Managed Certificate's Certificates");
      // Not a UUID can't be a Certificate; asking Postgres would only raise a type error.
      const [issued] = z.uuid().safeParse(certificateId).success
        ? await db.select().from(certificate).where(and(eq(certificate.id, certificateId), eq(certificate.managedCertificateId, mc.id), eq(certificate.organizationId, orgId)))
        : [];
      if (!issued) throw new HttpError(404, "Certificate not found");

      const revoked = await unitOfWork.run(actor, async (tx, change) => {
        // Under the Managed Certificate's lock, so two who revoke the same Certificate at once take turns and the second finds it revoked.
        await lockManagedCertificate(tx, orgId, mc.id);
        if ((await revocationsOf(tx, [issued.id])).has(issued.id)) throw new HttpError(409, "the Certificate is already revoked");
        try {
          await issuers.revoke(tx, orgId, certificateIssuerOf(issued), { certificate: issued.chainPem, reason });
        } catch (err) {
          if (!(err instanceof CertificateAuthorityError)) throw err;
          // A CA that says no is the caller's to fix, 422; one that does not answer is 502.
          throw new HttpError(err.kind === "unreachable" ? 502 : 422, err.message);
        }
        const [row] = await tx
          .insert(certificateRevocation)
          .values({ certificateId: issued.id, organizationId: orgId, reason, revokedById: actor.id, revokedByEmail: actor.email, revokedAt: change.occurredAt })
          .returning();
        await change.audit({
          organizationId: orgId,
          action: "certificate.revoked",
          target: { type: "managed_certificate", id: mc.id },
          detail: { certificateId: issued.id, fingerprint: issued.fingerprint, serial: issued.serial, reason },
        });
        return row!;
      });
      return c.json(toCertificate(issued, revoked), 200);
    },
  );
}
