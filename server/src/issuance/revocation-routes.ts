// Revoking a Certificate: an Owner of its Managed Certificate or an Organization Administrator tells the CA to distrust
// it, with an RFC 5280 reason. Only a person's request does: archiving, name changes and removing users revoke nothing,
// and nothing else is done to the Managed Certificate (a replacement is issued by Renewal, when asked for).
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, eq } from "drizzle-orm";
import { CertificateAuthorityError } from "./acme/certificate-authority";
import type { Db } from "../platform/db/client";
import { certificate } from "../platform/db/schema";
import { HttpError, errors, json } from "../platform/http";
import { certificateIssuerOf } from "./issuer";
import { Certificate, ManagedCertificateParams, toCertificate, type ManagedCertificateReader } from "../certificates/managed-certificate-reader";
import { lockManagedCertificate } from "../certificates/name-change";
import { RevocationReasonName, revocationsOf } from "./revocation";
import { awaiting, revocationRequestsOf, type Revocations } from "./revocations";
import type { Actor, UnitOfWork } from "../platform/unit-of-work";

const CertificateParams = ManagedCertificateParams.extend({ certificateId: z.string().openapi({ param: { name: "certificateId", in: "path" } }) });

export function registerRevocationRoutes(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  unitOfWork: UnitOfWork;
  reader: ManagedCertificateReader;
  revocations: Revocations;
}) {
  const { app, db, requireUser, unitOfWork, reader, revocations } = ctx;
  const { findAsOwnerOr } = reader;

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/certificates/{certificateId}/revocation",
      tags: ["Revocation"],
      summary: "Revoke a Certificate with an RFC 5280 reason: the CA is told, and the Certificate shows as revoked",
      description:
        "Organization Administrators and the Managed Certificate's own Owners may, even once it is archived. The revocation is recorded and audited only once the CA has revoked the Certificate; " +
        "a Private CA revokes it by reissuing its CRL in the same change, so it is on the CRL the moment the request succeeds. " +
        "An ACME CA takes `unspecified`, `keyCompromise`, `superseded` and `cessationOfOperation`; a Private CA those and `affiliationChanged` and `privilegeWithdrawn`; another reason is refused with 422. " +
        "if it refuses or cannot be reached nothing is recorded and the request may be made again. " +
        "A CA reached through an Agent confirms later: the request is answered 202, the Certificate shows its `revocationRequest` as `pending`, and the revocation is recorded and audited once the CA confirms it, or the request shows as `failed` with the cause when the CA refuses, cannot be reached or does not answer by its deadline, and may be made again. " +
        "A revoked Certificate, or one whose revocation is pending, cannot be revoked again (409). Revoking does not issue a replacement: renew the Managed Certificate (with a new CSR, if the key is compromised) when one is needed.",
      request: {
        params: CertificateParams,
        body: { content: { "application/json": { schema: z.object({ reason: RevocationReasonName }) } } },
      },
      responses: {
        200: json(Certificate, "Revoked"),
        202: json(Certificate, "Requested: the CA confirms it later, and until then the Certificate shows its `revocationRequest`"),
        ...errors(400, 401, 403, 404, 409, 422, 502),
      },
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

      const outcome = await unitOfWork.run(actor, async (tx, change) => {
        // Under the Managed Certificate's lock, so two who revoke the same Certificate at once take turns and the second finds it revoked, or its revocation requested.
        await lockManagedCertificate(tx, orgId, mc.id);
        if ((await revocationsOf(tx, [issued.id])).has(issued.id)) throw new HttpError(409, "the Certificate is already revoked");
        if (awaiting((await revocationRequestsOf(tx, [issued.id])).get(issued.id))) throw new HttpError(409, "the Certificate's revocation is already requested, and waits for its CA to confirm it");
        try {
          const [answer] = await revocations.revoke(tx, change, orgId, certificateIssuerOf(issued), [{ target: { kind: "certificate", certificate: issued, requestedBy: actor }, reason }]);
          return answer!;
        } catch (err) {
          if (!(err instanceof CertificateAuthorityError)) throw err;
          // A CA that says no is the caller's to fix, 422; one that does not answer is 502.
          throw new HttpError(err.kind === "unreachable" ? 502 : 422, err.message);
        }
      });
      const revocation = (await revocationsOf(db, [issued.id])).get(issued.id);
      const request = (await revocationRequestsOf(db, [issued.id])).get(issued.id);
      return c.json(toCertificate(issued, revocation, request), outcome === "revoked" ? 200 : 202);
    },
  );
}
