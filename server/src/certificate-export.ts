// Downloads of a Managed Certificate's Certificates: the current one or any earlier one, as PEM, DER or PKCS#7 with
// the leaf alone, with its intermediates or with the root too (export.ts). A person signed in or an API key
// (api-keys.ts) may ask. A person, or a user's key, sees only what that person may see; an Organization's key sees the
// Organization's. There is no private key in any of it: the platform never has one (ADR 0002).
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import type { ApiKeys } from "./api-keys";
import type { Db } from "./db/client";
import { certificateIssuerOf, type Issuers } from "./issuer";
import { HttpError, errors } from "./http";
import { EXPORT_CHAINS, EXPORT_FORMATS, RootNotKnownError, encode, select } from "./export";
import type { ManagedCertificateReader } from "./managed-certificate-reader";
import { ManagedCertificateParams } from "./managed-certificate-reader";
import type { UnitOfWork } from "./unit-of-work";

const ExportQuery = z.object({
  format: z.enum(EXPORT_FORMATS).default("pem").openapi({ description: "`pem`, `der` (the certificates' DER encodings one after the other) or `p7b` (a PKCS#7 bundle, PEM-armored)." }),
  chain: z
    .enum(EXPORT_CHAINS)
    .default("with-intermediates")
    .openapi({ description: "`leaf` is the Certificate alone, `with-intermediates` adds the intermediates the CA served, `with-root` adds the root too." }),
});

const FILE_TYPES = ["application/x-pem-file", "application/pkix-cert", "application/x-pkcs7-certificates"];
const downloadResponses = {
  200: { description: "The Certificate in the format asked for", content: Object.fromEntries(FILE_TYPES.map((type) => [type, { schema: z.string() }])) },
  ...errors(400, 401, 403, 404, 422, 429),
};

export function registerCertificateExport(ctx: {
  app: OpenAPIHono;
  db: Db;
  apiKeys: ApiKeys;
  unitOfWork: UnitOfWork;
  reader: ManagedCertificateReader;
  issuers: Issuers;
}) {
  const { app, db, apiKeys, unitOfWork, reader, issuers } = ctx;

  /** `certificateId` is the Certificate asked for, or the current one when left out. */
  async function serve(c: any, orgId: string, id: string, certificateId: string | undefined, { format, chain }: z.infer<typeof ExportQuery>) {
    const caller = await apiKeys.callerOf(c);
    await apiKeys.authorizeCaller(caller, orgId, { managedCertificate: ["download"] });
    // A person sees what they may; an Organization's key, which is no one, sees the whole Organization.
    const mc = caller.user ? await reader.findReadable(caller.user, orgId, id) : await reader.findManagedCertificate(orgId, id);
    const certificates = await reader.certificatesOf(orgId, mc.id);
    // The newest is the current one. A Certificate that is not of this Managed Certificate, or not a Certificate, is not found.
    const wanted = certificateId ? certificates.find((row) => row.id === certificateId) : certificates[0];
    if (!wanted) throw new HttpError(404, certificateId ? "Certificate not found" : "no Certificate has been issued for this Managed Certificate yet");

    const encoded = await select(wanted.chainPem, chain, () => issuers.roots(db, orgId, certificateIssuerOf(wanted)))
      .then((certs) => encode(certs, format))
      .catch((err) => {
        if (err instanceof RootNotKnownError) throw new HttpError(422, err.message);
        throw err;
      });
    if (caller.apiKey) {
      const key = caller.apiKey;
      await unitOfWork.run(caller.user, (_tx, change) =>
        change.audit({
          organizationId: orgId,
          action: "api_key.used",
          target: { type: "managed_certificate", id: mc.id },
          detail: {
            apiKeyId: key.id,
            apiKeyName: key.name,
            apiKeyType: key.type,
            // An Organization's key acts as no one, so who made it is what leads back to a person.
            ...(key.createdBy && { createdBy: key.createdBy }),
            certificateId: wanted.id,
            format,
            chain,
          },
        }),
      );
    }

    const name = wanted.names[0]!.replace(/^\*\./, "wildcard.");
    const part = { leaf: ".leaf", "with-intermediates": "", "with-root": ".root" }[chain];
    const which = certificateId ? `.${wanted.fingerprint.slice(0, 8)}` : "";
    return c.body(encoded.body, 200, {
      "content-type": encoded.contentType,
      "content-disposition": `attachment; filename="${name}${which}${part}.${encoded.extension}"`,
    });
  }

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/certificate",
      tags: ["Managed Certificates"],
      summary: "Download the current Certificate",
      description:
        "As a person signed in, or with an API key in the `x-api-key` header. Without `format` and `chain` it is PEM with the intermediates the CA served. " +
        "`with-root` is refused (422) for a chain whose root the platform does not know. There is no PFX or JKS: the platform holds no private key.",
      request: { params: ManagedCertificateParams, query: ExportQuery },
      responses: downloadResponses,
    }),
    (c) => {
      const { orgId, id } = c.req.valid("param");
      return serve(c, orgId, id, undefined, c.req.valid("query"));
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/certificates/{certificateId}/download",
      tags: ["Managed Certificates"],
      summary: "Download any Certificate of the Managed Certificate, an earlier one included",
      description: "Like the current Certificate's download, for the Certificate with this id (see the list of Certificates).",
      request: { params: ManagedCertificateParams.extend({ certificateId: z.string().openapi({ param: { name: "certificateId", in: "path" } }) }), query: ExportQuery },
      responses: downloadResponses,
    }),
    (c) => {
      const { orgId, id, certificateId } = c.req.valid("param");
      return serve(c, orgId, id, certificateId, c.req.valid("query"));
    },
  );
}
