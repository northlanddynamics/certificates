// An Organization's Managed Certificates: created by an Organization Administrator with names, a key algorithm and a
// CSR (Key Custody: Owner), issued in the background (issuance.ts), and downloaded once a Certificate exists. The
// platform never sees the private key (ADR 0002): the CSR proves the Owner holds it.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, desc, eq, inArray } from "drizzle-orm";
import type { Authorizer } from "./authorization";
import { ACME_ENVIRONMENTS } from "./certificate-authority";
import { CsrError, KEY_ALGORITHMS, parseCsr } from "./csr";
import type { Db } from "./db/client";
import { certificate, issuance, managedCertificate } from "./db/schema";
import { HttpError, OrgParam, errors, isUniqueViolation, json } from "./http";
import { ISSUANCE_FAILURE_CODES } from "./issuance-failure";
import type { Issuances } from "./issuance";
import { MAX_NAMES, normalizeNames, sameNames } from "./names";
import { roleCan } from "./permissions";
import type { Actor, UnitOfWork } from "./unit-of-work";

const ManagedCertificateParams = OrgParam.extend({ id: z.string().openapi({ param: { name: "id", in: "path" } }) });

const Issuance = z.object({
  id: z.string(),
  status: z.enum(["running", "succeeded", "failed"]),
  startedAt: z.string(),
  finishedAt: z.string().nullable(),
  failure: z
    .object({ code: z.enum(ISSUANCE_FAILURE_CODES), message: z.string() })
    .nullable()
    .openapi({ description: "Why it failed: which step, and what the DNS Provider or the CA said." }),
  certificateId: z.string().nullable(),
});

const Certificate = z.object({
  id: z.string(),
  fingerprint: z.string().openapi({ description: "SHA-256 of the certificate, lower-case hex." }),
  serial: z.string(),
  notBefore: z.string(),
  notAfter: z.string(),
  names: z.array(z.string()),
  ca: z.string(),
  environment: z.enum(ACME_ENVIRONMENTS),
  acmeAccountId: z.string(),
  issuedAt: z.string(),
});

const ManagedCertificate = z.object({
  id: z.string(),
  names: z.array(z.string()),
  keyAlgorithm: z.enum(KEY_ALGORITHMS),
  keyCustody: z.enum(["owner"]),
  environment: z.enum(ACME_ENVIRONMENTS),
  createdAt: z.string(),
  issuance: Issuance.nullable().openapi({ description: "The latest attempt to issue a Certificate." }),
  currentCertificate: Certificate.nullable().openapi({ description: "The most recently issued Certificate." }),
});

type ManagedCertificateRow = typeof managedCertificate.$inferSelect;
const toIssuance = (row: typeof issuance.$inferSelect) => ({
  id: row.id,
  status: row.status,
  startedAt: row.startedAt.toISOString(),
  finishedAt: row.finishedAt?.toISOString() ?? null,
  failure: row.failureCode && row.failureMessage ? { code: row.failureCode, message: row.failureMessage } : null,
  certificateId: row.certificateId,
});
const toCertificate = (row: typeof certificate.$inferSelect) => ({
  id: row.id,
  fingerprint: row.fingerprint,
  serial: row.serial,
  notBefore: row.notBefore.toISOString(),
  notAfter: row.notAfter.toISOString(),
  names: row.names,
  ca: row.ca,
  environment: row.environment,
  acmeAccountId: row.acmeAccountId,
  issuedAt: row.issuedAt.toISOString(),
});

export function registerManagedCertificates(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  issuances: Issuances;
}) {
  const { app, db, requireUser, authorize, unitOfWork, issuances } = ctx;

  async function findManagedCertificate(orgId: string, id: string) {
    // Not a UUID can't be a Managed Certificate; asking Postgres would only raise a type error.
    const [row] = z.uuid().safeParse(id).success
      ? await db.select().from(managedCertificate).where(and(eq(managedCertificate.organizationId, orgId), eq(managedCertificate.id, id)))
      : [];
    if (!row) throw new HttpError(404, "Managed Certificate not found");
    return row;
  }

  /** The Managed Certificate's Certificates, the most recently stored first: the first is the current one. */
  const certificatesOf = (orgId: string, managedCertificateId: string) =>
    db
      .select()
      .from(certificate)
      .where(and(eq(certificate.organizationId, orgId), eq(certificate.managedCertificateId, managedCertificateId)))
      .orderBy(desc(certificate.createdAt), desc(certificate.id));

  /** The Managed Certificates as the API shows them: each with its latest Issuance and its current Certificate. */
  async function withState(rows: ManagedCertificateRow[]) {
    if (rows.length === 0) return [];
    const ids = rows.map((r) => r.id);
    const latestIssuances = await db
      .selectDistinctOn([issuance.managedCertificateId])
      .from(issuance)
      .where(inArray(issuance.managedCertificateId, ids))
      .orderBy(issuance.managedCertificateId, desc(issuance.createdAt), desc(issuance.id));
    const currentCertificates = await db
      .selectDistinctOn([certificate.managedCertificateId])
      .from(certificate)
      .where(inArray(certificate.managedCertificateId, ids))
      .orderBy(certificate.managedCertificateId, desc(certificate.createdAt), desc(certificate.id));
    return rows.map((row) => {
      const latest = latestIssuances.find((i) => i.managedCertificateId === row.id);
      const current = currentCertificates.find((c) => c.managedCertificateId === row.id);
      return {
        id: row.id,
        names: row.names,
        keyAlgorithm: row.keyAlgorithm,
        keyCustody: row.keyCustody,
        environment: row.environment,
        createdAt: row.createdAt.toISOString(),
        issuance: latest ? toIssuance(latest) : null,
        currentCertificate: current ? toCertificate(current) : null,
      };
    });
  }

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates",
      tags: ["Managed Certificates"],
      summary: "The Managed Certificates the caller may see",
      description: "Everyone in the Organization may ask; those who may not read Managed Certificates are shown none.",
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(ManagedCertificate) })), ...errors(401, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const { role } = await authorize(await requireUser(c), orgId);
      if (!roleCan(role, { managedCertificate: ["read"] })) return c.json({ items: [] }, 200);
      const rows = await db
        .select()
        .from(managedCertificate)
        .where(eq(managedCertificate.organizationId, orgId))
        .orderBy(asc(managedCertificate.createdAt), asc(managedCertificate.id));
      return c.json({ items: await withState(rows) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates",
      tags: ["Managed Certificates"],
      summary: "Create a Managed Certificate and start issuing its first Certificate",
      description:
        "The Owner keeps the private key and submits a CSR for it. The CSR must be for the key algorithm given and ask for exactly the names given. " +
        "Issuance runs in the background: the response shows it running, and the Managed Certificate shows the Certificate or the cause of the failure when it ends. " +
        "Staging is the default environment.",
      request: {
        params: OrgParam,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                names: z.array(z.string()).min(1).max(MAX_NAMES).openapi({ description: "DNS names; a wildcard is `*.` and a name." }),
                keyAlgorithm: z.enum(KEY_ALGORITHMS),
                csr: z.string().min(1).openapi({ description: "PEM." }),
                environment: z.enum(ACME_ENVIRONMENTS).default("staging").openapi({ description: "Which of the Organization's ACME accounts to issue through." }),
              }),
            },
          },
        },
      },
      responses: { 201: json(ManagedCertificate, "Created, with its first Issuance running"), ...errors(400, 401, 403, 404, 422) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { managedCertificate: ["create"] });

      const normalized = normalizeNames(body.names);
      if ("invalid" in normalized) throw new HttpError(400, `"${normalized.invalid}" cannot be a name to issue for`);
      const csr = await parseCsr(body.csr).catch((err) => {
        if (err instanceof CsrError) throw new HttpError(400, err.message);
        throw err;
      });
      if (csr.keyAlgorithm !== body.keyAlgorithm) {
        throw new HttpError(422, `the CSR's key is ${csr.keyAlgorithm}, but the Managed Certificate's key algorithm is ${body.keyAlgorithm}`);
      }
      if (!sameNames(csr.names, normalized.names)) {
        throw new HttpError(422, `the CSR must ask for exactly the names being issued (${normalized.names.join(", ")}), but asks for ${csr.names.join(", ")}`);
      }

      const created = await unitOfWork.run(actor, async (tx, change) => {
        const [row] = await tx
          .insert(managedCertificate)
          .values({
            organizationId: orgId,
            names: normalized.names,
            keyAlgorithm: body.keyAlgorithm,
            keyCustody: "owner",
            environment: body.environment,
            csr: body.csr,
          })
          .returning();
        await change.audit({
          organizationId: orgId,
          action: "managed_certificate.created",
          target: { type: "managed_certificate", id: row!.id },
          detail: { names: normalized.names, keyAlgorithm: body.keyAlgorithm, keyCustody: "owner", environment: body.environment, csrFingerprint: csr.fingerprint },
        });
        return { row: row!, issuanceId: await issuances.begin(tx, change, actor, row!) };
      });
      issuances.start(created.issuanceId);
      return c.json((await withState([created.row]))[0]!, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates/{id}",
      tags: ["Managed Certificates"],
      request: { params: ManagedCertificateParams },
      responses: { 200: json(ManagedCertificate), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { managedCertificate: ["read"] });
      return c.json((await withState([await findManagedCertificate(orgId, id)]))[0]!, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/issuances",
      tags: ["Managed Certificates"],
      summary: "Try issuing a Certificate again",
      description: "For when the last Issuance failed. It reuses the Managed Certificate's CSR. Only one runs at a time.",
      request: { params: ManagedCertificateParams },
      responses: { 202: json(Issuance, "Started"), ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { managedCertificate: ["issue"] });
      const mc = await findManagedCertificate(orgId, id);
      let issuanceId: string;
      try {
        issuanceId = await unitOfWork.run(actor, (tx, change) => issuances.begin(tx, change, actor, mc));
      } catch (err) {
        if (isUniqueViolation(err)) throw new HttpError(409, "an Issuance of this Managed Certificate is already running");
        throw err;
      }
      issuances.start(issuanceId);
      const [row] = await db.select().from(issuance).where(eq(issuance.id, issuanceId));
      return c.json(toIssuance(row!), 202);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/certificates",
      tags: ["Managed Certificates"],
      summary: "Every Certificate issued for the Managed Certificate, the newest first",
      request: { params: ManagedCertificateParams },
      responses: { 200: json(z.object({ items: z.array(Certificate) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { managedCertificate: ["read"] });
      const mc = await findManagedCertificate(orgId, id);
      return c.json({ items: (await certificatesOf(orgId, mc.id)).map(toCertificate) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/certificate.pem",
      tags: ["Managed Certificates"],
      summary: "Download the current Certificate as PEM, with its chain",
      description: "The Certificate followed by the intermediates the CA served. There is no private key in it: the platform never has one.",
      request: { params: ManagedCertificateParams },
      responses: {
        200: { description: "PEM", content: { "application/x-pem-file": { schema: z.string() } } },
        ...errors(401, 403, 404),
      },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { managedCertificate: ["read"] });
      const mc = await findManagedCertificate(orgId, id);
      const [current] = await certificatesOf(orgId, mc.id);
      if (!current) throw new HttpError(404, "no Certificate has been issued for this Managed Certificate yet");
      const filename = `${mc.names[0]!.replace(/^\*\./, "wildcard.")}.pem`;
      return c.body(current.chainPem, 200, {
        "content-type": "application/x-pem-file",
        "content-disposition": `attachment; filename="${filename}"`,
      });
    },
  );
}
