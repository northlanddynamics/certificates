// An Organization's Private CAs: its own CAs, from which a Managed Certificate can be issued instead of from an ACME CA,
// with no DCV. An Organization Administrator creates one; with a platform-made root, the platform makes a self-signed
// root and an Issuing CA under it, each with its own key in the KMS (ADR 0007), and the Private CA is active at once.
// Everyone in the Organization may see them and download their chains. Issuing from one is the Private CA kind of
// issuer (issuer.ts), which signs through `issueFrom` here.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import * as x509 from "@peculiar/x509";
import { and, asc, eq } from "drizzle-orm";
import type { Authorizer } from "./authorization";
import { makeIssuingCa, makeRoot, makeTlsServer, parseSubject, rootSubjectOf, type Signer } from "./ca-certificates";
import { KEY_ALGORITHMS } from "./csr";
import type { Db, Tx } from "./db/client";
import { privateCa } from "./db/schema";
import { HttpError, OrgParam, errors, isUniqueViolation, json } from "./http";
import { IssuanceFailure } from "./issuance-failure";
import type { Kms } from "./kms";
import { PRIVATE_CA_KINDS, PRIVATE_CA_STATUSES } from "./private-ca-kinds";
import type { Actor, UnitOfWork } from "./unit-of-work";

/** How long a TLS Certificate from a Private CA is valid for, at most until its Issuing CA ends. */
const TLS_VALIDITY_DAYS = 397;
const DAY_MS = 24 * 60 * 60 * 1000;

type PrivateCaRow = typeof privateCa.$inferSelect;

export const PrivateCaParams = OrgParam.extend({ id: z.string().openapi({ param: { name: "id", in: "path" } }) });

export const PrivateCa = z.object({
  id: z.string(),
  name: z.string(),
  kind: z.enum(PRIVATE_CA_KINDS).openapi({ description: "`platform_root`: the platform made its root and its Issuing CA. `organization_root`: the Organization's own root signs its Issuing CA." }),
  status: z.enum(PRIVATE_CA_STATUSES).openapi({ description: "Only an `active` one issues." }),
  keyAlgorithm: z.enum(KEY_ALGORITHMS),
  subject: z.string().openapi({ description: "The Issuing CA's subject, as a distinguished name." }),
  notAfter: z.string().nullable().openapi({ description: "When its Issuing CA ends; none until it has a certificate." }),
  createdAt: z.string(),
});

const certificateOf = (pem: string | null) => (pem ? new x509.X509Certificate(pem) : null);

const toPrivateCa = (row: PrivateCaRow) => ({
  id: row.id,
  name: row.name,
  kind: row.kind,
  status: row.status,
  keyAlgorithm: row.keyAlgorithm,
  subject: row.subject,
  notAfter: certificateOf(row.issuingCertificatePem)?.notAfter.toISOString() ?? null,
  createdAt: row.createdAt.toISOString(),
});

/** The Organization's Private CA, or none (also for what cannot be an id). */
export async function findPrivateCa(db: Db | Tx, organizationId: string, id: string): Promise<PrivateCaRow | undefined> {
  if (!z.uuid().safeParse(id).success) return undefined;
  const [row] = await db
    .select()
    .from(privateCa)
    .where(and(eq(privateCa.organizationId, organizationId), eq(privateCa.id, id)));
  return row;
}

/** The chain of the Private CA, PEM: its Issuing CA, then the root when the platform has it. */
const chainOf = (row: PrivateCaRow) => [row.issuingCertificatePem, row.rootCertificatePem].filter((pem): pem is string => pem !== null).join("");

/** What the Private CA kind of issuer issues with: signing a CSR from a Private CA, and its root. */
export interface PrivateCas {
  /**
   * Signs a TLS server Certificate for the CSR and its names from the Organization's Private CA, valid from now for
   * at most TLS_VALIDITY_DAYS and never past its Issuing CA. Resolves with the chain (PEM, the Certificate then the
   * Issuing CA) and the Private CA's name. Throws an IssuanceFailure when the Private CA cannot issue.
   */
  issueFrom(db: Db | Tx, organizationId: string, privateCaId: string, request: { csr: string; names: string[] }): Promise<{ chainPem: string; name: string }>;
  /** The Private CA's root (PEM), when the platform has it. */
  rootsOf(db: Db | Tx, organizationId: string, privateCaId: string): Promise<string[]>;
}

export function createPrivateCas({ kms, clock }: { kms: Kms; clock: () => Date }): PrivateCas {
  return {
    async issueFrom(db, organizationId, privateCaId, { csr, names }) {
      const ca = await findPrivateCa(db, organizationId, privateCaId);
      if (!ca) throw new IssuanceFailure("internal", "the Private CA is gone");
      if (ca.status !== "active" || !ca.issuingCertificatePem) throw new IssuanceFailure("ca_rejected", `the Private CA ${ca.name} is ${ca.status}, so it issues nothing`);
      const issuing = new x509.X509Certificate(ca.issuingCertificatePem);
      const notBefore = clock();
      if (issuing.notAfter <= notBefore) throw new IssuanceFailure("ca_rejected", `the Issuing CA of the Private CA ${ca.name} has ended`);
      const notAfter = new Date(Math.min(notBefore.getTime() + TLS_VALIDITY_DAYS * DAY_MS, issuing.notAfter.getTime()));
      const signer: Signer = { key: ca.issuingKey, context: organizationId, algorithm: ca.keyAlgorithm, certificate: issuing };
      const leaf = await makeTlsServer(kms, signer, { csr, names, notBefore, notAfter });
      return { chainPem: `${leaf.toString("pem")}\n${ca.issuingCertificatePem}`, name: ca.name };
    },
    async rootsOf(db, organizationId, privateCaId) {
      const ca = await findPrivateCa(db, organizationId, privateCaId);
      return ca?.rootCertificatePem ? [ca.rootCertificatePem] : [];
    },
  };
}

const MAX_LIFETIME_YEARS = 30;

export function registerPrivateCas(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  kms: Kms;
  clock: () => Date;
}) {
  const { app, db, requireUser, authorize, unitOfWork, kms, clock } = ctx;

  async function findReadable(actor: Actor, orgId: string, id: string) {
    await authorize(actor, orgId, { privateCa: ["read"] });
    const row = await findPrivateCa(db, orgId, id);
    if (!row) throw new HttpError(404, "Private CA not found");
    return row;
  }

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/private-cas",
      tags: ["Private CAs"],
      summary: "The Organization's Private CAs, oldest first",
      description: "Everyone in the Organization may ask, so as to propose a Managed Certificate against the right one.",
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(PrivateCa) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { privateCa: ["read"] });
      const rows = await db.select().from(privateCa).where(eq(privateCa.organizationId, orgId)).orderBy(asc(privateCa.createdAt), asc(privateCa.id));
      return c.json({ items: rows.map(toPrivateCa) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/private-cas",
      tags: ["Private CAs"],
      summary: "Create a Private CA with a platform-made root and Issuing CA",
      description:
        "The platform makes two keys in the KMS, of the algorithm given: a self-signed root's, and an Issuing CA's, which the root signs and which signs Certificates (pathLen 0). " +
        "`subject` is the Issuing CA's distinguished name and must have a common name; the root's is the same with \" Root\" added to the common name. Both are valid from now for `lifetimeYears`. " +
        "The Private CA is active at once. Only Organization Administrators may.",
      request: {
        params: OrgParam,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                name: z.string().trim().min(1).max(100),
                subject: z.string().min(1).max(1000).openapi({ example: "CN=Acme Internal TLS, O=Acme" }),
                keyAlgorithm: z.enum(KEY_ALGORITHMS).default("ecdsa-p256"),
                lifetimeYears: z.number().int().min(1).max(MAX_LIFETIME_YEARS).default(10),
              }),
            },
          },
        },
      },
      responses: { 201: json(PrivateCa, "Created, active"), ...errors(400, 401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { privateCa: ["create"] });
      const subject = parseSubject(body.subject);
      if (!subject) throw new HttpError(400, "the subject must be a distinguished name with a common name, such as CN=Acme Internal TLS, O=Acme");

      // The keys are made in the KMS first; a Private CA that is then not stored leaves only keys nothing refers to.
      const notBefore = clock();
      const notAfter = new Date(notBefore);
      notAfter.setUTCFullYear(notAfter.getUTCFullYear() + body.lifetimeYears);
      const rootKey = { key: await kms.createSigningKey(body.keyAlgorithm, orgId), context: orgId, algorithm: body.keyAlgorithm };
      const issuingKey = { key: await kms.createSigningKey(body.keyAlgorithm, orgId), context: orgId, algorithm: body.keyAlgorithm };
      const root = await makeRoot(kms, rootKey, { subject: rootSubjectOf(subject), notBefore, notAfter });
      const issuing = await makeIssuingCa(kms, { ...rootKey, certificate: root }, issuingKey, { subject, notBefore, notAfter });

      try {
        const row = await unitOfWork.run(actor, async (tx, change) => {
          const [row] = await tx
            .insert(privateCa)
            .values({
              organizationId: orgId,
              name: body.name,
              kind: "platform_root",
              status: "active",
              keyAlgorithm: body.keyAlgorithm,
              subject: subject.toString(),
              rootCertificatePem: root.toString("pem"),
              rootKey: rootKey.key,
              issuingCertificatePem: issuing.toString("pem"),
              issuingKey: issuingKey.key,
            })
            .returning();
          await change.audit({
            organizationId: orgId,
            action: "private_ca.created",
            target: { type: "private_ca", id: row!.id },
            detail: {
              name: body.name,
              kind: "platform_root",
              keyAlgorithm: body.keyAlgorithm,
              subject: subject.toString(),
              notAfter: notAfter.toISOString(),
              root: { serial: root.serialNumber, fingerprint: Buffer.from(await root.getThumbprint("SHA-256")).toString("hex") },
              issuingCa: { serial: issuing.serialNumber, fingerprint: Buffer.from(await issuing.getThumbprint("SHA-256")).toString("hex") },
            },
          });
          return row!;
        });
        return c.json(toPrivateCa(row), 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw new HttpError(409, `the Organization already has a Private CA named ${body.name}`);
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/private-cas/{id}",
      tags: ["Private CAs"],
      request: { params: PrivateCaParams },
      responses: { 200: json(PrivateCa), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      return c.json(toPrivateCa(await findReadable(await requireUser(c), orgId, id)), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/private-cas/{id}/chain",
      tags: ["Private CAs"],
      summary: "Download the Private CA's chain: its Issuing CA, then its root",
      description: "PEM. Distribute the root to whatever must trust the Certificates the Private CA issues.",
      request: { params: PrivateCaParams },
      responses: { 200: { description: "The chain, PEM", content: { "application/x-pem-file": { schema: z.string() } } }, ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const row = await findReadable(await requireUser(c), orgId, id);
      const fileName = row.name.replace(/[^A-Za-z0-9._-]+/g, "-").toLowerCase() || "private-ca";
      return c.body(chainOf(row), 200, { "content-type": "application/x-pem-file", "content-disposition": `attachment; filename="${fileName}.chain.pem"` });
    },
  );
}
