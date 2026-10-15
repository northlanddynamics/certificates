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
import type { Issuer } from "./issuer";
import type { Kms } from "./kms";
import { constraintNamesOf, namesOutside, normalizePermittedNames, samePermittedNames, type PermittedNames } from "./permitted-names";
import { PRIVATE_CA_KINDS, PRIVATE_CA_STATUSES } from "./private-ca-kinds";
import type { Actor, UnitOfWork } from "./unit-of-work";

/** A Private CA's validity limits unless it sets its own: what browsers accept of a public CA's TLS Certificates. */
const DEFAULT_VALIDITY_DAYS = 397;
/** The longest any Private CA's TLS Certificates may be valid for. */
export const MAX_VALIDITY_DAYS = 3650;
const DAY_MS = 24 * 60 * 60 * 1000;

type PrivateCaRow = typeof privateCa.$inferSelect;

export const PrivateCaParams = OrgParam.extend({ id: z.string().openapi({ param: { name: "id", in: "path" } }) });

const MAX_RULES = 100;

/** A Private CA's permitted name rules, as they are given and shown. */
const PermittedNamesField = z
  .object({
    exact: z.array(z.string().max(255)).max(MAX_RULES).default([]).openapi({ description: "Names permitted exactly: a DNS name, or a wildcard (`*.` then a DNS name), which permits that wildcard alone." }),
    zones: z.array(z.string().max(255)).max(MAX_RULES).default([]).openapi({ description: "Zones: each permits the name and every name beneath it, wildcards included. Never a wildcard." }),
  })
  .openapi({ description: "The names the Private CA may issue for, normalised as names are (lower case, no trailing dot). No IP addresses." });

/** The rules given, normalised; a 400 when they cannot be rules. */
function permittedNamesAsked(rules: PermittedNames): PermittedNames {
  const normal = normalizePermittedNames(rules);
  if ("invalid" in normal) throw new HttpError(400, normal.invalid);
  return normal.rules;
}

/** A number of days a TLS Certificate is valid for. */
export const validityDaysField = z.number().int().min(1).max(MAX_VALIDITY_DAYS);

/** A Private CA's validity limits, as they are given and shown. */
const ValidityField = z
  .object({
    maximumDays: validityDaysField.openapi({ description: "The longest a Managed Certificate on it may choose." }),
    defaultDays: validityDaysField.openapi({ description: "What one that chooses none gets; at most `maximumDays`." }),
  })
  .openapi({ description: "How long the TLS Certificates it issues are valid for, in days. Never past its Issuing CA's end, whatever these say." });
type Validity = z.infer<typeof ValidityField>;

/** The limits given; a 422 when the default is above the maximum. */
function validityAsked(validity: Validity): Validity {
  if (validity.defaultDays > validity.maximumDays) throw new HttpError(422, `the default validity (${validity.defaultDays} days) is above the maximum (${validity.maximumDays} days)`);
  return validity;
}

/** Each of the limits `to` changes from `from`, as `{ from, to }`; none when it changes none. */
function validityChanges(from: Validity, to: Validity) {
  const changed = (["maximumDays", "defaultDays"] as const).filter((field) => from[field] !== to[field]);
  return changed.length === 0 ? undefined : Object.fromEntries(changed.map((field) => [field, { from: from[field], to: to[field] }]));
}

/** A Private CA's validity limits, from its row. */
const validityOf = (row: PrivateCaRow): Validity => ({ maximumDays: row.maxValidityDays, defaultDays: row.defaultValidityDays });

/** A Private CA's rules, from its row. */
export const permittedNamesOf = (row: PrivateCaRow): PermittedNames => ({ exact: row.permittedExactNames, zones: row.permittedZones });

export const PrivateCa = z.object({
  id: z.string(),
  name: z.string(),
  kind: z.enum(PRIVATE_CA_KINDS).openapi({ description: "`platform_root`: the platform made its root and its Issuing CA. `organization_root`: the Organization's own root signs its Issuing CA." }),
  status: z.enum(PRIVATE_CA_STATUSES).openapi({ description: "Only an `active` one issues." }),
  keyAlgorithm: z.enum(KEY_ALGORITHMS),
  subject: z.string().openapi({ description: "The Issuing CA's subject, as a distinguished name." }),
  notAfter: z.string().nullable().openapi({ description: "When its Issuing CA ends; none until it has a certificate." }),
  permittedNames: z
    .object({ exact: z.array(z.string()), zones: z.array(z.string()) })
    .openapi({ description: "Its permitted name rules: it issues for no other name. One made before there were rules has none, and issues for nothing until they are set." }),
  validity: ValidityField,
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
  permittedNames: permittedNamesOf(row),
  validity: validityOf(row),
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

/** Why the Private CA issues nothing now, or none when it issues. */
export const issuingRefusal = (ca: PrivateCaRow) => (ca.status === "active" && ca.issuingCertificatePem ? undefined : `the Private CA ${ca.name} is ${ca.status}, so it issues nothing`);

/** Why a Managed Certificate on the Private CA may not choose `validityDays`: it is above the maximum. None when it may, or chooses none. */
export const validityRefusal = (ca: PrivateCaRow, validityDays: number | null) =>
  validityDays !== null && validityDays > ca.maxValidityDays ? `a validity of ${validityDays} days is above the Private CA ${ca.name}'s maximum of ${ca.maxValidityDays} days` : undefined;

/** Why the Private CA may not issue for the names (normalised): those its permitted name rules do not permit. None when it may. */
export function namesRefusal(ca: PrivateCaRow, names: string[]) {
  const outside = namesOutside(permittedNamesOf(ca), names);
  return outside.length === 0 ? undefined : `${outside.join(", ")} ${outside.length === 1 ? "is" : "are"} outside the permitted names of the Private CA ${ca.name}`;
}

/** Why the issuer may not issue for the names (normalised): none for an ACME issuer, which checks control of them instead. */
export async function issuerNamesRefusal(db: Db | Tx, organizationId: string, issuer: Issuer, names: string[]) {
  if (issuer.kind !== "private_ca") return undefined;
  const ca = await findPrivateCa(db, organizationId, issuer.privateCaId);
  return ca ? namesRefusal(ca, names) : "the Organization has no such Private CA";
}

/** The chain of the Private CA, PEM: its Issuing CA, then the root when the platform has it. */
const chainOf = (row: PrivateCaRow) => [row.issuingCertificatePem, row.rootCertificatePem].filter((pem): pem is string => pem !== null).join("");

/** What the Private CA kind of issuer issues with: signing a CSR from a Private CA, and its root. */
export interface PrivateCas {
  /**
   * Signs a TLS server Certificate for the CSR and its names from the Organization's Private CA, valid from now for
   * `validityDays` (its default when none), but never longer than its maximum nor past its Issuing CA. Resolves with the chain (PEM, the Certificate then the
   * Issuing CA) and the Private CA's name. Throws an IssuanceFailure when the Private CA cannot issue, or not for one of
   * the names.
   */
  issueFrom(db: Db | Tx, organizationId: string, privateCaId: string, request: { csr: string; names: string[]; validityDays: number | null }): Promise<{ chainPem: string; name: string }>;
  /** The Private CA's root (PEM), when the platform has it. */
  rootsOf(db: Db | Tx, organizationId: string, privateCaId: string): Promise<string[]>;
}

export function createPrivateCas({ kms, clock }: { kms: Kms; clock: () => Date }): PrivateCas {
  return {
    async issueFrom(db, organizationId, privateCaId, { csr, names, validityDays }) {
      const ca = await findPrivateCa(db, organizationId, privateCaId);
      if (!ca) throw new IssuanceFailure("internal", "the Private CA is gone");
      const refusal = issuingRefusal(ca);
      if (refusal) throw new IssuanceFailure("ca_rejected", refusal);
      // A backstop: names outside the rules are refused when they are asked for, but the rules may have changed since.
      const outside = namesRefusal(ca, names);
      if (outside) throw new IssuanceFailure("name_not_permitted", outside);
      const issuing = new x509.X509Certificate(ca.issuingCertificatePem!);
      const notBefore = clock();
      if (issuing.notAfter <= notBefore) throw new IssuanceFailure("ca_rejected", `the Issuing CA of the Private CA ${ca.name} has ended`);
      // The maximum may have been lowered since the Managed Certificate chose its validity.
      const days = Math.min(validityDays ?? ca.defaultValidityDays, ca.maxValidityDays);
      const notAfter = new Date(Math.min(notBefore.getTime() + days * DAY_MS, issuing.notAfter.getTime()));
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
        "`validity` sets how long its TLS Certificates are valid for (397 days for both unless given); a default above the maximum is refused with 422. " +
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
                permittedNames: PermittedNamesField,
                validity: ValidityField.default({ maximumDays: DEFAULT_VALIDITY_DAYS, defaultDays: DEFAULT_VALIDITY_DAYS }),
              }),
            },
          },
        },
      },
      responses: { 201: json(PrivateCa, "Created, active"), ...errors(400, 401, 403, 404, 409, 422) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { privateCa: ["create"] });
      const subject = parseSubject(body.subject);
      if (!subject) throw new HttpError(400, "the subject must be a distinguished name with a common name, such as CN=Acme Internal TLS, O=Acme");
      const permittedNames = permittedNamesAsked(body.permittedNames);
      const validity = validityAsked(body.validity);

      const taken = () => new HttpError(409, `the Organization already has a Private CA named ${body.name}`);
      const [named] = await db
        .select({ id: privateCa.id })
        .from(privateCa)
        .where(and(eq(privateCa.organizationId, orgId), eq(privateCa.name, body.name)));
      if (named) throw taken();

      // The keys are made in the KMS first; a Private CA that is then not stored (one of the same name was made meanwhile) leaves only keys nothing refers to.
      const notBefore = clock();
      const notAfter = new Date(notBefore);
      notAfter.setUTCFullYear(notAfter.getUTCFullYear() + body.lifetimeYears);
      const rootKey = { key: await kms.createSigningKey(body.keyAlgorithm, orgId), context: orgId, algorithm: body.keyAlgorithm };
      const issuingKey = { key: await kms.createSigningKey(body.keyAlgorithm, orgId), context: orgId, algorithm: body.keyAlgorithm };
      const root = await makeRoot(kms, rootKey, { subject: rootSubjectOf(subject), notBefore, notAfter });
      const issuing = await makeIssuingCa(kms, { ...rootKey, certificate: root }, issuingKey, { subject, notBefore, notAfter, permittedDnsNames: constraintNamesOf(permittedNames) });

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
              permittedExactNames: permittedNames.exact,
              permittedZones: permittedNames.zones,
              maxValidityDays: validity.maximumDays,
              defaultValidityDays: validity.defaultDays,
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
              permittedNames,
              validity,
              root: { serial: root.serialNumber, fingerprint: Buffer.from(await root.getThumbprint("SHA-256")).toString("hex") },
              issuingCa: { serial: issuing.serialNumber, fingerprint: Buffer.from(await issuing.getThumbprint("SHA-256")).toString("hex") },
            },
          });
          return row!;
        });
        return c.json(toPrivateCa(row), 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw taken();
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
      method: "patch",
      path: "/api/organizations/{orgId}/private-cas/{id}",
      tags: ["Private CAs"],
      summary: "Change a Private CA's permitted name rules or validity limits",
      description:
        "What is given replaces what it had, and decides what it issues from then on: what it has already issued is unaffected. " +
        "A platform-made Issuing CA keeps the name constraints it was made with, which relying parties enforce; going beyond them needs a new Issuing CA. " +
        "A default validity above the maximum is refused with 422. A Managed Certificate that chose a validity above a lowered maximum gets the maximum. " +
        "Only Organization Administrators may.",
      request: {
        params: PrivateCaParams,
        body: { content: { "application/json": { schema: z.object({ permittedNames: PermittedNamesField.optional(), validity: ValidityField.optional() }) } } },
      },
      responses: { 200: json(PrivateCa, "Changed"), ...errors(400, 401, 403, 404, 422) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { privateCa: ["update"] });
      const permittedNames = body.permittedNames && permittedNamesAsked(body.permittedNames);
      const validity = body.validity && validityAsked(body.validity);
      if (!z.uuid().safeParse(id).success) throw new HttpError(404, "Private CA not found");
      const row = await unitOfWork.run(actor, async (tx, change) => {
        // Under the row's lock, so what the Audit Event says it changed from is what it replaced.
        const [ca] = await tx
          .select()
          .from(privateCa)
          .where(and(eq(privateCa.organizationId, orgId), eq(privateCa.id, id)))
          .for("update");
        if (!ca) throw new HttpError(404, "Private CA not found");
        const namesChanged = permittedNames && !samePermittedNames(permittedNamesOf(ca), permittedNames) ? { from: permittedNamesOf(ca), to: permittedNames } : undefined;
        const validityChanged = validity && validityChanges(validityOf(ca), validity);
        if (!namesChanged && !validityChanged) return ca;
        const [updated] = await tx
          .update(privateCa)
          .set({
            ...(namesChanged && { permittedExactNames: namesChanged.to.exact, permittedZones: namesChanged.to.zones }),
            ...(validityChanged && { maxValidityDays: validity.maximumDays, defaultValidityDays: validity.defaultDays }),
          })
          .where(eq(privateCa.id, ca.id))
          .returning();
        await change.audit({
          organizationId: orgId,
          action: "private_ca.updated",
          target: { type: "private_ca", id: ca.id },
          detail: { name: ca.name, ...(namesChanged && { permittedNames: namesChanged }), ...(validityChanged && { validity: validityChanged }) },
        });
        return updated!;
      });
      return c.json(toPrivateCa(row), 200);
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
