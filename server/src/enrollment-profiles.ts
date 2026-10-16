// An Organization's Enrollment Profiles: templates under which devices obtain Device Certificates in bulk from one of its
// Private CAs' Issuing CAs, with no Approval and no Owners. A profile fixes the Issuing CA, the validity, key usage and
// extended key usages of what it issues and the device keys it certifies, and names the Enrollment Validator
// (enrollment-validator.ts) that decides each request: its kind, its settings and its write-only secret. A profile whose
// validator does not vouch for names carries name rules (name-rules.ts) instead. Devices enroll at its SCEP URL (scep.ts), under an opaque public
// id. The platform makes each profile an RA: a software RSA key, held as a Secret, and a certificate the Issuing CA signs
// for it, which open SCEP requests and sign SCEP responses (ADR 0007). Only Organization Administrators see or change them.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import * as x509 from "@peculiar/x509";
import { and, asc, eq } from "drizzle-orm";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import type { Authorizer } from "./authorization";
import type { Db } from "./db/client";
import { enrollmentProfile } from "./db/schema";
import {
  DEFAULT_DEVICE_EXTENDED_KEY_USAGES,
  DEFAULT_DEVICE_KEY_USAGES,
  DEFAULT_DEVICE_VALIDITY_DAYS,
  DEVICE_EXTENDED_KEY_USAGE_NAMES,
  DEVICE_KEY_TYPES,
  DEVICE_KEY_USAGES,
  MAX_DEVICE_VALIDITY_DAYS,
} from "./enrollment-profile-kinds";
import { describeValidatorError, type EnrollmentValidators } from "./enrollment-validator";
import type { EnrollmentValidatorRuns } from "./enrollment-validators";
import { HttpError, OrgParam, errors, isUniqueViolation, json } from "./http";
import { IssuanceFailure } from "./issuance-failure";
import { NameRules } from "./name-rules";
import { findIssuingCa, issuingRefusal, type PrivateCas } from "./private-ca";
import type { Secrets } from "./secrets";
import type { Actor, UnitOfWork } from "./unit-of-work";

type ProfileRow = typeof enrollmentProfile.$inferSelect;

/** How long an RA certificate is valid for, in days, though never past its Issuing CA's end. */
const RA_VALIDITY_DAYS = 730;

const ProfileParams = OrgParam.extend({ id: z.string().openapi({ param: { name: "id", in: "path" } }) });

const nonEmptyUnique = <T extends z.ZodType>(item: T) =>
  z
    .array(item)
    .min(1)
    .refine((values) => new Set(values).size === values.length, "no value may be given twice");

export const EnrollmentProfile = z.object({
  id: z.string(),
  name: z.string(),
  publicId: z.string().openapi({ description: "The opaque id its SCEP URL is under, which says nothing else about it or the Organization." }),
  scepUrl: z.string().openapi({ description: "Where devices enroll over SCEP: paste it into the device management platform's SCEP profile." }),
  issuingCaId: z.string(),
  privateCaId: z.string(),
  validityDays: z.number().int().openapi({ description: "How long its Device Certificates are valid for, though never past the Issuing CA's end." }),
  keyUsage: z.array(z.enum(DEVICE_KEY_USAGES)),
  extendedKeyUsage: z.array(z.enum(DEVICE_EXTENDED_KEY_USAGE_NAMES)),
  allowedKeyTypes: z.array(z.enum(DEVICE_KEY_TYPES)).openapi({ description: "The device keys it certifies; a request for another is refused." }),
  validator: z
    .object({ kind: z.string(), settings: z.record(z.string(), z.unknown()), hasSecret: z.boolean().openapi({ description: "Whether it holds a secret, which is never shown." }) })
    .openapi({ description: "The Enrollment Validator that decides each request." }),
  nameRules: NameRules.nullable().openapi({ description: "What a device's names must keep; none when the validator vouches for names." }),
  raCertificate: z.object({ subject: z.string(), serial: z.string(), notAfter: z.string() }).openapi({ description: "The RA certificate devices encrypt their requests to, which signs the platform's answers." }),
  createdAt: z.string(),
});

/** The SCEP URL of the profile with this public id, on the platform's base URL. */
export const scepUrlOf = (baseURL: string, publicId: string) => `${baseURL.replace(/\/+$/, "")}/scep/${publicId}`;

function toProfile(row: ProfileRow, privateCaId: string, baseURL: string): z.infer<typeof EnrollmentProfile> {
  const ra = new x509.X509Certificate(row.raCertificatePem);
  return {
    id: row.id,
    name: row.name,
    publicId: row.publicId,
    scepUrl: scepUrlOf(baseURL, row.publicId),
    issuingCaId: row.issuingCaId,
    privateCaId,
    validityDays: row.validityDays,
    keyUsage: row.keyUsage,
    extendedKeyUsage: row.extendedKeyUsage,
    allowedKeyTypes: row.allowedKeyTypes,
    validator: { kind: row.validatorKind, settings: row.validatorSettings, hasSecret: row.validatorSecretId !== null },
    nameRules: row.nameRules,
    raCertificate: { subject: ra.subject, serial: ra.serialNumber.toUpperCase(), notAfter: ra.notAfter.toISOString() },
    createdAt: row.createdAt.toISOString(),
  };
}

const isId = (id: string) => z.uuid().safeParse(id).success;

/** What is wrong with `input` as seen by `schema`, as a 400 that quotes none of it (it may be a secret). */
function refuse<T>(what: string, schema: z.ZodType<T>, input: unknown): T {
  const parsed = schema.safeParse(input);
  if (parsed.success) return parsed.data;
  throw new HttpError(400, `${what}: ${parsed.error.issues.map((i) => [...i.path, i.message].join(": ")).join("; ")}`);
}

export function registerEnrollmentProfiles(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  secrets: Secrets;
  privateCas: PrivateCas;
  /** The validator kinds the platform runs, and how it runs a profile's. */
  kinds: EnrollmentValidators;
  validators: EnrollmentValidatorRuns;
  /** Where the platform is served, which SCEP URLs are under. */
  baseURL: string;
}) {
  const { app, db, requireUser, authorize, unitOfWork, secrets, privateCas, kinds, validators, baseURL } = ctx;

  /** The Organization's profile with its Issuing CA and Private CA; a 404 when it has none such. */
  async function findProfile(orgId: string, id: string) {
    const notFound = () => new HttpError(404, "Enrollment Profile not found");
    if (!isId(id)) throw notFound();
    const [row] = await db
      .select()
      .from(enrollmentProfile)
      .where(and(eq(enrollmentProfile.organizationId, orgId), eq(enrollmentProfile.id, id)));
    if (!row) throw notFound();
    const of = await findIssuingCa(db, orgId, row.issuingCaId);
    return { row, of: of! };
  }

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/enrollment-validator-kinds",
      tags: ["Enrollment Profiles"],
      summary: "The Enrollment Validator kinds an Enrollment Profile can name",
      description:
        "Those the platform runs. With none, no Enrollment Profile can be created. `vouchesForNames` says whether it checks the names a device asks for; a profile whose validator does not must carry name rules. " +
        "`takesSecret` whether it is configured with a secret. Only Organization Administrators may ask.",
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(z.object({ kind: z.string(), vouchesForNames: z.boolean(), takesSecret: z.boolean() })) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { enrollmentProfile: ["read"] });
      return c.json({ items: Object.entries(kinds).map(([kind, of]) => ({ kind, vouchesForNames: of.vouchesForNames, takesSecret: of.secret !== undefined })) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/enrollment-profiles",
      tags: ["Enrollment Profiles"],
      summary: "The Organization's Enrollment Profiles, oldest first",
      description: "Only Organization Administrators may ask.",
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(EnrollmentProfile) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { enrollmentProfile: ["read"] });
      const rows = await db.select().from(enrollmentProfile).where(eq(enrollmentProfile.organizationId, orgId)).orderBy(asc(enrollmentProfile.createdAt), asc(enrollmentProfile.id));
      const items = await Promise.all(rows.map(async (row) => toProfile(row, (await findIssuingCa(db, orgId, row.issuingCaId))!.ca.id, baseURL)));
      return c.json({ items }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/enrollment-profiles",
      tags: ["Enrollment Profiles"],
      summary: "Create an Enrollment Profile on an Issuing CA",
      description:
        "`issuingCaId` must be an active Issuing CA of one of the Organization's Private CAs, under an active root (422 otherwise). `validator.kind` must be one the platform runs (`.../enrollment-validator-kinds`; 422 otherwise), with the `settings` its kind takes and, when it takes one, its `secret`, which is stored as a Secret and never shown (400 otherwise). " +
        "A profile whose validator does not vouch for names must have `nameRules`, and one whose validator does must have none (422 otherwise). " +
        "Device Certificates are valid for `validityDays` (365 unless given), never past the Issuing CA's end, with `keyUsage` (digitalSignature and keyEncipherment unless given) and `extendedKeyUsage` (clientAuth unless given), " +
        "and the subject and subject alternative names of the device's CSR; nothing else a CSR asks for. A device key not in `allowedKeyTypes` (every RSA size unless given) is refused. " +
        "The platform makes the profile's RA: a software RSA key, held as a Secret, and a certificate the Issuing CA signs for it. The profile is given an opaque public id, under which its SCEP URL is. " +
        "Names are unique within the Organization (409). Only Organization Administrators may.",
      request: {
        params: OrgParam,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                name: z.string().trim().min(1).max(100),
                issuingCaId: z.string(),
                validityDays: z.number().int().min(1).max(MAX_DEVICE_VALIDITY_DAYS).default(DEFAULT_DEVICE_VALIDITY_DAYS),
                keyUsage: nonEmptyUnique(z.enum(DEVICE_KEY_USAGES)).default(DEFAULT_DEVICE_KEY_USAGES),
                extendedKeyUsage: nonEmptyUnique(z.enum(DEVICE_EXTENDED_KEY_USAGE_NAMES)).default(DEFAULT_DEVICE_EXTENDED_KEY_USAGES),
                allowedKeyTypes: nonEmptyUnique(z.enum(DEVICE_KEY_TYPES)).default([...DEVICE_KEY_TYPES]),
                validator: z.object({ kind: z.string(), settings: z.record(z.string(), z.unknown()).default({}), secret: z.string().optional() }),
                nameRules: NameRules.optional(),
              }),
            },
          },
        },
      },
      responses: { 201: json(EnrollmentProfile, "Created"), ...errors(400, 401, 403, 404, 409, 422) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { enrollmentProfile: ["create"] });
      const kind = Object.hasOwn(kinds, body.validator.kind) ? kinds[body.validator.kind]! : undefined;
      if (!kind) throw new HttpError(422, `the platform runs no Enrollment Validator of the kind ${body.validator.kind}`);
      const settings = refuse("validator.settings", kind.settings, body.validator.settings) as Record<string, unknown>;
      if (kind.secret && body.validator.secret === undefined) throw new HttpError(400, `validator.secret: an Enrollment Validator of the kind ${body.validator.kind} needs one`);
      if (!kind.secret && body.validator.secret !== undefined) throw new HttpError(400, `validator.secret: an Enrollment Validator of the kind ${body.validator.kind} takes none`);
      const validatorSecret = kind.secret ? refuse("validator.secret", kind.secret, body.validator.secret) : undefined;
      if (kind.vouchesForNames && body.nameRules) throw new HttpError(422, `an Enrollment Validator of the kind ${body.validator.kind} vouches for the names a device asks for, so the profile takes no name rules`);
      if (!kind.vouchesForNames && !body.nameRules) throw new HttpError(422, `an Enrollment Validator of the kind ${body.validator.kind} does not vouch for the names a device asks for, so the profile must have name rules`);
      const of = isId(body.issuingCaId) ? await findIssuingCa(db, orgId, body.issuingCaId) : undefined;
      if (!of) throw new HttpError(422, "the Organization has no such Issuing CA");
      const refusal = issuingRefusal(of);
      if (refusal) throw new HttpError(422, refusal);

      const taken = () => new HttpError(409, `the Organization already has an Enrollment Profile named ${body.name}`);
      const [named] = await db
        .select({ id: enrollmentProfile.id })
        .from(enrollmentProfile)
        .where(and(eq(enrollmentProfile.organizationId, orgId), eq(enrollmentProfile.name, body.name)));
      if (named) throw taken();

      const publicId = randomBytes(16).toString("hex");
      const ra = generateKeyPairSync("rsa", { modulusLength: 2048 });
      let raCertificate: x509.X509Certificate;
      try {
        raCertificate = await privateCas.issueRa(db, orgId, of.issuing.id, {
          publicKey: ra.publicKey.export({ format: "der", type: "spki" }),
          subject: new x509.Name([{ CN: [`SCEP RA ${publicId}`] }]),
          validityDays: RA_VALIDITY_DAYS,
        });
      } catch (err) {
        if (err instanceof IssuanceFailure) throw new HttpError(422, err.message);
        throw err;
      }

      try {
        const row = await unitOfWork.run(actor, async (tx, change) => {
          const raKeySecretId = await secrets.create(tx, orgId, ra.privateKey.export({ format: "pem", type: "pkcs8" }).toString());
          const validatorSecretId = validatorSecret === undefined ? null : await secrets.create(tx, orgId, validatorSecret);
          const [row] = await tx
            .insert(enrollmentProfile)
            .values({
              organizationId: orgId,
              name: body.name,
              publicId,
              issuingCaId: of.issuing.id,
              validityDays: body.validityDays,
              keyUsage: body.keyUsage,
              extendedKeyUsage: body.extendedKeyUsage,
              allowedKeyTypes: body.allowedKeyTypes,
              validatorKind: body.validator.kind,
              validatorSettings: settings,
              validatorSecretId,
              nameRules: body.nameRules ?? null,
              raCertificatePem: raCertificate.toString("pem"),
              raKeySecretId,
            })
            .returning();
          await change.audit({
            organizationId: orgId,
            action: "enrollment_profile.created",
            target: { type: "enrollment_profile", id: row!.id },
            detail: {
              name: body.name,
              issuingCa: { id: of.issuing.id, subject: of.issuing.subject },
              validityDays: body.validityDays,
              keyUsage: body.keyUsage,
              extendedKeyUsage: body.extendedKeyUsage,
              allowedKeyTypes: body.allowedKeyTypes,
              validator: { kind: body.validator.kind, settings },
              nameRules: body.nameRules ?? null,
              raCertificate: { serial: raCertificate.serialNumber.toUpperCase(), notAfter: raCertificate.notAfter.toISOString() },
            },
          });
          return row!;
        });
        return c.json(toProfile(row, of.ca.id, baseURL), 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw taken();
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/enrollment-profiles/{id}",
      tags: ["Enrollment Profiles"],
      request: { params: ProfileParams },
      responses: { 200: json(EnrollmentProfile), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { enrollmentProfile: ["read"] });
      const { row, of } = await findProfile(orgId, id);
      return c.json(toProfile(row, of.ca.id, baseURL), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/enrollment-profiles/{id}/ca-certificate",
      tags: ["Enrollment Profiles"],
      summary: "Download the CA certificate devices must trust: the profile's root, or its Issuing CA",
      description: "PEM, for the device management platform's trusted certificate profile: `ca` `root` (the default) or `issuing`. Only Organization Administrators may.",
      request: { params: ProfileParams, query: z.object({ ca: z.enum(["root", "issuing"]).default("root") }) },
      responses: { 200: { description: "The certificate, PEM", content: { "application/x-pem-file": { schema: z.string() } } }, ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const { ca } = c.req.valid("query");
      await authorize(await requireUser(c), orgId, { enrollmentProfile: ["read"] });
      const { row, of } = await findProfile(orgId, id);
      const pem = ca === "root" ? of.ca.rootCertificatePem : of.issuing.certificatePem;
      if (!pem) throw new HttpError(404, `the Private CA has no ${ca === "root" ? "root" : "Issuing CA certificate"} yet`);
      const fileName = `${row.name.replace(/[^A-Za-z0-9._-]+/g, "-").toLowerCase() || "enrollment-profile"}.${ca}.pem`;
      return c.body(pem, 200, { "content-type": "application/x-pem-file", "content-disposition": `attachment; filename="${fileName}"` });
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/enrollment-profiles/{id}/validator/test",
      tags: ["Enrollment Profiles"],
      summary: "Test the Enrollment Validator's connection",
      description:
        "Asks the profile's validator whether its service can be reached with its settings and secret, without validating or revoking anything. Always 200; `ok` says whether it worked and `error` why not. " +
        "Only Organization Administrators may.",
      request: { params: ProfileParams },
      responses: { 200: json(z.object({ ok: z.boolean(), error: z.string().optional() }), "Whether the validator's service could be reached"), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { enrollmentProfile: ["update"] });
      const { row } = await findProfile(orgId, id);
      // The service is asked outside any transaction: only the record of the test is written in one.
      const outcome: { ok: true } | { ok: false; error: string } = await validators
        .open(db, row)
        .then((validator) => validator.test())
        .then(
          () => ({ ok: true as const }),
          (err: unknown) => ({ ok: false as const, error: describeValidatorError(err) }),
        );
      await unitOfWork.run(actor, (_tx, change) =>
        change.audit({ organizationId: orgId, action: "enrollment_validator.tested", target: { type: "enrollment_profile", id: row.id }, detail: { validator: { kind: row.validatorKind }, ...outcome } }),
      );
      return c.json(outcome, 200);
    },
  );
}
