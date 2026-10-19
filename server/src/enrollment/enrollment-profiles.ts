// An Organization's Enrollment Profiles: templates under which devices obtain Device Certificates in bulk from one of its
// Private CAs' Issuing CAs, with no Approval and no Owners. A profile fixes the Issuing CA, the validity, key usage and
// extended key usages of what it issues and the device keys it certifies, and names the Enrollment Validator
// (enrollment-validator.ts) that decides each request: its kind, its settings and its write-only secret. A profile whose
// validator does not vouch for names may carry name rules (name-rules.ts) instead. Devices enroll at its SCEP URL (scep.ts), under an opaque public
// id. The platform makes each profile an RA: a software RSA key, held as a Secret, and a certificate the Issuing CA signs
// for it, which open SCEP requests and sign SCEP responses (ADR 0007). Only Organization Administrators see or change them.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import * as x509 from "@peculiar/x509";
import { and, asc, eq } from "drizzle-orm";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import type { Authorizer } from "../tenancy/authorization";
import type { Db, Tx } from "../platform/db/client";
import { enrollmentProfile } from "../platform/db/schema";
import {
  DEFAULT_DEVICE_EXTENDED_KEY_USAGES,
  DEFAULT_DEVICE_RETENTION_DAYS,
  DEFAULT_DEVICE_KEY_USAGES,
  DEFAULT_DEVICE_VALIDITY_DAYS,
  DEFAULT_SHARED_CHALLENGE_VALIDITY_DAYS,
  DEVICE_EXTENDED_KEY_USAGE_NAMES,
  DEFAULT_DEVICE_KEY_TYPES,
  DEVICE_KEY_TYPES,
  DEVICE_KEY_USAGES,
  MAX_DEVICE_RETENTION_DAYS,
  MAX_DEVICE_VALIDITY_DAYS,
} from "./enrollment-profile-kinds";
import { describeValidatorError, kindOf, kindsOf, type EnrollmentValidators } from "./enrollment-validator";
import type { EnrollmentValidatorRuns } from "./enrollment-validators";
import { HttpError, OrgParam, errors, isUniqueViolation, json } from "../platform/http";
import { IssuanceFailure } from "../issuance/issuance-failure";
import { NameRules } from "./name-rules";
import { enrollmentProfileRefusal, findIssuingCa, issuingRefusal, type IssuingCaOf, type PrivateCas } from "../private-ca/private-ca";
import type { Secrets } from "../platform/crypto/secrets";
import { sharedChallengesOf, type SharedChallenges } from "./shared-challenge";
import type { Actor, UnitOfWork } from "../platform/unit-of-work";
import { fingerprintOf } from "../pki/fingerprint";

type ProfileRow = typeof enrollmentProfile.$inferSelect;

/** How long an RA certificate is valid for, in days, though never past its Issuing CA's end. */
const RA_VALIDITY_DAYS = 730;

const ProfileParams = OrgParam.extend({ id: z.string().openapi({ param: { name: "id", in: "path" } }) });

const RetentionDays = z
  .number()
  .int()
  .min(0)
  .max(MAX_DEVICE_RETENTION_DAYS)
  .openapi({ description: "How many days after it ends a Device Certificate is pruned (its Audit Events are kept)." });

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
  caFingerprint: z.string().openapi({ description: "The SHA-256 fingerprint (lower-case hex) of the CA certificate GetCACert serves, its Issuing CA's, which a SCEP profile can be told to expect." }),
  issuingCaId: z.string(),
  privateCaId: z.string(),
  validityDays: z.number().int().openapi({ description: "How long its Device Certificates are valid for, though never past the Issuing CA's end." }),
  keyUsage: z.array(z.enum(DEVICE_KEY_USAGES)),
  extendedKeyUsage: z.array(z.enum(DEVICE_EXTENDED_KEY_USAGE_NAMES)),
  allowedKeyTypes: z.array(z.enum(DEVICE_KEY_TYPES)).openapi({ description: "The device keys it certifies; a request for another is refused." }),
  validator: z
    .object({ kind: z.string(), settings: z.record(z.string(), z.unknown()), hasSecret: z.boolean().openapi({ description: "Whether it holds a secret, which is never shown." }) })
    .openapi({ description: "The Enrollment Validator that decides each request." }),
  nameRules: NameRules.nullable().openapi({ description: "What a device's names must keep; none when the validator vouches for names, or when the profile issues the names a device asks for within its Issuing CA's permitted name rules." }),
  sharedChallenge: z
    .object({ id: z.string() })
    .nullable()
    .openapi({ description: "Its Shared Challenge, by id only: the challenge is shown once, when it is made, and never again. None when its validator's kind uses none." }),
  previousSharedChallenge: z
    .object({ id: z.string(), expiresAt: z.string() })
    .nullable()
    .openapi({ description: "The Shared Challenge it held before its last rotation, by id, which devices may still present until `expiresAt` unless it is retired first. None when there is none still valid." }),
  raCertificate: z.object({ subject: z.string(), serial: z.string(), notAfter: z.string() }).openapi({ description: "The RA certificate devices encrypt their requests to, which signs the platform's answers." }),
  enabled: z.boolean().openapi({ description: "Whether it takes enrollment requests; a disabled profile refuses every one, and keeps the Device Certificates it issued." }),
  retentionDays: z.number().int().openapi({ description: "How many days after it ends a Device Certificate it issued is pruned; its Audit Events are kept." }),
  createdAt: z.string(),
});

/** A profile as its create and Shared Challenge rotation responses show it: with the Shared Challenge itself, which is shown only then. */
const CreatedEnrollmentProfile = EnrollmentProfile.extend({
  sharedChallenge: z
    .object({ id: z.string(), challenge: z.string().openapi({ description: "The Shared Challenge, which every device presents as its CSR's challengePassword. Shown only here: the platform keeps only its hash." }) })
    .nullable(),
});

/** The SCEP URL of the profile with this public id, on the platform's base URL. */
export const scepUrlOf = (baseURL: string, publicId: string) => `${baseURL.replace(/\/+$/, "")}/scep/${publicId}`;

function toProfile(row: ProfileRow, of: IssuingCaOf, baseURL: string, now: Date): z.infer<typeof EnrollmentProfile> {
  const ra = new x509.X509Certificate(row.raCertificatePem);
  // A profile is made only on an Issuing CA that has its certificate, which it then keeps.
  const caFingerprint = fingerprintOf(new x509.X509Certificate(of.issuing.certificatePem!).rawData);
  return {
    id: row.id,
    name: row.name,
    publicId: row.publicId,
    scepUrl: scepUrlOf(baseURL, row.publicId),
    caFingerprint,
    issuingCaId: row.issuingCaId,
    privateCaId: of.ca.id,
    validityDays: row.validityDays,
    keyUsage: row.keyUsage,
    extendedKeyUsage: row.extendedKeyUsage,
    allowedKeyTypes: row.allowedKeyTypes,
    validator: { kind: row.validatorKind, settings: row.validatorSettings, hasSecret: row.validatorSecretId !== null },
    nameRules: row.nameRules,
    ...sharedChallengesOf(row, now),
    raCertificate: { subject: ra.subject, serial: ra.serialNumber.toUpperCase(), notAfter: ra.notAfter.toISOString() },
    enabled: row.enabled,
    retentionDays: row.retentionDays,
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
  sharedChallenges: SharedChallenges;
  /** Where the platform is served, which SCEP URLs are under. */
  baseURL: string;
  clock: () => Date;
}) {
  const { app, db, requireUser, authorize, unitOfWork, secrets, privateCas, kinds, validators, sharedChallenges, baseURL, clock } = ctx;

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

  /**
   * A new RA for the profile with this public id: a software RSA key (PKCS #8 PEM) and a certificate the Issuing CA
   * signs for it. A 422 when the Issuing CA does not issue.
   */
  async function makeRa(orgId: string, issuingCaId: string, publicId: string) {
    const key = generateKeyPairSync("rsa", { modulusLength: 2048 });
    try {
      const certificate = await privateCas.issueRa(db, orgId, issuingCaId, {
        publicKey: key.publicKey.export({ format: "der", type: "spki" }),
        subject: new x509.Name([{ CN: [`SCEP RA ${publicId}`] }]),
        validityDays: RA_VALIDITY_DAYS,
      });
      return { certificate, privateKeyPem: key.privateKey.export({ format: "pem", type: "pkcs8" }).toString() };
    } catch (err) {
      if (err instanceof IssuanceFailure) throw new HttpError(422, err.message);
      throw err;
    }
  }

  /** The RA certificate as Audit Events name it. */
  const raOf = (certificate: x509.X509Certificate) => ({ serial: certificate.serialNumber.toUpperCase(), notAfter: certificate.notAfter.toISOString() });

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/enrollment-validator-kinds",
      tags: ["Enrollment Profiles"],
      summary: "The Enrollment Validator kinds an Enrollment Profile can name",
      description:
        "Those the platform runs. With none, no Enrollment Profile can be created. `vouchesForNames` says whether it checks the names a device asks for; a profile whose validator does not may carry name rules, and otherwise issues the names a device asks for within its Issuing CA's permitted name rules. " +
        "`takesSecret` whether it is configured with a secret, and `allowsRenewal` whether a device may renew with a SCEP RenewalReq rather than enroll again, and `usesSharedChallenge` whether a device enrolls by presenting the profile's Shared Challenge, which the platform makes. Only Organization Administrators may ask.",
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(z.object({ kind: z.string(), vouchesForNames: z.boolean(), takesSecret: z.boolean(), allowsRenewal: z.boolean(), usesSharedChallenge: z.boolean() })) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { enrollmentProfile: ["read"] });
      return c.json({ items: kindsOf(kinds).map((of) => ({ kind: of.name, vouchesForNames: of.vouchesForNames, takesSecret: of.secret !== undefined, allowsRenewal: of.allowsRenewal, usesSharedChallenge: of.usesSharedChallenge })) }, 200);
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
      const items = await Promise.all(rows.map(async (row) => toProfile(row, (await findIssuingCa(db, orgId, row.issuingCaId))!, baseURL, clock())));
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
        "A profile whose validator does not vouch for names may carry `nameRules`, which a device's names must keep; without them it issues the names a device asks for, within the Issuing CA's permitted name rules. One whose validator vouches for names must have none (422 otherwise). " +
        "When its validator's kind uses a Shared Challenge, the platform makes one and returns it, as `sharedChallenge.challenge`, in this response only: it keeps only its hash, so it is never shown again. Every device presents it as its CSR's challengePassword. " +
        "Device Certificates are valid for `validityDays` (365 unless given, or 90 when its validator's kind uses a Shared Challenge, since nothing revokes those automatically), never past the Issuing CA's end, with `keyUsage` (digitalSignature and keyEncipherment unless given) and `extendedKeyUsage` (clientAuth unless given), " +
        "and the subject and subject alternative names of the device's CSR; nothing else a CSR asks for. A device key not in `allowedKeyTypes` (RSA 2048, 3072 and 4096 unless given) is refused; `rsa-1024`, which can be broken, is allowed only when given. " +
        "A Device Certificate is pruned `retentionDays` (365 unless given) after it ends. " +
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
                validityDays: z.number().int().min(1).max(MAX_DEVICE_VALIDITY_DAYS).optional(),
                keyUsage: nonEmptyUnique(z.enum(DEVICE_KEY_USAGES)).default(DEFAULT_DEVICE_KEY_USAGES),
                extendedKeyUsage: nonEmptyUnique(z.enum(DEVICE_EXTENDED_KEY_USAGE_NAMES)).default(DEFAULT_DEVICE_EXTENDED_KEY_USAGES),
                allowedKeyTypes: nonEmptyUnique(z.enum(DEVICE_KEY_TYPES)).default(DEFAULT_DEVICE_KEY_TYPES),
                validator: z.object({ kind: z.string(), settings: z.record(z.string(), z.unknown()).default({}), secret: z.string().optional() }),
                nameRules: NameRules.optional(),
                retentionDays: RetentionDays.default(DEFAULT_DEVICE_RETENTION_DAYS),
              }),
            },
          },
        },
      },
      responses: { 201: json(CreatedEnrollmentProfile, "Created"), ...errors(400, 401, 403, 404, 409, 422) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { enrollmentProfile: ["create"] });
      const kind = kindOf(kinds, body.validator.kind);
      if (!kind) throw new HttpError(422, `the platform runs no Enrollment Validator of the kind ${body.validator.kind}`);
      const settings = refuse("validator.settings", kind.settings, body.validator.settings) as Record<string, unknown>;
      if (kind.secret && body.validator.secret === undefined) throw new HttpError(400, `validator.secret: an Enrollment Validator of the kind ${body.validator.kind} needs one`);
      if (!kind.secret && body.validator.secret !== undefined) throw new HttpError(400, `validator.secret: an Enrollment Validator of the kind ${body.validator.kind} takes none`);
      const validatorSecret = kind.secret ? refuse("validator.secret", kind.secret, body.validator.secret) : undefined;
      if (kind.vouchesForNames && body.nameRules) throw new HttpError(422, `an Enrollment Validator of the kind ${body.validator.kind} vouches for the names a device asks for, so the profile takes no name rules`);
      const of = isId(body.issuingCaId) ? await findIssuingCa(db, orgId, body.issuingCaId) : undefined;
      if (!of) throw new HttpError(422, "the Organization has no such Issuing CA");
      const refusal = issuingRefusal(of) ?? enrollmentProfileRefusal(of.ca);
      if (refusal) throw new HttpError(422, refusal);

      const taken = () => new HttpError(409, `the Organization already has an Enrollment Profile named ${body.name}`);
      const [named] = await db
        .select({ id: enrollmentProfile.id })
        .from(enrollmentProfile)
        .where(and(eq(enrollmentProfile.organizationId, orgId), eq(enrollmentProfile.name, body.name)));
      if (named) throw taken();

      const publicId = randomBytes(16).toString("hex");
      const ra = await makeRa(orgId, of.issuing.id, publicId);
      const raCertificate = ra.certificate;
      const shared = kind.usesSharedChallenge ? sharedChallenges.issue() : undefined;
      const validityDays = body.validityDays ?? (shared ? DEFAULT_SHARED_CHALLENGE_VALIDITY_DAYS : DEFAULT_DEVICE_VALIDITY_DAYS);

      try {
        const row = await unitOfWork.run(actor, async (tx, change) => {
          const raKeySecretId = await secrets.create(tx, orgId, ra.privateKeyPem);
          const validatorSecretId = validatorSecret === undefined ? null : await secrets.create(tx, orgId, validatorSecret);
          const [row] = await tx
            .insert(enrollmentProfile)
            .values({
              organizationId: orgId,
              name: body.name,
              publicId,
              issuingCaId: of.issuing.id,
              validityDays,
              keyUsage: body.keyUsage,
              extendedKeyUsage: body.extendedKeyUsage,
              allowedKeyTypes: body.allowedKeyTypes,
              validatorKind: body.validator.kind,
              validatorSettings: settings,
              validatorSecretId,
              nameRules: body.nameRules ?? null,
              ...shared?.held,
              retentionDays: body.retentionDays,
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
              validityDays,
              keyUsage: body.keyUsage,
              extendedKeyUsage: body.extendedKeyUsage,
              allowedKeyTypes: body.allowedKeyTypes,
              validator: { kind: body.validator.kind, settings },
              nameRules: body.nameRules ?? null,
              ...(shared && { sharedChallenge: { id: shared.shown.id } }),
              retentionDays: body.retentionDays,
              raCertificate: raOf(raCertificate),
            },
          });
          return row!;
        });
        return c.json({ ...toProfile(row, of, baseURL, clock()), sharedChallenge: shared?.shown ?? null }, 201);
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
      return c.json(toProfile(row, of, baseURL, clock()), 200);
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
        "Asks the profile's validator whether its service can be reached with its settings and secret, without validating or revoking anything. Always 200; `ok` says whether it worked and `error` why not, and `note` what the test could not prove (an Intune test cannot prove the scep_challenge_provider permission without validating a request). " +
        "Only Organization Administrators may.",
      request: { params: ProfileParams },
      responses: { 200: json(z.object({ ok: z.boolean(), error: z.string().optional(), note: z.string().optional() }), "Whether the validator's service could be reached"), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { enrollmentProfile: ["update"] });
      const { row } = await findProfile(orgId, id);
      // The service is asked outside any transaction: only the record of the test is written in one.
      const outcome: { ok: true; note?: string } | { ok: false; error: string } = await validators
        .open(db, row)
        .then((validator) => validator.test())
        .then(
          (tested) => ({ ok: true as const, ...(tested?.note ? { note: tested.note.slice(0, 1000) } : {}) }),
          (err: unknown) => ({ ok: false as const, error: describeValidatorError(err) }),
        );
      await unitOfWork.run(actor, (_tx, change) =>
        change.audit({ organizationId: orgId, action: "enrollment_validator.tested", target: { type: "enrollment_profile", id: row.id }, detail: { validator: { kind: row.validatorKind }, ...outcome } }),
      );
      return c.json(outcome, 200);
    },
  );

  /**
   * The profile's row, locked for the rest of the change, so that two changes to it take turns. A 409 when it is no
   * longer `read` as it was before the change, which decided on it.
   */
  async function locked(tx: Tx, read: ProfileRow) {
    const [row] = await tx.select().from(enrollmentProfile).where(eq(enrollmentProfile.id, read.id)).for("update");
    const changed = (["enabled", "issuingCaId", "retentionDays", "raCertificatePem"] as const).some((field) => row![field] !== read[field]);
    if (changed) throw new HttpError(409, "the Enrollment Profile was changed meanwhile; ask again");
    return row!;
  }

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/enrollment-profiles/{id}/disable",
      tags: ["Enrollment Profiles"],
      summary: "Disable an Enrollment Profile: it refuses all enrollment from now on",
      description:
        "Every enrollment request at its SCEP URL is refused (FAILURE badRequest, and an `enrollment.refused` Audit Event), whatever its validator would say. " +
        "Its Device Certificates are kept, and stay on their Issuing CA's CRL while revoked, and can still be revoked; they are pruned as before. A disabled profile is never enabled again (409 when it is already disabled): create another. " +
        "Only Organization Administrators may.",
      request: { params: ProfileParams },
      responses: { 200: json(EnrollmentProfile, "Disabled"), ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { enrollmentProfile: ["disable"] });
      const { row: found, of } = await findProfile(orgId, id);
      if (!found.enabled) throw new HttpError(409, "the Enrollment Profile is already disabled");
      const row = await unitOfWork.run(actor, async (tx, change) => {
        const current = await locked(tx, found);
        const [row] = await tx.update(enrollmentProfile).set({ enabled: false }).where(eq(enrollmentProfile.id, id)).returning();
        await change.audit({ organizationId: orgId, action: "enrollment_profile.disabled", target: { type: "enrollment_profile", id }, detail: { name: current.name } });
        return row!;
      });
      return c.json(toProfile(row, of, baseURL, clock()), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/api/organizations/{orgId}/enrollment-profiles/{id}",
      tags: ["Enrollment Profiles"],
      summary: "Point an Enrollment Profile at another Issuing CA, or change its retention period, name rules or allowed device keys",
      description:
        "`issuingCaId` must be an active Issuing CA of one of the Organization's Private CAs, under an active root (422 otherwise): the way on once the profile's Issuing CA is retired, which refuses enrollment until then. " +
        "The new Issuing CA signs a new RA certificate for a new RA key, which `GetCACert` serves from then on with the new chain, so redeploy the trusted certificate profile in the device management platform when the root changes. " +
        "Device Certificates already issued stay their Issuing CA's, on its CRL once revoked. `retentionDays` is how many days after it ends a Device Certificate is pruned. " +
        "`nameRules` replaces the name rules of a profile whose validator does not vouch for names, from its next request on, and null removes them, so that it issues the names a device asks for within its Issuing CA's permitted name rules; a profile whose validator vouches for names takes none (422). " +
        "`allowedKeyTypes` replaces the device keys it certifies, from its next request on; Device Certificates already issued stay. " +
        "What is not given is left as it is; a change that changes nothing is not audited. Only Organization Administrators may.",
      request: {
        params: ProfileParams,
        body: { content: { "application/json": { schema: z.object({ issuingCaId: z.string().optional(), retentionDays: RetentionDays.optional(), nameRules: NameRules.nullable().optional(), allowedKeyTypes: nonEmptyUnique(z.enum(DEVICE_KEY_TYPES)).optional() }) } } },
      },
      responses: { 200: json(EnrollmentProfile, "Updated"), ...errors(400, 401, 403, 404, 409, 422) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { enrollmentProfile: ["update"] });
      const found = await findProfile(orgId, id);
      const repointing = body.issuingCaId !== undefined && body.issuingCaId !== found.row.issuingCaId;
      // The Issuing CA it is pointed at and the RA that one signed, when it is pointed at another.
      let to: { of: IssuingCaOf; ra: Awaited<ReturnType<typeof makeRa>> } | undefined;
      if (repointing) {
        const of = isId(body.issuingCaId!) ? await findIssuingCa(db, orgId, body.issuingCaId!) : undefined;
        if (!of) throw new HttpError(422, "the Organization has no such Issuing CA");
        const refusal = issuingRefusal(of) ?? enrollmentProfileRefusal(of.ca);
        if (refusal) throw new HttpError(422, refusal);
        // Signed before the change, as when a profile is created: the KMS is not asked inside a transaction.
        to = { of, ra: await makeRa(orgId, of.issuing.id, found.row.publicId) };
      }
      const retaining = body.retentionDays !== undefined && body.retentionDays !== found.row.retentionDays;
      if (body.nameRules) {
        const kind = kindOf(kinds, found.row.validatorKind);
        if (!kind) throw new HttpError(422, `the platform runs no Enrollment Validator of the kind ${found.row.validatorKind}`);
        if (kind.vouchesForNames) throw new HttpError(422, `an Enrollment Validator of the kind ${found.row.validatorKind} vouches for the names a device asks for, so the profile takes no name rules`);
      }
      const changingNameRules = body.nameRules !== undefined && !isDeepStrictEqual(body.nameRules, found.row.nameRules);
      const changingKeyTypes = body.allowedKeyTypes !== undefined && !isDeepStrictEqual(body.allowedKeyTypes, found.row.allowedKeyTypes);
      if (!to && !retaining && !changingNameRules && !changingKeyTypes) return c.json(toProfile(found.row, found.of, baseURL, clock()), 200);

      const row = await unitOfWork.run(actor, async (tx, change) => {
        const current = await locked(tx, found.row);
        if (to) await secrets.replace(tx, orgId, current.raKeySecretId, to.ra.privateKeyPem);
        const [row] = await tx
          .update(enrollmentProfile)
          .set({ ...(to && { issuingCaId: to.of.issuing.id, raCertificatePem: to.ra.certificate.toString("pem") }), ...(retaining && { retentionDays: body.retentionDays }), ...(changingNameRules && { nameRules: body.nameRules }), ...(changingKeyTypes && { allowedKeyTypes: body.allowedKeyTypes }) })
          .where(eq(enrollmentProfile.id, id))
          .returning();
        await change.audit({
          organizationId: orgId,
          action: "enrollment_profile.updated",
          target: { type: "enrollment_profile", id },
          detail: {
            name: current.name,
            changes: {
              ...(to && { issuingCa: { from: { id: found.of.issuing.id, subject: found.of.issuing.subject }, to: { id: to.of.issuing.id, subject: to.of.issuing.subject } } }),
              ...(retaining && { retentionDays: { from: current.retentionDays, to: body.retentionDays } }),
              ...(changingNameRules && { nameRules: { from: current.nameRules, to: body.nameRules } }),
              ...(changingKeyTypes && { allowedKeyTypes: { from: current.allowedKeyTypes, to: body.allowedKeyTypes } }),
            },
            ...(to && { raCertificate: raOf(to.ra.certificate) }),
          },
        });
        return row!;
      });
      return c.json(toProfile(row, to?.of ?? found.of, baseURL, clock()), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/enrollment-profiles/{id}/ra-rotation",
      tags: ["Enrollment Profiles"],
      summary: "Replace an Enrollment Profile's RA certificate and key, before the certificate ends",
      description:
        "The profile's Issuing CA signs a new RA certificate for a new RA key, valid for two years but never past the Issuing CA's end (422 when the Issuing CA does not issue). " +
        "`GetCACert` serves it from then on; a request encrypted to the old RA certificate is no longer opened, and its device enrolls again. Only Organization Administrators may.",
      request: { params: ProfileParams },
      responses: { 200: json(EnrollmentProfile, "Rotated"), ...errors(401, 403, 404, 409, 422) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { enrollmentProfile: ["update"] });
      const found = await findProfile(orgId, id);
      const refusal = issuingRefusal(found.of);
      if (refusal) throw new HttpError(422, refusal);
      const ra = await makeRa(orgId, found.row.issuingCaId, found.row.publicId);
      const row = await unitOfWork.run(actor, async (tx, change) => {
        const current = await locked(tx, found.row);
        await secrets.replace(tx, orgId, current.raKeySecretId, ra.privateKeyPem);
        const [row] = await tx.update(enrollmentProfile).set({ raCertificatePem: ra.certificate.toString("pem") }).where(eq(enrollmentProfile.id, id)).returning();
        await change.audit({
          organizationId: orgId,
          action: "enrollment_profile.ra_rotated",
          target: { type: "enrollment_profile", id },
          detail: { name: current.name, from: raOf(new x509.X509Certificate(current.raCertificatePem)), to: raOf(ra.certificate) },
        });
        return row!;
      });
      return c.json(toProfile(row, found.of, baseURL, clock()), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/enrollment-profiles/{id}/shared-challenge/rotation",
      tags: ["Enrollment Profiles"],
      summary: "Rotate an Enrollment Profile's Shared Challenge, keeping the old one as the previous until it expires",
      description:
        "The platform makes a new Shared Challenge and returns it, as `sharedChallenge.challenge`, in this response only: it keeps only its hash. Devices may present either it or the previous one, its old Shared Challenge, until `previousExpiresAt` (required, in the future; 422 otherwise) or until the previous one is retired, so that devices the device management platform has not yet reached keep enrolling. " +
        "Refused (409) while the profile still holds a previous Shared Challenge that has not expired: retire it first. A profile whose validator's kind uses no Shared Challenge has none to rotate (422). Only Organization Administrators may.",
      request: { params: ProfileParams, body: { content: { "application/json": { schema: z.object({ previousExpiresAt: z.iso.datetime({ offset: true }).openapi({ description: "When the previous Shared Challenge stops being accepted." }) }) } } } },
      responses: { 200: json(CreatedEnrollmentProfile, "Rotated"), ...errors(400, 401, 403, 404, 409, 422) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const previousExpiresAt = new Date(c.req.valid("json").previousExpiresAt);
      const actor = await requireUser(c);
      await authorize(actor, orgId, { enrollmentProfile: ["update"] });
      const found = await findProfile(orgId, id);
      const { row, shown } = await sharedChallenges.rotate(actor, found.row, previousExpiresAt);
      return c.json({ ...toProfile(row, found.of, baseURL, clock()), sharedChallenge: shown }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/enrollment-profiles/{id}/shared-challenge/previous/retirement",
      tags: ["Enrollment Profiles"],
      summary: "Retire an Enrollment Profile's previous Shared Challenge at once",
      description:
        "Devices presenting the previous Shared Challenge are refused from now on, before its expiry; Device Certificates issued under it are kept. 409 when the profile holds no previous Shared Challenge that has not expired. Only Organization Administrators may.",
      request: { params: ProfileParams },
      responses: { 200: json(EnrollmentProfile, "Retired"), ...errors(401, 403, 404, 409) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { enrollmentProfile: ["update"] });
      const found = await findProfile(orgId, id);
      const row = await sharedChallenges.retire(actor, found.row);
      return c.json(toProfile(row, found.of, baseURL, clock()), 200);
    },
  );
}
