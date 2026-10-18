// An Enrollment Profile's Device Certificates as Organization Administrators see them: the inventory of what devices
// enrolled for (scep.ts), kept apart from the Managed Certificates. A fleet has thousands, so the list is paged on the
// server and searched there, by subject, subject alternative name, serial or the device ID its Enrollment Validator
// knows the device by, and filtered by status. Each can be looked at and its certificate downloaded, and revoked, which
// puts it on its Issuing CA's CRL in the same change (device-certificate-revocation.ts).
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, desc, eq, gt, isNotNull, isNull, lte, or, sql, type SQL } from "drizzle-orm";
import type { Authorizer } from "./authorization";
import { CertificateAuthorityError } from "./certificate-authority";
import type { Db } from "./db/client";
import { deviceCertificate, enrollmentProfile, issuingCa } from "./db/schema";
import type { DeviceCertificateRevocations } from "./device-certificate-revocation";
import { DEVICE_KEY_TYPES, WEAK_DEVICE_KEY_TYPE } from "./enrollment-profile-kinds";
import { HttpError, OrgParam, PageQuery, errors, json, pageOf } from "./http";
import { REVOCATION_REASONS_OF } from "./revocation-reasons";
import type { Actor, UnitOfWork } from "./unit-of-work";

const DEVICE_CERTIFICATE_STATUSES = ["active", "expired", "revoked"] as const;
type DeviceCertificateStatus = (typeof DEVICE_CERTIFICATE_STATUSES)[number];

const DeviceRevocationReason = z.enum(REVOCATION_REASONS_OF.private_ca).openapi({ description: "The RFC 5280 reason, of those a Private CA offers." });

export const DeviceCertificate = z.object({
  id: z.string(),
  enrollmentProfileId: z.string(),
  serial: z.string().openapi({ description: "Upper-case hex." }),
  subject: z.string(),
  subjectAltNames: z.array(z.object({ type: z.string(), value: z.string() })),
  deviceId: z.string().nullable().openapi({ description: "The device as its Enrollment Validator knows it, such as Intune's device ID; none when the request did not say." }),
  keyType: z.enum(DEVICE_KEY_TYPES).openapi({ description: "The device's key. `rsa-1024` is weak: it can be broken." }),
  sharedChallenge: z
    .object({ id: z.string() })
    .nullable()
    .openapi({ description: "The Shared Challenge its request presented, by id, which tells whether it was issued under its profile's current or previous one; none for a renewal, or when its profile's validator's kind uses none." }),
  issuer: z.string().openapi({ description: "The Issuing CA's subject." }),
  notBefore: z.string(),
  notAfter: z.string(),
  status: z.enum(DEVICE_CERTIFICATE_STATUSES).openapi({ description: "`revoked` once revoked, whenever it ends; otherwise `expired` once it has ended, and `active` until then." }),
  revocation: z.object({ reason: DeviceRevocationReason, revokedAt: z.string() }).nullable(),
  createdAt: z.string(),
});

const ProfileParams = OrgParam.extend({ id: z.string().openapi({ param: { name: "id", in: "path" } }) });
const CertificateParams = ProfileParams.extend({ certificateId: z.string().openapi({ param: { name: "certificateId", in: "path" } }) });

const DeviceCertificateQuery = PageQuery.extend({
  q: z
    .string()
    .trim()
    .max(200)
    .optional()
    .openapi({ description: "Matches part of the subject, a subject alternative name, the serial (hex, of any case, with or without colons) or the device ID, ignoring case." }),
  status: z.enum(DEVICE_CERTIFICATE_STATUSES).optional(),
  weakKey: z.literal("true").optional().meta({ description: "Only those for a weak key, one that can be broken (`rsa-1024`)." }),
});

const isId = (id: string) => z.uuid().safeParse(id).success;

/** `text` as a LIKE pattern that matches it anywhere, its wildcards taken literally. */
const containing = (text: string) => `%${text.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;

/** What a search for `q` matches. */
function matching(q: string): SQL {
  const pattern = containing(q);
  const hex = q.replace(/[\s:]/g, "").toUpperCase();
  return or(
    sql`${deviceCertificate.subject} ilike ${pattern}`,
    sql`exists (select 1 from jsonb_array_elements(${deviceCertificate.subjectAltNames}) as name where name->>'value' ilike ${pattern})`,
    ...(/^[0-9A-F]+$/.test(hex) ? [sql`${deviceCertificate.serial} like ${containing(hex)}`] : []),
    sql`${deviceCertificate.deviceId} ilike ${pattern}`,
  )!;
}

/** What has `status` as of `now`: the rule `toDeviceCertificate` gives each its status by, in SQL. */
function inStatus(status: DeviceCertificateStatus, now: Date): SQL {
  if (status === "revoked") return isNotNull(deviceCertificate.revokedAt);
  return and(isNull(deviceCertificate.revokedAt), status === "active" ? gt(deviceCertificate.notAfter, now) : lte(deviceCertificate.notAfter, now))!;
}

type Row = { certificate: typeof deviceCertificate.$inferSelect; issuer: string };

/** The Device Certificate as the API shows it; its status as `inStatus` finds it. */
function toDeviceCertificate({ certificate: row, issuer }: Row, now: Date): z.infer<typeof DeviceCertificate> {
  return {
    id: row.id,
    enrollmentProfileId: row.enrollmentProfileId,
    serial: row.serial,
    subject: row.subject,
    subjectAltNames: row.subjectAltNames,
    deviceId: row.deviceId,
    keyType: row.keyType,
    sharedChallenge: row.sharedChallengeId === null ? null : { id: row.sharedChallengeId },
    issuer,
    notBefore: row.notBefore.toISOString(),
    notAfter: row.notAfter.toISOString(),
    status: row.revokedAt ? "revoked" : row.notAfter <= now ? "expired" : "active",
    revocation: row.revokedAt ? { reason: row.revocationReason!, revokedAt: row.revokedAt.toISOString() } : null,
    createdAt: row.createdAt.toISOString(),
  };
}

export function registerDeviceCertificates(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  revocations: DeviceCertificateRevocations;
  clock: () => Date;
}) {
  const { app, db, requireUser, authorize, unitOfWork, revocations, clock } = ctx;

  /** A 404 unless the Organization has the profile. */
  async function requireProfile(orgId: string, id: string) {
    const [found] = isId(id)
      ? await db
          .select({ id: enrollmentProfile.id })
          .from(enrollmentProfile)
          .where(and(eq(enrollmentProfile.organizationId, orgId), eq(enrollmentProfile.id, id)))
      : [];
    if (!found) throw new HttpError(404, "Enrollment Profile not found");
  }

  const selection = { certificate: deviceCertificate, issuer: issuingCa.subject };
  const ofProfile = (orgId: string, id: string) => and(eq(deviceCertificate.organizationId, orgId), eq(deviceCertificate.enrollmentProfileId, id));

  /** The profile's Device Certificate; a 404 when it has none such. */
  async function findCertificate(orgId: string, id: string, certificateId: string): Promise<Row> {
    await requireProfile(orgId, id);
    const [row] = isId(certificateId)
      ? await db
          .select(selection)
          .from(deviceCertificate)
          .innerJoin(issuingCa, eq(issuingCa.id, deviceCertificate.issuingCaId))
          .where(and(ofProfile(orgId, id), eq(deviceCertificate.id, certificateId)))
      : [];
    if (!row) throw new HttpError(404, "Device Certificate not found");
    return row;
  }

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/enrollment-profiles/{id}/device-certificates",
      tags: ["Device Certificates"],
      summary: "The Device Certificates an Enrollment Profile issued, newest first",
      description:
        "A page at a time; `total` is how many match, whatever the page. `q` searches the subject, subject alternative names, serial and device ID; `status` keeps those `active`, `expired` or `revoked`; `weakKey` those for a weak key. They combine. " +
        "Only Organization Administrators may ask.",
      request: { params: ProfileParams, query: DeviceCertificateQuery },
      responses: { 200: json(pageOf(DeviceCertificate)), ...errors(400, 401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const query = c.req.valid("query");
      await authorize(await requireUser(c), orgId, { deviceCertificate: ["read"] });
      await requireProfile(orgId, id);
      const now = clock();
      const where = and(ofProfile(orgId, id), query.q ? matching(query.q) : undefined, query.status ? inStatus(query.status, now) : undefined, query.weakKey ? eq(deviceCertificate.keyType, WEAK_DEVICE_KEY_TYPE) : undefined);
      const [total, rows] = await Promise.all([
        db.$count(deviceCertificate, where),
        db
          .select(selection)
          .from(deviceCertificate)
          .innerJoin(issuingCa, eq(issuingCa.id, deviceCertificate.issuingCaId))
          .where(where)
          .orderBy(desc(deviceCertificate.createdAt), desc(deviceCertificate.id))
          .limit(query.pageSize)
          .offset((query.page - 1) * query.pageSize),
      ]);
      return c.json({ items: rows.map((row) => toDeviceCertificate(row, now)), total, page: query.page, pageSize: query.pageSize }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/enrollment-profiles/{id}/device-certificates/{certificateId}",
      tags: ["Device Certificates"],
      summary: "A Device Certificate",
      description: "Only Organization Administrators may ask.",
      request: { params: CertificateParams },
      responses: { 200: json(DeviceCertificate), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id, certificateId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { deviceCertificate: ["read"] });
      return c.json(toDeviceCertificate(await findCertificate(orgId, id, certificateId), clock()), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/enrollment-profiles/{id}/device-certificates/{certificateId}/certificate",
      tags: ["Device Certificates"],
      summary: "Download a Device Certificate",
      description: "PEM: the certificate alone. Its Issuing CA and root are the profile's `.../ca-certificate`. Only Organization Administrators may.",
      request: { params: CertificateParams },
      responses: { 200: { description: "The certificate, PEM", content: { "application/x-pem-file": { schema: z.string() } } }, ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id, certificateId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { deviceCertificate: ["read"] });
      const { certificate } = await findCertificate(orgId, id, certificateId);
      return c.body(certificate.certificatePem, 200, { "content-type": "application/x-pem-file", "content-disposition": `attachment; filename="${certificate.serial.toLowerCase()}.pem"` });
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/enrollment-profiles/{id}/device-certificates/{certificateId}/revocation",
      tags: ["Device Certificates"],
      summary: "Revoke a Device Certificate with an RFC 5280 reason: it is on its Issuing CA's CRL the moment this succeeds",
      description:
        "The CRL is reissued in the same change, so the Revocation is recorded, audited and published together, or not at all (502 when the KMS did not answer to sign the CRL, 422 when it refused; ask again). " +
        "The reasons a Private CA offers are taken; a revoked Device Certificate cannot be revoked again (409). Only Organization Administrators may.",
      request: {
        params: CertificateParams,
        body: { content: { "application/json": { schema: z.object({ reason: DeviceRevocationReason }) } } },
      },
      responses: { 200: json(DeviceCertificate, "Revoked"), ...errors(400, 401, 403, 404, 409, 422, 502) },
    }),
    async (c) => {
      const { orgId, id, certificateId } = c.req.valid("param");
      const { reason } = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { deviceCertificate: ["revoke"] });
      const { certificate: found } = await findCertificate(orgId, id, certificateId);

      await unitOfWork.run(actor, async (tx, change) => {
        const [revoked] = await revocations.revoke(tx, change, orgId, [{ id: found.id, reason }]).catch((err: unknown) => {
          // As when an Issuing CA is revoked: a KMS that does not answer is 502, one that says no 422.
          if (err instanceof CertificateAuthorityError) throw new HttpError(err.kind === "unreachable" ? 502 : 422, err.message);
          throw err;
        });
        if (!revoked) throw new HttpError(409, "the Device Certificate is already revoked");
      });
      return c.json(toDeviceCertificate(await findCertificate(orgId, id, certificateId), clock()), 200);
    },
  );
}
