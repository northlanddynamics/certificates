// An Organization's Certificate Profiles: how it issues one kind of Managed Certificate, which members request against
// instead of choosing a CA, a key algorithm, a validity and a Renewal Policy themselves. A profile fixes its issuer (an
// ACME CA the Organization has an ACME Account with, or an active Issuing CA of one of its Private CAs), the key
// algorithms a requester's key may have, the validity for a Private CA, the starting Renewal Policy, and may name a
// Team to be co-Owner of what is made from it. These are copied onto each Managed Certificate made from it (ADR 0012),
// so editing a profile changes none already made. Only Organization Administrators create and edit them; every member
// lists the enabled ones.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, eq } from "drizzle-orm";
import { isDeepStrictEqual } from "node:util";
import type { Authorizer } from "../tenancy/authorization";
import { roleCan } from "../tenancy/permissions";
import type { Db, Tx } from "../platform/db/client";
import { acmeAccount, certificateProfile, team } from "../platform/db/schema";
import { HttpError, OrgParam, errors, isUniqueViolation, json } from "../platform/http";
import type { AcmeCas } from "../issuance/acme/acme-cas";
import { issuerColumns, issuerOf, type Issuer } from "../issuance/issuer";
import { KEY_ALGORITHMS, type KeyAlgorithm } from "../pki/csr";
import { findIssuingCa, issuingCaLabel, issuingRefusal, keyAlgorithmRefusal, validityDaysField, validityRefusal } from "../private-ca/private-ca";
import { RenewalPolicy } from "./managed-certificate-reader";
import type { Actor, UnitOfWork } from "../platform/unit-of-work";

type ProfileRow = typeof certificateProfile.$inferSelect;
type Policy = z.infer<typeof RenewalPolicy>;
type TeamRef = { id: string; name: string };

const DEFAULT_RENEWAL_POLICY: Policy = { mode: "automatic", daysBeforeExpiry: 30 };

const ProfileParams = OrgParam.extend({ id: z.string().openapi({ param: { name: "id", in: "path" } }) });

const Name = z.string().trim().min(1).max(100);
const Description = z.string().trim().max(1000);
const AllowedKeyAlgorithms = z
  .array(z.enum(KEY_ALGORITHMS))
  .min(1)
  .refine((values) => new Set(values).size === values.length, "no value may be given twice")
  .openapi({ description: "The key algorithms a requester's key may have: some of those the issuer takes (an ML-DSA Private CA takes only ML-DSA ones, and every other issuer none)." });
const ValidityDays = validityDaysField.openapi({ description: "For a Private CA issuer only: how many days its Certificates are valid for, at most the Issuing CA's maximum; the Issuing CA's default when none." });
const DefaultTeamId = z.string().openapi({ description: "A Team of the Organization made co-Owner of each Managed Certificate made from the profile." });

const ProfileIssuer = z
  .discriminatedUnion("kind", [z.object({ kind: z.literal("acme"), acmeCaId: z.string().min(1) }), z.object({ kind: z.literal("private_ca"), issuingCaId: z.string() })])
  .openapi({ description: "`acme`: the ACME CA `acmeCaId`, through the Organization's ACME Account with it. `private_ca`: the Issuing CA `issuingCaId` of one of its Private CAs." });

export const CertificateProfile = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  issuer: ProfileIssuer,
  allowedKeyAlgorithms: z.array(z.enum(KEY_ALGORITHMS)),
  validityDays: z.number().int().nullable().openapi({ description: "For a Private CA issuer: how many days its Certificates are valid for; none for the Issuing CA's default, and always none for an ACME CA, which decides." }),
  renewalPolicy: RenewalPolicy.openapi({ description: "The Renewal Policy each Managed Certificate made from it starts with." }),
  defaultTeam: z.object({ id: z.string(), name: z.string() }).nullable().openapi({ description: "The Team made co-Owner of each Managed Certificate made from it; none when it names none." }),
  enabled: z.boolean().openapi({ description: "Whether members may request through it." }),
  createdAt: z.string(),
});

const policyOf = (row: ProfileRow): Policy => ({ mode: row.renewalMode, daysBeforeExpiry: row.renewalDaysBeforeExpiry });

function toProfile(row: ProfileRow, defaultTeam: TeamRef | null): z.infer<typeof CertificateProfile> {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    issuer: issuerOf(row),
    allowedKeyAlgorithms: row.allowedKeyAlgorithms,
    validityDays: row.validityDays,
    renewalPolicy: policyOf(row),
    defaultTeam,
    enabled: row.enabled,
    createdAt: row.createdAt.toISOString(),
  };
}

const isId = (id: string) => z.uuid().safeParse(id).success;

/** What a profile issues with, as it is checked against its issuer. */
type Issuing = { issuer: Issuer; allowedKeyAlgorithms: KeyAlgorithm[]; validityDays: number | null };

export function registerCertificateProfiles(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  acmeCas: AcmeCas;
}) {
  const { app, db, requireUser, authorize, unitOfWork, acmeCas } = ctx;

  /**
   * Why a profile may not issue with these: a 400 for a validity with an ACME CA, which decides its own; a 422 for an
   * ACME CA the Organization cannot use or has no ACME Account with, an Issuing CA that is not its own or does not
   * issue, a validity above the Issuing CA's maximum, or a key algorithm the issuer does not take. None when it may.
   */
  async function issuingRefused(tx: Db | Tx, orgId: string, { issuer, allowedKeyAlgorithms, validityDays }: Issuing): Promise<HttpError | undefined> {
    const keysRefusal = (on: { caKeyAlgorithm?: KeyAlgorithm; label: string }) =>
      allowedKeyAlgorithms.map((algorithm) => keyAlgorithmRefusal(algorithm, on)).find((refusal) => refusal !== undefined);
    if (issuer.kind === "acme") {
      if (validityDays !== null) return new HttpError(400, "a validity can be fixed only by a profile whose issuer is a Private CA");
      const ca = await acmeCas.find(orgId, issuer.acmeCaId);
      if (!ca) return new HttpError(422, "the Organization has no such ACME CA");
      const [account] = await tx
        .select({ id: acmeAccount.id })
        .from(acmeAccount)
        .where(and(eq(acmeAccount.organizationId, orgId), eq(acmeAccount.acmeCaId, ca.id)));
      if (!account) return new HttpError(422, `the Organization has no ACME Account with ${ca.name}; register one first`);
      const refusal = keysRefusal({ label: ca.name });
      return refusal ? new HttpError(422, refusal) : undefined;
    }
    const of = await findIssuingCa(tx, orgId, issuer.issuingCaId);
    if (!of) return new HttpError(422, "the Organization has no such Issuing CA");
    const refusal = issuingRefusal(of) ?? validityRefusal(of, validityDays) ?? keysRefusal({ caKeyAlgorithm: of.ca.keyAlgorithm, label: issuingCaLabel(of) });
    return refusal ? new HttpError(422, refusal) : undefined;
  }

  /** The Organization's Team by id; a 422 when it has none such. */
  async function teamOf(tx: Db | Tx, orgId: string, id: string): Promise<TeamRef> {
    const [row] = await tx
      .select({ id: team.id, name: team.name })
      .from(team)
      .where(and(eq(team.organizationId, orgId), eq(team.id, id)));
    if (!row) throw new HttpError(422, "the Organization has no such Team");
    return row;
  }

  /** The default Team of each profile, by its id. */
  async function defaultTeamsOf(orgId: string, rows: ProfileRow[]) {
    const named = new Map<string, TeamRef>();
    if (rows.some((row) => row.defaultTeamId !== null)) {
      for (const row of await db.select({ id: team.id, name: team.name }).from(team).where(eq(team.organizationId, orgId))) named.set(row.id, row);
    }
    return (row: ProfileRow) => (row.defaultTeamId === null ? null : (named.get(row.defaultTeamId) ?? null));
  }

  /** Whether the caller sees disabled profiles too: those who manage them do. */
  const seesDisabled = (role: string) => roleCan(role, { certificateProfile: ["update"] });

  const taken = (name: string) => new HttpError(409, `the Organization already has a Certificate Profile named ${name}`);

  /** A 409 when the Organization already has a profile with this name. */
  async function refuseTakenName(tx: Tx, orgId: string, name: string) {
    const [named] = await tx
      .select({ id: certificateProfile.id })
      .from(certificateProfile)
      .where(and(eq(certificateProfile.organizationId, orgId), eq(certificateProfile.name, name)));
    if (named) throw taken(name);
  }

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/certificate-profiles",
      tags: ["Certificate Profiles"],
      summary: "The Organization's Certificate Profiles, by name",
      description: "Everyone in the Organization may ask, and sees the enabled ones; Organization Administrators see the disabled ones too.",
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(CertificateProfile) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const { role } = await authorize(await requireUser(c), orgId, { certificateProfile: ["read"] });
      const rows = await db
        .select()
        .from(certificateProfile)
        .where(and(eq(certificateProfile.organizationId, orgId), seesDisabled(role) ? undefined : eq(certificateProfile.enabled, true)))
        .orderBy(asc(certificateProfile.name), asc(certificateProfile.id));
      const teamOfRow = await defaultTeamsOf(orgId, rows);
      return c.json({ items: rows.map((row) => toProfile(row, teamOfRow(row))) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/certificate-profiles",
      tags: ["Certificate Profiles"],
      summary: "Create a Certificate Profile",
      description:
        "`issuer` is an ACME CA the Organization has an ACME Account with, or an active Issuing CA of one of its Private CAs, under an active root (422 otherwise). " +
        "`allowedKeyAlgorithms` are some of those the issuer takes (422 otherwise): an ML-DSA Private CA takes only ML-DSA ones, every other issuer none. " +
        "`validityDays` is for a Private CA only (400 with an ACME CA), at most its Issuing CA's maximum (422 otherwise). " +
        "`renewalPolicy` is what each Managed Certificate made from it starts with (automatic, 30 days before expiry, unless given), and `defaultTeamId` a Team of the Organization (422 otherwise) made co-Owner of each. " +
        "Names are unique within the Organization (409). Only Organization Administrators may.",
      request: {
        params: OrgParam,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                name: Name,
                description: Description.default(""),
                issuer: ProfileIssuer,
                allowedKeyAlgorithms: AllowedKeyAlgorithms,
                validityDays: ValidityDays.optional(),
                renewalPolicy: RenewalPolicy.default(DEFAULT_RENEWAL_POLICY),
                defaultTeamId: DefaultTeamId.optional(),
              }),
            },
          },
        },
      },
      responses: { 201: json(CertificateProfile, "Created"), ...errors(400, 401, 403, 404, 409, 422) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { certificateProfile: ["create"] });
      const issuing: Issuing = { issuer: body.issuer, allowedKeyAlgorithms: body.allowedKeyAlgorithms, validityDays: body.validityDays ?? null };

      try {
        const { row, defaultTeam } = await unitOfWork.run(actor, async (tx, change) => {
          const refusal = await issuingRefused(tx, orgId, issuing);
          if (refusal) throw refusal;
          const defaultTeam = body.defaultTeamId === undefined ? null : await teamOf(tx, orgId, body.defaultTeamId);
          await refuseTakenName(tx, orgId, body.name);
          const [row] = await tx
            .insert(certificateProfile)
            .values({
              organizationId: orgId,
              name: body.name,
              description: body.description,
              ...issuerColumns(issuing.issuer),
              allowedKeyAlgorithms: issuing.allowedKeyAlgorithms,
              validityDays: issuing.validityDays,
              renewalMode: body.renewalPolicy.mode,
              renewalDaysBeforeExpiry: body.renewalPolicy.daysBeforeExpiry,
              defaultTeamId: defaultTeam?.id ?? null,
            })
            .returning();
          await change.audit({
            organizationId: orgId,
            action: "certificate_profile.created",
            target: { type: "certificate_profile", id: row!.id },
            detail: {
              name: body.name,
              description: body.description,
              issuer: issuing.issuer,
              allowedKeyAlgorithms: issuing.allowedKeyAlgorithms,
              validityDays: issuing.validityDays,
              renewalPolicy: body.renewalPolicy,
              defaultTeam,
            },
          });
          return { row: row!, defaultTeam };
        });
        return c.json(toProfile(row, defaultTeam), 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw taken(body.name);
        throw err;
      }
    },
  );

  /** The Organization's profile, as the caller may see it: a 404 when it has none such, or it is disabled and the caller sees only enabled ones. */
  async function findProfile(orgId: string, id: string, role: string) {
    const notFound = () => new HttpError(404, "Certificate Profile not found");
    if (!isId(id)) throw notFound();
    const [row] = await db
      .select()
      .from(certificateProfile)
      .where(and(eq(certificateProfile.organizationId, orgId), eq(certificateProfile.id, id)));
    if (!row || (!row.enabled && !seesDisabled(role))) throw notFound();
    return row;
  }

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/certificate-profiles/{id}",
      tags: ["Certificate Profiles"],
      description: "Everyone in the Organization may ask about an enabled one; only Organization Administrators about a disabled one (404 otherwise).",
      request: { params: ProfileParams },
      responses: { 200: json(CertificateProfile), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const { role } = await authorize(await requireUser(c), orgId, { certificateProfile: ["read"] });
      const row = await findProfile(orgId, id, role);
      return c.json(toProfile(row, (await defaultTeamsOf(orgId, [row]))(row)), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/api/organizations/{orgId}/certificate-profiles/{id}",
      tags: ["Certificate Profiles"],
      summary: "Edit a Certificate Profile, including pointing it at another issuer",
      description:
        "What is not given is left as it is; `validityDays` and `defaultTeamId` null remove them. A change to `issuer`, `allowedKeyAlgorithms` or `validityDays` is checked, with what is left as it is, as when a profile is created (400 or 422), so pointing it at another issuer may need its key algorithms or validity changed with it. " +
        "Managed Certificates already made from it keep what they were made with. Names are unique within the Organization (409). A change that changes nothing is not audited. Only Organization Administrators may.",
      request: {
        params: ProfileParams,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                name: Name.optional(),
                description: Description.optional(),
                issuer: ProfileIssuer.optional(),
                allowedKeyAlgorithms: AllowedKeyAlgorithms.optional(),
                validityDays: ValidityDays.nullable().optional(),
                renewalPolicy: RenewalPolicy.optional(),
                defaultTeamId: DefaultTeamId.nullable().optional(),
              }),
            },
          },
        },
      },
      responses: { 200: json(CertificateProfile, "Updated"), ...errors(400, 401, 403, 404, 409, 422) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      const { role } = await authorize(actor, orgId, { certificateProfile: ["update"] });
      await findProfile(orgId, id, role);

      try {
        const { row, defaultTeam } = await unitOfWork.run(actor, async (tx, change) => {
          // Locked, so that two edits take turns and each is checked against what the other left.
          const [current] = await tx.select().from(certificateProfile).where(eq(certificateProfile.id, id)).for("update");
          const before = toProfile(current!, current!.defaultTeamId === null ? null : await teamOf(tx, orgId, current!.defaultTeamId));
          const issuing: Issuing = {
            issuer: body.issuer ?? issuerOf(current!),
            allowedKeyAlgorithms: body.allowedKeyAlgorithms ?? current!.allowedKeyAlgorithms,
            validityDays: body.validityDays === undefined ? current!.validityDays : body.validityDays,
          };
          const after = {
            ...before,
            ...(body.name !== undefined && { name: body.name }),
            ...(body.description !== undefined && { description: body.description }),
            ...issuing,
            ...(body.renewalPolicy && { renewalPolicy: body.renewalPolicy }),
            ...(body.defaultTeamId !== undefined && { defaultTeam: body.defaultTeamId === null ? null : await teamOf(tx, orgId, body.defaultTeamId) }),
          };
          const fields = ["name", "description", "issuer", "allowedKeyAlgorithms", "validityDays", "renewalPolicy", "defaultTeam"] as const;
          const changed = fields.filter((field) => !isDeepStrictEqual(before[field], after[field]));
          if (changed.length === 0) return { row: current!, defaultTeam: before.defaultTeam };
          if (changed.some((field) => field === "issuer" || field === "allowedKeyAlgorithms" || field === "validityDays")) {
            const refusal = await issuingRefused(tx, orgId, issuing);
            if (refusal) throw refusal;
          }
          if (changed.includes("name")) await refuseTakenName(tx, orgId, after.name);
          const [row] = await tx
            .update(certificateProfile)
            .set({
              name: after.name,
              description: after.description,
              ...issuerColumns(issuing.issuer),
              allowedKeyAlgorithms: issuing.allowedKeyAlgorithms,
              validityDays: issuing.validityDays,
              renewalMode: after.renewalPolicy.mode,
              renewalDaysBeforeExpiry: after.renewalPolicy.daysBeforeExpiry,
              defaultTeamId: after.defaultTeam?.id ?? null,
            })
            .where(eq(certificateProfile.id, id))
            .returning();
          await change.audit({
            organizationId: orgId,
            action: "certificate_profile.updated",
            target: { type: "certificate_profile", id },
            detail: { name: after.name, changes: Object.fromEntries(changed.map((field) => [field, { from: before[field], to: after[field] }])) },
          });
          return { row: row!, defaultTeam: after.defaultTeam };
        });
        return c.json(toProfile(row, defaultTeam), 200);
      } catch (err) {
        if (isUniqueViolation(err)) throw taken(body.name!);
        throw err;
      }
    },
  );
}
