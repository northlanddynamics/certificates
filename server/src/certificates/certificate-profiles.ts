// An Organization's Certificate Profiles: how it issues one kind of Managed Certificate, which members request against
// instead of choosing a CA, a key algorithm, a validity and a Renewal Policy themselves. A profile fixes its issuer (an
// ACME CA the Organization has an ACME Account with, or an active Issuing CA of one of its Private CAs), the key
// algorithms a requester's key may have, the validity for a Private CA, the starting Renewal Policy, and may name a
// Team to be co-Owner of what is made from it. These are copied onto each Managed Certificate made from it (ADR 0012),
// so editing a profile changes none already made. Its name rules (profile-name-rules.ts) are not copied: a
// non-administrator's request and Name Change keep to them as they are now, as is whether it is enabled: while it is
// disabled nothing is issued under it (issuance.ts refuses to begin). Only Organization Administrators create, edit,
// disable and enable them; every member lists the enabled ones.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, count, eq, inArray, isNull } from "drizzle-orm";
import { isDeepStrictEqual } from "node:util";
import type { Authorizer } from "../tenancy/authorization";
import { roleCan } from "../tenancy/permissions";
import type { Db, Tx } from "../platform/db/client";
import { acmeAccount, certificateProfile, managedCertificate, nameChange, team } from "../platform/db/schema";
import { HttpError, OrgParam, errors, isUniqueViolation, json } from "../platform/http";
import type { AcmeCas } from "../issuance/acme/acme-cas";
import { issuerColumns, issuerOf, type Issuer } from "../issuance/issuer";
import { KEY_ALGORITHMS, type KeyAlgorithm } from "../pki/csr";
import { findIssuingCa, issuingCaLabel, issuingRefusal, keyAlgorithmRefusal, validityDaysField, validityRefusal } from "../private-ca/private-ca";
import { RenewalPolicy } from "./managed-certificate-reader";
import { NO_NAME_RULES, ProfileNameRulesField, ProfileNameRulesShown, normalizeProfileNameRules, profileNamesRefusal, type ProfileNameRules } from "./profile-name-rules";
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
  nameRules: ProfileNameRulesShown.openapi({
    description:
      "What a non-administrator's names must keep to when they request through it, and in a Name Change of what was made from it, as the rules are now: " +
      "within `exact` or `zones` (any name when both are empty), at most `maxNames` of them, and no wildcard unless `wildcards`. The issuer's limits still apply.",
  }),
  enabled: z.boolean().openapi({ description: "Whether anything is issued under it: while it is disabled, nobody may request through it and nothing made from it is approved, has its names changed or renews." }),
  createdAt: z.string(),
});

const CertificateProfileRead = CertificateProfile.extend({
  linked: z
    .number()
    .int()
    .openapi({ description: "How many live (approved, not archived) Managed Certificates were made from it and are still linked to it: those that stop renewing while it is disabled." }),
  pending: z
    .object({ proposals: z.number().int(), nameChanges: z.number().int() })
    .openapi({ description: "How many Proposals through it, and Name Changes of Managed Certificates made from it, await Approval: what disabling it holds, as they cannot be approved while it is disabled." }),
});

const policyOf = (row: ProfileRow): Policy => ({ mode: row.renewalMode, daysBeforeExpiry: row.renewalDaysBeforeExpiry });
export const nameRulesOf = (row: ProfileRow): ProfileNameRules => ({ exact: row.allowedExactNames, zones: row.allowedZones, maxNames: row.maxNames, wildcards: row.wildcardsAllowed });
const nameRulesColumns = (rules: ProfileNameRules) => ({ allowedExactNames: rules.exact, allowedZones: rules.zones, maxNames: rules.maxNames, wildcardsAllowed: rules.wildcards });

/** The rules given, normalised; a 400 when they cannot be rules. */
function nameRulesAsked(rules: ProfileNameRules): ProfileNameRules {
  const normal = normalizeProfileNameRules(rules);
  if ("invalid" in normal) throw new HttpError(400, normal.invalid);
  return normal.rules;
}

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
    nameRules: nameRulesOf(row),
    enabled: row.enabled,
    createdAt: row.createdAt.toISOString(),
  };
}

const isId = (id: string) => z.uuid().safeParse(id).success;

/** Whether the Organization has an ACME Account with the ACME CA. */
async function hasAcmeAccount(tx: Db | Tx, orgId: string, acmeCaId: string) {
  const [account] = await tx
    .select({ id: acmeAccount.id })
    .from(acmeAccount)
    .where(and(eq(acmeAccount.organizationId, orgId), eq(acmeAccount.acmeCaId, acmeCaId)));
  return account !== undefined;
}

const noAcmeAccount = (caName: string) => `the Organization has no ACME Account with ${caName}; register one first`;

/** Why nothing may be issued under the profile now, naming it; none when it is enabled. */
export const disabledRefusal = (profile: { name: string; enabled: boolean }) =>
  profile.enabled ? undefined : `the Certificate Profile ${profile.name} is disabled, so nothing is issued under it`;

/** What a Managed Certificate requested through a profile is made with, copied from it (ADR 0012). */
export type RequestedThrough = {
  profile: { id: string; name: string };
  issuer: Issuer;
  validityDays: number | null;
  renewalPolicy: Policy;
  defaultTeamId: string | null;
  nameRules: ProfileNameRules;
};

/**
 * The Organization's profile a Managed Certificate with a key of `keyAlgorithm` is requested through, and what it is
 * made with. A 422 when the Organization has no such profile, it is disabled, it does not allow the key algorithm, or its
 * issuer is no longer usable: an ACME CA the Organization has no ACME Account with, or an Issuing CA that does not issue.
 * The names, the CSR, the profile's name rules (for a non-administrator) and the issuer's own limits are the request's to check.
 */
export async function requestedThrough(db: Db | Tx, acmeCas: AcmeCas, orgId: string, profileId: string, keyAlgorithm: KeyAlgorithm): Promise<RequestedThrough> {
  const [row] = isId(profileId)
    ? await db
        .select()
        .from(certificateProfile)
        .where(and(eq(certificateProfile.organizationId, orgId), eq(certificateProfile.id, profileId)))
    : [];
  // A disabled profile is as good as none to those who may not see it, and refused to everyone.
  if (!row) throw new HttpError(422, "the Organization has no such Certificate Profile");
  const disabled = disabledRefusal(row);
  if (disabled) throw new HttpError(422, disabled);
  if (!row.allowedKeyAlgorithms.includes(keyAlgorithm)) {
    throw new HttpError(422, `the Certificate Profile ${row.name} allows keys of ${row.allowedKeyAlgorithms.join(", ")}, not ${keyAlgorithm}`);
  }
  const issuer = issuerOf(row);
  const unusable = (why: string) => new HttpError(422, `the Certificate Profile ${row.name} cannot issue now: ${why}`);
  if (issuer.kind === "acme") {
    const ca = await acmeCas.find(orgId, issuer.acmeCaId);
    if (!ca) throw unusable("the Organization has no such ACME CA");
    if (!(await hasAcmeAccount(db, orgId, ca.id))) throw unusable(noAcmeAccount(ca.name));
  } else {
    const of = await findIssuingCa(db, orgId, issuer.issuingCaId);
    const refusal = of ? issuingRefusal(of) : "the Organization has no such Issuing CA";
    if (refusal) throw unusable(refusal);
  }
  return { profile: { id: row.id, name: row.name }, issuer, validityDays: row.validityDays, renewalPolicy: policyOf(row), defaultTeamId: row.defaultTeamId, nameRules: nameRulesOf(row) };
}

/**
 * Why a Managed Certificate made from the profile `profileId` may not have its names changed to these (normalised): the
 * profile is disabled, for everyone; or, for a non-administrator (`heldToNameRules`), the names its name rules, as they
 * are now, do not allow. None when it may.
 */
export async function profileNameChangeRefusal(db: Db | Tx, profileId: string, names: string[], heldToNameRules: boolean) {
  const [row] = await db.select().from(certificateProfile).where(eq(certificateProfile.id, profileId));
  return disabledRefusal(row!) ?? (heldToNameRules ? profileNamesRefusal(row!.name, nameRulesOf(row!), names) : undefined);
}

/** The profile's Managed Certificates that are not archived. */
const liveOf = (profileId: string) => and(eq(managedCertificate.certificateProfileId, profileId), isNull(managedCertificate.archivedAt));

/** How many live Managed Certificates are linked to the profile: approved, or made without needing Approval, and not archived. */
async function linkedOf(db: Db, profileId: string) {
  const [linked] = await db
    .select({ n: count() })
    .from(managedCertificate)
    .where(and(liveOf(profileId), inArray(managedCertificate.approvalStatus, ["approved", "not_required"])));
  return linked!.n;
}

/** How many Proposals through the profile, and Name Changes of what was made from it, await Approval; not those of an archived Managed Certificate, which cannot be approved. */
async function pendingOf(db: Db, profileId: string) {
  const live = liveOf(profileId);
  const [proposals] = await db
    .select({ n: count() })
    .from(managedCertificate)
    .where(and(live, eq(managedCertificate.approvalStatus, "pending")));
  const [nameChanges] = await db
    .select({ n: count() })
    .from(nameChange)
    .innerJoin(managedCertificate, and(eq(managedCertificate.id, nameChange.managedCertificateId), eq(managedCertificate.organizationId, nameChange.organizationId)))
    .where(and(live, eq(nameChange.status, "pending")));
  return { proposals: proposals!.n, nameChanges: nameChanges!.n };
}

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
      if (!(await hasAcmeAccount(tx, orgId, ca.id))) return new HttpError(422, noAcmeAccount(ca.name));
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
        "`nameRules` limit the names a non-administrator may request through it (none unless given); ones that are not names, or a wildcard among `exact` when `wildcards` is off, are refused with 400. " +
        "Its issuer, the requester's key algorithm, its validity and its Renewal Policy are copied onto each Managed Certificate made from it, so editing it later changes none of them; " +
        "its name rules and whether it is enabled are checked live, on each request through it and each Name Change of what was made from it. While it is disabled nothing is issued under it, Renewal included (ADR 0012). " +
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
                nameRules: ProfileNameRulesField.optional(),
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
      const nameRules = body.nameRules ? nameRulesAsked(body.nameRules) : NO_NAME_RULES;

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
              ...nameRulesColumns(nameRules),
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
              nameRules,
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
      summary: "A Certificate Profile, with what disabling it would stop",
      description:
        "Everyone in the Organization may ask about an enabled one; only Organization Administrators about a disabled one (404 otherwise). " +
        "`linked` counts the live Managed Certificates made from it, which stop renewing while it is disabled, and `pending` what awaits Approval under it, which disabling it would hold.",
      request: { params: ProfileParams },
      responses: { 200: json(CertificateProfileRead), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const { role } = await authorize(await requireUser(c), orgId, { certificateProfile: ["read"] });
      const row = await findProfile(orgId, id, role);
      return c.json({ ...toProfile(row, (await defaultTeamsOf(orgId, [row]))(row)), linked: await linkedOf(db, row.id), pending: await pendingOf(db, row.id) }, 200);
    },
  );

  for (const enabled of [false, true]) {
    const verb = enabled ? "enable" : "disable";
    app.openapi(
      createRoute({
        method: "post",
        path: `/api/organizations/{orgId}/certificate-profiles/{id}/${verb}`,
        tags: ["Certificate Profiles"],
        summary: enabled ? "Enable a disabled Certificate Profile again" : "Disable a Certificate Profile: nothing more is issued under it until it is enabled again",
        description: enabled
          ? "Members see it again and may request through it, and the Proposals and Name Changes from it that are pending may be approved again; the Managed Certificates made from it renew again, a due one on the scheduler's next pass. 409 when it is already enabled. Only Organization Administrators may."
          : "Every request through it is refused (422), Organization Administrators' too, and members no longer see it. Proposals through it, and Name Changes of Managed Certificates made from it, " +
            "stay pending: they may be rejected, and approving one is refused (422) until it is enabled again. The live Managed Certificates made from it stop renewing: the scheduler marks a due one " +
            "as blocked and tells its Subscribers once, and \"Renew now\" is refused (422), until it is enabled again or the Managed Certificate is detached from it. Reading it counts both. 409 when it is already disabled. Only Organization Administrators may.",
        request: { params: ProfileParams },
        responses: { 200: json(CertificateProfile, enabled ? "Enabled" : "Disabled"), ...errors(401, 403, 404, 409) },
      }),
      async (c) => {
        const { orgId, id } = c.req.valid("param");
        const actor = await requireUser(c);
        const { role } = await authorize(actor, orgId, { certificateProfile: ["disable"] });
        await findProfile(orgId, id, role);
        const row = await unitOfWork.run(actor, async (tx, change) => {
          // Locked, so that an Issuance beginning under it (which reads it under a share lock) sees it as it is after this.
          const [current] = await tx.select().from(certificateProfile).where(eq(certificateProfile.id, id)).for("update");
          if (current!.enabled === enabled) throw new HttpError(409, `the Certificate Profile is already ${enabled ? "enabled" : "disabled"}`);
          const [row] = await tx.update(certificateProfile).set({ enabled }).where(eq(certificateProfile.id, id)).returning();
          await change.audit({
            organizationId: orgId,
            action: enabled ? "certificate_profile.enabled" : "certificate_profile.disabled",
            target: { type: "certificate_profile", id },
            detail: { name: current!.name },
          });
          return row!;
        });
        return c.json(toProfile(row, (await defaultTeamsOf(orgId, [row]))(row)), 200);
      },
    );
  }

  app.openapi(
    createRoute({
      method: "patch",
      path: "/api/organizations/{orgId}/certificate-profiles/{id}",
      tags: ["Certificate Profiles"],
      summary: "Edit a Certificate Profile, including pointing it at another issuer",
      description:
        "What is not given is left as it is; `validityDays` and `defaultTeamId` null remove them. A change to `issuer`, `allowedKeyAlgorithms` or `validityDays` is checked, with what is left as it is, as when a profile is created (400 or 422), so pointing it at another issuer may need its key algorithms or validity changed with it. " +
        "`nameRules` replaces its name rules, checked as when a profile is created; it changes no pending Proposal, and the next request or Name Change keeps to the new ones. " +
        "Managed Certificates already made from it keep the issuer, key algorithm, validity and Renewal Policy they were made with; its name rules, as they are now, still bind a non-administrator's Name Change of one. Names are unique within the Organization (409). A change that changes nothing is not audited. Only Organization Administrators may.",
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
                nameRules: ProfileNameRulesField.optional(),
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
      const nameRules = body.nameRules && nameRulesAsked(body.nameRules);

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
            ...(nameRules && { nameRules }),
          };
          const fields = ["name", "description", "issuer", "allowedKeyAlgorithms", "validityDays", "renewalPolicy", "defaultTeam", "nameRules"] as const;
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
              ...nameRulesColumns(after.nameRules),
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
