// An Organization's settings for Certificate Profiles: so far whether a profile is required. Requiring one has whoever
// may not create a Managed Certificate outright (who lacks `managedCertificate.create`) propose one only through a
// profile, with their API keys too; the create route refuses the rest (managed-certificates.ts) and `/api/me` tells the
// caller whether they may request without one. Organization Administrators, and Name Changes, are unaffected. It is off
// by default, so that an Organization keeps working as before until an Organization Administrator turns it on.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { eq } from "drizzle-orm";
import type { Authorizer } from "../tenancy/authorization";
import type { Db, Tx } from "../platform/db/client";
import { certificateProfileSettings } from "../platform/db/schema";
import { HttpError, OrgParam, errors, json } from "../platform/http";
import type { Actor, UnitOfWork } from "../platform/unit-of-work";

const Settings = z.object({
  requireProfile: z.boolean().openapi({
    description: "Whether those who may not create a Managed Certificate outright (without `managedCertificate.create`) may propose one only through a Certificate Profile, with their API keys too.",
  }),
});
type Settings = z.infer<typeof Settings>;
const SettingsChange = Settings.partial().openapi({ description: "What to change; what is left out stays as it is." });

const DEFAULTS: Settings = { requireProfile: false };

/** The Organization's settings. */
export async function certificateProfileSettingsOf(db: Db | Tx, organizationId: string): Promise<Settings> {
  const [row] = await db
    .select({ requireProfile: certificateProfileSettings.requireProfile })
    .from(certificateProfileSettings)
    .where(eq(certificateProfileSettings.organizationId, organizationId));
  return row ?? DEFAULTS;
}

/**
 * Whether one may request a Managed Certificate without a profile under these settings: whoever may create one outright
 * (`mayCreate`) always may, anyone else only while no profile is required.
 */
export const requestsWithoutProfile = (settings: Settings, mayCreate: boolean) => mayCreate || !settings.requireProfile;

/** Why a request without a profile is refused (403) to one who may not create outright, while a profile is required. */
export const profileRequiredRefusal = () =>
  new HttpError(403, "the Organization requires a Certificate Profile: propose through one (`profileId`), or ask an Organization Administrator");

/** The Organization's settings, locked for the rest of the transaction. */
async function lockSettings(tx: Tx, organizationId: string, occurredAt: Date): Promise<Settings> {
  await tx.insert(certificateProfileSettings).values({ organizationId, updatedAt: occurredAt }).onConflictDoNothing();
  const [row] = await tx
    .select({ requireProfile: certificateProfileSettings.requireProfile })
    .from(certificateProfileSettings)
    .where(eq(certificateProfileSettings.organizationId, organizationId))
    .for("update");
  return row!;
}

export function registerCertificateProfileSettings(ctx: { app: OpenAPIHono; db: Db; requireUser(c: any): Promise<Actor>; authorize: Authorizer["authorize"]; unitOfWork: UnitOfWork }) {
  const { app, db, requireUser, authorize, unitOfWork } = ctx;

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/certificate-profile-settings",
      tags: ["Certificate Profiles"],
      summary: "The Organization's settings for Certificate Profiles",
      description: "Everyone in the Organization may ask. `/api/me` says whether the caller may request a Managed Certificate without a profile.",
      request: { params: OrgParam },
      responses: { 200: json(Settings), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { certificateProfile: ["read"] });
      return c.json(await certificateProfileSettingsOf(db, orgId), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/api/organizations/{orgId}/certificate-profile-settings",
      tags: ["Certificate Profiles"],
      summary: "Change the Organization's settings for Certificate Profiles",
      description:
        "Requiring a profile refuses (403) a request for a Managed Certificate without `profileId` from whoever may not create one outright, and from their API keys; " +
        "Organization Administrators, and Name Changes of Managed Certificates already made, are unaffected. A change is an Audit Event. Only Organization Administrators may.",
      request: { params: OrgParam, body: { content: { "application/json": { schema: SettingsChange } } } },
      responses: { 200: json(Settings), ...errors(400, 401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const asked = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { certificateProfile: ["update"] });
      const changed = await unitOfWork.run(actor, async (tx, change) => {
        // Serialises concurrent changes, so each records the value the one before left.
        const before = await lockSettings(tx, orgId, change.occurredAt);
        const after = { ...before, ...asked };
        if (after.requireProfile === before.requireProfile) return before;
        await tx.update(certificateProfileSettings).set({ ...after, updatedAt: change.occurredAt }).where(eq(certificateProfileSettings.organizationId, orgId));
        await change.audit({
          organizationId: orgId,
          action: "certificate_profile_settings.changed",
          target: { type: "organization", id: orgId },
          detail: { requireProfile: { from: before.requireProfile, to: after.requireProfile } },
        });
        return after;
      });
      return c.json(changed, 200);
    },
  );
}
