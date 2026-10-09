// API keys: a user's key for scripts and pipelines, made with Better Auth's API-key plugin. It belongs to the person
// who made it and is scoped to one Organization, carrying the permissions that person held there when it was made; the
// Organization is in the key's metadata. Used, it acts as that person: it reaches only the Organization it was made
// for, only what its person may still do and see there, and only the routes that ask for `callerOf` (so far, the
// downloads). Keys are made and revoked through this module's routes by a signed-in person, never by a key, each
// change on the unit of work with its Audit Event; the plugin's own HTTP endpoints are not served (auth.ts).
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { eq } from "drizzle-orm";
import type { Context } from "hono";
import { API_KEY_HEADER, createAuth, type Auth, type AuthConfig } from "./auth";
import type { Authorizer } from "./authorization";
import type { Db } from "./db/client";
import { user } from "./db/schema";
import { HttpError, OrgParam, errors, json } from "./http";
import { carries, permissionsOf, type Permissions } from "./permissions";
import type { Actor, UnitOfWork } from "./unit-of-work";

const MAX_NAME_LENGTH = 100;

/** The key a request was made with, as far as the platform needs to know it. */
export interface ApiKeyUse {
  id: string;
  name: string;
  organizationId: string;
  /** What the key carries: its person's permissions in the Organization when it was made. */
  permissions: Record<string, string[]>;
}

/** Who is asking: a person with a session, or the person behind an API key. */
export interface Caller {
  user: Actor;
  apiKey: ApiKeyUse | null;
}

const ApiKeyView = z.object({
  id: z.string(),
  name: z.string(),
  start: z.string().nullable().openapi({ description: "The first characters of the key, to tell keys apart. The key itself is shown only when it is made." }),
  permissions: z.record(z.string(), z.array(z.string())).openapi({ description: "What the key carries: its person's permissions in the Organization when it was made." }),
  expiresAt: z.string().nullable(),
  createdAt: z.string(),
});
const ApiKeyParams = OrgParam.extend({ keyId: z.string().openapi({ param: { name: "keyId", in: "path" } }) });

type StoredKey = {
  id: string;
  name: string | null;
  start: string | null;
  permissions: Record<string, string[]> | null;
  metadata: Record<string, unknown> | null;
  expiresAt: Date | string | null;
  createdAt: Date | string;
};
const iso = (d: Date | string) => new Date(d).toISOString();
const toView = (key: StoredKey) => ({
  id: key.id,
  name: key.name ?? "",
  start: key.start,
  permissions: key.permissions ?? {},
  expiresAt: key.expiresAt ? iso(key.expiresAt) : null,
  createdAt: iso(key.createdAt),
});

export function registerApiKeys(ctx: {
  app: OpenAPIHono;
  db: Db;
  auth: Auth;
  authConfig: Omit<AuthConfig, "db" | "organization">;
  requireUser(c: Context): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
}) {
  const { app, db, auth, authConfig, requireUser, authorize, unitOfWork } = ctx;

  /** The keys of the signed-in person made for the Organization. */
  async function keysOf(c: Context, orgId: string): Promise<StoredKey[]> {
    const { apiKeys } = (await auth.api.listApiKeys({ headers: c.req.raw.headers, query: {} })) as unknown as { apiKeys: StoredKey[] };
    return apiKeys.filter((key) => key.metadata?.organizationId === orgId);
  }

  /**
   * Who is asking: the person behind the API key if the request carries one, or else the signed-in person. A key
   * that is not valid, is expired, revoked or over its rate limit gets no further.
   */
  async function callerOf(c: Context): Promise<Caller> {
    const key = c.req.header(API_KEY_HEADER);
    if (!key) return { user: await requireUser(c), apiKey: null };
    const verified = await auth.api.verifyApiKey({ body: { key } });
    if (!verified.valid || !verified.key) {
      const code = verified.error?.code;
      if (code === "RATE_LIMITED" || code === "USAGE_EXCEEDED") throw new HttpError(429, "too many requests with this API key");
      throw new HttpError(401, "invalid API key");
    }
    const metadata = verified.key.metadata as Record<string, unknown> | null;
    const [person] = await db.select({ id: user.id, email: user.email, banned: user.banned }).from(user).where(eq(user.id, verified.key.referenceId));
    // A person the Platform Operator banned has no sessions, and so no keys.
    if (!person || person.banned || typeof metadata?.organizationId !== "string") throw new HttpError(401, "invalid API key");
    return {
      user: { id: person.id, email: person.email },
      apiKey: {
        id: verified.key.id,
        name: verified.key.name ?? "",
        organizationId: metadata.organizationId,
        permissions: (verified.key.permissions ?? {}) as Record<string, string[]>,
      },
    };
  }

  /**
   * Whether the caller may do this in the Organization: for a person, what their role allows; for a key, that too
   * (a person who has since left, or lost the permission, has lost it for their keys) and the key must have been made
   * for this Organization and carry the permission. A key's Organization is not revealed to be anything but unknown.
   */
  async function authorizeCaller(caller: Caller, orgId: string, permissions: Permissions) {
    if (caller.apiKey) {
      if (caller.apiKey.organizationId !== orgId) throw new HttpError(404, "organization not found");
      if (!carries(caller.apiKey.permissions, permissions)) throw new HttpError(403, "not permitted");
    }
    return authorize(caller.user, orgId, permissions);
  }

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/api-keys",
      tags: ["API keys"],
      summary: "Make an API key for the Organization",
      description:
        "Any member of the Organization may. The key acts as them, carries the permissions they hold now, and works only in this Organization and only for what they may still see and do there. " +
        "It is sent in the `x-api-key` header, so far to download Certificates. Its value is in this response and nowhere else: it cannot be read again, only revoked. " +
        "A person makes and revokes keys signed in; an API key cannot.",
      request: {
        params: OrgParam,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                name: z.string().min(1).max(MAX_NAME_LENGTH).openapi({ description: "What the key is for, such as the pipeline that uses it." }),
                expiresInDays: z.number().int().min(1).max(365).optional().openapi({ description: "Left out, the key does not expire." }),
              }),
            },
          },
        },
      },
      responses: { 201: json(ApiKeyView.extend({ key: z.string() }), "Created"), ...errors(400, 401, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const { name, expiresInDays } = c.req.valid("json");
      const actor = await requireUser(c);
      const { role } = await authorize(actor, orgId);
      const permissions = permissionsOf(role);
      const created = await unitOfWork.run(actor, async (tx, change) => {
        const made = (await createAuth({ ...authConfig, db: tx }).api.createApiKey({
          body: {
            userId: actor.id,
            name,
            expiresIn: expiresInDays ? expiresInDays * 24 * 3600 : undefined,
            metadata: { organizationId: orgId },
            permissions: permissions as Record<string, string[]>,
          },
        })) as unknown as StoredKey & { key: string };
        await change.audit({
          organizationId: orgId,
          action: "api_key.created",
          target: { type: "api_key", id: made.id },
          detail: { name, expiresAt: made.expiresAt ? iso(made.expiresAt) : null, permissions },
        });
        return made;
      });
      return c.json({ ...toView(created), key: created.key }, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/api-keys",
      tags: ["API keys"],
      summary: "The caller's own API keys for the Organization",
      description: "Only the caller's: not even an Organization Administrator sees another person's keys. Their values are never shown.",
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(ApiKeyView) })), ...errors(401, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId);
      const keys = await keysOf(c, orgId);
      return c.json({ items: keys.sort((a, b) => iso(a.createdAt).localeCompare(iso(b.createdAt)) || a.id.localeCompare(b.id)).map(toView) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/api/organizations/{orgId}/api-keys/{keyId}",
      tags: ["API keys"],
      summary: "Revoke one of the caller's API keys",
      request: { params: ApiKeyParams },
      responses: { 200: json(z.object({ revoked: z.literal(true) })), ...errors(401, 404) },
    }),
    async (c) => {
      const { orgId, keyId } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId);
      const key = (await keysOf(c, orgId)).find((k) => k.id === keyId);
      if (!key) throw new HttpError(404, "API key not found");
      await unitOfWork.run(actor, async (tx, change) => {
        await createAuth({ ...authConfig, db: tx }).api.deleteApiKey({ body: { keyId }, headers: c.req.raw.headers });
        await change.audit({ organizationId: orgId, action: "api_key.revoked", target: { type: "api_key", id: keyId }, detail: { name: key.name ?? "" } });
      });
      return c.json({ revoked: true as const }, 200);
    },
  );

  return { callerOf, authorizeCaller };
}

export type ApiKeys = ReturnType<typeof registerApiKeys>;
