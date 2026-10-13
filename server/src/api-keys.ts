// API keys, for scripts and pipelines, made with Better Auth's API-key plugin in two kinds:
//  - a user's key belongs to the person who made it and is scoped to one Organization (in its metadata). It acts as that
//    person: it carries the permissions they held there when it was made, reaches only that Organization, only what the
//    person may still see and do there, and dies with their membership or a ban;
//  - an Organization's key belongs to the Organization, which only Organization Administrators make, see and revoke. It
//    acts as no one: it carries an explicit set of permissions (only downloads so far), sees every Managed Certificate
//    of the Organization, and outlives whoever made it, who is recorded in its metadata.
// Either kind opens only the routes that ask `callerOf`. Keys are made and revoked through this module's routes by a
// signed-in person, never by a key, each change on the unit of work with its Audit Event; the plugin's own HTTP
// endpoints are not served (auth.ts).
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { eq } from "drizzle-orm";
import type { Context } from "hono";
import { API_KEY_CONFIG, API_KEY_HEADER, createAuth, type Auth, type AuthConfig } from "./auth";
import type { Authorizer } from "./authorization";
import type { Db } from "./db/client";
import { user } from "./db/schema";
import { HttpError, OrgParam, PageQuery, errors, json, pageOf } from "./http";
import { carries, permissionsOf, roleCan, type Permissions } from "./permissions";
import type { Actor, UnitOfWork } from "./unit-of-work";

// The plugin's own limit on a key's name (its `maximumNameLength` default); the API refuses longer ones the same way.
const MAX_NAME_LENGTH = 32;

export const API_KEY_TYPES = ["user", "organization"] as const;
type ApiKeyType = (typeof API_KEY_TYPES)[number];

/** What an Organization's key carries: downloads, which are all a key opens so far. */
const ORGANIZATION_KEY_PERMISSIONS = { managedCertificate: ["download"] } as const satisfies Permissions;

type Person = { id: string; email: string };

/** The key a request was made with, as far as the platform needs to know it. */
export interface ApiKeyUse {
  id: string;
  name: string;
  type: ApiKeyType;
  organizationId: string;
  /** What the key carries: for a user's key, its person's permissions in the Organization when it was made. */
  permissions: Record<string, string[]>;
  /** Who made an Organization's key. */
  createdBy: Person | null;
}

/**
 * Who is asking: a person with a session, the person behind a user's API key, or, with an Organization's API key,
 * no one (`user` is null).
 */
export interface Caller {
  user: Actor | null;
  apiKey: ApiKeyUse | null;
}

const ApiKeyView = z.object({
  id: z.string(),
  type: z.enum(API_KEY_TYPES),
  name: z.string(),
  start: z.string().nullable().openapi({ description: "The first characters of the key, to tell keys apart. The key itself is shown only when it is made." }),
  permissions: z.record(z.string(), z.array(z.string())).openapi({ description: "What the key carries." }),
  createdBy: z.object({ id: z.string(), email: z.string() }).nullable().openapi({ description: "Who made an Organization's key; a user's key is its user's." }),
  expiresAt: z.string().nullable(),
  createdAt: z.string(),
});
const ApiKeyParams = OrgParam.extend({ keyId: z.string().openapi({ param: { name: "keyId", in: "path" } }) });

type StoredKey = {
  id: string;
  configId?: string | null;
  name: string | null;
  start: string | null;
  permissions: Record<string, string[]> | null;
  metadata: Record<string, unknown> | null;
  expiresAt: Date | string | null;
  createdAt: Date | string;
};
const iso = (d: Date | string) => new Date(d).toISOString();
const typeOf = (key: StoredKey): ApiKeyType => (key.configId === API_KEY_CONFIG.organization ? "organization" : "user");
const makerOf = (key: StoredKey) => (key.metadata?.createdBy as Person | undefined) ?? null;
const toView = (key: StoredKey) => ({
  id: key.id,
  type: typeOf(key),
  name: key.name ?? "",
  start: key.start,
  permissions: key.permissions ?? {},
  createdBy: typeOf(key) === "organization" ? makerOf(key) : null,
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

  /**
   * The keys the signed-in person may see in the Organization: their own, and, for those who may read them, the
   * Organization's.
   */
  async function keysOf(c: Context, actorRole: string, orgId: string): Promise<StoredKey[]> {
    const list = async (query: Record<string, string>) =>
      ((await auth.api.listApiKeys({ headers: c.req.raw.headers, query })) as unknown as { apiKeys: StoredKey[] }).apiKeys;
    const own = (await list({})).filter((key) => key.metadata?.organizationId === orgId);
    const theirs = roleCan(actorRole, { apiKey: ["read"] }) ? await list({ organizationId: orgId, configId: API_KEY_CONFIG.organization }) : [];
    return [...own, ...theirs].sort((a, b) => iso(a.createdAt).localeCompare(iso(b.createdAt)) || a.id.localeCompare(b.id));
  }

  /**
   * Who is asking: whoever the API key stands for if the request carries one, or else the signed-in person. A key that
   * is not valid, is expired, revoked or over its rate limit gets no further.
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
    const stored = verified.key as unknown as StoredKey & { referenceId: string };
    const type = typeOf(stored);
    const use = { id: stored.id, name: stored.name ?? "", type, permissions: stored.permissions ?? {}, createdBy: makerOf(stored) };
    // An Organization's key is owned by the Organization itself.
    if (type === "organization") return { user: null, apiKey: { ...use, organizationId: stored.referenceId } };

    const organizationId = stored.metadata?.organizationId;
    const [person] = await db.select({ id: user.id, email: user.email, banned: user.banned }).from(user).where(eq(user.id, stored.referenceId));
    // A person the Platform Operator banned has no sessions, and so no keys.
    if (!person || person.banned || typeof organizationId !== "string") throw new HttpError(401, "invalid API key");
    return { user: { id: person.id, email: person.email }, apiKey: { ...use, organizationId } };
  }

  /**
   * Whether the caller may do this in the Organization. A person: what their role allows. A key: it must have been made
   * for this Organization (which it is not told is anything but unknown otherwise) and carry the permission; and a user's
   * key is only as good as its person is now (one who has left, or lost the permission, has lost it for their keys).
   */
  async function authorizeCaller(caller: Caller, orgId: string, permissions: Permissions) {
    if (caller.apiKey) {
      if (caller.apiKey.organizationId !== orgId) throw new HttpError(404, "organization not found");
      if (!carries(caller.apiKey.permissions, permissions)) throw new HttpError(403, "not permitted");
    }
    if (caller.user) await authorize(caller.user, orgId, permissions);
  }

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/api-keys",
      tags: ["API keys"],
      summary: "Make an API key for the Organization",
      description:
        "A user's key (`type: user`, the default) may be made by any member of the Organization. It acts as them, carries the permissions they hold now, and works only in this Organization and only for what they may still see and do there. " +
        "An Organization's key (`type: organization`) is made by an Organization Administrator, belongs to the Organization and outlives them; it sees every Managed Certificate of the Organization and carries only downloads. " +
        "A key is sent in the `x-api-key` header, so far to download Certificates. Its value is in this response and nowhere else: it cannot be read again, only revoked. " +
        "A person makes and revokes keys signed in; an API key cannot.",
      request: {
        params: OrgParam,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                name: z.string().min(1).max(MAX_NAME_LENGTH).openapi({ description: "What the key is for, such as the pipeline that uses it." }),
                type: z.enum(API_KEY_TYPES).default("user"),
                expiresInDays: z.number().int().min(1).max(365).optional().openapi({ description: "Left out, the key does not expire." }),
              }),
            },
          },
        },
      },
      responses: { 201: json(ApiKeyView.extend({ key: z.string() }), "Created"), ...errors(400, 401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const { name, type, expiresInDays } = c.req.valid("json");
      const actor = await requireUser(c);
      const { role } = await authorize(actor, orgId, type === "organization" ? { apiKey: ["create"] } : undefined);
      const permissions: Record<string, string[]> = type === "organization" ? { managedCertificate: [...ORGANIZATION_KEY_PERMISSIONS.managedCertificate] } : permissionsOf(role);
      const created = await unitOfWork.run(actor, async (tx, change) => {
        const made = (await createAuth({ ...authConfig, db: tx }).api.createApiKey({
          body: {
            userId: actor.id,
            name,
            expiresIn: expiresInDays ? expiresInDays * 24 * 3600 : undefined,
            permissions,
            ...(type === "organization"
              ? { configId: API_KEY_CONFIG.organization, organizationId: orgId, metadata: { organizationId: orgId, createdBy: { id: actor.id, email: actor.email } } }
              : { metadata: { organizationId: orgId } }),
          },
        })) as unknown as StoredKey & { key: string };
        await change.audit({
          organizationId: orgId,
          action: "api_key.created",
          target: { type: "api_key", id: made.id },
          detail: { name, type, expiresAt: made.expiresAt ? iso(made.expiresAt) : null, permissions },
        });
        return made;
      });
      return c.json({ ...toView(created), type, createdBy: type === "organization" ? { id: actor.id, email: actor.email } : null, key: created.key }, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/api-keys",
      tags: ["API keys"],
      summary: "The API keys the caller may see in the Organization, oldest first, a page at a time",
      description:
        "The caller's own keys and, for an Organization Administrator, the Organization's keys. Not even an Organization Administrator sees another person's own keys. Their values are never shown. `total` is how many the caller may see, whatever the page.",
      request: { params: OrgParam, query: PageQuery },
      responses: { 200: json(pageOf(ApiKeyView)), ...errors(400, 401, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const { page, pageSize } = c.req.valid("query");
      const { role } = await authorize(await requireUser(c), orgId);
      // The plugin lists a person's keys in one go, so the page is cut from the whole.
      const keys = await keysOf(c, role, orgId);
      return c.json({ items: keys.slice((page - 1) * pageSize, page * pageSize).map(toView), total: keys.length, page, pageSize }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/api/organizations/{orgId}/api-keys/{keyId}",
      tags: ["API keys"],
      summary: "Revoke one of the API keys the caller may see",
      description: "The caller's own, or, for an Organization Administrator, one of the Organization's.",
      request: { params: ApiKeyParams },
      responses: { 200: json(z.object({ revoked: z.literal(true) })), ...errors(401, 404) },
    }),
    async (c) => {
      const { orgId, keyId } = c.req.valid("param");
      const actor = await requireUser(c);
      const { role } = await authorize(actor, orgId);
      const key = (await keysOf(c, role, orgId)).find((k) => k.id === keyId);
      if (!key) throw new HttpError(404, "API key not found");
      await unitOfWork.run(actor, async (tx, change) => {
        await createAuth({ ...authConfig, db: tx }).api.deleteApiKey({ body: { keyId, configId: typeOf(key) === "organization" ? API_KEY_CONFIG.organization : API_KEY_CONFIG.user }, headers: c.req.raw.headers });
        await change.audit({ organizationId: orgId, action: "api_key.revoked", target: { type: "api_key", id: keyId }, detail: { name: key.name ?? "", type: typeOf(key) } });
      });
      return c.json({ revoked: true as const }, 200);
    },
  );

  return { callerOf, authorizeCaller };
}

export type ApiKeys = ReturnType<typeof registerApiKeys>;
