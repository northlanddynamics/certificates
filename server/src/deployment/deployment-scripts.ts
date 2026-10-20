// An Organization's library of Deployment Scripts: the Bash or PowerShell an Agent runs to put a newly obtained key and
// Certificate to use. Agents run these on their hosts, so only Organization Administrators may add to the library
// (ADR 0004: the permission is `deploymentScript.upload`, which no other role holds). A script is a name and an
// interpreter; what it says is kept as versions that are only ever added, each identified by the SHA-256 of its content,
// which is what an Agent checks before it runs one.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, desc, eq, inArray, max } from "drizzle-orm";
import type { Authorizer } from "../tenancy/authorization";
import type { Db, Tx } from "../platform/db/client";
import { deploymentScript, deploymentScriptVersion } from "../platform/db/schema";
import { SCRIPT_INTERPRETERS } from "./deployment-script-kinds";
import { HttpError, OrgParam, PageQuery, anyOf, errors, isUniqueViolation, json, pageOf } from "../platform/http";
import type { Actor, Change, UnitOfWork } from "../platform/unit-of-work";
import { sha256Hex } from "../platform/crypto/sha256";
import { ScriptParameter, ScriptParametersError, declaredParameters } from "./script-parameters";


/** The hash that identifies a version: SHA-256 of the content's UTF-8 bytes, lower-case hex. */
export const scriptHash = (content: string) => sha256Hex(content);

type VersionRow = typeof deploymentScriptVersion.$inferSelect;
type ScriptRow = typeof deploymentScript.$inferSelect;

const Name = z.string().trim().min(1).max(100);
export const MAX_SCRIPT_BYTES = 256 * 1024;
const Content = z
  .string()
  .refine((c) => c.trim().length > 0, "a script cannot be empty")
  // Postgres cannot store it, and no shell script has one.
  .refine((c) => !c.includes("\u0000"), "a script cannot contain a NUL character")
  .refine((c) => Buffer.byteLength(c, "utf8") <= MAX_SCRIPT_BYTES, `a script is at most ${MAX_SCRIPT_BYTES / 1024} KiB`)
  .openapi({ description: "The script, exactly as it is to run: its bytes are what the hash identifies, so nothing is trimmed or its line endings changed. Up to 256 KiB." });
const Version = z.object({
  version: z.number().int().openapi({ description: "1 for the first, then one more each time." }),
  hash: z.string().openapi({ description: "SHA-256 of the content's UTF-8 bytes, lower-case hex: what identifies the version, and what an Agent checks before it runs it." }),
  size: z.number().int().openapi({ description: "The content's length in bytes." }),
  parameters: z.array(ScriptParameter).openapi({ description: "What the content's `# deploy-params:begin` section declares, in its order: none for a script without one." }),
  uploadedBy: z.string(),
  uploadedAt: z.string(),
});
const Script = z.object({ id: z.string(), name: Name, interpreter: z.enum(SCRIPT_INTERPRETERS), latestVersion: Version });

/** The parameters `content` declares; a section that cannot be used refuses the upload. */
function parametersOf(content: string) {
  try {
    return declaredParameters(content);
  } catch (err) {
    if (err instanceof ScriptParametersError) throw new HttpError(422, err.message);
    throw err;
  }
}

/** Adds `content` to `script` as its version `version` and audits the upload with the hash: what both ways of uploading share. */
async function addVersion(tx: Tx, change: Change, actor: Actor, script: ScriptRow, version: number, content: string, parameters: ScriptParameter[]) {
  const [row] = await tx
    .insert(deploymentScriptVersion)
    .values({
      scriptId: script.id,
      organizationId: script.organizationId,
      version,
      hash: scriptHash(content),
      content,
      size: Buffer.byteLength(content, "utf8"),
      parameters,
      uploadedById: actor.id,
      uploadedByEmail: actor.email,
      uploadedAt: change.occurredAt,
    })
    .returning();
  await change.audit({
    organizationId: script.organizationId,
    action: "deployment_script.uploaded",
    target: { type: "deployment_script", id: script.id },
    detail: { name: script.name, interpreter: script.interpreter, version, hash: row!.hash },
  });
  return row!;
}

const ScriptsQuery = PageQuery.extend({
  interpreter: anyOf(SCRIPT_INTERPRETERS).optional().meta({ description: "Those run by any of these interpreters, comma-separated." }),
});
const ScriptParams = OrgParam.extend({ scriptId: z.string().openapi({ param: { name: "scriptId", in: "path" } }) });
const VersionParams = ScriptParams.extend({ hash: z.string().openapi({ param: { name: "hash", in: "path" } }) });
const ScriptWithVersions = Script.extend({ versions: z.array(Version).openapi({ description: "Every version, newest first." }) });
const VersionWithContent = Version.extend({ content: Content });

const toVersion = (row: VersionRow) => ({ version: row.version, hash: row.hash, size: row.size, parameters: row.parameters, uploadedBy: row.uploadedByEmail, uploadedAt: row.uploadedAt.toISOString() });
const toScript = (script: ScriptRow, latest: VersionRow) => ({ id: script.id, name: script.name, interpreter: script.interpreter, latestVersion: toVersion(latest) });

export function registerDeploymentScripts(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
}) {
  const { app, db, requireUser, authorize, unitOfWork } = ctx;

  async function findScript(orgId: string, scriptId: string) {
    // Not a UUID can't be a script; asking Postgres would only raise a type error.
    const [row] = z.uuid().safeParse(scriptId).success
      ? await db.select().from(deploymentScript).where(and(eq(deploymentScript.organizationId, orgId), eq(deploymentScript.id, scriptId)))
      : [];
    if (!row) throw new HttpError(404, "Deployment Script not found");
    return row;
  }

  const versionsOf = (scriptId: string) =>
    db.select().from(deploymentScriptVersion).where(eq(deploymentScriptVersion.scriptId, scriptId)).orderBy(desc(deploymentScriptVersion.version));

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/deployment-scripts",
      tags: ["Deployment Scripts"],
      summary: "List the Deployment Scripts, oldest first, a page at a time",
      description: "Each with its latest version; the content is not included, ask for a version to see it. `total` is how many match the filter, whatever the page.",
      request: { params: OrgParam, query: ScriptsQuery },
      responses: { 200: json(pageOf(Script)), ...errors(400, 401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { deploymentScript: ["read"] });
      const { page, pageSize, interpreter } = c.req.valid("query");
      const where = and(
        eq(deploymentScript.organizationId, orgId),
        interpreter ? inArray(deploymentScript.interpreter, interpreter.split(",") as ScriptRow["interpreter"][]) : undefined,
      );
      const [total, scripts] = await Promise.all([
        db.$count(deploymentScript, where),
        db.select().from(deploymentScript).where(where).orderBy(asc(deploymentScript.createdAt), asc(deploymentScript.id)).limit(pageSize).offset((page - 1) * pageSize),
      ]);
      const latest = scripts.length === 0 ? [] : await db
        .selectDistinctOn([deploymentScriptVersion.scriptId], {
          scriptId: deploymentScriptVersion.scriptId,
          version: deploymentScriptVersion.version,
          hash: deploymentScriptVersion.hash,
          size: deploymentScriptVersion.size,
          parameters: deploymentScriptVersion.parameters,
          uploadedByEmail: deploymentScriptVersion.uploadedByEmail,
          uploadedAt: deploymentScriptVersion.uploadedAt,
        })
        .from(deploymentScriptVersion)
        .where(
          and(
            eq(deploymentScriptVersion.organizationId, orgId),
            inArray(deploymentScriptVersion.scriptId, scripts.map((s) => s.id)),
          ),
        )
        .orderBy(deploymentScriptVersion.scriptId, desc(deploymentScriptVersion.version));
      const latestOf = new Map(latest.map((v) => [v.scriptId, v]));
      return c.json({ items: scripts.map((script) => toScript(script, latestOf.get(script.id) as VersionRow)), total, page, pageSize }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/deployment-scripts/{scriptId}",
      tags: ["Deployment Scripts"],
      summary: "A Deployment Script and all its versions",
      request: { params: ScriptParams },
      responses: { 200: json(ScriptWithVersions), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, scriptId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { deploymentScript: ["read"] });
      const script = await findScript(orgId, scriptId);
      const versions = await versionsOf(script.id);
      return c.json({ ...toScript(script, versions[0]!), versions: versions.map(toVersion) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/deployment-scripts/{scriptId}/versions/{hash}",
      tags: ["Deployment Scripts"],
      summary: "One version of a Deployment Script, with its content",
      description: "Versions are never changed or removed, so an earlier one can always be seen by its hash.",
      request: { params: VersionParams },
      responses: { 200: json(VersionWithContent), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, scriptId, hash } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { deploymentScript: ["read"] });
      const script = await findScript(orgId, scriptId);
      const [row] = await db
        .select()
        .from(deploymentScriptVersion)
        .where(and(eq(deploymentScriptVersion.scriptId, script.id), eq(deploymentScriptVersion.hash, hash.toLowerCase())));
      if (!row) throw new HttpError(404, "that version of the Deployment Script was not found");
      return c.json({ ...toVersion(row), content: row.content }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/deployment-scripts/{scriptId}/versions",
      tags: ["Deployment Scripts"],
      summary: "Upload a new version of a Deployment Script",
      description:
        "Adds a version; no version is ever changed. The interpreter stays the script's own. Content the script already has is refused, " +
        "so a hash names one of its versions. A parameter section that cannot be used is refused with `422`.",
      request: { params: ScriptParams, body: { content: { "application/json": { schema: z.object({ content: Content }) } } } },
      responses: { 201: json(Script, "Created"), ...errors(400, 401, 403, 404, 409, 422) },
    }),
    async (c) => {
      const { orgId, scriptId } = c.req.valid("param");
      const { content } = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { deploymentScript: ["upload"] });
      const existing = await findScript(orgId, scriptId);
      const parameters = parametersOf(content);
      const hash = scriptHash(content);
      const added = await unitOfWork.run(actor, async (tx, change) => {
        // Under the script's row, so uploads at once are numbered one after the other.
        const [script] = await tx.select().from(deploymentScript).where(eq(deploymentScript.id, existing.id)).for("update");
        const [same] = await tx
          .select({ version: deploymentScriptVersion.version })
          .from(deploymentScriptVersion)
          .where(and(eq(deploymentScriptVersion.scriptId, existing.id), eq(deploymentScriptVersion.hash, hash)));
        if (same) throw new HttpError(409, `the script already has this content, as version ${same.version}`);
        const [last] = await tx.select({ version: max(deploymentScriptVersion.version) }).from(deploymentScriptVersion).where(eq(deploymentScriptVersion.scriptId, existing.id));
        const version = (last?.version ?? 0) + 1;
        const row = await addVersion(tx, change, actor, script!, version, content, parameters);
        return toScript(script!, row);
      });
      return c.json(added, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/deployment-scripts",
      tags: ["Deployment Scripts"],
      summary: "Upload a Deployment Script",
      description:
        "Adds a script to the library as its version 1. Upload a change to it as a new version of the same script. Parameters are declared " +
        "in a comment block of the content, `# deploy-params:begin` to `# deploy-params:end`, holding a JSON array once each line's leading " +
        "`# ` is removed; a section that cannot be used is refused with `422`.",
      request: {
        params: OrgParam,
        body: { content: { "application/json": { schema: z.object({ name: Name, interpreter: z.enum(SCRIPT_INTERPRETERS), content: Content }) } } },
      },
      responses: { 201: json(Script, "Created"), ...errors(400, 401, 403, 404, 409, 422) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const body = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { deploymentScript: ["upload"] });
      const parameters = parametersOf(body.content);
      try {
        const created = await unitOfWork.run(actor, async (tx, change) => {
          const [script] = await tx.insert(deploymentScript).values({ organizationId: orgId, name: body.name, interpreter: body.interpreter, createdAt: change.occurredAt }).returning();
          const version = await addVersion(tx, change, actor, script!, 1, body.content, parameters);
          return toScript(script!, version);
        });
        return c.json(created, 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw new HttpError(409, `the Organization already has a Deployment Script named "${body.name}"`);
        throw err;
      }
    },
  );
}
