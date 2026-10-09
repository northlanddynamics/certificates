// An Organization's ACME account with its CA, in staging or production. The account's key is a secret (secrets.ts):
// it is generated and kept by the platform, and no route returns it. It can be replaced with a key the CA accepts for
// the account, or tested, and that is all.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, eq } from "drizzle-orm";
import { createPrivateKey } from "node:crypto";
import type { Authorizer } from "./authorization";
import { ACME_ENVIRONMENTS, CertificateAuthorityError, type CertificateAuthority } from "./certificate-authority";
import type { Db } from "./db/client";
import { acmeAccount } from "./db/schema";
import { HttpError, OrgParam, errors, isUniqueViolation, json } from "./http";
import type { Secrets } from "./secrets";
import type { Actor, UnitOfWork } from "./unit-of-work";

const Environment = z.enum(ACME_ENVIRONMENTS);
const AccountParams = OrgParam.extend({ accountId: z.string().openapi({ param: { name: "accountId", in: "path" } }) });
// Deliberately without any key material: this is every shape the account is ever returned in.
const Account = z.object({
  id: z.string(),
  environment: Environment,
  accountUrl: z.string(),
  contactEmail: z.string().nullable(),
});
const toAccount = (row: typeof acmeAccount.$inferSelect) => ({
  id: row.id,
  environment: row.environment as z.infer<typeof Environment>,
  accountUrl: row.accountUrl,
  contactEmail: row.contactEmail,
});

/** Whatever the CA's refusal is, as the HTTP error it should be. */
function caFailure(err: unknown, rejectedStatus: 422 | 502): never {
  if (!(err instanceof CertificateAuthorityError)) throw err;
  throw new HttpError(err.kind === "unreachable" ? 502 : rejectedStatus, err.message);
}

/** The key as PKCS#8 PEM, or null when `pem` is not a private key we can use as an account key (RSA or EC). */
function normalizeAccountKey(pem: string): string | null {
  try {
    const key = createPrivateKey(pem);
    if (key.asymmetricKeyType !== "rsa" && key.asymmetricKeyType !== "ec") return null;
    return key.export({ type: "pkcs8", format: "pem" }).toString();
  } catch {
    return null;
  }
}

export function registerAcmeAccounts(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  unitOfWork: UnitOfWork;
  secrets: Secrets;
  certificateAuthority: CertificateAuthority;
}) {
  const { app, db, requireUser, authorize, unitOfWork, secrets, certificateAuthority: ca } = ctx;

  async function findAccount(orgId: string, accountId: string) {
    // Not a UUID can't be an account; asking Postgres would only raise a type error.
    const [row] = z.uuid().safeParse(accountId).success
      ? await db.select().from(acmeAccount).where(and(eq(acmeAccount.organizationId, orgId), eq(acmeAccount.id, accountId)))
      : [];
    if (!row) throw new HttpError(404, "ACME account not found");
    return row;
  }

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/acme-accounts",
      tags: ["ACME accounts"],
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(Account) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { acmeAccount: ["read"] });
      const rows = await db
        .select()
        .from(acmeAccount)
        .where(eq(acmeAccount.organizationId, orgId))
        .orderBy(asc(acmeAccount.createdAt), asc(acmeAccount.id));
      return c.json({ items: rows.map(toAccount) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/acme-accounts",
      tags: ["ACME accounts"],
      summary: "Register the Organization's account with the CA",
      description:
        "Creates the account under a key the platform generates and keeps; the key is never returned. " +
        "Staging is the default environment. The caller must agree to the CA's terms of service.",
      request: {
        params: OrgParam,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                environment: Environment.default("staging"),
                contactEmail: z.email().optional(),
                termsOfServiceAgreed: z.literal(true),
              }),
            },
          },
        },
      },
      responses: { 201: json(Account, "Created"), ...errors(400, 401, 403, 404, 409, 502) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const { environment, contactEmail } = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { acmeAccount: ["create"] });
      const [existing] = await db
        .select({ id: acmeAccount.id })
        .from(acmeAccount)
        .where(and(eq(acmeAccount.organizationId, orgId), eq(acmeAccount.environment, environment)));
      if (existing) throw new HttpError(409, `the Organization already has a ${environment} ACME account`);

      const created = await ca.createAccount(environment, { contactEmail }).catch((err) => caFailure(err, 502));
      try {
        const row = await unitOfWork.run(actor, async (tx, change) => {
          const secretId = await secrets.create(tx, orgId, created.accountKey);
          const [row] = await tx
            .insert(acmeAccount)
            .values({ organizationId: orgId, environment, accountUrl: created.accountUrl, contactEmail: contactEmail ?? null, secretId })
            .returning();
          await change.audit({
            organizationId: orgId,
            action: "acme_account.created",
            target: { type: "acme_account", id: row!.id },
            detail: { environment, accountUrl: created.accountUrl, contactEmail: contactEmail ?? null },
          });
          return row!;
        });
        return c.json(toAccount(row), 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw new HttpError(409, `the Organization already has a ${environment} ACME account`);
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/api/organizations/{orgId}/acme-accounts/{accountId}/key",
      tags: ["ACME accounts"],
      summary: "Replace the account's key",
      description:
        "For when the account's key was changed at the CA. The new key (a PEM private key, RSA or EC) is checked " +
        "against the CA first and replaces the stored key only if the CA accepts it for this account. " +
        "Keys are write-only: nothing returns the stored one.",
      request: {
        params: AccountParams,
        body: { content: { "application/json": { schema: z.object({ privateKey: z.string().min(1) }) } } },
      },
      responses: { 200: json(Account), ...errors(400, 401, 403, 404, 422, 502) },
    }),
    async (c) => {
      const { orgId, accountId } = c.req.valid("param");
      const { privateKey } = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { acmeAccount: ["update"] });
      const account = await findAccount(orgId, accountId);
      const accountKey = normalizeAccountKey(privateKey);
      if (!accountKey) throw new HttpError(400, "not a usable private key (PEM, RSA or EC)");

      const environment = account.environment as z.infer<typeof Environment>;
      await ca.checkAccount(environment, { accountUrl: account.accountUrl, accountKey }).catch((err) => caFailure(err, 422));
      await unitOfWork.run(actor, async (tx, change) => {
        await secrets.replace(tx, orgId, account.secretId, accountKey);
        await change.audit({
          organizationId: orgId,
          action: "acme_account.key_replaced",
          target: { type: "acme_account", id: account.id },
          detail: { environment },
        });
      });
      return c.json(toAccount(account), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/acme-accounts/{accountId}/test",
      tags: ["ACME accounts"],
      summary: "Check that the stored key still works at the CA",
      request: { params: AccountParams },
      responses: {
        200: json(z.object({ ok: z.boolean(), error: z.string().optional() }), "Whether the CA accepts the stored key"),
        ...errors(401, 403, 404),
      },
    }),
    async (c) => {
      const { orgId, accountId } = c.req.valid("param");
      await authorize(await requireUser(c), orgId, { acmeAccount: ["test"] });
      const account = await findAccount(orgId, accountId);
      const accountKey = await secrets.open(db, orgId, account.secretId);
      try {
        await ca.checkAccount(account.environment as z.infer<typeof Environment>, { accountUrl: account.accountUrl, accountKey });
        return c.json({ ok: true }, 200);
      } catch (err) {
        if (!(err instanceof CertificateAuthorityError)) throw err;
        return c.json({ ok: false, error: err.message }, 200);
      }
    },
  );
}
