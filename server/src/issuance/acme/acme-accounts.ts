// The ACME CAs an Organization can use (acme-cas.ts), and its ACME Account with each, at most one per ACME CA. The
// account's key is a secret (secrets.ts): it is generated and kept by the platform, and no route returns it. It can be
// replaced with a key the CA accepts for the account, or tested, and that is all.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, eq } from "drizzle-orm";
import { createPrivateKey } from "node:crypto";
import type { Authorizer } from "../../tenancy/authorization";
import { roleCan } from "../../tenancy/permissions";
import { CertificateAuthorityError, type AcmeCertificateAuthority } from "./certificate-authority";
import { ACME_CA_TAGS, AcmeCaId, DEFAULT_ACME_CA_ID, type AcmeCa, type AcmeCas } from "./acme-cas";
import type { Db } from "../../platform/db/client";
import { acmeAccount } from "../../platform/db/schema";
import { HttpError, OrgParam, errors, isUniqueViolation, json } from "../../platform/http";
import type { Secrets } from "../../platform/crypto/secrets";
import type { Actor, UnitOfWork } from "../../platform/unit-of-work";

const AccountParams = OrgParam.extend({ accountId: z.string().openapi({ param: { name: "accountId", in: "path" } }) });
// Deliberately without any key material: this is every shape the account is ever returned in.
const Account = z.object({
  id: z.string(),
  acmeCaId: z.string().openapi({ description: "The ACME CA it is an account with." }),
  accountUrl: z.string(),
  contactEmail: z.string().nullable(),
});
const toAccount = (row: typeof acmeAccount.$inferSelect) => ({
  id: row.id,
  acmeCaId: row.acmeCaId,
  accountUrl: row.accountUrl,
  contactEmail: row.contactEmail,
});

/** A CA that says no (a rate limit, a refused key) is the caller's to fix, 422; one that does not answer is 502. */
function caFailure(err: unknown): never {
  if (!(err instanceof CertificateAuthorityError)) throw err;
  throw new HttpError(err.kind === "unreachable" ? 502 : 422, err.message);
}

const AcmeCaShown = z.object({
  id: z.string(),
  name: z.string(),
  directoryUrl: z.string().nullable().openapi({ description: "Where its ACME directory is served: its configuration, shown only to those who may read the ACME accounts, and none for anyone else." }),
  tag: z.enum(ACME_CA_TAGS).nullable().openapi({ description: "What it is for, `staging` or `production`, as a label that changes nothing about how it issues; none for an untagged one." }),
  builtIn: z.boolean().openapi({ description: "Built into the platform, the same for every Organization and read-only: Let's Encrypt Staging and Production." }),
});
const toAcmeCa = ({ id, name, directoryUrl, tag, builtIn }: AcmeCa, configurationShown: boolean) => ({ id, name, directoryUrl: configurationShown ? directoryUrl : null, tag, builtIn });

const alreadyRegistered = (ca: AcmeCa) => new HttpError(409, `the Organization already has an ACME account with ${ca.name}`);

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
  certificateAuthority: AcmeCertificateAuthority;
  acmeCas: AcmeCas;
}) {
  const { app, db, requireUser, authorize, unitOfWork, secrets, certificateAuthority: ca, acmeCas } = ctx;


  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/acme-cas",
      tags: ["ACME accounts"],
      summary: "The ACME CAs the Organization can use",
      description:
        "The built-in ones, Let's Encrypt Staging then Production. A Managed Certificate on one issues through the Organization's ACME account with it. " +
        "Anyone in the Organization may list them, to choose one for a Managed Certificate; only those who may read the ACME accounts see their configuration.",
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(AcmeCaShown) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const { role } = await authorize(await requireUser(c), orgId);
      const configurationShown = roleCan(role, { acmeAccount: ["read"] });
      return c.json({ items: (await acmeCas.list(orgId)).map((ca) => toAcmeCa(ca, configurationShown)) }, 200);
    },
  );

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
      summary: "Register the Organization's account with an ACME CA",
      description:
        "Creates the account under a key the platform generates and keeps; the key is never returned. " +
        "Let's Encrypt Staging is the default ACME CA; one the Organization cannot use is 404, and one it has an account with already is 409. The caller must agree to the CA's terms of service.",
      request: {
        params: OrgParam,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                acmeCaId: AcmeCaId.default(DEFAULT_ACME_CA_ID),
                contactEmail: z.email().optional(),
                termsOfServiceAgreed: z.literal(true),
              }),
            },
          },
        },
      },
      responses: { 201: json(Account, "Created"), ...errors(400, 401, 403, 404, 409, 422, 502) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const { acmeCaId, contactEmail } = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { acmeAccount: ["create"] });
      const acmeCa = await acmeCas.find(orgId, acmeCaId);
      if (!acmeCa) throw new HttpError(404, "ACME CA not found");
      const [existing] = await db
        .select({ id: acmeAccount.id })
        .from(acmeAccount)
        .where(and(eq(acmeAccount.organizationId, orgId), eq(acmeAccount.acmeCaId, acmeCaId)));
      if (existing) throw alreadyRegistered(acmeCa);

      const created = await ca.createAccount(acmeCa, { contactEmail }).catch((err) => caFailure(err));
      try {
        const row = await unitOfWork.run(actor, async (tx, change) => {
          const secretId = await secrets.create(tx, orgId, created.accountKey);
          const [row] = await tx
            .insert(acmeAccount)
            .values({ organizationId: orgId, acmeCaId, accountUrl: created.accountUrl, contactEmail: contactEmail ?? null, secretId })
            .returning();
          await change.audit({
            organizationId: orgId,
            action: "acme_account.created",
            target: { type: "acme_account", id: row!.id },
            detail: { acmeCaId, accountUrl: created.accountUrl, contactEmail: contactEmail ?? null },
          });
          return row!;
        });
        return c.json(toAccount(row), 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw alreadyRegistered(acmeCa);
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

      await ca.checkAccount(await acmeCas.get(orgId, account.acmeCaId), { accountUrl: account.accountUrl, accountKey }).catch((err) => caFailure(err));
      await unitOfWork.run(actor, async (tx, change) => {
        await secrets.replace(tx, orgId, account.secretId, accountKey);
        await change.audit({
          organizationId: orgId,
          action: "acme_account.key_replaced",
          target: { type: "acme_account", id: account.id },
          detail: { acmeCaId: account.acmeCaId },
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
        await ca.checkAccount(await acmeCas.get(orgId, account.acmeCaId), { accountUrl: account.accountUrl, accountKey });
        return c.json({ ok: true }, 200);
      } catch (err) {
        if (!(err instanceof CertificateAuthorityError)) throw err;
        return c.json({ ok: false, error: err.message }, 200);
      }
    },
  );
}
