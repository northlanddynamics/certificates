// The ACME CAs an Organization can use (acme-cas.ts), and its ACME Account with each, at most one per ACME CA. A custom
// ACME CA is created together with its account, in one change: one the CA will not register is not saved. The
// account's key is a secret (secrets.ts): it is generated and kept by the platform, and no route returns it. It can be
// replaced with a key the CA accepts for the account, or tested, and that is all. So is the HMAC key of the External
// Account Binding a custom ACME CA may require: given once, when the CA is added, and never returned.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, eq } from "drizzle-orm";
import { createPrivateKey } from "node:crypto";
import type { Authorizer } from "../../tenancy/authorization";
import { roleCan } from "../../tenancy/permissions";
import { CertificateAuthorityError, type AcmeCertificateAuthority, type CaAccount } from "./certificate-authority";
import { ACME_CA_TAGS, AcmeCaId, BUILT_IN_ACME_CAS, DEFAULT_ACME_CA_ID, customAcmeCa, type AcmeCa, type AcmeCas } from "./acme-cas";
import type { Db, Tx } from "../../platform/db/client";
import { acmeAccount, acmeCa as acmeCaTable } from "../../platform/db/schema";
import { HttpError, OrgParam, errors, isUniqueViolation, json } from "../../platform/http";
import type { Secrets } from "../../platform/crypto/secrets";
import type { Actor, Change, UnitOfWork } from "../../platform/unit-of-work";

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
  builtIn: z.boolean().openapi({ description: "Built into the platform, the same for every Organization and read-only: Let's Encrypt Staging and Production. A custom one is the Organization's own." }),
  externalAccountBinding: z
    .object({ keyId: z.string() })
    .nullable()
    .openapi({ description: "The key id of the External Account Binding its account was registered with, shown like the directory URL; never its HMAC key. None when there was none." }),
  hasAccount: z.boolean().openapi({ description: "Whether the Organization has an ACME account with it, without which a Managed Certificate on it cannot be issued. A custom one always has." }),
});
const toAcmeCa = ({ id, name, directoryUrl, tag, externalAccountKeyId, builtIn }: AcmeCa, { configurationShown, hasAccount }: { configurationShown: boolean; hasAccount: boolean }) => ({
  id,
  name,
  directoryUrl: configurationShown ? directoryUrl : null,
  tag,
  builtIn,
  hasAccount,
  externalAccountBinding: configurationShown && externalAccountKeyId ? { keyId: externalAccountKeyId } : null,
});

const alreadyRegistered = (ca: AcmeCa) => new HttpError(409, `the Organization already has an ACME account with ${ca.name}`);
const nameTaken = (name: string) => new HttpError(409, `there is already an ACME CA named ${name}`);

const NewAcmeCa = z.object({
  name: z.string().trim().min(1).max(100),
  directoryUrl: z
    .url()
    .refine((url) => url.startsWith("https://"), "the directory URL must be https")
    .openapi({ description: "Where the CA's ACME directory is served: https, and not at a loopback or link-local address (refused with 422). Fixed once created." }),
  tag: z.enum(ACME_CA_TAGS).nullable().default(null).openapi({ description: "What it is for, `staging` or `production`, or none: a label that changes nothing about how it issues." }),
  externalAccountBinding: z
    .object({
      keyId: z.string().trim().min(1).max(1000),
      hmacKey: z
        .string()
        .trim()
        // base64url, as RFC 8555 has it; plain base64, which some CAs hand out, is taken too.
        .regex(/^[A-Za-z0-9_\-+/]+={0,2}$/, "the HMAC key must be base64 or base64url, as the CA gives it")
        .openapi({ description: "Write-only: kept as a secret and never returned." }),
    })
    .optional()
    .openapi({ description: "For a CA that requires External Account Binding: the key id and HMAC key it issued, given together. Fixed once created." }),
  contactEmail: z.email().optional(),
  termsOfServiceAgreed: z.literal(true),
});

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

  /** Saves the account the CA registered, its key as a secret, and audits it, in the change at hand. */
  async function saveAccount(tx: Tx, change: Change, orgId: string, acmeCaId: string, created: CaAccount, contactEmail: string | undefined) {
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
  }


  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/acme-cas",
      tags: ["ACME accounts"],
      summary: "The ACME CAs the Organization can use",
      description:
        "The built-in ones, Let's Encrypt Staging then Production, then the Organization's custom ones in the order they were added. A Managed Certificate on one issues through the Organization's ACME account with it. " +
        "Anyone in the Organization may list them, and see which it has an account with, to choose one for a Managed Certificate; only those who may read the ACME accounts see their configuration.",
      request: { params: OrgParam },
      responses: { 200: json(z.object({ items: z.array(AcmeCaShown) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const { role } = await authorize(await requireUser(c), orgId);
      const configurationShown = roleCan(role, { acmeAccount: ["read"] });
      const registered = new Set((await db.select({ acmeCaId: acmeAccount.acmeCaId }).from(acmeAccount).where(eq(acmeAccount.organizationId, orgId))).map((a) => a.acmeCaId));
      return c.json({ items: (await acmeCas.list(orgId)).map((ca) => toAcmeCa(ca, { configurationShown, hasAccount: registered.has(ca.id) })) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/acme-cas",
      tags: ["ACME accounts"],
      summary: "Add a custom ACME CA and register the Organization's account with it",
      description:
        "One change: the platform registers an account with the CA under a key it generates and keeps (never returned), and saves the CA and the account only once the CA has accepted it. " +
        "A CA that refuses is 422 with its reason, one that does not answer is 502, and either way nothing is saved. Names are unique within the Organization, the built-in ones' included (409). " +
        "A CA that requires External Account Binding is given its key id and HMAC key; the HMAC key is kept as a secret and never returned. " +
        "The caller must agree to the CA's terms of service.",
      request: { params: OrgParam, body: { content: { "application/json": { schema: NewAcmeCa } } } },
      responses: { 201: json(z.object({ acmeCa: AcmeCaShown, account: Account }), "Created"), ...errors(400, 401, 403, 404, 409, 422, 502) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const { name, directoryUrl, tag, externalAccountBinding, contactEmail } = c.req.valid("json");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { acmeAccount: ["create"] });
      // Checked before the CA is asked, so that a name taken already leaves no account behind at the CA.
      const [sameName] = await db.select({ id: acmeCaTable.id }).from(acmeCaTable).where(and(eq(acmeCaTable.organizationId, orgId), eq(acmeCaTable.name, name)));
      if (sameName || BUILT_IN_ACME_CAS.some((ca) => ca.name === name)) throw nameTaken(name);

      // Not saved yet, so it has no id; registering needs only where it is, and it is checked there as a custom one.
      const externalAccountKeyId = externalAccountBinding?.keyId ?? null;
      const created = await ca
        .createAccount({ id: "", name, directoryUrl, tag, externalAccountKeyId, builtIn: false }, { contactEmail, externalAccountBinding })
        .catch((err) => caFailure(err));
      try {
        const { caRow, accountRow } = await unitOfWork.run(actor, async (tx, change) => {
          const externalAccountSecretId = externalAccountBinding ? await secrets.create(tx, orgId, externalAccountBinding.hmacKey) : null;
          const [caRow] = await tx.insert(acmeCaTable).values({ organizationId: orgId, name, directoryUrl, tag, externalAccountKeyId, externalAccountSecretId }).returning();
          await change.audit({
            organizationId: orgId,
            action: "acme_ca.created",
            target: { type: "acme_ca", id: caRow!.id },
            detail: { name, directoryUrl, tag, externalAccountBinding: externalAccountKeyId ? { keyId: externalAccountKeyId } : null },
          });
          return { caRow: caRow!, accountRow: await saveAccount(tx, change, orgId, caRow!.id, created, contactEmail) };
        });
        return c.json({ acmeCa: toAcmeCa(customAcmeCa(caRow), { configurationShown: true, hasAccount: true }), account: toAccount(accountRow) }, 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw nameTaken(name);
        throw err;
      }
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
        "Let's Encrypt Staging is the default ACME CA; one the Organization cannot use is 404, and one it has an account with already is 409 (a custom ACME CA has its account from when it was added). The caller must agree to the CA's terms of service.",
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
        const row = await unitOfWork.run(actor, (tx, change) => saveAccount(tx, change, orgId, acmeCaId, created, contactEmail));
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
