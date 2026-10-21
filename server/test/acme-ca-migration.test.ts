// The migration that makes Let's Encrypt two built-in ACME CAs (0048): a database holding ACME accounts, a Managed
// Certificate and its issued Certificate in the shape from before, where each was in an environment, staging or
// production, is migrated, and the platform then shows each with the built-in ACME CA of that environment, and renews
// and revokes through the same account. It runs on a database of its own, made here, migrated first to the migration
// before (0047); the data from before is written as that version stored it, the only way there is to have it.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import acme from "acme-client";
import { randomBytes } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { Pool } from "pg";
import { createDb } from "../src/platform/db/client";
import { createLocalKms } from "../src/platform/crypto/kms";
import { createSecrets } from "../src/platform/crypto/secrets";
import { runMigrations } from "../src/platform/migrate";
import { BIND, PASSWORD, PEBBLE_DIRECTORY, TEST_DATABASE_URL, TEST_KMS_KEY, createHarness, type Harness } from "./support/harness";

const DATABASE = "certs_test_acme_ca_migration";
const databaseUrl = (() => {
  const url = new URL(TEST_DATABASE_URL);
  url.pathname = `/${DATABASE}`;
  return url.toString();
})();
const MIGRATIONS = join(import.meta.dir, "..", "drizzle");
/** The last migration before ACME CAs replaced environments. */
const BEFORE = "0047_deployment_parameters";

let server: Pool;
let h: Harness;

/** Migrates the database to `BEFORE`, from a copy of the migrations that ends there. */
async function migrateToBefore() {
  const folder = mkdtempSync(join(tmpdir(), "migrations-"));
  try {
    cpSync(MIGRATIONS, folder, { recursive: true });
    const journalPath = join(folder, "meta", "_journal.json");
    const journal = JSON.parse(readFileSync(journalPath, "utf8")) as { entries: { tag: string }[] };
    journal.entries = journal.entries.slice(0, journal.entries.findIndex((e) => e.tag === BEFORE) + 1);
    writeFileSync(journalPath, JSON.stringify(journal));
    const pool = new Pool({ connectionString: databaseUrl });
    await migrate(createDb(pool), { migrationsFolder: folder });
    await pool.end();
  } finally {
    rmSync(folder, { recursive: true, force: true });
  }
}

beforeAll(async () => {
  server = new Pool({ connectionString: TEST_DATABASE_URL });
  await server.query(`drop database if exists ${DATABASE} with (force)`);
  await server.query(`create database ${DATABASE}`);
  await migrateToBefore();
  h = await createHarness({}, { databaseUrl, migrate: false });
});
// The database is left for the next run to drop, before it connects: dropping it here, with force, would cut off the
// harness's connections while they close.
afterAll(async () => {
  await h?.close();
  await server.end();
});

/**
 * What the platform stored before the migration: a staging ACME account registered at the CA (Pebble), with its key a
 * secret, a production one, a Managed Certificate in staging, and a Certificate it had through the staging account.
 */
async function storeOldShape(orgId: string) {
  const secrets = createSecrets(createLocalKms(TEST_KMS_KEY));
  const accountKey = (await acme.crypto.createPrivateEcdsaKey("P-256")).toString();
  const client = new acme.Client({ directoryUrl: PEBBLE_DIRECTORY, accountKey });
  await client.createAccount({ termsOfServiceAgreed: true });
  const accountUrl = client.getAccountUrl();
  const account = async (environment: string, url: string, key: string) => {
    const secretId = await h.db.transaction((tx) => secrets.create(tx, orgId, key));
    const {
      rows: [row],
    } = await h.pool.query(`insert into acme_account (organization_id, environment, account_url, contact_email, secret_id) values ($1, $2, $3, 'pki@acme.test', $4) returning id`, [
      orgId,
      environment,
      url,
      secretId,
    ]);
    return row.id as string;
  };
  const stagingAccountId = await account("staging", accountUrl, accountKey);
  const productionAccountId = await account("production", "https://acme.test/acct/2", (await acme.crypto.createPrivateEcdsaKey("P-256")).toString());

  const name = `t${randomBytes(5).toString("hex")}.${BIND.zone}`;
  const [, csr] = await acme.crypto.createCsr({ commonName: name, altNames: [name] }, await acme.crypto.createPrivateEcdsaKey("P-256"));
  const {
    rows: [mc],
  } = await h.pool.query(
    `insert into managed_certificate (organization_id, names, key_algorithm, key_custody, issuer_kind, environment, csr) values ($1, $2, 'ecdsa-p256', 'owner', 'acme', 'staging', $3) returning id`,
    [orgId, [name], csr.toString()],
  );
  const issuedAt = new Date("2026-01-01T00:00:00Z");
  const {
    rows: [certificate],
  } = await h.pool.query(
    `insert into certificate (organization_id, managed_certificate_id, fingerprint, serial, not_before, not_after, names, chain_pem, ca, issuer_kind, environment, acme_account_id, issued_at)
     values ($1, $2, $3, '01', $4, $5, $6, 'not-a-chain', 'lets-encrypt', 'acme', 'staging', $7, $4) returning id`,
    [orgId, mc.id, randomBytes(32).toString("hex"), issuedAt, new Date("2026-04-01T00:00:00Z"), [name], stagingAccountId],
  );
  await h.pool.query(`insert into issuance (organization_id, managed_certificate_id, status, kind, certificate_id, started_at, finished_at) values ($1, $2, 'succeeded', 'first_issue', $3, $4, $4)`, [
    orgId,
    mc.id,
    certificate.id,
    issuedAt,
  ]);
  return { stagingAccountId, productionAccountId, accountUrl, managedCertificateId: mc.id as string, certificateId: certificate.id as string };
}

describe("migrating ACME environments to the built-in ACME CAs", () => {
  test("each account, Managed Certificate and Certificate is with the built-in ACME CA of its environment, and the Managed Certificate still renews and revokes", async () => {
    const operator = await h.createOperator("op@platform.test", PASSWORD);
    const org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
    const old = await storeOldShape(org.orgId);

    await runMigrations(h.pool);

    const accounts = await h.api(`/api/organizations/${org.orgId}/acme-accounts`, { cookie: org.cookie });
    expect(accounts.body.items).toEqual([
      { id: old.stagingAccountId, acmeCaId: "letsencrypt-staging", accountUrl: old.accountUrl, contactEmail: "pki@acme.test" },
      { id: old.productionAccountId, acmeCaId: "letsencrypt-production", accountUrl: "https://acme.test/acct/2", contactEmail: "pki@acme.test" },
    ]);
    // The key came through: the CA still accepts it for the account.
    expect((await h.api(`/api/organizations/${org.orgId}/acme-accounts/${old.stagingAccountId}/test`, { cookie: org.cookie, method: "POST", body: {} })).body).toEqual({ ok: true });
    // One account per ACME CA still holds.
    expect((await h.api(`/api/organizations/${org.orgId}/acme-accounts`, { cookie: org.cookie, body: { termsOfServiceAgreed: true } })).status).toBe(409);

    const mcPath = `/api/organizations/${org.orgId}/managed-certificates/${old.managedCertificateId}`;
    expect((await h.api(mcPath, { cookie: org.cookie })).body).toMatchObject({
      acmeCaId: "letsencrypt-staging",
      issuer: { kind: "acme", acmeCaId: "letsencrypt-staging" },
      currentCertificate: { id: old.certificateId, acmeCaId: "letsencrypt-staging", acmeAccountId: old.stagingAccountId, issuingCaId: null },
    });
    // Certificates are as immutable as before.
    await expect(h.pool.query(`update certificate set names = '{}'`)).rejects.toThrow("certificate is immutable");
    const tagged = async (tag: string) => (await h.api(`/api/organizations/${org.orgId}/managed-certificates?tag=${tag}`, { cookie: org.cookie })).body.items.map((i: any) => i.id);
    expect(await tagged("staging")).toEqual([old.managedCertificateId]);
    expect(await tagged("production")).toEqual([]);

    // It renews through the same account, now the account with Let's Encrypt Staging.
    const dns = await h.api(`/api/organizations/${org.orgId}/dns-providers`, {
      cookie: org.cookie,
      body: { name: "BIND", type: "rfc2136", settings: { server: BIND.server, port: BIND.port, zone: BIND.zone, keyName: BIND.keyName }, secret: BIND.keySecret },
    });
    expect(dns.status).toBe(201);
    expect((await h.api(`${mcPath}/renewals`, { cookie: org.cookie, body: {} })).status).toBe(202);
    await h.settleIssuances();
    const renewed = (await h.api(mcPath, { cookie: org.cookie })).body;
    expect(renewed.issuance).toMatchObject({ kind: "renewal", status: "succeeded" });
    expect(renewed.currentCertificate).toMatchObject({ acmeCaId: "letsencrypt-staging", acmeAccountId: old.stagingAccountId });

    const revoked = await h.api(`${mcPath}/certificates/${renewed.currentCertificate.id}/revocation`, { cookie: org.cookie, body: { reason: "superseded" } });
    expect(revoked.status).toBe(200);
    expect(h.revocations).toHaveLength(1);
  });
});
