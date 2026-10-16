// The migration that gives Private CAs their own Issuing CAs (0035): a database holding a Private CA, a Managed
// Certificate on it and its issued Certificate in the shape from before, where the Private CA was its one Issuing CA,
// is migrated, and the platform then shows that Issuing CA with the same certificate, rules and limits, and issues and
// renews the Managed Certificate from it. It runs on a database of its own, made here, migrated first to the migration
// before (0034); the data from before is written as that version stored it, the only way there is to have it.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import acme from "acme-client";
import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { Pool } from "pg";
import { makeIssuingCa, makeRoot, makeTlsServer } from "../src/ca-certificates";
import { createDb } from "../src/db/client";
import { createLocalKms } from "../src/kms";
import { runMigrations } from "../src/migrate";
import { PASSWORD, TEST_DATABASE_URL, TEST_KMS_KEY, createHarness, type Harness } from "./harness";

const DATABASE = "certs_test_issuing_ca_migration";
const databaseUrl = (() => {
  const url = new URL(TEST_DATABASE_URL);
  url.pathname = `/${DATABASE}`;
  return url.toString();
})();
const MIGRATIONS = join(import.meta.dir, "..", "drizzle");
/** The last migration before Issuing CAs had their own table. */
const BEFORE = "0034_private_ca_validity";

const JAN_1 = Date.parse("2026-01-01T00:00:00Z");
const days = (n: number) => new Date(JAN_1 + n * 86_400_000);

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

/** The certificates of a PEM bundle, in order. */
const certificatesIn = (pem: string) => (pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map((one) => new x509.X509Certificate(one));

/**
 * What the platform stored before the migration for a Private CA (its Issuing CA on its own row), a Managed Certificate
 * from it and the Certificate it issued, with keys in the KMS the harness's platform uses.
 */
async function storeOldShape(orgId: string) {
  const kms = createLocalKms(TEST_KMS_KEY);
  const algorithm = "ecdsa-p256" as const;
  const rootKey = { key: await kms.createSigningKey(algorithm, orgId), context: orgId, algorithm };
  const issuingKey = { key: await kms.createSigningKey(algorithm, orgId), context: orgId, algorithm };
  const notBefore = days(0);
  const notAfter = days(5 * 365);
  const subject = new x509.Name("CN=Acme Internal TLS, O=Acme");
  const root = await makeRoot(kms, rootKey, { subject: new x509.Name("CN=Acme Internal TLS Root, O=Acme"), notBefore, notAfter });
  // Where these say they publish matters not here: nothing is fetched from it.
  const publication = { crl: "http://pki.platform.test/ca.crl", caIssuers: "http://pki.platform.test/ca.crt" };
  const issuing = await makeIssuingCa(kms, { ...rootKey, certificate: root }, issuingKey, { subject, notBefore, notAfter, permittedDnsNames: ["internal.acme"], publication });

  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csrBuffer] = await acme.crypto.createCsr({ commonName: "app.internal.acme", altNames: ["app.internal.acme"] }, key);
  const csr = csrBuffer.toString();
  const leaf = await makeTlsServer(kms, { ...issuingKey, certificate: issuing }, { csr, names: ["app.internal.acme"], notBefore, notAfter: days(30), publication });

  const {
    rows: [ca],
  } = await h.pool.query(
    `insert into private_ca (organization_id, name, kind, status, key_algorithm, subject, root_certificate_pem, root_key, issuing_certificate_pem, issuing_key, permitted_exact_names, permitted_zones, max_validity_days, default_validity_days)
     values ($1, 'Internal TLS', 'platform_root', 'active', $2, $3, $4, $5, $6, $7, '{app.corp.example}', '{internal.acme}', 90, 30) returning id`,
    [orgId, algorithm, subject.toString(), root.toString("pem"), rootKey.key, issuing.toString("pem"), issuingKey.key],
  );
  const {
    rows: [mc],
  } = await h.pool.query(
    `insert into managed_certificate (organization_id, names, key_algorithm, key_custody, issuer_kind, private_ca_id, csr)
     values ($1, '{app.internal.acme}', $2, 'owner', 'private_ca', $3, $4) returning id`,
    [orgId, algorithm, ca.id, csr],
  );
  const fingerprint = createHash("sha256").update(Buffer.from(leaf.rawData)).digest("hex");
  const {
    rows: [certificate],
  } = await h.pool.query(
    `insert into certificate (organization_id, managed_certificate_id, fingerprint, serial, not_before, not_after, names, chain_pem, ca, issuer_kind, private_ca_id, issued_at)
     values ($1, $2, $3, $4, $5, $6, '{app.internal.acme}', $7, 'Internal TLS', 'private_ca', $8, $5) returning id`,
    [orgId, mc.id, fingerprint, leaf.serialNumber.toUpperCase(), notBefore, days(30), `${leaf.toString("pem")}\n${issuing.toString("pem")}`, ca.id],
  );
  await h.pool.query(`insert into issuance (organization_id, managed_certificate_id, status, kind, certificate_id, started_at, finished_at) values ($1, $2, 'succeeded', 'first_issue', $3, $4, $4)`, [
    orgId,
    mc.id,
    certificate.id,
    notBefore,
  ]);
  return { privateCaId: ca.id as string, managedCertificateId: mc.id as string, root, issuing, leaf };
}

describe("migrating a Private CA to one with its own Issuing CA", () => {
  test("leaves one Issuing CA with its data, and the Managed Certificate still issues and renews from it", async () => {
    const operator = await h.createOperator("op@platform.test", PASSWORD);
    const org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
    const old = await storeOldShape(org.orgId);

    await runMigrations(h.pool);

    const ca = await h.api(`/api/organizations/${org.orgId}/private-cas/${old.privateCaId}`, { cookie: org.cookie });
    expect(ca.status).toBe(200);
    expect(ca.body).toMatchObject({ name: "Internal TLS", kind: "platform_root", status: "active", root: { subject: old.root.subject, notAfter: old.root.notAfter.toISOString() } });
    expect(ca.body.issuingCas).toEqual([
      {
        id: expect.any(String),
        subject: "CN=Acme Internal TLS, O=Acme",
        status: "active",
        notAfter: old.issuing.notAfter.toISOString(),
        permittedNames: { exact: ["app.corp.example"], zones: ["internal.acme"] },
        validity: { maximumDays: 90, defaultDays: 30 },
        // What its certificate was made with, which its rules need not match.
        nameConstraints: { permitted: ["dns:internal.acme"], excluded: ["ip:0.0.0.0/0", "ip:::/0"] },
      },
    ]);
    const issuingCa = ca.body.issuingCas[0];
    const chain = await h.app.request(`http://localhost/api/organizations/${org.orgId}/private-cas/${old.privateCaId}/issuing-cas/${issuingCa.id}/chain`, { headers: { cookie: org.cookie } });
    const [issuing, root] = certificatesIn(await chain.text());
    expect(issuing!.equal(old.issuing)).toBe(true);
    expect(root!.equal(old.root)).toBe(true);

    const mcPath = `/api/organizations/${org.orgId}/managed-certificates/${old.managedCertificateId}`;
    const mc = await h.api(mcPath, { cookie: org.cookie });
    expect(mc.body).toMatchObject({
      issuer: { kind: "private_ca", issuingCa: { id: issuingCa.id, subject: issuingCa.subject }, privateCa: { id: old.privateCaId, name: "Internal TLS" } },
      currentCertificate: { serial: old.leaf.serialNumber.toUpperCase(), issuingCaId: issuingCa.id },
    });

    expect((await h.api(`${mcPath}/renewals`, { cookie: org.cookie, body: {} })).status).toBe(202);
    await h.settleIssuances();
    const renewed = (await h.api(mcPath, { cookie: org.cookie })).body;
    expect(renewed.issuance).toMatchObject({ kind: "renewal", status: "succeeded" });
    expect(renewed.currentCertificate).toMatchObject({ issuingCaId: issuingCa.id, notBefore: days(0).toISOString(), notAfter: days(30).toISOString() });
    const download = await h.app.request(`http://localhost${mcPath}/certificate?chain=with-root`, { headers: { cookie: org.cookie } });
    const [leaf, servedIssuing, servedRoot] = certificatesIn(await download.text());
    expect(await leaf!.verify({ publicKey: old.issuing.publicKey, signatureOnly: true })).toBe(true);
    expect(servedIssuing!.equal(old.issuing)).toBe(true);
    expect(servedRoot!.equal(old.root)).toBe(true);

    h.setNow(days(27));
    expect(await h.runRenewalScheduler()).toBe(1);
    await h.settleIssuances();
    expect((await h.api(mcPath, { cookie: org.cookie })).body).toMatchObject({ issuance: { kind: "renewal", status: "succeeded" }, currentCertificate: { notBefore: days(27).toISOString(), notAfter: days(57).toISOString() } });
  });
});
