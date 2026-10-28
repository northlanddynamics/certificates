// The migration that has Enrollment Profiles and Device Certificates name their issuer by kind (0059): a profile and
// Device Certificates stored as they were before, with only an Issuing CA, are migrated, and the platform then shows the
// profile as it did, enrolls and renews devices under it, and revokes their Device Certificates. It runs on a database
// of its own, made here. The rows are made through the API and then put back in the shape from before (0058), the
// columns 0059 adds dropped, before 0059 itself is run on them: the only way there is to have such rows with real keys.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Pool } from "pg";
import { PASSWORD, TEST_DATABASE_URL, createHarness, type Harness } from "./support/harness";
import { scepDevice } from "./support/scep-device";

const DATABASE = "certs_test_enrollment_issuer_migration";
const databaseUrl = (() => {
  const url = new URL(TEST_DATABASE_URL);
  url.pathname = `/${DATABASE}`;
  return url.toString();
})();
const MIGRATION = join(import.meta.dir, "..", "drizzle", "0059_enrollment_issuer_kind.sql");

let server: Pool;
let h: Harness;

beforeAll(async () => {
  server = new Pool({ connectionString: TEST_DATABASE_URL });
  await server.query(`drop database if exists ${DATABASE} with (force)`);
  await server.query(`create database ${DATABASE}`);
  h = await createHarness({}, { databaseUrl });
});
// The database is left for the next run to drop, before it connects: dropping it here, with force, would cut off the
// harness's connections while they close.
afterAll(async () => {
  await h?.close();
  await server.end();
});

/** Puts the Enrollment Profiles and Device Certificates back in their shape from before 0059. */
async function toShapeBefore() {
  for (const table of ["enrollment_profile", "device_certificate"]) {
    await h.pool.query(`alter table ${table} drop constraint ${table}_issuer_kind`);
    await h.pool.query(`alter table ${table} drop column issuer_kind`);
    await h.pool.query(`alter table ${table} alter column issuing_ca_id set not null`);
  }
}

/** Runs 0059 as the migrator does: each of its statements in turn. */
async function migrate() {
  for (const statement of readFileSync(MIGRATION, "utf8").split("--> statement-breakpoint")) await h.pool.query(statement);
}

const read = (cert: { raw: Buffer }) => new x509.X509Certificate(new Uint8Array(cert.raw));

describe("migrating Enrollment Profiles to name their issuer by kind", () => {
  test("leaves each on its Issuing CA: the profile shows the same, devices enroll and renew, and Device Certificates are listed and revoked", async () => {
    const operator = await h.createOperator("op@platform.test", PASSWORD);
    const org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
    const ca = await h.api(`/api/organizations/${org.orgId}/private-cas`, {
      cookie: org.cookie,
      body: { name: "Devices", subject: "CN=Acme Devices, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["devices.acme"] } },
    });
    expect(ca.status).toBe(201);
    const issuingCaId = ca.body.issuingCas[0].id as string;
    const created = await h.api(`/api/organizations/${org.orgId}/enrollment-profiles`, { cookie: org.cookie, body: { name: "Macs", issuingCaId, validator: { kind: "shared_challenge" } } });
    expect(created.status).toBe(201);
    const profilePath = `/api/organizations/${org.orgId}/enrollment-profiles/${created.body.id}`;
    const device = scepDevice(h, created.body.scepUrl);
    const challengePassword = created.body.sharedChallenge.challenge as string;
    const first = await device.enroll({ subject: "CN=first", challengePassword });
    const before = { profile: (await h.api(profilePath, { cookie: org.cookie })).body, certificates: (await h.api(`${profilePath}/device-certificates`, { cookie: org.cookie })).body };

    await toShapeBefore();
    await migrate();

    expect((await h.api(profilePath, { cookie: org.cookie })).body).toEqual(before.profile);
    expect(before.profile).toMatchObject({ issuingCaId, privateCaId: ca.body.id });
    expect((await h.api(`${profilePath}/device-certificates`, { cookie: org.cookie })).body).toEqual(before.certificates);

    const second = await device.enroll({ subject: "CN=second", challengePassword });
    const renewed = await device.renew({ subject: "CN=first" }, first);
    const issuing = (await device.client.getCACert()).ca;
    for (const cert of [second, renewed]) expect(await read(cert.certificate).verify({ publicKey: read(issuing).publicKey, signatureOnly: true })).toBe(true);

    const listed = (await h.api(`${profilePath}/device-certificates`, { cookie: org.cookie })).body.items as { id: string; subject: string; status: string }[];
    expect(listed.map((one) => [one.subject, one.status])).toEqual([
      ["CN=first", "active"],
      ["CN=second", "active"],
      ["CN=first", "revoked"],
    ]);
    const revoked = await h.api(`${profilePath}/device-certificates/${listed[1]!.id}/revocation`, { cookie: org.cookie, body: { reason: "keyCompromise" } });
    expect(revoked.status).toBe(200);
    expect(revoked.body).toMatchObject({ status: "revoked", revocation: { reason: "keyCompromise" } });
  });
});
