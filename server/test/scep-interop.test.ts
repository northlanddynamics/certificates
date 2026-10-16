// Interoperability: a real third-party SCEP client, micromdm/scep's scepclient, enrolls against the platform and gets a
// Device Certificate. It runs in a container (`scepclient` in docker-compose.yml, built from docker/scepclient), so the
// app is served on a real port of the host for it. It encrypts with PKCS#1 v1.5 and single DES and signs with SHA-1,
// whatever GetCACaps offers, which is why the platform accepts them.
import { afterAll, beforeAll, beforeEach, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { PASSWORD, createHarness, type Harness } from "./harness";

let h: Harness;
let server: ReturnType<typeof Bun.serve>;
let org: { orgId: string; cookie: string };

beforeAll(async () => {
  h = await createHarness();
  server = Bun.serve({ hostname: "0.0.0.0", port: 0, fetch: h.app.fetch });
});
beforeEach(async () => {
  await h.reset();
  const operator = await h.createOperator("op@platform.test", PASSWORD);
  org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
});
afterAll(async () => {
  server.stop(true);
  await h.close();
});

/** Runs micromdm's scepclient with these arguments; what it printed (the certificate it was issued, PEM) and how it ended. */
async function scepclient(args: string[]) {
  const run = Bun.spawn(["docker", "compose", "run", "--rm", "scepclient", ...args], { cwd: new URL("../..", import.meta.url).pathname, stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, exitCode] = await Promise.all([new Response(run.stdout).text(), new Response(run.stderr).text(), run.exited]);
  return { stdout, stderr, exitCode };
}

test("micromdm's scepclient enrolls and gets a Device Certificate under the profile", async () => {
  const cas = `/api/organizations/${org.orgId}/private-cas`;
  const ca = await h.api(cas, {
    cookie: org.cookie,
    body: { name: "Devices", subject: "CN=Acme Devices, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["devices.acme"] } },
  });
  expect(ca.status).toBe(201);
  const profile = await h.api(`/api/organizations/${org.orgId}/enrollment-profiles`, {
    cookie: org.cookie,
    body: { name: "Wi-Fi", issuingCaId: ca.body.issuingCas[0].id, validator: { kind: "test_allow" } },
  });
  expect(profile.status).toBe(201);
  const scepUrl = `http://host.docker.internal:${server.port}/scep/${profile.body.publicId}`;

  // The selector has it encrypt to the RA certificate alone, the one with keyEncipherment; without it, it would encrypt to
  // every certificate GetCACert gives, the Issuing CA's too, which it cannot when that key is not RSA.
  const run = await scepclient(["-server-url", scepUrl, "-key-encipherment-selector", "-challenge", "one-time-challenge", "-cn", "laptop-01", "-organization", "Acme", "-dnsname", "laptop-01.devices.acme"]);
  expect(run.exitCode, run.stderr).toBe(0);

  const cert = new x509.X509Certificate(run.stdout);
  expect(cert.subject).toContain("CN=laptop-01");
  expect(cert.getExtension(x509.SubjectAlternativeNameExtension)!.names.toJSON()).toEqual([{ type: "dns", value: "laptop-01.devices.acme" }]);
  expect(cert.getExtension(x509.ExtendedKeyUsageExtension)!.usages).toEqual(["1.3.6.1.5.5.7.3.2"]);
  expect(h.enrollmentValidations.map((v) => v.challengePassword)).toEqual(["one-time-challenge"]);

  const listed = await h.api(`/api/organizations/${org.orgId}/enrollment-profiles/${profile.body.id}/device-certificates`, { cookie: org.cookie });
  expect(listed.body.items.map((item: { serial: string }) => item.serial)).toEqual([cert.serialNumber.toUpperCase()]);
}, 120_000);
