// Interoperability: a real third-party SCEP client, micromdm/scep's scepclient, enrolls against the platform and gets a
// Device Certificate. It runs in a container (`scepclient` in docker-compose.yml, built from docker/scepclient), so the
// app is served on a real port of the host for it. It encrypts with PKCS#1 v1.5 and single DES and signs with SHA-1,
// whatever GetCACaps offers, which is why the platform accepts them. It also enrolls under a Shared Challenge profile,
// the way a Mac managed by Iru or network gear does: one static challenge, the same for every device.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
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

const profiles = () => `/api/organizations/${org.orgId}/enrollment-profiles`;

/** A new Enrollment Profile with this validator on a new Private CA, as its create response shows it, and where scepclient reaches it. */
async function createProfile(validator: { kind: string }) {
  const ca = await h.api(`/api/organizations/${org.orgId}/private-cas`, {
    cookie: org.cookie,
    body: { name: "Devices", subject: "CN=Acme Devices, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["devices.acme"] } },
  });
  expect(ca.status).toBe(201);
  const profile = await h.api(profiles(), { cookie: org.cookie, body: { name: "Wi-Fi", issuingCaId: ca.body.issuingCas[0].id, validator } });
  expect(profile.status).toBe(201);
  const chain = await h.app.request(`http://localhost/api/organizations/${org.orgId}/private-cas/${ca.body.id}/issuing-cas/${ca.body.issuingCas[0].id}/chain`, { headers: { cookie: org.cookie } });
  const [issuing, root] = ((await chain.text()).match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map((pem) => new x509.X509Certificate(pem));
  return { profile: profile.body, scepUrl: `http://host.docker.internal:${server.port}/scep/${profile.body.publicId}`, issuing: issuing!, root: root! };
}

/** Enrolls with scepclient for a device of this name, presenting this challenge. The selector has it encrypt to the RA
 * certificate alone, the one with keyEncipherment; without it, it would encrypt to every certificate GetCACert gives, the
 * Issuing CA's too, which it cannot when that key is not RSA. */
const enroll = (scepUrl: string, name: string, challenge: string) =>
  scepclient(["-server-url", scepUrl, "-key-encipherment-selector", "-challenge", challenge, "-cn", name, "-organization", "Acme", "-dnsname", `${name}.devices.acme`]);

test("micromdm's scepclient enrolls and gets a Device Certificate under the profile", async () => {
  const { profile, scepUrl } = await createProfile({ kind: "test_allow" });
  const run = await enroll(scepUrl, "laptop-01", "one-time-challenge");
  expect(run.exitCode, run.stderr).toBe(0);

  const cert = new x509.X509Certificate(run.stdout);
  expect(cert.subject).toContain("CN=laptop-01");
  expect(cert.getExtension(x509.SubjectAlternativeNameExtension)!.names.toJSON()).toEqual([{ type: "dns", value: "laptop-01.devices.acme" }]);
  expect(cert.getExtension(x509.ExtendedKeyUsageExtension)!.usages).toEqual(["1.3.6.1.5.5.7.3.2"]);
  expect(h.enrollmentValidations.map((v) => v.challengePassword)).toEqual(["one-time-challenge"]);

  const listed = await h.api(`${profiles()}/${profile.id}/device-certificates`, { cookie: org.cookie });
  expect(listed.body.items.map((item: { serial: string }) => item.serial)).toEqual([cert.serialNumber.toUpperCase()]);
}, 120_000);

describe("micromdm's scepclient under a Shared Challenge profile", () => {
  test("gets a Device Certificate that chains to the root when it presents the Shared Challenge", async () => {
    const { profile, scepUrl, issuing, root } = await createProfile({ kind: "shared_challenge" });
    const run = await enroll(scepUrl, "mac-01", profile.sharedChallenge.challenge);
    expect(run.exitCode, run.stderr).toBe(0);

    const cert = new x509.X509Certificate(run.stdout);
    expect(cert.subject).toContain("CN=mac-01");
    // The builder follows each issuer by its signature, so the path ends in the root only if each link verifies.
    const path = await new x509.X509ChainBuilder({ certificates: [issuing, root] }).build(cert);
    expect(path.map((c) => c.subject)).toEqual([cert.subject, issuing.subject, root.subject]);
  }, 120_000);

  test("enrolls with both the current and the previous Shared Challenge after a rotation", async () => {
    const { profile, scepUrl } = await createProfile({ kind: "shared_challenge" });
    const previous = profile.sharedChallenge as { id: string; challenge: string };
    const rotated = await h.api(`${profiles()}/${profile.id}/shared-challenge/rotation`, { cookie: org.cookie, body: { previousExpiresAt: "2026-01-15T00:00:00.000Z" } });
    expect(rotated.status).toBe(200);
    const current = rotated.body.sharedChallenge as { id: string; challenge: string };

    const underCurrent = await enroll(scepUrl, "mac-03", current.challenge);
    expect(underCurrent.exitCode, underCurrent.stderr).toBe(0);
    const underPrevious = await enroll(scepUrl, "mac-04", previous.challenge);
    expect(underPrevious.exitCode, underPrevious.stderr).toBe(0);

    const listed = (await h.api(`${profiles()}/${profile.id}/device-certificates`, { cookie: org.cookie })).body.items as { serial: string; sharedChallenge: { id: string } }[];
    expect(new Map(listed.map((c) => [c.serial, c.sharedChallenge]))).toEqual(
      new Map([
        [new x509.X509Certificate(underCurrent.stdout).serialNumber.toUpperCase(), { id: current.id }],
        [new x509.X509Certificate(underPrevious.stdout).serialNumber.toUpperCase(), { id: previous.id }],
      ]),
    );
  }, 120_000);

  test("is refused with a wrong challenge, and reports the FAILURE", async () => {
    const { profile, scepUrl } = await createProfile({ kind: "shared_challenge" });
    const run = await enroll(scepUrl, "mac-02", "guessed-challenge-value");
    expect(run.exitCode, run.stdout).not.toBe(0);
    expect(run.stderr).toContain("PKCSReq (19) request failed, failInfo: badRequest (2)");
    expect(run.stdout).toBe("");

    const events = (await h.api(`/api/organizations/${org.orgId}/audit-events`, { cookie: org.cookie })).body.items as { action: string }[];
    expect(events.filter((e) => e.action === "enrollment.refused")).toHaveLength(1);
    expect((await h.api(`${profiles()}/${profile.id}/device-certificates`, { cookie: org.cookie })).body.items).toEqual([]);
  }, 120_000);
});
