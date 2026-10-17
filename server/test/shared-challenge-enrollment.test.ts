// Shared Challenge enrollment (the tracer): an Organization Administrator creates an Enrollment Profile whose Enrollment
// Validator is the Shared Challenge kind, is shown its Shared Challenge once, and a device such as a Mac managed by Iru
// enrolls by presenting it as its CSR's challengePassword. Every check is of what a device, an administrator and a
// relying party see: SCEP answers, the certificates, the CRL, the API and Audit Events.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { createHash } from "node:crypto";
import { FailInfo, ScepFailureError } from "ts-scep";
import { PASSWORD, createHarness, type Harness } from "./harness";
import { scepDevice } from "./scep-device";

let h: Harness;
let operator: string;
let org: { orgId: string; cookie: string };

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  operator = await h.createOperator("op@platform.test", PASSWORD);
  org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
});
afterAll(async () => {
  await h.close();
});

const DAY_MS = 86_400_000;
const START = Date.parse("2026-01-01T00:00:00Z");
const cas = (orgId = org.orgId) => `/api/organizations/${orgId}/private-cas`;
const profiles = (orgId = org.orgId) => `/api/organizations/${orgId}/enrollment-profiles`;
const auditOf = async (target = org) => (await h.api(`/api/organizations/${target.orgId}/audit-events`, { cookie: target.cookie })).body.items as { action: string; actor: any; target: any; detail: any }[];
const read = (cert: { raw: Buffer }) => new x509.X509Certificate(new Uint8Array(cert.raw));

/** A new Private CA with a platform-made root, and its first Issuing CA as `issuing`. */
async function createCa(target = org, name = "Macs") {
  const res = await h.api(cas(target.orgId), {
    cookie: target.cookie,
    body: { name, subject: "CN=Acme Macs, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["macs.acme"] } },
  });
  expect(res.status).toBe(201);
  return { id: res.body.id as string, issuing: res.body.issuingCas[0] as { id: string } };
}

type Created = { id: string; scepUrl: string; validityDays: number; caFingerprint: string; sharedChallenge: { id: string; challenge: string } };

/** A new Shared Challenge Enrollment Profile on a new Private CA, as its create response shows it. */
async function createProfile(extra: Record<string, unknown> = {}, target = org) {
  const ca = await createCa(target, String(extra.name ?? "Macs"));
  const res = await h.api(profiles(target.orgId), { cookie: target.cookie, body: { name: "Macs", issuingCaId: ca.issuing.id, validator: { kind: "shared_challenge" }, ...extra } });
  expect(res.status).toBe(201);
  return { ca, profile: res.body as Created };
}

describe("a Shared Challenge Enrollment Profile", () => {
  test("is offered as a validator kind that uses a Shared Challenge, does not vouch for names, takes no secret and allows renewal", async () => {
    const res = await h.api(`/api/organizations/${org.orgId}/enrollment-validator-kinds`, { cookie: org.cookie });
    expect(res.status).toBe(200);
    const items = res.body.items as { kind: string; vouchesForNames: boolean; takesSecret: boolean; allowsRenewal: boolean; usesSharedChallenge: boolean }[];
    expect(items.find((k) => k.kind === "shared_challenge")).toEqual({ kind: "shared_challenge", vouchesForNames: false, takesSecret: false, allowsRenewal: true, usesSharedChallenge: true });
    expect(items.find((k) => k.kind === "intune")!.usesSharedChallenge).toBe(false);
  });

  test("is created with a Shared Challenge the platform makes, shown in the create response only and never in a later read or Audit Event", async () => {
    const { profile } = await createProfile();
    const { id, challenge } = profile.sharedChallenge;
    expect(typeof id).toBe("string");
    // At least 128 bits of randomness, in characters a SCEP client and Iru's form take.
    expect(challenge).toMatch(/^[0-9a-f]{32,}$/);
    const other = await createProfile({ name: "Other Macs" });
    expect(other.profile.sharedChallenge.challenge).not.toBe(challenge);

    const fetched = await h.api(`${profiles()}/${profile.id}`, { cookie: org.cookie });
    expect(fetched.body.sharedChallenge).toEqual({ id });
    const listed = await h.api(profiles(), { cookie: org.cookie });
    expect(JSON.stringify(listed.body)).not.toContain(challenge);
    expect(JSON.stringify(fetched.body)).not.toContain(challenge);

    const events = await auditOf();
    expect(JSON.stringify(events)).not.toContain(challenge);
    const created = events.find((e) => e.action === "enrollment_profile.created" && e.target.id === profile.id)!;
    expect(created.detail.sharedChallenge).toEqual({ id });
    expect(created.detail.nameRules).toBeNull();
  });

  test("tests its validator successfully, with a note that there is nothing external to reach", async () => {
    const { profile } = await createProfile();
    const res = await h.api(`${profiles()}/${profile.id}/validator/test`, { cookie: org.cookie, method: "POST" });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.note).toContain("no external service");
  });
});

describe("a device enrolling with a Shared Challenge", () => {
  test("is issued a Device Certificate with the subject and SANs from its CSR when it presents the Shared Challenge", async () => {
    const { profile } = await createProfile();
    const device = scepDevice(h, profile.scepUrl);

    const { certificate } = await device.enroll({
      subject: "CN=C02XK1ZJJGH5, O=Acme",
      subjectAltNames: { dns: ["c02xk1zjjgh5.macs.acme"], email: ["jane@acme.test"] },
      challengePassword: profile.sharedChallenge.challenge,
    });
    const cert = read(certificate);
    expect(cert.subject).toBe("O=Acme, CN=C02XK1ZJJGH5");
    expect(cert.getExtension(x509.SubjectAlternativeNameExtension)!.names.toJSON()).toEqual([
      { type: "dns", value: "c02xk1zjjgh5.macs.acme" },
      { type: "email", value: "jane@acme.test" },
    ]);
    // 90 days unless the profile says otherwise.
    expect(profile.validityDays).toBe(90);
    expect(cert.notAfter.getTime()).toBe(START + 90 * DAY_MS);
    const issued = (await auditOf()).filter((e) => e.action === "device_certificate.issued");
    expect(issued).toHaveLength(1);
    expect(JSON.stringify(await auditOf())).not.toContain(profile.sharedChallenge.challenge);
  });

  test("queues nothing to tell its validator, so that the CSR carrying the Shared Challenge is not kept", async () => {
    const { profile } = await createProfile();
    await scepDevice(h, profile.scepUrl).enroll({ subject: "CN=mac-04", challengePassword: profile.sharedChallenge.challenge });
    expect(await h.deliverEnrollmentNotifications()).toBe(0);
  });

  test("is refused, FAILURE badRequest with enrollment.refused, without the Shared Challenge or with a wrong one, and the reason never quotes what was sent", async () => {
    const { profile } = await createProfile();
    const device = scepDevice(h, profile.scepUrl);

    const missing = await device.enroll({ subject: "CN=mac-01" }).catch((err) => err);
    const wrong = await device.enroll({ subject: "CN=mac-02", challengePassword: "guessed-challenge-value" }).catch((err) => err);
    for (const failure of [missing, wrong]) {
      expect(failure).toBeInstanceOf(ScepFailureError);
      expect(failure.failInfo).toBe(FailInfo.badRequest);
      expect(failure.failInfoText).toContain("Shared Challenge");
    }
    expect(wrong.failInfoText).not.toContain("guessed-challenge-value");

    const events = await auditOf();
    expect(events.some((e) => e.action === "device_certificate.issued")).toBe(false);
    const refusals = events.filter((e) => e.action === "enrollment.refused");
    expect(refusals.map((e) => e.detail.reason).sort()).toEqual([missing.failInfoText, wrong.failInfoText].sort());
    expect(refusals[0]!.detail.validator).toEqual({ kind: "shared_challenge" });
    expect(JSON.stringify(events)).not.toContain("guessed-challenge-value");
    expect((await h.api(`${profiles()}/${profile.id}/device-certificates`, { cookie: org.cookie })).body.items).toEqual([]);
  });

  test("with one Organization's Shared Challenge is refused under another Organization's profile", async () => {
    const other = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    const ours = await createProfile();
    const theirs = await createProfile({}, other);

    const failure = await scepDevice(h, theirs.profile.scepUrl).enroll({ subject: "CN=mac-03", challengePassword: ours.profile.sharedChallenge.challenge }).catch((err) => err);
    expect(failure).toBeInstanceOf(ScepFailureError);
    expect((await auditOf(other)).filter((e) => e.action === "enrollment.refused")).toHaveLength(1);
    const { certificate } = await scepDevice(h, theirs.profile.scepUrl).enroll({ subject: "CN=mac-03", challengePassword: theirs.profile.sharedChallenge.challenge });
    expect(read(certificate).subject).toBe("CN=mac-03");
  });
});

describe("a device renewing under a Shared Challenge profile", () => {
  test("is offered Renewal by GetCACaps, and renews with a RenewalReq without the Shared Challenge, superseding what it held", async () => {
    const { profile } = await createProfile();
    const device = scepDevice(h, profile.scepUrl);
    expect((await device.client.getCACaps()).has("Renewal")).toBe(true);
    const first = await device.enroll({ subject: "CN=mac-10", challengePassword: profile.sharedChallenge.challenge });
    h.setNow(new Date(START + 60 * DAY_MS));

    const renewed = await device.renew({ subject: "CN=mac-10" }, first);
    expect(read(renewed.certificate).notAfter.getTime()).toBe(START + 150 * DAY_MS);
    const listed = (await h.api(`${profiles()}/${profile.id}/device-certificates`, { cookie: org.cookie })).body.items as { serial: string; status: string; revocation?: { reason: string } }[];
    expect(listed.map((c) => [c.serial, c.status, c.revocation?.reason])).toEqual([
      [renewed.certificate.serialNumber.toUpperCase(), "active", undefined],
      [first.certificate.serialNumber.toUpperCase(), "revoked", "superseded"],
    ]);
  });

  test("with a PKCSReq for the same subject as another Device Certificate revokes nothing", async () => {
    const { profile } = await createProfile();
    const device = scepDevice(h, profile.scepUrl);
    await device.enroll({ subject: "CN=mac-11", challengePassword: profile.sharedChallenge.challenge });
    await device.enroll({ subject: "CN=mac-11", challengePassword: profile.sharedChallenge.challenge });

    const listed = (await h.api(`${profiles()}/${profile.id}/device-certificates`, { cookie: org.cookie })).body.items as { status: string }[];
    expect(listed.map((c) => c.status)).toEqual(["active", "active"]);
  });
});

describe("what a Shared Challenge profile issues", () => {
  test("is bounded by its Issuing CA's Permitted Name Rules when it has no Name Rules", async () => {
    const { profile } = await createProfile();
    const device = scepDevice(h, profile.scepUrl);

    const failure = await device.enroll({ subject: "CN=mac-20", subjectAltNames: { dns: ["mac-20.elsewhere.test"] }, challengePassword: profile.sharedChallenge.challenge }).catch((err) => err);
    expect(failure).toBeInstanceOf(ScepFailureError);
    expect(failure.failInfoText).toContain("mac-20.elsewhere.test");
  });

  test("is valid for the validity the administrator sets, up to the maximum", async () => {
    const { profile } = await createProfile({ validityDays: 30 });
    expect(profile.validityDays).toBe(30);
    const { certificate } = await scepDevice(h, profile.scepUrl).enroll({ subject: "CN=mac-21", challengePassword: profile.sharedChallenge.challenge });
    expect(read(certificate).notAfter.getTime()).toBe(START + 30 * DAY_MS);

    const ca = await createCa(org, "Too long");
    const tooLong = await h.api(profiles(), { cookie: org.cookie, body: { name: "Too long", issuingCaId: ca.issuing.id, validator: { kind: "shared_challenge" }, validityDays: 1826 } });
    expect(tooLong.status).toBe(400);
  });

  test("is rate limited like every SCEP endpoint", async () => {
    const { profile } = await createProfile();
    h.scepRateLimit.perProfile = 2;
    const getCaCaps = () => h.app.request(`${profile.scepUrl}?operation=GetCACaps`, { headers: { "x-forwarded-for": "198.51.100.9" } });
    expect((await getCaCaps()).status).toBe(200);
    expect((await getCaCaps()).status).toBe(200);
    expect((await getCaCaps()).status).toBe(429);
  });
});

describe("every Enrollment Profile", () => {
  test("shows the SHA-256 fingerprint of the CA certificate GetCACert serves, with its SCEP URL", async () => {
    const { profile } = await createProfile();
    const { ca } = await scepDevice(h, profile.scepUrl).client.getCACert();
    expect(profile.caFingerprint).toBe(createHash("sha256").update(ca.raw).digest("hex"));

    const caForIntune = await createCa(org, "Intune devices");
    const other = await h.api(profiles(), { cookie: org.cookie, body: { name: "Intune", issuingCaId: caForIntune.issuing.id, validator: { kind: "test_allow" } } });
    expect(other.body.sharedChallenge).toBeNull();
    expect(other.body.validityDays).toBe(365);
    const fetched = await h.api(`${profiles()}/${other.body.id}`, { cookie: org.cookie });
    expect(fetched.body.caFingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(fetched.body.caFingerprint).not.toBe(profile.caFingerprint);
  });
});
