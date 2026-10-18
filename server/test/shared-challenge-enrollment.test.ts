// Shared Challenge enrollment (the tracer): an Organization Administrator creates an Enrollment Profile whose Enrollment
// Validator is the Shared Challenge kind, is shown its Shared Challenge once, and a device such as a Mac managed by Iru
// enrolls by presenting it as its CSR's challengePassword. Every check is of what a device, an administrator and a
// relying party see: SCEP answers, the certificates, the CRL, the API and Audit Events.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { createHash } from "node:crypto";
import { FailInfo, ScepFailureError } from "ts-scep";
import { PASSWORD, createHarness, type Harness } from "./support/harness";
import { scepDevice } from "./support/scep-device";

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

const rotate = (profileId: string, previousExpiresAt: string | undefined, cookie = org.cookie) =>
  h.api(`${profiles()}/${profileId}/shared-challenge/rotation`, { cookie, body: previousExpiresAt === undefined ? {} : { previousExpiresAt } });
const retire = (profileId: string, cookie = org.cookie) => h.api(`${profiles()}/${profileId}/shared-challenge/previous/retirement`, { cookie, method: "POST", body: {} });
const at = (days: number) => new Date(START + days * DAY_MS).toISOString();

describe("rotating a Shared Challenge", () => {
  test("returns a new Shared Challenge once, and both it and the previous one enroll until the previous one expires", async () => {
    const { profile } = await createProfile();
    const res = await rotate(profile.id, at(14));
    expect(res.status).toBe(200);
    const { id, challenge } = res.body.sharedChallenge as { id: string; challenge: string };
    expect(challenge).toMatch(/^[0-9a-f]{32,}$/);
    expect(challenge).not.toBe(profile.sharedChallenge.challenge);
    expect(id).not.toBe(profile.sharedChallenge.id);
    expect(res.body.previousSharedChallenge).toEqual({ id: profile.sharedChallenge.id, expiresAt: at(14) });

    const fetched = await h.api(`${profiles()}/${profile.id}`, { cookie: org.cookie });
    expect(fetched.body.sharedChallenge).toEqual({ id });
    expect(fetched.body.previousSharedChallenge).toEqual({ id: profile.sharedChallenge.id, expiresAt: at(14) });
    expect(JSON.stringify(fetched.body)).not.toContain(challenge);

    const device = scepDevice(h, profile.scepUrl);
    await device.enroll({ subject: "CN=mac-30", challengePassword: challenge });
    await device.enroll({ subject: "CN=mac-31", challengePassword: profile.sharedChallenge.challenge });

    h.setNow(new Date(START + 14 * DAY_MS));
    const expired = await device.enroll({ subject: "CN=mac-32", challengePassword: profile.sharedChallenge.challenge }).catch((err) => err);
    expect(expired).toBeInstanceOf(ScepFailureError);
    expect(expired.failInfoText).toContain("Shared Challenge");
    await device.enroll({ subject: "CN=mac-33", challengePassword: challenge });
    expect((await h.api(`${profiles()}/${profile.id}`, { cookie: org.cookie })).body.previousSharedChallenge).toBeNull();
  });

  test("is refused while a previous Shared Challenge is still valid, and allowed once it has expired", async () => {
    const { profile } = await createProfile();
    expect((await rotate(profile.id, at(7))).status).toBe(200);
    const again = await rotate(profile.id, at(7));
    expect(again.status).toBe(409);
    expect(again.body.sharedChallenge).toBeUndefined();

    h.setNow(new Date(START + 7 * DAY_MS));
    expect((await rotate(profile.id, at(14))).status).toBe(200);
  });

  test("needs the previous Shared Challenge's expiry, in the future", async () => {
    const { profile } = await createProfile();
    expect((await rotate(profile.id, undefined)).status).toBe(400);
    expect((await rotate(profile.id, "next week")).status).toBe(400);
    expect((await rotate(profile.id, at(0))).status).toBe(422);
  });

  test("is refused for a profile whose validator's kind uses no Shared Challenge", async () => {
    const ca = await createCa(org, "Intune devices");
    const other = await h.api(profiles(), { cookie: org.cookie, body: { name: "Intune", issuingCaId: ca.issuing.id, validator: { kind: "test_allow" } } });
    expect((await rotate(other.body.id, at(7))).status).toBe(422);
    expect(other.body.previousSharedChallenge).toBeNull();
  });
});

describe("retiring a previous Shared Challenge", () => {
  test("refuses the previous Shared Challenge at once, while the current one still enrolls", async () => {
    const { profile } = await createProfile();
    const rotated = (await rotate(profile.id, at(30))).body.sharedChallenge as { id: string; challenge: string };
    const res = await retire(profile.id);
    expect(res.status).toBe(200);
    expect(res.body.previousSharedChallenge).toBeNull();
    expect(res.body.sharedChallenge).toEqual({ id: rotated.id });

    const device = scepDevice(h, profile.scepUrl);
    const refused = await device.enroll({ subject: "CN=mac-40", challengePassword: profile.sharedChallenge.challenge }).catch((err) => err);
    expect(refused).toBeInstanceOf(ScepFailureError);
    await device.enroll({ subject: "CN=mac-41", challengePassword: rotated.challenge });

    expect((await retire(profile.id)).status).toBe(409);
    // With none left valid, it may rotate again.
    expect((await rotate(profile.id, at(30))).status).toBe(200);
  });

  test("is refused when there is no previous Shared Challenge", async () => {
    const { profile } = await createProfile();
    expect((await retire(profile.id)).status).toBe(409);
  });
});

describe("the Audit Events of a Shared Challenge's rotation", () => {
  test("record the rotation, the retirement by an administrator and the expiry with no actor, never with a Shared Challenge in them", async () => {
    const { profile } = await createProfile();
    const first = (await rotate(profile.id, at(10))).body.sharedChallenge as { id: string; challenge: string };
    h.setNow(new Date(START + 1 * DAY_MS));
    await retire(profile.id);
    h.setNow(new Date(START + 2 * DAY_MS));
    const second = (await rotate(profile.id, at(5))).body.sharedChallenge as { id: string; challenge: string };

    // Not yet expired: the pass clears nothing.
    expect(await h.expireSharedChallenges()).toBe(0);
    h.setNow(new Date(START + 5 * DAY_MS));
    expect(await h.expireSharedChallenges()).toBe(1);
    expect(await h.expireSharedChallenges()).toBe(0);

    const events = (await auditOf()).filter((e) => e.target.id === profile.id && e.action.startsWith("enrollment_profile.shared_challenge_"));
    expect(events.map((e) => [e.action, e.actor?.email ?? null, e.detail])).toEqual([
      ["enrollment_profile.shared_challenge_rotated", "admin@acme.test", { name: "Macs", sharedChallenge: { id: first.id }, previous: { id: profile.sharedChallenge.id, expiresAt: at(10) } }],
      ["enrollment_profile.shared_challenge_retired", "admin@acme.test", { name: "Macs", sharedChallenge: { id: profile.sharedChallenge.id }, expired: false }],
      ["enrollment_profile.shared_challenge_rotated", "admin@acme.test", { name: "Macs", sharedChallenge: { id: second.id }, previous: { id: first.id, expiresAt: at(5) } }],
      ["enrollment_profile.shared_challenge_retired", null, { name: "Macs", sharedChallenge: { id: first.id }, expired: true }],
    ]);
    const all = JSON.stringify(await auditOf());
    for (const challenge of [profile.sharedChallenge.challenge, first.challenge, second.challenge]) expect(all).not.toContain(challenge);
  });

  test("record the expiry of a previous Shared Challenge the pass has not reached before a rotation replaces it", async () => {
    const { profile } = await createProfile();
    const first = (await rotate(profile.id, at(5))).body.sharedChallenge as { id: string };
    h.setNow(new Date(START + 6 * DAY_MS));
    expect((await rotate(profile.id, at(20))).status).toBe(200);

    const retired = (await auditOf()).filter((e) => e.action === "enrollment_profile.shared_challenge_retired");
    expect(retired.map((e) => [e.actor?.email ?? null, e.detail.sharedChallenge])).toEqual([[null, { id: profile.sharedChallenge.id }]]);
    expect(first.id).not.toBe(profile.sharedChallenge.id);
  });
});

describe("rotating and retiring a Shared Challenge", () => {
  test("are only for Organization Administrators", async () => {
    const { profile } = await createProfile();
    expect((await rotate(profile.id, at(7))).status).toBe(200);
    for (const role of ["member", "approver"]) {
      const email = `${role}@acme.test`;
      const invited = await h.api("/api/auth/organization/invite-member", { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
      const cookie = await h.signUp(email, PASSWORD);
      await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
      const signedIn = await h.signIn(email, PASSWORD);
      expect((await retire(profile.id, signedIn)).status).toBe(403);
      expect((await rotate(profile.id, at(8), signedIn)).status).toBe(403);
    }
    expect((await h.api(`${profiles()}/${profile.id}`, { cookie: org.cookie })).body.previousSharedChallenge).not.toBeNull();
  });
});

describe("the Shared Challenge a Device Certificate was issued under", () => {
  test("is recorded for each, current or previous, and none for a renewal, in its details and its device_certificate.issued Audit Event", async () => {
    const { profile } = await createProfile();
    const device = scepDevice(h, profile.scepUrl);
    const underFirst = await device.enroll({ subject: "CN=mac-50", challengePassword: profile.sharedChallenge.challenge });
    const rotated = (await rotate(profile.id, at(30))).body.sharedChallenge as { id: string; challenge: string };
    const underPrevious = await device.enroll({ subject: "CN=mac-51", challengePassword: profile.sharedChallenge.challenge });
    const underCurrent = await device.enroll({ subject: "CN=mac-52", challengePassword: rotated.challenge });
    h.setNow(new Date(START + 1 * DAY_MS));
    const renewed = await device.renew({ subject: "CN=mac-52" }, underCurrent);

    const expected = new Map([
      [underFirst.certificate.serialNumber.toUpperCase(), { id: profile.sharedChallenge.id }],
      [underPrevious.certificate.serialNumber.toUpperCase(), { id: profile.sharedChallenge.id }],
      [underCurrent.certificate.serialNumber.toUpperCase(), { id: rotated.id }],
      [renewed.certificate.serialNumber.toUpperCase(), null],
    ]);
    const listed = (await h.api(`${profiles()}/${profile.id}/device-certificates`, { cookie: org.cookie })).body.items as { id: string; serial: string; sharedChallenge: { id: string } | null }[];
    expect(new Map(listed.map((c) => [c.serial, c.sharedChallenge]))).toEqual(expected);
    for (const { id, serial } of listed) {
      const details = await h.api(`${profiles()}/${profile.id}/device-certificates/${id}`, { cookie: org.cookie });
      expect(details.body.sharedChallenge).toEqual(expected.get(serial)!);
    }
    const issued = (await auditOf()).filter((e) => e.action === "device_certificate.issued");
    expect(new Map(issued.map((e) => [e.detail.serial, e.detail.sharedChallenge]))).toEqual(expected);
  });

  test("is none for a profile whose validator's kind uses no Shared Challenge", async () => {
    const ca = await createCa(org, "Intune devices");
    const other = await h.api(profiles(), { cookie: org.cookie, body: { name: "Intune", issuingCaId: ca.issuing.id, validator: { kind: "test_allow" } } });
    await scepDevice(h, other.body.scepUrl).enroll({ subject: "CN=device-01" });
    const listed = (await h.api(`${profiles()}/${other.body.id}/device-certificates`, { cookie: org.cookie })).body.items as { sharedChallenge: unknown }[];
    expect(listed.map((c) => c.sharedChallenge)).toEqual([null]);
    expect((await auditOf()).find((e) => e.action === "device_certificate.issued")!.detail.sharedChallenge).toBeNull();
  });
});
