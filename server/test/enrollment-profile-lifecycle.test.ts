// An Enrollment Profile over its life: an Organization Administrator disables it, which stops enrollment but keeps what
// it issued; points it at a new Issuing CA when the old one is retired; and rotates its RA certificate. Device
// Certificates long expired are pruned after the profile's retention period, their Audit Events kept. Every check is of
// what a device, an administrator and a relying party see: SCEP answers, the certificates, the CRL, the API and Audit Events.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { ScepFailureError } from "ts-scep";
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
const auditOf = async () => (await h.api(`/api/organizations/${org.orgId}/audit-events`, { cookie: org.cookie })).body.items as { action: string; actor: any; target: any; detail: any }[];
const certificatesIn = (pem: string) => (pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map((one) => new x509.X509Certificate(one));
const read = (cert: { raw: Buffer }) => new x509.X509Certificate(new Uint8Array(cert.raw));

/** A new Private CA with a platform-made root, and its first Issuing CA as `issuing`. */
async function createCa(target = org, keyAlgorithm = "ecdsa-p256") {
  const res = await h.api(cas(target.orgId), {
    cookie: target.cookie,
    body: { name: keyAlgorithm === "ecdsa-p256" ? "Devices" : `Devices ${keyAlgorithm}`, subject: "CN=Acme Devices, O=Acme", keyAlgorithm, lifetimeYears: 5, permittedNames: { exact: [], zones: ["devices.acme"] } },
  });
  expect(res.status).toBe(201);
  return { id: res.body.id as string, issuing: res.body.issuingCas[0] as { id: string } };
}

/** A second Issuing CA under the Private CA's root. */
async function addIssuingCa(ca: { id: string }) {
  const res = await h.api(`${cas()}/${ca.id}/issuing-cas`, { cookie: org.cookie, body: { subject: "CN=Acme Devices 2, O=Acme", permittedNames: { exact: [], zones: ["devices.acme"] } } });
  expect(res.status).toBe(201);
  return res.body as { id: string; subject: string };
}

const retire = async (ca: { id: string }, issuingCaId: string) => expect((await h.api(`${cas()}/${ca.id}/issuing-cas/${issuingCaId}/retire`, { cookie: org.cookie, body: {} })).status).toBe(200);

async function createProfile(issuingCaId: string, extra: Record<string, unknown> = {}) {
  const res = await h.api(profiles(), { cookie: org.cookie, body: { name: "Wi-Fi", issuingCaId, validator: { kind: "test_allow" }, ...extra } });
  expect(res.status).toBe(201);
  return res.body as { id: string; publicId: string; scepUrl: string; enabled: boolean; retentionDays: number; raCertificate: { serial: string; notAfter: string } };
}

const profileOf = async (id: string) => (await h.api(`${profiles()}/${id}`, { cookie: org.cookie })).body;
const disable = (id: string, cookie = org.cookie) => h.api(`${profiles()}/${id}/disable`, { cookie, body: {} });
const update = (id: string, body: unknown, cookie = org.cookie) => h.api(`${profiles()}/${id}`, { cookie, method: "PATCH", body });
const rotateRa = (id: string, cookie = org.cookie) => h.api(`${profiles()}/${id}/ra-rotation`, { cookie, body: {} });
const certificatesOf = async (id: string, query = "") => (await h.api(`${profiles()}/${id}/device-certificates${query}`, { cookie: org.cookie })).body;

/** The CRL a certificate's CRL Distribution Point names, fetched from there as a relying party would. */
async function crlFor(cert: x509.X509Certificate) {
  const cdp = cert.getExtension(x509.CRLDistributionPointsExtension)!;
  const res = await h.app.request(cdp.distributionPoints[0]!.distributionPoint!.fullName![0]!.uniformResourceIdentifier!);
  expect(res.status).toBe(200);
  return new x509.X509Crl(new Uint8Array(await res.arrayBuffer()));
}

describe("an Enrollment Profile and an ML-DSA Issuing CA", () => {
  test("is refused one at creation, with the reason, and the CA list says it takes none", async () => {
    const ca = await createCa(org, "ml-dsa-65");
    const res = await h.api(profiles(), { cookie: org.cookie, body: { name: "Wi-Fi", issuingCaId: ca.issuing.id, validator: { kind: "test_allow" } } });
    expect(res.status).toBe(422);
    expect(res.body.error).toMatch(/ML-DSA/);
    expect(res.body.error).toMatch(/SCEP/);
    expect((await h.api(profiles(), { cookie: org.cookie })).body.items).toEqual([]);

    const listed = (await h.api(cas(), { cookie: org.cookie })).body.items as { id: string; enrollmentProfileRefusal: string | null }[];
    expect(listed.find((one) => one.id === ca.id)!.enrollmentProfileRefusal).toMatch(/ML-DSA/);
  });

  test("is refused being repointed to one, and is left as it was", async () => {
    const classical = await createCa();
    const profile = await createProfile(classical.issuing.id);
    const quantum = await createCa(org, "ml-dsa-87");

    const res = await update(profile.id, { issuingCaId: quantum.issuing.id });
    expect(res.status).toBe(422);
    expect(res.body.error).toMatch(/ML-DSA/);
    expect(await profileOf(profile.id)).toMatchObject({ issuingCaId: classical.issuing.id, raCertificate: profile.raCertificate });
    expect((await auditOf()).filter((e) => e.action === "enrollment_profile.updated")).toEqual([]);

    const listed = (await h.api(cas(), { cookie: org.cookie })).body.items as { id: string; enrollmentProfileRefusal: string | null }[];
    expect(listed.find((one) => one.id === classical.id)!.enrollmentProfileRefusal).toBeNull();
  });
});

describe("disabling an Enrollment Profile", () => {
  test("refuses all enrollment, audited, and keeps its Device Certificates and their CRL entries", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    expect(profile.enabled).toBe(true);
    const device = scepDevice(h, profile.scepUrl);
    const revoked = read((await device.enroll({ subject: "CN=lost" })).certificate);
    const kept = read((await device.enroll({ subject: "CN=kept" })).certificate);
    const lost = (await certificatesOf(profile.id)).items.find((c: { subject: string }) => c.subject === "CN=lost");
    expect((await h.api(`${profiles()}/${profile.id}/device-certificates/${lost.id}/revocation`, { cookie: org.cookie, body: { reason: "keyCompromise" } })).status).toBe(200);
    const validationsBefore = h.enrollmentValidations.length;

    const res = await disable(profile.id);
    expect(res.status).toBe(200);
    expect(res.body.enabled).toBe(false);
    expect((await profileOf(profile.id)).enabled).toBe(false);

    const failure = await device.enroll({ subject: "CN=after" }).catch((err) => err);
    expect(failure).toBeInstanceOf(ScepFailureError);
    expect(failure.failInfoText).toContain("disabled");
    expect(h.enrollmentValidations).toHaveLength(validationsBefore);
    expect((await auditOf()).filter((e) => e.action === "enrollment.refused").map((e) => e.detail.reason)).toEqual([failure.failInfoText]);

    const listed = await certificatesOf(profile.id);
    expect(listed.items.map((c: { subject: string; status: string }) => [c.subject, c.status]).sort()).toEqual([
      ["CN=kept", "active"],
      ["CN=lost", "revoked"],
    ]);
    expect((await crlFor(kept)).entries.map((e) => e.serialNumber.toUpperCase())).toEqual([revoked.serialNumber.toUpperCase()]);

    const disabled = (await auditOf()).filter((e) => e.action === "enrollment_profile.disabled");
    expect(disabled).toHaveLength(1);
    expect(disabled[0]).toMatchObject({ actor: { email: "admin@acme.test" }, target: { type: "enrollment_profile", id: profile.id }, detail: { name: "Wi-Fi" } });

    expect((await disable(profile.id)).status).toBe(409);
  });

  test("is only for Organization Administrators", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    const invited = await h.api("/api/auth/organization/invite-member", { cookie: org.cookie, body: { email: "member@acme.test", role: "member", organizationId: org.orgId } });
    const cookie = await h.signUp("member@acme.test", PASSWORD);
    await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
    const member = await h.signIn("member@acme.test", PASSWORD);

    expect((await disable(profile.id, member)).status).toBe(403);
    expect((await update(profile.id, { retentionDays: 30 }, member)).status).toBe(403);
    expect((await rotateRa(profile.id, member)).status).toBe(403);
    expect((await profileOf(profile.id)).enabled).toBe(true);
    expect((await disable(crypto.randomUUID())).status).toBe(404);
  });
});

describe("pointing an Enrollment Profile at another Issuing CA", () => {
  test("a profile whose Issuing CA is retired refuses enrollment until it is pointed at an active one, which then issues with a new RA certificate", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    const device = scepDevice(h, profile.scepUrl);
    const before = read((await device.enroll({ subject: "CN=before" })).certificate);
    const next = await addIssuingCa(ca);
    await retire(ca, ca.issuing.id);

    const refused = await device.enroll({ subject: "CN=during" }).catch((err) => err);
    expect(refused).toBeInstanceOf(ScepFailureError);
    expect(refused.failInfoText).toContain("retired");

    h.setNow(new Date(START + DAY_MS));
    const res = await update(profile.id, { issuingCaId: next.id });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ issuingCaId: next.id, privateCaId: ca.id, scepUrl: profile.scepUrl });
    expect(res.body.raCertificate.serial).not.toBe(profile.raCertificate.serial);

    // GetCACert now gives the new Issuing CA and an RA certificate it signed, to a device that asks afresh.
    const certs = await scepDevice(h, profile.scepUrl).client.getCACert();
    const issuing = read(certs.ca);
    expect(issuing.subject).toBe(next.subject);
    const ra = read(certs.encryptionCertificate);
    expect(ra.serialNumber.toUpperCase()).toBe(res.body.raCertificate.serial);
    expect(await ra.verify({ publicKey: issuing.publicKey, signatureOnly: true })).toBe(true);

    const after = read((await scepDevice(h, profile.scepUrl).enroll({ subject: "CN=after" })).certificate);
    expect(after.issuer).toBe(next.subject);
    expect(await after.verify({ publicKey: issuing.publicKey, signatureOnly: true })).toBe(true);
    // What the retired Issuing CA issued stays its own, on its CRL when revoked.
    const listed = (await certificatesOf(profile.id)).items as { id: string; subject: string; issuer: string }[];
    expect(listed.map((c) => [c.subject, c.issuer])).toEqual([
      ["CN=after", next.subject],
      ["CN=before", before.issuer],
    ]);
    const old = listed.find((c) => c.subject === "CN=before")!;
    expect((await h.api(`${profiles()}/${profile.id}/device-certificates/${old.id}/revocation`, { cookie: org.cookie, body: { reason: "superseded" } })).status).toBe(200);
    expect((await crlFor(before)).entries.map((e) => e.serialNumber.toUpperCase())).toEqual([before.serialNumber.toUpperCase()]);
    expect((await crlFor(after)).entries).toEqual([]);

    const updated = (await auditOf()).filter((e) => e.action === "enrollment_profile.updated");
    expect(updated).toHaveLength(1);
    expect(updated[0]).toMatchObject({
      actor: { email: "admin@acme.test" },
      target: { type: "enrollment_profile", id: profile.id },
      detail: { name: "Wi-Fi", changes: { issuingCa: { from: { id: ca.issuing.id }, to: { id: next.id, subject: next.subject } } }, raCertificate: { serial: res.body.raCertificate.serial } },
    });
  });

  test("is refused an Issuing CA that does not issue or is not the Organization's, and changes the retention period alone", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    const next = await addIssuingCa(ca);
    await retire(ca, next.id);
    const other = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    const theirs = await createCa(other);

    expect((await update(profile.id, { issuingCaId: next.id })).status).toBe(422);
    expect((await update(profile.id, { issuingCaId: theirs.issuing.id })).status).toBe(422);
    expect((await update(profile.id, { issuingCaId: "not-an-id" })).status).toBe(422);
    expect((await update(profile.id, { retentionDays: -1 })).status).toBe(400);
    expect((await profileOf(profile.id)).issuingCaId).toBe(ca.issuing.id);

    const res = await update(profile.id, { retentionDays: 30 });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ retentionDays: 30, issuingCaId: ca.issuing.id, raCertificate: profile.raCertificate });
    const updated = (await auditOf()).filter((e) => e.action === "enrollment_profile.updated");
    expect(updated.map((e) => e.detail)).toEqual([{ name: "Wi-Fi", changes: { retentionDays: { from: 365, to: 30 } } }]);

    // Nothing that changes nothing is audited.
    expect((await update(profile.id, { retentionDays: 30 })).status).toBe(200);
    expect((await update(profile.id, {})).status).toBe(200);
    expect((await auditOf()).filter((e) => e.action === "enrollment_profile.updated")).toHaveLength(1);
  });
});

describe("changing the device keys an Enrollment Profile allows", () => {
  test("allowing rsa-1024 issues to a 1024-bit key from then on, and is audited, in the profile's created and updated Audit Events alike", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    const device = scepDevice(h, profile.scepUrl);
    expect(await device.enroll({ subject: "CN=mac-01", keyBits: 1024 }).catch((err) => err)).toBeInstanceOf(ScepFailureError);

    const res = await update(profile.id, { allowedKeyTypes: ["rsa-1024", "rsa-2048", "rsa-3072", "rsa-4096"] });
    expect(res.status).toBe(200);
    expect(res.body.allowedKeyTypes).toEqual(["rsa-1024", "rsa-2048", "rsa-3072", "rsa-4096"]);
    expect((await device.enroll({ subject: "CN=mac-01", keyBits: 1024 })).certificate.publicKey.asymmetricKeyDetails?.modulusLength).toBe(1024);

    expect((await update(profile.id, { allowedKeyTypes: ["rsa-2048"] })).status).toBe(200);
    expect(await device.enroll({ subject: "CN=mac-02", keyBits: 1024 }).catch((err) => err)).toBeInstanceOf(ScepFailureError);
    // Nothing that changes nothing is audited; no key type at all, or one no profile takes, is refused.
    expect((await update(profile.id, { allowedKeyTypes: ["rsa-2048"] })).status).toBe(200);
    expect((await update(profile.id, { allowedKeyTypes: [] })).status).toBe(400);
    expect((await update(profile.id, { allowedKeyTypes: ["ecdsa-p256"] })).status).toBe(400);

    const created = (await auditOf()).find((e) => e.action === "enrollment_profile.created");
    expect(created!.detail.allowedKeyTypes).toEqual(["rsa-2048", "rsa-3072", "rsa-4096"]);
    const updated = (await auditOf()).filter((e) => e.action === "enrollment_profile.updated");
    expect(updated.map((e) => e.detail)).toEqual([
      { name: "Wi-Fi", changes: { allowedKeyTypes: { from: ["rsa-2048", "rsa-3072", "rsa-4096"], to: ["rsa-1024", "rsa-2048", "rsa-3072", "rsa-4096"] } } },
      { name: "Wi-Fi", changes: { allowedKeyTypes: { from: ["rsa-1024", "rsa-2048", "rsa-3072", "rsa-4096"], to: ["rsa-2048"] } } },
    ]);
  });
});

describe("rotating an Enrollment Profile's RA certificate", () => {
  test("issues a new RA certificate and key from its Issuing CA, which GetCACert serves from then on and devices enroll with", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    const before = await scepDevice(h, profile.scepUrl).client.getCACert();
    const oldRa = read(before.encryptionCertificate);

    h.setNow(new Date(START + 600 * DAY_MS));
    const res = await rotateRa(profile.id);
    expect(res.status).toBe(200);
    expect(res.body.raCertificate.serial).not.toBe(profile.raCertificate.serial);
    expect(res.body.raCertificate.notAfter).toBe(new Date(START + (600 + 730) * DAY_MS).toISOString());

    const device = scepDevice(h, profile.scepUrl);
    const certs = await device.client.getCACert();
    const ra = read(certs.encryptionCertificate);
    expect(ra.serialNumber.toUpperCase()).toBe(res.body.raCertificate.serial);
    expect(Buffer.from(ra.publicKey.rawData).equals(Buffer.from(oldRa.publicKey.rawData))).toBe(false);
    expect(await ra.verify({ publicKey: read(certs.ca).publicKey, signatureOnly: true })).toBe(true);
    expect(read((await device.enroll({ subject: "CN=after-rotation" })).certificate).subject).toBe("CN=after-rotation");

    const rotated = (await auditOf()).filter((e) => e.action === "enrollment_profile.ra_rotated");
    expect(rotated).toHaveLength(1);
    expect(rotated[0]).toMatchObject({
      actor: { email: "admin@acme.test" },
      target: { type: "enrollment_profile", id: profile.id },
      detail: { name: "Wi-Fi", from: { serial: profile.raCertificate.serial, notAfter: profile.raCertificate.notAfter }, to: { serial: res.body.raCertificate.serial, notAfter: res.body.raCertificate.notAfter } },
    });
    expect(JSON.stringify(rotated[0])).not.toContain("PRIVATE KEY");
  });

  test("is refused while the profile's Issuing CA does not issue", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    await retire(ca, ca.issuing.id);

    expect((await rotateRa(profile.id)).status).toBe(422);
    expect((await profileOf(profile.id)).raCertificate).toEqual(profile.raCertificate);
    expect((await auditOf()).some((e) => e.action === "enrollment_profile.ra_rotated")).toBe(false);
  });
});

describe("pruning Device Certificates", () => {
  test("deletes those that ended more than their profile's retention period ago, revoked or not, with one Audit Event per pass, and keeps their Audit Events", async () => {
    const ca = await createCa();
    const short = await createProfile(ca.issuing.id, { name: "Short", validityDays: 10, retentionDays: 30 });
    expect(short.retentionDays).toBe(30);
    const standard = await createProfile(ca.issuing.id, { name: "Standard", validityDays: 10 });
    expect(standard.retentionDays).toBe(365);
    await scepDevice(h, short.scepUrl).enroll({ subject: "CN=short-a" });
    await scepDevice(h, short.scepUrl).enroll({ subject: "CN=short-b" });
    await scepDevice(h, standard.scepUrl).enroll({ subject: "CN=standard" });
    const revocable = (await certificatesOf(short.id)).items.find((c: { subject: string }) => c.subject === "CN=short-b");
    expect((await h.api(`${profiles()}/${short.id}/device-certificates/${revocable.id}/revocation`, { cookie: org.cookie, body: { reason: "keyCompromise" } })).status).toBe(200);
    h.setNow(new Date(START + 20 * DAY_MS));
    await scepDevice(h, short.scepUrl).enroll({ subject: "CN=short-later" });

    // Ended on day 10: kept until 30 days after, to the moment.
    h.setNow(new Date(START + 40 * DAY_MS));
    expect(await h.pruneDeviceCertificates()).toBe(0);
    expect((await certificatesOf(short.id)).total).toBe(3);

    h.setNow(new Date(START + 40 * DAY_MS + 1));
    expect(await h.pruneDeviceCertificates()).toBe(2);
    expect((await certificatesOf(short.id)).items.map((c: { subject: string }) => c.subject)).toEqual(["CN=short-later"]);
    expect((await certificatesOf(standard.id)).items.map((c: { subject: string }) => c.subject)).toEqual(["CN=standard"]);

    const pruned = (await auditOf()).filter((e) => e.action === "device_certificate.pruned");
    expect(pruned).toHaveLength(1);
    expect(pruned[0]).toMatchObject({ actor: { id: null, email: null }, target: { type: "organization", id: org.orgId }, detail: { count: 2, enrollmentProfiles: [{ id: short.id, name: "Short", count: 2 }] } });
    const audit = await auditOf();
    expect(audit.filter((e) => e.action === "device_certificate.issued")).toHaveLength(4);
    expect(audit.filter((e) => e.action === "device_certificate.revoked")).toHaveLength(1);

    // A pass that prunes nothing leaves no Audit Event; the next one, past the standard profile's year, prunes it.
    expect(await h.pruneDeviceCertificates()).toBe(0);
    h.setNow(new Date(START + (10 + 365) * DAY_MS + 1));
    expect(await h.pruneDeviceCertificates()).toBe(2);
    expect((await certificatesOf(standard.id)).total).toBe(0);
    expect((await auditOf()).filter((e) => e.action === "device_certificate.pruned").map((e) => e.detail.count)).toEqual([2, 2]);
  });

  test("follows a retention period changed later, and prunes a disabled profile's too, each Organization's on its own", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id, { validityDays: 10 });
    await scepDevice(h, profile.scepUrl).enroll({ subject: "CN=device" });
    expect((await disable(profile.id)).status).toBe(200);
    const other = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    const theirCa = await createCa(other);
    const theirs = await h.api(profiles(other.orgId), { cookie: other.cookie, body: { name: "Theirs", issuingCaId: theirCa.issuing.id, validator: { kind: "test_allow" }, validityDays: 10, retentionDays: 0 } });
    await scepDevice(h, theirs.body.scepUrl).enroll({ subject: "CN=globex-device" });

    h.setNow(new Date(START + 12 * DAY_MS));
    expect(await h.pruneDeviceCertificates()).toBe(1);
    expect((await certificatesOf(profile.id)).total).toBe(1);
    expect((await update(profile.id, { retentionDays: 1 })).status).toBe(200);
    expect(await h.pruneDeviceCertificates()).toBe(1);
    expect((await certificatesOf(profile.id)).total).toBe(0);

    const pruned = (await auditOf()).filter((e) => e.action === "device_certificate.pruned");
    expect(pruned.map((e) => e.detail)).toEqual([{ count: 1, enrollmentProfiles: [{ id: profile.id, name: "Wi-Fi", count: 1 }] }]);
  });
});
