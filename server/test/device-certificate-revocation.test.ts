// Device Certificate Revocation through its own interface: what an administrator, a revocation feed and a RenewalReq all
// revoke through. Devices enroll over SCEP to have Device Certificates to revoke; each check is of what `revoke` answers,
// the Audit Events and the CRL a relying party fetches.
import { afterAll, beforeAll, beforeEach, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { randomUUID } from "node:crypto";
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

const read = (cert: { raw: Buffer }) => new x509.X509Certificate(new Uint8Array(cert.raw));
const auditOf = async (target = org) => (await h.api(`/api/organizations/${target.orgId}/audit-events`, { cookie: target.cookie })).body.items as { action: string; actor: any; target: any; detail: any }[];
/** The `device_certificate.revoked` Audit Events, by subject. */
const revokedEvents = async (target = org) => (await auditOf(target)).filter((e) => e.action === "device_certificate.revoked").sort((x, y) => x.detail.subject.localeCompare(y.detail.subject));

/** An Enrollment Profile on a new Private CA's Issuing CA, with two enrolled Device Certificates, oldest first. */
async function enrolled(target = org) {
  const ca = await h.api(`/api/organizations/${target.orgId}/private-cas`, {
    cookie: target.cookie,
    body: { name: "Devices", subject: "CN=Acme Devices, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["devices.acme"] } },
  });
  expect(ca.status).toBe(201);
  const profile = await h.api(`/api/organizations/${target.orgId}/enrollment-profiles`, { cookie: target.cookie, body: { name: "Wi-Fi", issuingCaId: ca.body.issuingCas[0].id, validator: { kind: "test_allow" } } });
  expect(profile.status).toBe(201);
  const device = scepDevice(h, profile.body.scepUrl);
  const first = read((await device.enroll({ subject: "CN=first" })).certificate);
  const second = read((await device.enroll({ subject: "CN=second" })).certificate);
  const listed = await h.api(`/api/organizations/${target.orgId}/enrollment-profiles/${profile.body.id}/device-certificates`, { cookie: target.cookie });
  const items = listed.body.items as { id: string; serial: string; subject: string }[];
  const a = items.find((item) => item.subject === "CN=first")!;
  const b = items.find((item) => item.subject === "CN=second")!;
  return { profile: profile.body as { id: string }, a, b, cert: first, serials: [first.serialNumber.toUpperCase(), second.serialNumber.toUpperCase()] };
}

/** The CRL a certificate's CRL Distribution Point names, as a relying party fetches it. */
async function crlFor(cert: x509.X509Certificate) {
  const cdp = cert.getExtension(x509.CRLDistributionPointsExtension)!;
  const res = await h.app.request(cdp.distributionPoints[0]!.distributionPoint!.fullName![0]!.uniformResourceIdentifier!);
  return new x509.X509Crl(new Uint8Array(await res.arrayBuffer()));
}

const revoke = (orgId: string, revocations: Parameters<Harness["deviceCertificateRevocations"]["revoke"]>[3]) =>
  h.unitOfWork.run(null, (tx, change) => h.deviceCertificateRevocations.revoke(tx, change, orgId, revocations));

test("revokes each in the order given, once: one already revoked, asked twice or not the Organization's is answered false", async () => {
  const { profile, a, b, cert, serials } = await enrolled();
  const outcomes = await revoke(org.orgId, [
    { id: b.id, reason: "keyCompromise", by: { enrollmentValidator: { kind: "test_allow" } } },
    { id: a.id, reason: "superseded", by: { renewal: { serial: "ABCD" } } },
    { id: b.id, reason: "cessationOfOperation" },
    { id: randomUUID(), reason: "unspecified" },
  ]);
  expect(outcomes).toEqual([true, true, false, false]);

  const events = await revokedEvents();
  expect(events.every((e) => e.actor.id === null)).toBe(true);
  expect(events.map((e) => [e.target.id, e.detail])).toEqual([
    [a.id, { enrollmentProfile: { id: profile.id, name: "Wi-Fi" }, serial: a.serial, subject: "CN=first", reason: "superseded", by: { renewal: { serial: "ABCD" } } }],
    [b.id, { enrollmentProfile: { id: profile.id, name: "Wi-Fi" }, serial: b.serial, subject: "CN=second", reason: "keyCompromise", by: { enrollmentValidator: { kind: "test_allow" } } }],
  ]);
  const crl = await crlFor(cert);
  expect(Object.fromEntries(crl.entries.map((e) => [e.serialNumber.toUpperCase(), e.reason]))).toEqual({ [serials[0]!]: x509.X509CrlReason.superseded, [serials[1]!]: x509.X509CrlReason.keyCompromise });

  // Asked again, nothing changes: no Revocation is recorded twice, nor its reason replaced.
  expect(await revoke(org.orgId, [{ id: a.id, reason: "keyCompromise" }])).toEqual([false]);
  expect(await revokedEvents()).toHaveLength(2);
  expect((await crlFor(cert)).entries.find((e) => e.serialNumber.toUpperCase() === serials[0])!.reason).toBe(x509.X509CrlReason.superseded);
});

test("revokes nothing of another Organization's", async () => {
  const { a } = await enrolled();
  const other = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
  expect(await revoke(other.orgId, [{ id: a.id, reason: "keyCompromise" }])).toEqual([false]);
  expect(await revokedEvents()).toEqual([]);
});

test("nothing is revoked when the CRL cannot be signed: the change rolls back, Revocations and Audit Events too", async () => {
  const { a, cert } = await enrolled();
  h.kms.failing = true;
  await expect(revoke(org.orgId, [{ id: a.id, reason: "keyCompromise" }])).rejects.toThrow();
  h.kms.failing = false;
  expect(await revokedEvents()).toEqual([]);
  expect((await crlFor(cert)).entries).toEqual([]);
  expect(await revoke(org.orgId, [{ id: a.id, reason: "keyCompromise" }])).toEqual([true]);
});

test("asked for nothing, it does nothing", async () => {
  expect(await revoke(org.orgId, [])).toEqual([]);
});
