// Revocations a CA confirms later: an issuer kind may take a revocation request and confirm or refuse it afterwards, as a
// CA reached through an Agent does. Until it confirms, nothing is revoked: the Certificate shows that its revocation was
// requested and cannot be revoked again; once it confirms, the Revocation and its Audit Event are recorded, attributed to
// whoever asked; refused, unreachable or not answered in time, the request fails with its cause and the Certificate stays
// unrevoked. Device Certificates go the same way. The kind here is the test-only held issuer, in front of a Private CA.
// No Pebble and no DNS; time is the harness's clock.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import acme from "acme-client";
import { CertificateAuthorityError } from "../src/issuance/acme/certificate-authority";
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

const JAN_1 = Date.parse("2026-01-01T00:00:00Z");
const DAY = 86_400_000;
const days = (n: number) => new Date(JAN_1 + n * DAY);

const BA = "/api/auth/organization";

/** A new member of the Organization, signed in, with their id. */
async function join(email: string, role: string) {
  const invited = await h.api(`${BA}/invite-member`, { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
  await h.api(`${BA}/accept-invitation`, { cookie: await h.signUp(email, PASSWORD), body: { invitationId: invited.body.id } });
  const cookie = await h.signIn(email, PASSWORD);
  return { cookie, userId: (await h.api("/api/me", { cookie })).body.user.id as string };
}

const api = (path: string, opts: { body?: unknown; method?: string } = {}) => h.api(`/api/organizations/${org.orgId}${path}`, { cookie: org.cookie, ...opts });
const auditOf = async () => (await api("/audit-events")).body.items as { action: string; actor: any; target: any; detail: any }[];
const actions = async () => (await auditOf()).map((e) => e.action);

async function createCa(zones: string[]) {
  const res = await api("/private-cas", { body: { name: "Internal", subject: "CN=Acme Internal, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones } } });
  expect(res.status).toBe(201);
  return res.body.issuingCas[0].id as string;
}

/** A Managed Certificate issued at once from a Private CA, and its Certificate. */
async function issued() {
  const issuingCaId = await createCa(["internal.acme"]);
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: "app.internal.acme", altNames: ["app.internal.acme"] }, key);
  const res = await api("/managed-certificates", { body: { names: ["app.internal.acme"], keyAlgorithm: "ecdsa-p256", csr: csr.toString(), issuer: { kind: "private_ca", issuingCaId } } });
  expect(res.status).toBe(201);
  await h.settleIssuances();
  const mc = (await api(`/managed-certificates/${res.body.id}`)).body;
  expect(mc.currentCertificate).not.toBeNull();
  return { mcId: mc.id as string, certificateId: mc.currentCertificate.id as string };
}

const revoke = (mcId: string, certificateId: string, reason = "keyCompromise") => api(`/managed-certificates/${mcId}/certificates/${certificateId}/revocation`, { body: { reason } });
const certificateOf = async (mcId: string, certificateId: string) => (await api(`/managed-certificates/${mcId}/certificates/${certificateId}`)).body;
const heldRequest = (i = 0) => h.heldIssuer.revocations[i]!.requestId;

describe("a Certificate whose CA confirms its revocation later", () => {
  test("is answered 202 and shows its revocation requested, with nothing revoked yet", async () => {
    const { mcId, certificateId } = await issued();
    h.heldIssuer.holdingRevocations = true;

    const res = await revoke(mcId, certificateId);

    expect(res.status).toBe(202);
    expect(res.body.revocation).toBeNull();
    expect(res.body.revocationRequest).toEqual({
      reason: "keyCompromise",
      status: "pending",
      requestedAt: days(0).toISOString(),
      requestedBy: { id: expect.any(String), email: "admin@acme.test" },
      deadline: days(7).toISOString(),
      failure: null,
    });
    expect(await certificateOf(mcId, certificateId)).toMatchObject({ revocation: null, revocationRequest: { status: "pending" } });
    expect((await api(`/managed-certificates/${mcId}`)).body.currentCertificate).toMatchObject({ revocation: null, revocationRequest: { status: "pending" } });
    expect(await actions()).not.toContain("certificate.revoked");
    const requested = (await auditOf()).find((e) => e.action === "certificate.revocation_requested")!;
    expect(requested).toMatchObject({ actor: { email: "admin@acme.test" }, target: { type: "managed_certificate", id: mcId }, detail: { certificateId, reason: "keyCompromise" } });
    expect(h.heldIssuer.revocations).toHaveLength(1);
  });

  test("cannot be revoked again while it waits", async () => {
    const { mcId, certificateId } = await issued();
    h.heldIssuer.holdingRevocations = true;
    expect((await revoke(mcId, certificateId)).status).toBe(202);

    const again = await revoke(mcId, certificateId, "superseded");

    expect(again.status).toBe(409);
    expect(h.heldIssuer.revocations).toHaveLength(1);
  });

  test("is revoked once the CA confirms: recorded and audited as revoked by whoever asked", async () => {
    const { mcId, certificateId } = await issued();
    h.heldIssuer.holdingRevocations = true;
    await revoke(mcId, certificateId);
    h.setNow(days(2));

    expect(await h.heldIssuer.confirmRevocation(heldRequest())).toBe(true);

    const certificate = await certificateOf(mcId, certificateId);
    expect(certificate.revocation).toEqual({ reason: "keyCompromise", revokedAt: days(2).toISOString(), revokedBy: { id: expect.any(String), email: "admin@acme.test" } });
    expect(certificate.revocationRequest).toBeNull();
    const revoked = (await auditOf()).filter((e) => e.action === "certificate.revoked");
    expect(revoked).toHaveLength(1);
    expect(revoked[0]).toMatchObject({ actor: { email: "admin@acme.test" }, target: { type: "managed_certificate", id: mcId }, detail: { certificateId, reason: "keyCompromise" } });

    // Confirmed twice, it is recorded once; and it cannot be revoked again.
    expect(await h.heldIssuer.confirmRevocation(heldRequest())).toBe(false);
    expect((await auditOf()).filter((e) => e.action === "certificate.revoked")).toHaveLength(1);
    expect((await revoke(mcId, certificateId)).status).toBe(409);
  });

  test("an Owner's request is recorded as the Owner's once confirmed", async () => {
    const { mcId, certificateId } = await issued();
    const owner = await join("owner@acme.test", "member");
    expect((await api(`/managed-certificates/${mcId}/owners`, { body: { type: "user", id: owner.userId } })).status).toBe(200);
    h.heldIssuer.holdingRevocations = true;
    const res = await h.api(`/api/organizations/${org.orgId}/managed-certificates/${mcId}/certificates/${certificateId}/revocation`, { cookie: owner.cookie, body: { reason: "cessationOfOperation" } });
    expect(res.status).toBe(202);

    await h.heldIssuer.confirmRevocation(heldRequest());

    expect((await certificateOf(mcId, certificateId)).revocation).toMatchObject({ reason: "cessationOfOperation", revokedBy: { email: "owner@acme.test" } });
    expect((await auditOf()).find((e) => e.action === "certificate.revoked")!.actor).toMatchObject({ email: "owner@acme.test" });
  });

  test("refused, it fails with the CA's reason and stays unrevoked; it may then be asked again", async () => {
    const { mcId, certificateId } = await issued();
    h.heldIssuer.holdingRevocations = true;
    await revoke(mcId, certificateId);
    h.setNow(days(1));

    expect(await h.heldIssuer.refuseRevocation(heldRequest(), new CertificateAuthorityError("rejected", "the CA does not know this serial"))).toBe(true);

    const certificate = await certificateOf(mcId, certificateId);
    expect(certificate.revocation).toBeNull();
    expect(certificate.revocationRequest).toMatchObject({ status: "failed", failure: { code: "rejected", message: "the CA does not know this serial" } });
    expect(await actions()).not.toContain("certificate.revoked");
    expect((await auditOf()).find((e) => e.action === "certificate.revocation_failed")).toMatchObject({
      actor: { email: "admin@acme.test" },
      detail: { certificateId, reason: "keyCompromise", failure: { code: "rejected", message: "the CA does not know this serial" } },
    });
    // A late confirmation of the failed request changes nothing.
    expect(await h.heldIssuer.confirmRevocation(heldRequest())).toBe(false);
    expect((await certificateOf(mcId, certificateId)).revocation).toBeNull();

    // Asked again, of a CA that revokes at once this time, it is revoked and the failed request is gone.
    h.heldIssuer.holdingRevocations = false;
    const again = await revoke(mcId, certificateId, "superseded");
    expect(again.status).toBe(200);
    expect(again.body).toMatchObject({ revocation: { reason: "superseded" }, revocationRequest: null });
  });

  test("an unreachable CA fails it as unreachable", async () => {
    const { mcId, certificateId } = await issued();
    h.heldIssuer.holdingRevocations = true;
    await revoke(mcId, certificateId);

    await h.heldIssuer.refuseRevocation(heldRequest(), new CertificateAuthorityError("unreachable", "no Agent could reach the CA"));

    expect((await certificateOf(mcId, certificateId)).revocationRequest).toMatchObject({ status: "failed", failure: { code: "unreachable", message: "no Agent could reach the CA" } });
  });

  test("not confirmed by its deadline, it fails as timed out, and is still revoked if the CA confirms late", async () => {
    const { mcId, certificateId } = await issued();
    h.heldIssuer.holdingRevocations = true;
    await revoke(mcId, certificateId);

    h.setNow(days(6));
    expect(await h.timeOutRevocations()).toBe(0);
    h.setNow(days(7));
    expect(await h.timeOutRevocations()).toBe(1);

    expect((await certificateOf(mcId, certificateId)).revocationRequest).toMatchObject({ status: "failed", failure: { code: "timed_out" } });
    expect(await h.timeOutRevocations()).toBe(0);
    expect((await certificateOf(mcId, certificateId)).revocation).toBeNull();

    h.setNow(days(8));
    expect(await h.heldIssuer.confirmRevocation(heldRequest())).toBe(true);
    expect(await certificateOf(mcId, certificateId)).toMatchObject({ revocation: { reason: "keyCompromise", revokedAt: days(8).toISOString() }, revocationRequest: null });
  });

  test("a CA that revokes at once is never requested", async () => {
    const { mcId, certificateId } = await issued();

    const res = await revoke(mcId, certificateId);

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ revocation: { reason: "keyCompromise" }, revocationRequest: null });
    expect(await actions()).not.toContain("certificate.revocation_requested");
  });
});

/** An Enrollment Profile on a new Private CA's Issuing CA, with one enrolled Device Certificate. */
async function enrolled() {
  const issuingCaId = await createCa(["devices.acme"]);
  const profile = await api("/enrollment-profiles", { body: { name: "Wi-Fi", issuingCaId, validator: { kind: "test_allow" } } });
  expect(profile.status).toBe(201);
  const device = scepDevice(h, profile.body.scepUrl);
  const cert = new x509.X509Certificate(new Uint8Array((await device.enroll({ subject: "CN=laptop" })).certificate.raw));
  const listed = await api(`/enrollment-profiles/${profile.body.id}/device-certificates`);
  return { profileId: profile.body.id as string, id: listed.body.items[0].id as string, serial: cert.serialNumber.toUpperCase() };
}

const deviceCertificateOf = async (profileId: string, id: string) => (await api(`/enrollment-profiles/${profileId}/device-certificates/${id}`)).body;
const revokeDevices = (revocations: Parameters<Harness["deviceCertificateRevocations"]["revoke"]>[3]) =>
  h.unitOfWork.run(null, (tx, change) => h.deviceCertificateRevocations.revoke(tx, change, org.orgId, revocations));

describe("a Device Certificate whose CA confirms its revocation later", () => {
  test("revoked by an Organization Administrator, is requested, then revoked as theirs once confirmed", async () => {
    const { profileId, id } = await enrolled();
    h.heldIssuer.holdingRevocations = true;

    const res = await api(`/enrollment-profiles/${profileId}/device-certificates/${id}/revocation`, { body: { reason: "cessationOfOperation" } });

    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({ status: "active", revocation: null, revocationRequest: { status: "pending", reason: "cessationOfOperation", requestedBy: { email: "admin@acme.test" } } });
    expect((await api(`/enrollment-profiles/${profileId}/device-certificates/${id}/revocation`, { body: { reason: "keyCompromise" } })).status).toBe(409);
    expect(await actions()).not.toContain("device_certificate.revoked");

    h.setNow(days(1));
    expect(await h.heldIssuer.confirmRevocation(heldRequest())).toBe(true);

    expect(await deviceCertificateOf(profileId, id)).toMatchObject({ status: "revoked", revocation: { reason: "cessationOfOperation", revokedAt: days(1).toISOString() }, revocationRequest: null });
    const revoked = (await auditOf()).filter((e) => e.action === "device_certificate.revoked");
    expect(revoked).toHaveLength(1);
    expect(revoked[0]).toMatchObject({ actor: { email: "admin@acme.test" }, target: { type: "device_certificate", id }, detail: { reason: "cessationOfOperation" } });
    expect(revoked[0]!.detail.by).toBeUndefined();
  });

  test("revoked by a revocation feed or as superseded, is requested, and recorded with who asked once confirmed", async () => {
    const { profileId, id, serial } = await enrolled();
    h.heldIssuer.holdingRevocations = true;

    expect(await revokeDevices([{ id, reason: "superseded", by: { renewal: { serial: "ABCD" } } }])).toEqual(["requested"]);
    expect(await revokeDevices([{ id, reason: "keyCompromise", by: { enrollmentValidator: { kind: "test_allow" } } }])).toEqual([false]);
    expect(await deviceCertificateOf(profileId, id)).toMatchObject({ status: "active", revocationRequest: { status: "pending", reason: "superseded", requestedBy: null } });
    expect((await auditOf()).find((e) => e.action === "device_certificate.revocation_requested")).toMatchObject({ actor: { id: null }, detail: { serial, reason: "superseded", by: { renewal: { serial: "ABCD" } } } });

    await h.heldIssuer.confirmRevocation(heldRequest());

    expect(await deviceCertificateOf(profileId, id)).toMatchObject({ status: "revoked", revocation: { reason: "superseded" } });
    expect((await auditOf()).find((e) => e.action === "device_certificate.revoked")).toMatchObject({ actor: { id: null }, detail: { serial, reason: "superseded", by: { renewal: { serial: "ABCD" } } } });
  });

  test("refused, it stays active with the cause, and may be revoked again", async () => {
    const { profileId, id } = await enrolled();
    h.heldIssuer.holdingRevocations = true;
    await revokeDevices([{ id, reason: "keyCompromise", by: { enrollmentValidator: { kind: "test_allow" } } }]);

    await h.heldIssuer.refuseRevocation(heldRequest(), new CertificateAuthorityError("rejected", "denied by the CA"));

    expect(await deviceCertificateOf(profileId, id)).toMatchObject({ status: "active", revocation: null, revocationRequest: { status: "failed", failure: { code: "rejected", message: "denied by the CA" } } });
    expect((await auditOf()).find((e) => e.action === "device_certificate.revocation_failed")).toMatchObject({ detail: { reason: "keyCompromise", failure: { code: "rejected" } } });

    h.heldIssuer.holdingRevocations = false;
    expect(await revokeDevices([{ id, reason: "keyCompromise" }])).toEqual([true]);
    expect(await deviceCertificateOf(profileId, id)).toMatchObject({ status: "revoked", revocationRequest: null });
  });
});
