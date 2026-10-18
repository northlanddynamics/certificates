// Rolling over an Issuing CA by hand, and revoking one. An Organization Administrator adds a new Issuing CA under the
// same root, repoints Managed Certificates to it and retires the old one, which issues nothing more but keeps publishing
// its CRL until its last Certificate expires; relying parties that trust the root need nothing new. A platform-made
// Issuing CA can also be revoked, which puts it on its root's CRL. Every check is of what an outside party sees: the
// API's answers, the certificates, the CRLs and Audit Events.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import acme from "acme-client";
import { PASSWORD, createHarness, type Harness } from "./support/harness";

let h: Harness;
let operator: string;
let org: { orgId: string; cookie: string };
let globex: { orgId: string; cookie: string };

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  operator = await h.createOperator("op@platform.test", PASSWORD);
  org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
  globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
});
afterAll(async () => {
  await h.close();
});

const JAN_1 = Date.parse("2026-01-01T00:00:00Z");
const DAY = 86_400_000;

const api = (path: string, body?: unknown, { method, as = org }: { method?: string; as?: { orgId: string; cookie: string } } = {}) =>
  h.api(`/api/organizations/${as.orgId}${path}`, { cookie: as.cookie, body, method });
const auditOf = async () => (await api("/audit-events")).body.items as { action: string; actor: any; target: any; detail: any }[];

const ZONES = { exact: [], zones: ["internal.acme"] };
const NEW_CA = { name: "Internal TLS", subject: "CN=Acme Internal TLS, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: ZONES };

type Ca = { id: string; issuing: { id: string } };

/** A new Private CA with a platform-made root, and its first Issuing CA as `issuing`. */
async function createCa(body: Record<string, unknown> = NEW_CA, as = org): Promise<Ca> {
  const res = await api("/private-cas", body, { as });
  expect(res.status).toBe(201);
  return { id: res.body.id, issuing: res.body.issuingCas[0] };
}

/** Another Issuing CA under the Private CA's root. */
async function addIssuingCa(ca: { id: string }, subject: string, permittedNames: unknown = ZONES): Promise<Ca> {
  const res = await api(`/private-cas/${ca.id}/issuing-cas`, { subject, permittedNames });
  expect(res.status).toBe(201);
  return { id: ca.id, issuing: res.body };
}

/** The Issuing CA as the Private CA lists it. */
async function issuingCaOf(ca: Ca) {
  const res = await api(`/private-cas/${ca.id}`);
  return (res.body.issuingCas as { id: string; status: string; notAfter: string }[]).find((i) => i.id === ca.issuing.id)!;
}

const certificatesIn = (pem: string) => (pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map((one) => new x509.X509Certificate(one));

/** The Issuing CA's chain: the Issuing CA, then the root. */
async function chainOf(ca: Ca) {
  const res = await h.app.request(`http://localhost/api/organizations/${org.orgId}/private-cas/${ca.id}/issuing-cas/${ca.issuing.id}/chain`, { headers: { cookie: org.cookie } });
  const [issuing, root] = certificatesIn(await res.text());
  return { issuing: issuing!, root: root! };
}

async function join(email: string, role: string) {
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return { orgId: org.orgId, cookie: await h.signIn(email, PASSWORD) };
}

async function request(names: string[]) {
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() };
}

/** The Managed Certificate once its latest Issuance has ended. */
async function ended(id: string) {
  await h.settleIssuances();
  const res = await api(`/managed-certificates/${id}`);
  expect(res.body.issuance.status).not.toBe("running");
  return res.body;
}

/** A Managed Certificate on the Issuing CA, issued. */
async function issued(ca: Ca, names = ["app.internal.acme"], extra: Record<string, unknown> = {}) {
  const created = await api("/managed-certificates", { ...(await request(names)), issuer: { kind: "private_ca", issuingCaId: ca.issuing.id }, ...extra });
  expect(created.status).toBe(201);
  const mc = await ended(created.body.id);
  expect(mc.issuance.status).toBe("succeeded");
  return mc;
}

const retire = (ca: Ca, as = org) => api(`/private-cas/${ca.id}/issuing-cas/${ca.issuing.id}/retire`, {}, { method: "POST", as });
const renew = (mcId: string) => api(`/managed-certificates/${mcId}/renewals`, {}, { method: "POST" });

describe("retiring an Issuing CA", () => {
  test("it is retired: Renewal from it fails with a clear failure, and a new Managed Certificate on it is refused", async () => {
    const ca = await createCa();
    const mc = await issued(ca);

    const res = await retire(ca);

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ id: ca.issuing.id, status: "retired" });
    expect((await issuingCaOf(ca)).status).toBe("retired");
    expect((await renew(mc.id)).status).toBe(202);
    const failed = await ended(mc.id);
    expect(failed.issuance).toMatchObject({ kind: "renewal", status: "failed", failure: { code: "ca_rejected" } });
    expect(failed.issuance.failure.message).toContain("retired");
    const refused = await api("/managed-certificates", { ...(await request(["db.internal.acme"])), issuer: { kind: "private_ca", issuingCaId: ca.issuing.id } });
    expect(refused.status).toBe(422);
    expect(refused.body.error).toContain("retired");
  });

  test("the other Issuing CAs under its root keep issuing", async () => {
    const ca = await createCa();
    const next = await addIssuingCa(ca, "CN=Acme Internal TLS 2, O=Acme");

    expect((await retire(ca)).status).toBe(200);

    expect((await issuingCaOf(next)).status).toBe("active");
    await issued(next);
  });

  test("is audited as private_ca.retired, naming the Issuing CA; retiring it again is refused", async () => {
    const ca = await createCa();
    await retire(ca);

    const again = await retire(ca);

    expect(again.status).toBe(422);
    expect((await auditOf()).filter((e) => e.action === "private_ca.retired")).toMatchObject([
      { actor: { email: "admin@acme.test" }, target: { type: "private_ca", id: ca.id }, detail: { name: "Internal TLS", issuingCa: { id: ca.issuing.id, subject: "CN=Acme Internal TLS, O=Acme" } } },
    ]);
  });

  test("only an Organization Administrator may; another Organization's Issuing CA is not found", async () => {
    const ca = await createCa();
    const theirs = await createCa(NEW_CA, globex);

    for (const role of ["approver", "member"]) expect((await retire(ca, await join(`${role}@acme.test`, role))).status).toBe(403);
    expect((await api(`/private-cas/${theirs.id}/issuing-cas/${theirs.issuing.id}/retire`, {}, { method: "POST" })).status).toBe(404);
    expect((await issuingCaOf(ca)).status).toBe("active");
  });
});

/** The CRL published at the URL, as a relying party fetches it. */
async function crlAt(url: string) {
  const res = await h.app.request(url);
  expect(res.status).toBe(200);
  return new x509.X509Crl(new Uint8Array(await res.arrayBuffer()));
}

/** The URL of the CRL the certificate's CRL Distribution Point names. */
const crlUrlOf = (cert: x509.X509Certificate) => cert.getExtension(x509.CRLDistributionPointsExtension)!.distributionPoints[0]!.distributionPoint!.fullName![0]!.uniformResourceIdentifier!;

/** The leaf of the Managed Certificate's current Certificate. */
async function leafOf(mcId: string) {
  const res = await h.app.request(`http://localhost/api/organizations/${org.orgId}/managed-certificates/${mcId}/certificate?chain=leaf`, { headers: { cookie: org.cookie } });
  return certificatesIn(await res.text())[0]!;
}

describe("a retired Issuing CA's CRL", () => {
  test("is reissued, and lists what is revoked, until its last Certificate expires; then it is reissued no more", async () => {
    const ca = await createCa();
    const mc = await issued(ca, ["app.internal.acme"], { validityDays: 10 });
    const leaf = await leafOf(mc.id);
    expect((await retire(ca)).status).toBe(200);

    h.setNow(new Date(JAN_1 + 4 * DAY));
    expect(await h.runCrlScheduler()).toBe(2);
    const revoked = await api(`/managed-certificates/${mc.id}/certificates/${mc.currentCertificate.id}/revocation`, { reason: "superseded" });
    expect(revoked.status).toBe(200);
    expect((await crlAt(crlUrlOf(leaf))).entries.map((e) => e.serialNumber.toUpperCase())).toEqual([mc.currentCertificate.serial]);

    h.setNow(new Date(JAN_1 + 8 * DAY));
    expect(await h.runCrlScheduler()).toBe(2);
    const last = await crlAt(crlUrlOf(leaf));
    expect(last.thisUpdate.toISOString()).toBe(new Date(JAN_1 + 8 * DAY).toISOString());

    // Its last Certificate has expired: only the root's CRL is reissued.
    h.setNow(new Date(JAN_1 + 12 * DAY));
    expect(await h.runCrlScheduler()).toBe(1);
    expect((await crlAt(crlUrlOf(leaf))).thisUpdate.getTime()).toBe(last.thisUpdate.getTime());
  });
});

const repoint = (mcId: string, issuer: unknown, as = org) => api(`/managed-certificates/${mcId}/issuer`, { issuer }, { method: "PUT", as });

describe("repointing a Managed Certificate to another Issuing CA", () => {
  test("rolls it over under the same root: its next Certificate comes from the new Issuing CA, with no Approval, and the old one can then be retired", async () => {
    const ca = await createCa();
    const mc = await issued(ca);
    const next = await addIssuingCa(ca, "CN=Acme Internal TLS 2, O=Acme");

    const res = await repoint(mc.id, { kind: "private_ca", issuingCaId: next.issuing.id });

    expect(res.status).toBe(200);
    expect(res.body.issuer).toMatchObject({ kind: "private_ca", issuingCa: { id: next.issuing.id, subject: "CN=Acme Internal TLS 2, O=Acme" }, privateCa: { id: ca.id } });
    expect((await retire(ca)).status).toBe(200);
    expect((await renew(mc.id)).status).toBe(202);
    const renewed = await ended(mc.id);
    expect(renewed.issuance).toMatchObject({ kind: "renewal", status: "succeeded" });
    expect(renewed.currentCertificate.issuingCaId).toBe(next.issuing.id);
    const leaf = await leafOf(mc.id);
    const { issuing, root } = await chainOf(next);
    expect(await leaf.verify({ publicKey: issuing, signatureOnly: true })).toBe(true);
    expect(root.equal((await chainOf(ca)).root)).toBe(true);
  });

  test("is audited as managed_certificate.issuer_changed, from and to", async () => {
    const ca = await createCa();
    const mc = await issued(ca);
    const next = await addIssuingCa(ca, "CN=Acme Internal TLS 2, O=Acme");

    await repoint(mc.id, { kind: "private_ca", issuingCaId: next.issuing.id });

    expect((await auditOf()).filter((e) => e.action === "managed_certificate.issuer_changed")).toMatchObject([
      {
        actor: { email: "admin@acme.test" },
        target: { type: "managed_certificate", id: mc.id },
        detail: { from: { kind: "private_ca", issuingCaId: ca.issuing.id }, to: { kind: "private_ca", issuingCaId: next.issuing.id } },
      },
    ]);
  });

  test("may move it to an Issuing CA of another Private CA, under another root", async () => {
    const ca = await createCa();
    const mc = await issued(ca);
    const other = await createCa({ ...NEW_CA, name: "Other", subject: "CN=Acme Other, O=Acme" });

    expect((await repoint(mc.id, { kind: "private_ca", issuingCaId: other.issuing.id })).status).toBe(200);

    await renew(mc.id);
    expect((await ended(mc.id)).currentCertificate.issuingCaId).toBe(other.issuing.id);
  });

  test("is refused when its names are outside the new Issuing CA's rules, and it stays where it was", async () => {
    const ca = await createCa();
    const mc = await issued(ca);
    const devices = await addIssuingCa(ca, "CN=Acme Devices, O=Acme", { exact: [], zones: ["devices.acme"] });

    const res = await repoint(mc.id, { kind: "private_ca", issuingCaId: devices.issuing.id });

    expect(res.status).toBe(422);
    expect(res.body.error).toContain("app.internal.acme");
    expect((await api(`/managed-certificates/${mc.id}`)).body.issuer.issuingCa.id).toBe(ca.issuing.id);
    expect((await auditOf()).filter((e) => e.action === "managed_certificate.issuer_changed")).toEqual([]);
  });

  test("is refused to an Issuing CA that is retired, or another Organization's", async () => {
    const ca = await createCa();
    const mc = await issued(ca);
    const retired = await addIssuingCa(ca, "CN=Acme Retired, O=Acme");
    await retire(retired);
    const theirs = await createCa(NEW_CA, globex);

    expect((await repoint(mc.id, { kind: "private_ca", issuingCaId: retired.issuing.id })).status).toBe(422);
    expect((await repoint(mc.id, { kind: "private_ca", issuingCaId: theirs.issuing.id })).status).toBe(422);
  });

  test("across kinds of issuer is refused, either way", async () => {
    const ca = await createCa();
    const onPrivateCa = await issued(ca);
    const onAcme = await api("/managed-certificates", { ...(await request(["www.acme.test"])), environment: "staging" });
    expect(onAcme.status).toBe(201);
    await h.settleIssuances();

    expect((await repoint(onPrivateCa.id, { kind: "acme", environment: "staging" })).status).toBe(422);
    expect((await repoint(onAcme.body.id, { kind: "private_ca", issuingCaId: ca.issuing.id })).status).toBe(422);
    expect((await api(`/managed-certificates/${onAcme.body.id}`)).body.issuer).toEqual({ kind: "acme", environment: "staging" });
  });

  test("only an Organization Administrator may, not even an Owner", async () => {
    const ca = await createCa();
    const mc = await issued(ca);
    const next = await addIssuingCa(ca, "CN=Acme Internal TLS 2, O=Acme");
    const member = await join("member@acme.test", "member");
    const memberId = (await h.api("/api/me", { cookie: member.cookie })).body.user.id;
    expect((await api(`/managed-certificates/${mc.id}/owners`, { type: "user", id: memberId })).status).toBe(200);
    const approver = await join("approver@acme.test", "approver");

    for (const as of [member, approver]) expect((await repoint(mc.id, { kind: "private_ca", issuingCaId: next.issuing.id }, as)).status).toBe(403);
    expect((await api(`/managed-certificates/${mc.id}`)).body.issuer.issuingCa.id).toBe(ca.issuing.id);
  });
});

const revokeCa = (ca: Ca, reason: string, as = org) => api(`/private-cas/${ca.id}/issuing-cas/${ca.issuing.id}/revocation`, { reason }, { as });

describe("revoking a platform-made Issuing CA", () => {
  test("puts it on its root's CRL at once, with the reason, and it issues nothing more", async () => {
    const ca = await createCa();
    const mc = await issued(ca);
    const { issuing, root } = await chainOf(ca);
    h.setNow(new Date(JAN_1 + DAY));

    const res = await revokeCa(ca, "keyCompromise");

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ id: ca.issuing.id, status: "revoked" });
    const crl = await crlAt(crlUrlOf(issuing));
    expect(await crl.verify({ publicKey: root })).toBe(true);
    expect(crl.entries.map((e) => ({ serial: e.serialNumber.toLowerCase(), reason: e.reason, at: e.revocationDate.toISOString() }))).toEqual([
      { serial: issuing.serialNumber.toLowerCase(), reason: x509.X509CrlReason.keyCompromise, at: new Date(JAN_1 + DAY).toISOString() },
    ]);
    await renew(mc.id);
    expect((await ended(mc.id)).issuance).toMatchObject({ status: "failed", failure: { code: "ca_rejected" } });
  });

  test("its own CRL keeps being reissued while a Certificate it signed is unexpired, so relying parties never see it go stale", async () => {
    const ca = await createCa();
    const mc = await issued(ca, ["app.internal.acme"], { validityDays: 10 });
    const leaf = await leafOf(mc.id);
    expect((await revokeCa(ca, "cACompromise")).status).toBe(200);

    h.setNow(new Date(JAN_1 + 4 * DAY));
    expect(await h.runCrlScheduler()).toBe(2);
    expect((await crlAt(crlUrlOf(leaf))).thisUpdate.toISOString()).toBe(new Date(JAN_1 + 4 * DAY).toISOString());

    h.setNow(new Date(JAN_1 + 12 * DAY));
    expect(await h.runCrlScheduler()).toBe(1);
  });

  test("leaves the other Issuing CAs under its root as they are, and its root's CRL lists only it", async () => {
    const ca = await createCa();
    const next = await addIssuingCa(ca, "CN=Acme Internal TLS 2, O=Acme");

    expect((await revokeCa(ca, "superseded")).status).toBe(200);

    expect((await issuingCaOf(next)).status).toBe("active");
    await issued(next);
    const { issuing } = await chainOf(next);
    expect((await crlAt(crlUrlOf(issuing))).entries.map((e) => e.serialNumber.toLowerCase())).toEqual([(await chainOf(ca)).issuing.serialNumber.toLowerCase()]);
  });

  test("a retired one may be revoked too; one revoked already may not be again", async () => {
    const ca = await createCa();
    await retire(ca);

    expect((await revokeCa(ca, "cessationOfOperation")).status).toBe(200);
    expect((await revokeCa(ca, "keyCompromise")).status).toBe(422);
  });

  test("is audited as private_ca.revoked, naming the Issuing CA and the reason", async () => {
    const ca = await createCa();
    const { issuing } = await chainOf(ca);
    await revokeCa(ca, "keyCompromise");

    expect((await auditOf()).filter((e) => e.action === "private_ca.revoked")).toMatchObject([
      {
        actor: { email: "admin@acme.test" },
        target: { type: "private_ca", id: ca.id },
        detail: { name: "Internal TLS", issuingCa: { id: ca.issuing.id, subject: "CN=Acme Internal TLS, O=Acme", serial: issuing.serialNumber }, reason: "keyCompromise" },
      },
    ]);
  });

  test("only an Organization Administrator may; an unknown reason is refused", async () => {
    const ca = await createCa();

    for (const role of ["approver", "member"]) expect((await revokeCa(ca, "keyCompromise", await join(`${role}@acme.test`, role))).status).toBe(403);
    expect((await revokeCa(ca, "certificateHold")).status).toBe(400);
    expect((await issuingCaOf(ca)).status).toBe("active");
  });

  test("one under the Organization's own root is refused: that root revokes it", async () => {
    const res = await api("/private-cas", { name: "Own", kind: "organization_root", subject: "CN=Acme Own, O=Acme", keyAlgorithm: "ecdsa-p256", permittedNames: ZONES });
    expect(res.status).toBe(201);
    const own = { id: res.body.id, issuing: res.body.issuingCas[0] };

    const refused = await revokeCa(own, "keyCompromise");

    expect(refused.status).toBe(422);
    expect(refused.body.error).toContain("own root");
  });

  test("a KMS that does not sign the root's CRL leaves it unrevoked (502)", async () => {
    const ca = await createCa();

    h.kms.failing = true;
    expect((await revokeCa(ca, "keyCompromise")).status).toBe(502);
    h.kms.failing = false;

    expect((await issuingCaOf(ca)).status).toBe("active");
    expect((await auditOf()).filter((e) => e.action === "private_ca.revoked")).toEqual([]);
  });
});
