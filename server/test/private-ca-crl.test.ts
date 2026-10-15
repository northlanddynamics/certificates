// Revocation from a Private CA and its CRL: revoking a Certificate puts it on its Issuing CA's CRL at once, which any
// relying party fetches, with no credentials and over plain HTTP, from the URL in the Certificate's CRL Distribution
// Point. Every check is of what an outside party sees: the API's answers, the certificates, the CRLs and Audit Events.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import acme from "acme-client";
import { PASSWORD, PKI_BASE_URL, createHarness, type Harness } from "./harness";

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
const mcs = (orgId = org.orgId) => `/api/organizations/${orgId}/managed-certificates`;
const auditOf = async () => (await h.api(`/api/organizations/${org.orgId}/audit-events`, { cookie: org.cookie })).body.items as { action: string; actor: any; target: any; detail: any }[];

const NEW_CA = { name: "Internal TLS", subject: "CN=Acme Internal TLS, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["internal.acme"] } };

/** A new Private CA, and its first Issuing CA as `issuing`. */
async function createCa(body: Record<string, unknown> = NEW_CA, target = org) {
  const res = await h.api(cas(target.orgId), { cookie: target.cookie, body });
  expect(res.status).toBe(201);
  return { ...(res.body as { id: string; name: string }), issuing: res.body.issuingCas[0] as { id: string } };
}

/** Another Issuing CA under the Private CA's root. */
async function addIssuingCa(ca: { id: string }, subject: string) {
  const res = await h.api(`${cas()}/${ca.id}/issuing-cas`, { cookie: org.cookie, body: { subject, permittedNames: { exact: [], zones: ["internal.acme"] } } });
  expect(res.status).toBe(201);
  return { id: ca.id, issuing: res.body as { id: string } };
}

const certificatesIn = (pem: string) => (pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map((one) => new x509.X509Certificate(one));

/** The Issuing CA's chain: the Issuing CA, then the root. */
async function chainOf(ca: { id: string; issuing: { id: string } }) {
  const res = await h.app.request(`http://localhost${cas()}/${ca.id}/issuing-cas/${ca.issuing.id}/chain`, { headers: { cookie: org.cookie } });
  const [issuing, root] = certificatesIn(await res.text());
  return { issuing: issuing!, root: root! };
}

async function join(email: string, role: string) {
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}

async function request(names: string[]) {
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() };
}

/** A Managed Certificate issued from the Private CA's Issuing CA (`ca.issuing`), and its Certificate. */
async function issued(ca: { issuing: { id: string } }, names = ["app.internal.acme"], extra: Record<string, unknown> = {}) {
  const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(names)), issuer: { kind: "private_ca", issuingCaId: ca.issuing.id }, ...extra } });
  expect(created.status).toBe(201);
  await h.settleIssuances();
  const mc = (await h.api(`${mcs()}/${created.body.id}`, { cookie: org.cookie })).body;
  expect(mc.issuance.status).toBe("succeeded");
  const res = await h.app.request(`http://localhost${mcs()}/${mc.id}/certificate?chain=leaf`, { headers: { cookie: org.cookie } });
  const [leaf] = certificatesIn(await res.text());
  return { mc, certificate: mc.currentCertificate as { id: string; serial: string }, leaf: leaf! };
}

const revoke = (mcId: string, certificateId: string, reason: string, cookie = org.cookie) =>
  h.api(`${mcs()}/${mcId}/certificates/${certificateId}/revocation`, { cookie, body: { reason } });

/** The URLs a certificate names: its CRL Distribution Point's and its AIA caIssuers'. */
function urlsOf(cert: x509.X509Certificate) {
  const cdp = cert.getExtension(x509.CRLDistributionPointsExtension);
  const aia = cert.getExtension(x509.AuthorityInfoAccessExtension);
  return {
    crl: cdp?.distributionPoints.flatMap((point) => point.distributionPoint?.fullName?.map((name) => name.uniformResourceIdentifier) ?? []) ?? [],
    caIssuers: aia?.caIssuers.map((name) => name.value) ?? [],
  };
}

/** Fetches a public URL from the platform as a relying party does: no cookie, no credentials. */
async function fetchPublic(url: string) {
  const res = await h.app.request(url);
  return { status: res.status, headers: res.headers, body: new Uint8Array(await res.arrayBuffer()) };
}

/** The CRL the certificate's CRL Distribution Point names, fetched from there. */
async function crlFor(cert: x509.X509Certificate) {
  const [url] = urlsOf(cert).crl;
  expect(url).toBeDefined();
  const res = await fetchPublic(url!);
  expect(res.status).toBe(200);
  expect(res.headers.get("content-type")).toBe("application/pkix-crl");
  return new x509.X509Crl(res.body);
}

const CRL_NUMBER = "2.5.29.20";
/** A CRL's number, from its CRL Number extension (an INTEGER). */
function crlNumberOf(crl: x509.X509Crl) {
  const extension = crl.extensions.find((e) => e.type === CRL_NUMBER);
  expect(extension).toBeDefined();
  const value = new Uint8Array(extension!.value);
  expect(value[0]).toBe(0x02);
  return Number(BigInt(`0x${Buffer.from(value.subarray(2, 2 + value[1]!)).toString("hex")}`));
}

describe("revoking a Certificate issued from a Private CA", () => {
  test("puts it on its Issuing CA's CRL at once, with the reason, signed by the Issuing CA, with a greater CRL number and nextUpdate 7 days on", async () => {
    const ca = await createCa();
    const { issuing } = await chainOf(ca);
    const { mc, certificate, leaf } = await issued(ca);
    const before = await crlFor(leaf);
    expect(before.entries).toEqual([]);

    h.setNow(new Date(START + 60_000));
    const res = await revoke(mc.id, certificate.id, "affiliationChanged");

    expect(res.status).toBe(200);
    expect(res.body.revocation).toMatchObject({ reason: "affiliationChanged" });
    const crl = await crlFor(leaf);
    expect(await crl.verify({ publicKey: issuing })).toBe(true);
    expect(crl.issuer).toBe(issuing.subject);
    expect(crl.entries.map((e) => ({ serial: e.serialNumber.toUpperCase(), reason: e.reason, at: e.revocationDate.toISOString() }))).toEqual([
      { serial: certificate.serial, reason: x509.X509CrlReason.affiliationChanged, at: new Date(START + 60_000).toISOString() },
    ]);
    expect(crlNumberOf(crl)).toBeGreaterThan(crlNumberOf(before));
    expect(crl.thisUpdate.toISOString()).toBe(new Date(START + 60_000).toISOString());
    expect(crl.nextUpdate!.toISOString()).toBe(new Date(START + 60_000 + 7 * DAY_MS).toISOString());
  });
});

describe("the reasons a Private CA Certificate may be revoked for", () => {
  test.each([
    ["unspecified", undefined],
    ["keyCompromise", x509.X509CrlReason.keyCompromise],
    ["affiliationChanged", x509.X509CrlReason.affiliationChanged],
    ["superseded", x509.X509CrlReason.superseded],
    ["cessationOfOperation", x509.X509CrlReason.cessationOfOperation],
    ["privilegeWithdrawn", x509.X509CrlReason.privilegeWithdrawn],
  ])("%s is on the CRL with its RFC 5280 code (none for unspecified)", async (reason, code) => {
    const ca = await createCa();
    const { mc, certificate, leaf } = await issued(ca);

    expect((await revoke(mc.id, certificate.id, reason)).status).toBe(200);

    const [entry] = (await crlFor(leaf)).entries;
    expect(entry!.serialNumber.toUpperCase()).toBe(certificate.serial);
    expect(entry!.reason).toBe(code);
  });

  test("certificateHold is not one, and nothing is revoked", async () => {
    const ca = await createCa();
    const { mc, certificate, leaf } = await issued(ca);

    expect((await revoke(mc.id, certificate.id, "certificateHold")).status).toBe(400);

    expect((await crlFor(leaf)).entries).toEqual([]);
    expect((await h.api(`${mcs()}/${mc.id}`, { cookie: org.cookie })).body.currentCertificate.revocation).toBeNull();
  });

  test("is audited as certificate.revoked, with the issuer in its detail", async () => {
    const ca = await createCa();
    const { mc, certificate } = await issued(ca);
    await revoke(mc.id, certificate.id, "privilegeWithdrawn");

    expect((await auditOf()).filter((e) => e.action === "certificate.revoked")).toMatchObject([
      { target: { type: "managed_certificate", id: mc.id }, detail: { certificateId: certificate.id, serial: certificate.serial, reason: "privilegeWithdrawn", issuer: { kind: "private_ca", issuingCaId: ca.issuing.id } } },
    ]);
  });

  test("a Member who is not an Owner may not revoke it; once an Owner they may", async () => {
    const ca = await createCa();
    const { mc, certificate, leaf } = await issued(ca);
    const member = await join("member@acme.test", "member");
    const memberId = (await h.api("/api/me", { cookie: member })).body.user.id;

    expect((await revoke(mc.id, certificate.id, "keyCompromise", member)).status).toBe(403);
    expect((await crlFor(leaf)).entries).toEqual([]);

    expect((await h.api(`${mcs()}/${mc.id}/owners`, { cookie: org.cookie, body: { type: "user", id: memberId } })).status).toBe(200);
    expect((await revoke(mc.id, certificate.id, "keyCompromise", member)).status).toBe(200);
    expect((await crlFor(leaf)).entries).toHaveLength(1);
  });
});

describe("what a Private CA publishes", () => {
  test("a Certificate's CDP and AIA name public URLs on the platform's public base URL, under an opaque id, not the Organization's name", async () => {
    const ca = await createCa();
    const { leaf } = await issued(ca);

    expect(urlsOf(leaf)).toEqual({ crl: [`${PKI_BASE_URL}/pki/issuing-cas/${ca.issuing.id}/ca.crl`], caIssuers: [`${PKI_BASE_URL}/pki/issuing-cas/${ca.issuing.id}/ca.crt`] });
    expect(JSON.stringify(urlsOf(leaf))).not.toContain("acme");
  });

  test("is served with no credentials over plain HTTP and over HTTPS alike, never redirecting", async () => {
    const ca = await createCa();
    const { leaf } = await issued(ca);
    const [crlUrl] = urlsOf(leaf).crl;
    const [certificateUrl] = urlsOf(leaf).caIssuers;

    for (const url of [crlUrl!, certificateUrl!]) {
      const plain = await fetchPublic(url.replace(/^https?:/, "http:"));
      const secure = await fetchPublic(url.replace(/^https?:/, "https:"));
      expect(plain.status).toBe(200);
      expect(secure.status).toBe(200);
      expect(plain.headers.get("location")).toBeNull();
      expect(Buffer.from(plain.body).equals(Buffer.from(secure.body))).toBe(true);
    }
  });

  test("the AIA caIssuers is the Issuing CA's certificate, DER, which the Certificate verifies against", async () => {
    const ca = await createCa();
    const { issuing } = await chainOf(ca);
    const { leaf } = await issued(ca);

    const res = await fetchPublic(urlsOf(leaf).caIssuers[0]!);
    expect(res.headers.get("content-type")).toBe("application/pkix-cert");
    const fetched = new x509.X509Certificate(res.body);
    expect(fetched.equal(issuing)).toBe(true);
    expect(await leaf.verify({ publicKey: fetched.publicKey, signatureOnly: true })).toBe(true);
  });

  test("the Issuing CA names its platform-made root's CRL and certificate; the root's CRL is signed by the root and lists nothing yet", async () => {
    const ca = await createCa();
    const { issuing, root } = await chainOf(ca);

    expect(urlsOf(issuing)).toEqual({ crl: [`${PKI_BASE_URL}/pki/roots/${ca.id}/ca.crl`], caIssuers: [`${PKI_BASE_URL}/pki/roots/${ca.id}/ca.crt`] });
    expect(urlsOf(root)).toEqual({ crl: [], caIssuers: [] });
    expect(new x509.X509Certificate((await fetchPublic(urlsOf(issuing).caIssuers[0]!)).body).equal(root)).toBe(true);
    const rootCrl = await crlFor(issuing);
    expect(await rootCrl.verify({ publicKey: root })).toBe(true);
    expect(rootCrl.issuer).toBe(root.subject);
    expect(rootCrl.entries).toEqual([]);
    expect(rootCrl.nextUpdate!.getTime() - rootCrl.thisUpdate.getTime()).toBe(7 * DAY_MS);
  });

  test("a Certificate revoked from one Private CA is on that one's CRL only", async () => {
    const ca = await createCa();
    const other = await createCa({ ...NEW_CA, name: "Other" });
    const { mc, certificate, leaf } = await issued(ca);
    const { leaf: otherLeaf } = await issued(other);

    await revoke(mc.id, certificate.id, "keyCompromise");

    expect((await crlFor(leaf)).entries).toHaveLength(1);
    expect((await crlFor(otherLeaf)).entries).toEqual([]);
  });

  test("of two Issuing CAs under one root, a Certificate revoked from one is on that one's CRL only", async () => {
    const ca = await createCa();
    const devices = await addIssuingCa(ca, "CN=Acme Devices, O=Acme");
    const { mc, certificate, leaf } = await issued(ca);
    const { leaf: deviceLeaf } = await issued(devices);
    expect(urlsOf(deviceLeaf).crl).not.toEqual(urlsOf(leaf).crl);

    await revoke(mc.id, certificate.id, "keyCompromise");

    expect((await crlFor(leaf)).entries.map((e) => e.serialNumber.toUpperCase())).toEqual([certificate.serial]);
    const deviceCrl = await crlFor(deviceLeaf);
    expect(deviceCrl.entries).toEqual([]);
    expect(await deviceCrl.verify({ publicKey: (await chainOf(devices)).issuing })).toBe(true);
  });

  test("an Issuing CA added under the root publishes its CRL at once, and names the root's CRL and certificate as the first one does", async () => {
    const ca = await createCa();
    const devices = await addIssuingCa(ca, "CN=Acme Devices, O=Acme");
    const { issuing, root } = await chainOf(devices);

    expect(urlsOf(issuing)).toEqual(urlsOf((await chainOf(ca)).issuing));
    const crl = new x509.X509Crl((await fetchPublic(`${PKI_BASE_URL}/pki/issuing-cas/${devices.issuing.id}/ca.crl`)).body);
    expect(await crl.verify({ publicKey: issuing })).toBe(true);
    expect(crl.entries).toEqual([]);
    expect(await (await crlFor(issuing)).verify({ publicKey: root })).toBe(true);
  });

  test("nothing is served for an id that is not a Private CA's", async () => {
    for (const id of ["00000000-0000-0000-0000-000000000000", "not-an-id"]) {
      for (const kind of ["issuing-cas", "roots"]) {
        for (const file of ["ca.crl", "ca.crt"]) expect((await fetchPublic(`${PKI_BASE_URL}/pki/${kind}/${id}/${file}`)).status).toBe(404);
      }
    }
  });
});

describe("the scheduled reissue of a Private CA's CRLs", () => {
  test("reissues each CRL 3 days before its nextUpdate, with a greater number, and not before", async () => {
    const ca = await createCa();
    const { issuing } = await chainOf(ca);
    const { leaf } = await issued(ca);
    const first = await crlFor(leaf);
    const firstRoot = await crlFor(issuing);

    h.setNow(new Date(first.nextUpdate!.getTime() - 3 * DAY_MS - 1000));
    expect(await h.runCrlScheduler()).toBe(0);
    expect(crlNumberOf(await crlFor(leaf))).toBe(crlNumberOf(first));

    const at = new Date(first.nextUpdate!.getTime() - 3 * DAY_MS);
    h.setNow(at);
    expect(await h.runCrlScheduler()).toBe(2);
    const second = await crlFor(leaf);
    expect(crlNumberOf(second)).toBeGreaterThan(crlNumberOf(first));
    expect(second.thisUpdate.toISOString()).toBe(at.toISOString());
    expect(second.nextUpdate!.toISOString()).toBe(new Date(at.getTime() + 7 * DAY_MS).toISOString());
    expect(crlNumberOf(await crlFor(issuing))).toBeGreaterThan(crlNumberOf(firstRoot));

    // Once reissued, it is not due again on the next pass.
    expect(await h.runCrlScheduler()).toBe(0);
  });

  test("a revoked Certificate stays on the reissued CRL until it expires, and is then dropped", async () => {
    const ca = await createCa();
    const { mc, certificate, leaf } = await issued(ca, ["app.internal.acme"], { validityDays: 10 });
    await revoke(mc.id, certificate.id, "keyCompromise");

    h.setNow(new Date(START + 5 * DAY_MS));
    await h.runCrlScheduler();
    expect((await crlFor(leaf)).entries.map((e) => e.serialNumber.toUpperCase())).toEqual([certificate.serial]);

    h.setNow(new Date(leaf.notAfter.getTime() + 1000));
    await h.runCrlScheduler();
    const crl = await crlFor(leaf);
    expect(crl.thisUpdate.getTime()).toBeGreaterThan(leaf.notAfter.getTime());
    expect(crl.entries).toEqual([]);
  });

  test("when reissuing fails it is tried again on the next pass, and publishing again is an Audit Event", async () => {
    const ca = await createCa();
    const { leaf } = await issued(ca);
    const first = await crlFor(leaf);
    const failedAt = new Date(first.nextUpdate!.getTime() - 3 * DAY_MS);

    h.setNow(failedAt);
    h.kms.failing = true;
    expect(await h.runCrlScheduler()).toBe(0);
    expect(crlNumberOf(await crlFor(leaf))).toBe(crlNumberOf(first));
    expect((await auditOf()).filter((e) => e.action === "private_ca.crl_published")).toEqual([]);

    h.kms.failing = false;
    h.setNow(new Date(failedAt.getTime() + 60_000));
    expect(await h.runCrlScheduler()).toBe(2);
    expect(crlNumberOf(await crlFor(leaf))).toBeGreaterThan(crlNumberOf(first));
    const published = (await auditOf()).filter((e) => e.action === "private_ca.crl_published");
    expect(published).toHaveLength(2);
    expect(published).toContainEqual(expect.objectContaining({ actor: { id: null, email: null }, target: { type: "private_ca", id: ca.id }, detail: expect.objectContaining({ crl: "issuing", failingSince: failedAt.toISOString() }) }));
    expect(published).toContainEqual(expect.objectContaining({ detail: expect.objectContaining({ crl: "root" }) }));

    // A routine reissue is no event.
    h.setNow(new Date(failedAt.getTime() + 5 * DAY_MS));
    expect(await h.runCrlScheduler()).toBe(2);
    expect((await auditOf()).filter((e) => e.action === "private_ca.crl_published")).toHaveLength(2);
  });

  test("a revocation the KMS cannot sign a CRL for is refused with 502, and nothing is revoked", async () => {
    const ca = await createCa();
    const { mc, certificate, leaf } = await issued(ca);

    h.kms.failing = true;
    expect((await revoke(mc.id, certificate.id, "keyCompromise")).status).toBe(502);
    h.kms.failing = false;

    expect((await crlFor(leaf)).entries).toEqual([]);
    expect((await h.api(`${mcs()}/${mc.id}`, { cookie: org.cookie })).body.currentCertificate.revocation).toBeNull();
    expect((await auditOf()).filter((e) => e.action === "certificate.revoked")).toEqual([]);
    expect((await revoke(mc.id, certificate.id, "keyCompromise")).status).toBe(200);
  });
});
