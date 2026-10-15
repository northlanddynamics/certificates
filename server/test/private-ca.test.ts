// Private CAs: an Organization Administrator creates one with a platform-made root and Issuing CA, both keys in the
// (local) KMS, and anyone in the Organization downloads its chain. A Managed Certificate (Key Custody: Owner) created or
// proposed against it is issued with no ACME order and no DCV, and its chain verifies to the Private CA's root. There is
// no Pebble and no DNS here: what is checked is what an outside party sees, the API's answers and the certificates.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import acme from "acme-client";
import { webcrypto } from "node:crypto";
import { PASSWORD, createHarness, type Harness } from "./harness";

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

const cas = (orgId = org.orgId) => `/api/organizations/${orgId}/private-cas`;
const mcs = (orgId = org.orgId) => `/api/organizations/${orgId}/managed-certificates`;
const auditOf = async (target = org) => (await h.api(`/api/organizations/${target.orgId}/audit-events`, { cookie: target.cookie })).body.items as { action: string; target: any; detail: any }[];

const NEW_CA = { name: "Internal TLS", subject: "CN=Acme Internal TLS, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5 };

async function createCa(body: Record<string, unknown> = NEW_CA, target = org) {
  const res = await h.api(cas(target.orgId), { cookie: target.cookie, body });
  expect(res.status).toBe(201);
  return res.body as { id: string; name: string; status: string; kind: string; keyAlgorithm: string; subject: string; notAfter: string };
}

/** The certificates of a PEM bundle, in order. */
const certificatesIn = (pem: string) => (pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map((one) => new x509.X509Certificate(one));

async function chainOf(id: string, cookie = org.cookie, orgId = org.orgId) {
  const res = await h.app.request(`http://localhost${cas(orgId)}/${id}/chain`, { headers: { cookie } });
  return { status: res.status, certificates: res.status === 200 ? certificatesIn(await res.text()) : [] };
}

/** Whether `cert` is signed by `by`'s key. */
const signedBy = (cert: x509.X509Certificate, by: x509.X509Certificate) => cert.verify({ publicKey: by.publicKey, signatureOnly: true });

async function join(email: string, role: string, target = org) {
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: target.cookie, body: { email, role, organizationId: target.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}

describe("creating a Private CA with a platform-made root", () => {
  test("makes a root and an Issuing CA under it with separate keys, active, and its chain is the Issuing CA then the root", async () => {
    const ca = await createCa();

    expect(ca).toMatchObject({ name: "Internal TLS", kind: "platform_root", status: "active", keyAlgorithm: "ecdsa-p256" });
    const { status, certificates } = await chainOf(ca.id);
    expect(status).toBe(200);
    const [issuing, root] = certificates;
    expect(certificates).toHaveLength(2);

    expect(await signedBy(root!, root!)).toBe(true);
    expect(await signedBy(issuing!, root!)).toBe(true);
    expect(root!.subject).not.toBe(issuing!.subject);
    expect(issuing!.issuer).toBe(root!.subject);
    expect(Buffer.from(issuing!.publicKey.rawData).equals(Buffer.from(root!.publicKey.rawData))).toBe(false);
    expect(issuing!.subject).toBe("CN=Acme Internal TLS, O=Acme");
    expect(new Date(ca.notAfter).getTime()).toBe(issuing!.notAfter.getTime());

    const issuingConstraints = issuing!.getExtension(x509.BasicConstraintsExtension)!;
    expect(issuingConstraints).toMatchObject({ ca: true, pathLength: 0, critical: true });
    expect(root!.getExtension(x509.BasicConstraintsExtension)).toMatchObject({ ca: true, critical: true });
    expect(issuing!.getExtension(x509.KeyUsagesExtension)!.usages & x509.KeyUsageFlags.keyCertSign).toBeTruthy();
  });

  test.each(["ecdsa-p384", "rsa-2048"])("makes the CA keys of the algorithm asked for: %s", async (keyAlgorithm) => {
    const ca = await createCa({ ...NEW_CA, keyAlgorithm });

    const [issuing, root] = (await chainOf(ca.id)).certificates;
    expect(await signedBy(issuing!, root!)).toBe(true);
    const name = keyAlgorithm.startsWith("rsa") ? "RSASSA-PKCS1-v1_5" : "ECDSA";
    expect(issuing!.publicKey.algorithm.name).toBe(name);
    expect(root!.publicKey.algorithm.name).toBe(name);
  });

  test("is an Audit Event", async () => {
    const ca = await createCa();

    const created = (await auditOf()).filter((e) => e.action === "private_ca.created");
    expect(created).toMatchObject([{ target: { type: "private_ca", id: ca.id }, detail: { name: "Internal TLS", kind: "platform_root", keyAlgorithm: "ecdsa-p256" } }]);
  });

  test("refuses a subject that is not a distinguished name with a common name", async () => {
    for (const subject of ["not a dn", "O=Acme"]) {
      const res = await h.api(cas(), { cookie: org.cookie, body: { ...NEW_CA, subject } });
      expect(res.status).toBe(400);
    }
  });
});

describe("who may see and create Private CAs", () => {
  test.each(["member", "approver"])("a %s lists them and downloads their chains, and may not create one", async (role) => {
    const ca = await createCa();
    const cookie = await join(`${role}@acme.test`, role);

    const listed = await h.api(cas(), { cookie });
    expect(listed.status).toBe(200);
    expect(listed.body.items.map((i: { id: string }) => i.id)).toEqual([ca.id]);
    expect((await chainOf(ca.id, cookie)).certificates).toHaveLength(2);

    expect((await h.api(cas(), { cookie, body: { ...NEW_CA, name: "Mine" } })).status).toBe(403);
    expect((await h.api(cas(), { cookie })).body.items).toHaveLength(1);
  });

  test("/api/me reports that only an Organization Administrator may create, update, retire or revoke one, and everyone may read them", async () => {
    const member = await join("member@acme.test", "member");
    const permissions = async (cookie: string) => (await h.api("/api/me", { cookie })).body.organizations[0].permissions;

    expect((await permissions(org.cookie)).privateCa).toEqual(["read", "create", "update", "retire", "revoke"]);
    expect((await permissions(member)).privateCa).toEqual(["read"]);
  });

  test("another Organization's Private CA is not found", async () => {
    const globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    const theirs = await createCa(NEW_CA, globex);

    expect((await h.api(`${cas()}/${theirs.id}`, { cookie: org.cookie })).status).toBe(404);
    expect((await chainOf(theirs.id)).status).toBe(404);
    expect((await h.api(cas(), { cookie: org.cookie })).body.items).toEqual([]);
  });

  test("two of an Organization's Private CAs cannot have the same name", async () => {
    await createCa();

    expect((await h.api(cas(), { cookie: org.cookie, body: NEW_CA })).status).toBe(409);
  });
});

/** What an Owner submits: a CSR for the names under a fresh key, which stays here. */
async function request(names: string[]) {
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() };
}

/** A CSR that asks for the extended key usages too, which acme-client cannot make. */
async function requestWithUsages(names: string[], usages: string[]) {
  const algorithm = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
  const keys = await webcrypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);
  const csr = await x509.Pkcs10CertificateRequestGenerator.create(
    {
      name: `CN=${names[0]}`,
      keys: keys as CryptoKeyPair,
      signingAlgorithm: algorithm,
      extensions: [new x509.SubjectAlternativeNameExtension(names.map((value) => ({ type: "dns" as const, value }))), new x509.ExtendedKeyUsageExtension(usages)],
    },
    webcrypto as unknown as Crypto,
  );
  return { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString("pem") };
}

const fromCa = (privateCaId: string) => ({ issuer: { kind: "private_ca", privateCaId } });

/** The Managed Certificate once its latest Issuance has ended. */
async function ended(id: string, cookie = org.cookie) {
  await h.settleIssuances();
  const res = await h.api(`${mcs()}/${id}`, { cookie });
  expect(res.status).toBe(200);
  expect(res.body.issuance.status).not.toBe("running");
  return res.body;
}

async function downloaded(id: string, chain = "with-root") {
  const res = await h.app.request(`http://localhost${mcs()}/${id}/certificate?chain=${chain}`, { headers: { cookie: org.cookie } });
  expect(res.status).toBe(200);
  return certificatesIn(await res.text());
}

describe("issuing a Managed Certificate from a Private CA", () => {
  test("an Organization Administrator creates one and it is issued at once with no DCV, and its chain verifies to the root", async () => {
    const ca = await createCa();
    // No ACME account and no DNS Provider: nothing of ACME could issue it.
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.internal.acme", "*.svc.internal.acme"])), ...fromCa(ca.id) } });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ issuer: { kind: "private_ca", privateCa: { id: ca.id, name: "Internal TLS" } }, environment: null, approval: { status: "not_required" } });

    const mc = await ended(created.body.id);
    expect(mc.issuance).toMatchObject({ status: "succeeded", failure: null });
    expect(mc.currentCertificate).toMatchObject({ ca: "Internal TLS", privateCaId: ca.id, environment: null, acmeAccountId: null, names: ["app.internal.acme", "*.svc.internal.acme"] });

    const [leaf, issuing, root, ...rest] = await downloaded(mc.id);
    expect(rest).toEqual([]);
    const [caIssuing, caRoot] = (await chainOf(ca.id)).certificates;
    expect(issuing!.equal(caIssuing!)).toBe(true);
    expect(root!.equal(caRoot!)).toBe(true);
    expect(await signedBy(leaf!, issuing!)).toBe(true);
    expect(await signedBy(issuing!, root!)).toBe(true);
    const path = await new x509.X509ChainBuilder({ certificates: [issuing!, root!] }).build(leaf!);
    expect(path.map((c) => c.subject)).toEqual([leaf!.subject, issuing!.subject, root!.subject]);
  });

  test("the Certificate is a TLS server certificate for the approved names, with a 20-byte random serial", async () => {
    const ca = await createCa();
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.internal.acme", "api.internal.acme"])), ...fromCa(ca.id) } });
    const mc = await ended(created.body.id);

    const [leaf] = await downloaded(mc.id, "leaf");
    expect(leaf!.getExtension(x509.ExtendedKeyUsageExtension)!.usages).toEqual([x509.ExtendedKeyUsage.serverAuth]);
    expect(leaf!.getExtension(x509.SubjectAlternativeNameExtension)!.names.items.map((n) => n.value)).toEqual(["app.internal.acme", "api.internal.acme"]);
    expect(leaf!.getExtension(x509.BasicConstraintsExtension)!.ca).toBe(false);
    expect(leaf!.subject).toBe("CN=app.internal.acme");
    expect(leaf!.serialNumber).toMatch(/^[0-7][0-9a-f]{39}$/i);
    expect(leaf!.serialNumber.toUpperCase()).toBe(mc.currentCertificate.serial);
    expect(leaf!.notBefore.toISOString()).toBe("2026-01-01T00:00:00.000Z");
    expect(leaf!.notAfter.toISOString()).toBe(new Date(Date.parse("2026-01-01T00:00:00Z") + 397 * 86_400_000).toISOString());

    const other = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["other.internal.acme"])), ...fromCa(ca.id) } });
    expect((await ended(other.body.id)).currentCertificate.serial).not.toBe(leaf!.serialNumber.toUpperCase());
  });

  test("a CSR that asks for clientAuth gets it besides serverAuth", async () => {
    const ca = await createCa();
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await requestWithUsages(["app.internal.acme"], [x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth])), ...fromCa(ca.id) } });
    const mc = await ended(created.body.id);

    const [leaf] = await downloaded(mc.id, "leaf");
    expect(leaf!.getExtension(x509.ExtendedKeyUsageExtension)!.usages).toEqual([x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth]);
  });

  test("its Issuance is audited with the existing actions, the issuer in their detail", async () => {
    const ca = await createCa();
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.internal.acme"])), ...fromCa(ca.id) } });
    await ended(created.body.id);

    const events = (await auditOf()).filter((e) => e.target?.id === created.body.id);
    const issuer = { kind: "private_ca", privateCaId: ca.id };
    expect(events.find((e) => e.action === "managed_certificate.created")!.detail).toMatchObject({ issuer });
    expect(events.find((e) => e.action === "issuance.started")!.detail).toMatchObject({ issuer });
    expect(events.find((e) => e.action === "issuance.succeeded")!.detail).toMatchObject({ issuer });
  });
});

describe("proposing a Managed Certificate from a Private CA", () => {
  test("a Member proposes one, an Approver sees which Private CA it is and approves it, and only then is it issued", async () => {
    const ca = await createCa();
    const member = await join("member@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");

    const proposed = await h.api(mcs(), { cookie: member, body: { ...(await request(["app.internal.acme"])), ...fromCa(ca.id) } });
    expect(proposed.status).toBe(201);
    expect(proposed.body).toMatchObject({ approval: { status: "pending" }, issuance: null });

    const queue = await h.api(`/api/organizations/${org.orgId}/approvals`, { cookie: approver });
    expect(queue.body.items).toMatchObject([{ id: proposed.body.id, issuer: { kind: "private_ca", privateCa: { id: ca.id, name: "Internal TLS" } } }]);
    expect((await auditOf()).find((e) => e.action === "managed_certificate.proposed")!.detail).toMatchObject({ issuer: { kind: "private_ca", privateCaId: ca.id } });

    expect((await h.api(`${mcs()}/${proposed.body.id}/approve`, { cookie: approver, body: {} })).status).toBe(200);
    const mc = await ended(proposed.body.id, member);
    expect(mc.issuance.status).toBe("succeeded");
    const [leaf, issuing] = await downloaded(mc.id, "with-intermediates");
    expect(await signedBy(leaf!, issuing!)).toBe(true);
  });
});

describe("which Private CA a Managed Certificate may name", () => {
  test("not another Organization's: it is refused and nothing is created", async () => {
    const globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    const theirs = await createCa(NEW_CA, globex);

    const res = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.internal.acme"])), ...fromCa(theirs.id) } });

    expect(res.status).toBe(422);
    expect((await h.api(mcs(), { cookie: org.cookie })).body.items).toEqual([]);
    expect((await h.api(mcs(globex.orgId), { cookie: globex.cookie })).body.items).toEqual([]);
  });

  test("not one that does not exist, and not both a Private CA and an ACME environment", async () => {
    const ca = await createCa();
    const body = await request(["app.internal.acme"]);

    expect((await h.api(mcs(), { cookie: org.cookie, body: { ...body, ...fromCa("00000000-0000-0000-0000-000000000000") } })).status).toBe(422);
    expect((await h.api(mcs(), { cookie: org.cookie, body: { ...body, ...fromCa("not-an-id") } })).status).toBe(422);
    expect((await h.api(mcs(), { cookie: org.cookie, body: { ...body, ...fromCa(ca.id), environment: "staging" } })).status).toBe(400);
  });
});
