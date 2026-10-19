// ML-DSA Private CAs: an Organization Administrator creates one whose root and Issuing CA have ML-DSA-65 or ML-DSA-87
// keys in the (local) KMS, and a Managed Certificate (Key Custody: Owner) created or proposed on it from an ML-DSA CSR
// is issued with a chain that verifies to its root. What is checked is what an outside party sees: the API's answers
// and the certificates, verified with the X.509 library.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { webcrypto } from "node:crypto";
import { PASSWORD, PKI_BASE_URL, createHarness, type Harness } from "./support/harness";

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

const casOf = () => `/api/organizations/${org.orgId}/private-cas`;
const mcs = () => `/api/organizations/${org.orgId}/managed-certificates`;
const auditOf = async () => (await h.api(`/api/organizations/${org.orgId}/audit-events`, { cookie: org.cookie })).body.items as { action: string; target: any; detail: any }[];

/** The RFC 9881 OIDs of ML-DSA, for keys and signatures alike. */
const ML_DSA_OIDS = { "ml-dsa-44": "2.16.840.1.101.3.4.3.17", "ml-dsa-65": "2.16.840.1.101.3.4.3.18", "ml-dsa-87": "2.16.840.1.101.3.4.3.19" } as const;
type MlDsa = keyof typeof ML_DSA_OIDS;

const NEW_CA = { name: "Quantum TLS", subject: "CN=Acme Quantum TLS, O=Acme", lifetimeYears: 5, permittedNames: { exact: [], zones: ["internal.acme"] } };

async function createCa(keyAlgorithm: string) {
  const res = await h.api(casOf(), { cookie: org.cookie, body: { ...NEW_CA, keyAlgorithm } });
  expect(res.status).toBe(201);
  return { ...res.body, issuing: res.body.issuingCas[0] as { id: string } };
}

const certificatesIn = (pem: string) => (pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map((one) => new x509.X509Certificate(one));

async function download(path: string) {
  const res = await h.app.request(`http://localhost${path}`, { headers: { cookie: org.cookie } });
  expect(res.status).toBe(200);
  return certificatesIn(await res.text());
}

/** A CSR for the names under a fresh ML-DSA key made with Bun's native ML-DSA; the key stays here. */
async function mlDsaRequest(keyAlgorithm: MlDsa, names: string[]) {
  const algorithm = { name: keyAlgorithm.toUpperCase() };
  const keys = (await webcrypto.subtle.generateKey(algorithm, false, ["sign", "verify"])) as CryptoKeyPair;
  const csr = await x509.Pkcs10CertificateRequestGenerator.create(
    { name: `CN=${names[0]}`, keys, signingAlgorithm: algorithm, extensions: [new x509.SubjectAlternativeNameExtension(names.map((value) => ({ type: "dns" as const, value })))] },
    webcrypto as unknown as Crypto,
  );
  return { names, keyAlgorithm, csr: csr.toString("pem") };
}

const fromCa = (issuingCaId: string) => ({ issuer: { kind: "private_ca", issuingCaId } });

/**
 * How often the RFC 9881 AlgorithmIdentifier of `algorithm` appears in the DER `der`, as RFC 9881 has it: a SEQUENCE
 * of the OID alone, its parameters absent (not NULL). A certificate has it once for each of its signature fields and
 * its key that are of that algorithm.
 */
function algorithmIdentifiersIn(der: ArrayBuffer, algorithm: MlDsa) {
  const last = Number(ML_DSA_OIDS[algorithm].split(".").at(-1));
  const identifier = Buffer.from([0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, last]);
  const bytes = Buffer.from(der);
  let count = 0;
  for (let at = bytes.indexOf(identifier); at !== -1; at = bytes.indexOf(identifier, at + 1)) count++;
  return count;
}

async function ended(id: string, cookie = org.cookie) {
  await h.settleIssuances();
  const res = await h.api(`${mcs()}/${id}`, { cookie });
  expect(res.body.issuance.status).not.toBe("running");
  return res.body;
}

describe("an ML-DSA Private CA with a platform-made root", () => {
  test.each(["ml-dsa-65", "ml-dsa-87"] as const)("%s: its root and Issuing CA are ML-DSA keys signed with ML-DSA, and an ML-DSA Managed Certificate issued from it verifies to the root", async (caAlgorithm) => {
    const ca = await createCa(caAlgorithm);
    expect(ca).toMatchObject({ keyAlgorithm: caAlgorithm, status: "active" });

    const [issuing, root] = await download(`${casOf()}/${ca.id}/issuing-cas/${ca.issuing.id}/chain`);
    // Its key, the signature in what it signs, and the signature itself.
    for (const cert of [issuing!, root!]) expect(algorithmIdentifiersIn(cert.rawData, caAlgorithm)).toBe(3);
    expect(await root!.verify({ publicKey: root!.publicKey, signatureOnly: true })).toBe(true);
    expect(await issuing!.verify({ publicKey: root!.publicKey, signatureOnly: true })).toBe(true);

    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await mlDsaRequest("ml-dsa-44", ["app.internal.acme"])), ...fromCa(ca.issuing.id) } });
    expect(created.status).toBe(201);
    const mc = await ended(created.body.id);
    expect(mc.issuance).toMatchObject({ status: "succeeded", failure: null });

    const [leaf, ...above] = await download(`${mcs()}/${mc.id}/certificate?chain=with-root`);
    expect(algorithmIdentifiersIn(leaf!.rawData, "ml-dsa-44")).toBe(1);
    expect(algorithmIdentifiersIn(leaf!.rawData, caAlgorithm)).toBe(2);
    expect(await leaf!.verify({ publicKey: above[0]!.publicKey, signatureOnly: true })).toBe(true);
    const path = await new x509.X509ChainBuilder({ certificates: above }).build(leaf!);
    expect(path.map((c) => c.subject)).toEqual([leaf!.subject, issuing!.subject, root!.subject]);
  });
});

async function join(email: string, role: string) {
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}

describe("creating an ML-DSA Private CA", () => {
  test("ML-DSA-44 is refused for a CA key, and nothing is created", async () => {
    const res = await h.api(casOf(), { cookie: org.cookie, body: { ...NEW_CA, keyAlgorithm: "ml-dsa-44" } });
    expect(res.status).toBe(422);
    expect(res.body.error).toContain("ML-DSA-65 or ML-DSA-87");
    expect((await h.api(casOf(), { cookie: org.cookie })).body.items).toEqual([]);
  });

  test("under the Organization's own root makes only its Issuing CA's ML-DSA key, awaiting a root of the same algorithm", async () => {
    const res = await h.api(casOf(), { cookie: org.cookie, body: { ...NEW_CA, kind: "organization_root", lifetimeYears: undefined, keyAlgorithm: "ml-dsa-65" } });
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ kind: "organization_root", keyAlgorithm: "ml-dsa-65", root: null });
    expect(res.body.issuingCas).toMatchObject([{ status: "awaiting_signature" }]);
  });

  test("ML-DSA-44 is refused under the Organization's own root too", async () => {
    const res = await h.api(casOf(), { cookie: org.cookie, body: { ...NEW_CA, kind: "organization_root", lifetimeYears: undefined, keyAlgorithm: "ml-dsa-44" } });
    expect(res.status).toBe(422);
    expect(res.body.error).toContain("ML-DSA-65 or ML-DSA-87");
  });

  test("is an Audit Event that records its key algorithm", async () => {
    const ca = await createCa("ml-dsa-87");
    expect((await auditOf()).find((e) => e.action === "private_ca.created")).toMatchObject({ target: { id: ca.id }, detail: { keyAlgorithm: "ml-dsa-87" } });
  });
});

describe("the key algorithms each CA takes", () => {
  test("the Private CAs list says which key algorithms a Managed Certificate on each may have: ML-DSA ones on an ML-DSA Private CA, and only there", async () => {
    await createCa("ml-dsa-65");
    await h.api(casOf(), { cookie: org.cookie, body: { ...NEW_CA, name: "Classic TLS", subject: "CN=Acme Classic TLS", keyAlgorithm: "ecdsa-p256" } });

    const items = (await h.api(casOf(), { cookie: org.cookie })).body.items as { name: string; certificateKeyAlgorithms: string[] }[];
    expect(items.map((ca) => [ca.name, ca.certificateKeyAlgorithms])).toEqual([
      ["Quantum TLS", ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]],
      ["Classic TLS", ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"]],
    ]);
  });

  test("the API lists every key algorithm, those a Private CA's keys may be, and those an ACME CA takes", async () => {
    const res = await h.api("/api/key-algorithms", { cookie: org.cookie });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      keyAlgorithms: ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"],
      privateCaKeyAlgorithms: {
        platform_root: ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096", "ml-dsa-65", "ml-dsa-87"],
        organization_root: ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096", "ml-dsa-65", "ml-dsa-87"],
      },
      acmeKeyAlgorithms: ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"],
    });
    expect((await h.api("/api/key-algorithms")).status).toBe(401);
  });

  test("an ML-DSA Managed Certificate is refused on an ECDSA Private CA with a 422 that says why, and nothing is created", async () => {
    const res = await h.api(casOf(), { cookie: org.cookie, body: { ...NEW_CA, keyAlgorithm: "ecdsa-p256" } });
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await mlDsaRequest("ml-dsa-65", ["app.internal.acme"])), ...fromCa(res.body.issuingCas[0].id) } });
    expect(created.status).toBe(422);
    expect(created.body.error).toContain("not ml-dsa-65");
    expect((await h.api(mcs(), { cookie: org.cookie })).body.total).toBe(0);
  });

  test("an ML-DSA Managed Certificate is refused on an ACME CA, and an ECDSA one on an ML-DSA Private CA", async () => {
    const onAcme = await h.api(mcs(), { cookie: org.cookie, body: { ...(await mlDsaRequest("ml-dsa-65", ["app.internal.acme"])), issuer: { kind: "acme", environment: "staging" } } });
    expect(onAcme.status).toBe(422);
    expect(onAcme.body.error).toContain("an ACME CA takes keys of");

    const ca = await createCa("ml-dsa-65");
    const ecdsa = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({ name: "CN=app.internal.acme", keys: ecdsa as CryptoKeyPair, signingAlgorithm: { name: "ECDSA", hash: "SHA-256" } }, webcrypto as unknown as Crypto);
    const onMlDsa = await h.api(mcs(), { cookie: org.cookie, body: { names: ["app.internal.acme"], keyAlgorithm: "ecdsa-p256", csr: csr.toString("pem"), ...fromCa(ca.issuing.id) } });
    expect(onMlDsa.status).toBe(422);
    expect(onMlDsa.body.error).toContain("weak link");
  });
});

describe("a Managed Certificate on an ML-DSA Private CA", () => {
  test("cannot be repointed to an ECDSA Private CA, and stays where it was", async () => {
    const ca = await createCa("ml-dsa-65");
    const classic = await h.api(casOf(), { cookie: org.cookie, body: { ...NEW_CA, name: "Classic TLS", subject: "CN=Acme Classic TLS", keyAlgorithm: "ecdsa-p256" } });
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await mlDsaRequest("ml-dsa-65", ["app.internal.acme"])), ...fromCa(ca.issuing.id) } });

    const moved = await h.api(`${mcs()}/${created.body.id}/issuer`, { method: "PUT", cookie: org.cookie, body: fromCa(classic.body.issuingCas[0].id) });
    expect(moved.status).toBe(422);
    expect(moved.body.error).toContain("not ml-dsa-65");
    expect((await h.api(`${mcs()}/${created.body.id}`, { cookie: org.cookie })).body.issuer.issuingCa.id).toBe(ca.issuing.id);
  });

  test("its creation is an Audit Event that records its ML-DSA key algorithm", async () => {
    const ca = await createCa("ml-dsa-65");
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await mlDsaRequest("ml-dsa-65", ["app.internal.acme"])), ...fromCa(ca.issuing.id) } });
    expect((await auditOf()).find((e) => e.action === "managed_certificate.created")).toMatchObject({ target: { id: created.body.id }, detail: { keyAlgorithm: "ml-dsa-65" } });
  });

  test("a Member proposes one, an Approver approves it, and it is issued", async () => {
    const ca = await createCa("ml-dsa-65");
    const member = await join("member@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");

    const proposed = await h.api(mcs(), { cookie: member, body: { ...(await mlDsaRequest("ml-dsa-87", ["app.internal.acme"])), ...fromCa(ca.issuing.id) } });
    expect(proposed.status).toBe(201);
    expect(proposed.body).toMatchObject({ keyAlgorithm: "ml-dsa-87", approval: { status: "pending" }, issuance: null });
    expect((await auditOf()).find((e) => e.action === "managed_certificate.proposed")!.detail).toMatchObject({ keyAlgorithm: "ml-dsa-87" });

    expect((await h.api(`${mcs()}/${proposed.body.id}/approve`, { cookie: approver, body: {} })).status).toBe(200);
    expect((await ended(proposed.body.id, member)).issuance.status).toBe("succeeded");
  });

  test("its Certificate's facts name its ML-DSA key and signature", async () => {
    const ca = await createCa("ml-dsa-65");
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await mlDsaRequest("ml-dsa-44", ["app.internal.acme"])), ...fromCa(ca.issuing.id) } });
    const mc = await ended(created.body.id);

    const facts = await h.api(`${mcs()}/${mc.id}/certificates/${mc.currentCertificate.id}`, { cookie: org.cookie });
    expect(facts.status).toBe(200);
    expect(facts.body).toMatchObject({ keyAlgorithm: "ML-DSA-44", signatureAlgorithm: "ML-DSA-65" });
  });
});

/** A CSR for the names under a fresh ECDSA key, as an Owner of a classical Managed Certificate would send. */
async function ecdsaRequest(names: string[]) {
  const keys = (await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair;
  const csr = await x509.Pkcs10CertificateRequestGenerator.create(
    { name: `CN=${names[0]}`, keys, signingAlgorithm: { name: "ECDSA", hash: "SHA-256" }, extensions: [new x509.SubjectAlternativeNameExtension(names.map((value) => ({ type: "dns" as const, value })))] },
    webcrypto as unknown as Crypto,
  );
  return csr.toString("pem");
}

/** An ML-DSA Managed Certificate on a fresh ML-DSA-65 Private CA with its first Certificate issued, and the CA it is on. */
async function issuedOnMlDsaCa(keyAlgorithm: MlDsa = "ml-dsa-65") {
  const ca = await createCa("ml-dsa-65");
  const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await mlDsaRequest(keyAlgorithm, ["app.internal.acme"])), ...fromCa(ca.issuing.id) } });
  expect(created.status).toBe(201);
  const mc = await ended(created.body.id);
  expect(mc.issuance.status).toBe("succeeded");
  return { ca, mc };
}

const leafOf = async (id: string) => (await download(`${mcs()}/${id}/certificate`))[0]!;
const certificateCount = async (id: string) => (await h.api(`${mcs()}/${id}/certificates`, { cookie: org.cookie })).body.items.length as number;

describe("a Name Change of an ML-DSA Managed Certificate", () => {
  test("applies at once for an Organization Administrator with an ML-DSA CSR of the same algorithm, and the new Certificate is signed with ML-DSA", async () => {
    const { mc } = await issuedOnMlDsaCa("ml-dsa-65");
    const csr = (await mlDsaRequest("ml-dsa-65", ["www.internal.acme"])).csr;

    const changed = await h.api(`${mcs()}/${mc.id}/name-change`, { cookie: org.cookie, body: { names: ["www.internal.acme"], csr } });
    expect(changed.status).toBe(201);
    const after = await ended(mc.id);
    expect(after.issuance.status).toBe("succeeded");
    expect(after.names).toEqual(["www.internal.acme"]);

    const leaf = await leafOf(mc.id);
    expect(leaf.subject).toBe("CN=www.internal.acme");
    expect(algorithmIdentifiersIn(leaf.rawData, "ml-dsa-65")).toBe(3);
    expect((await auditOf()).find((e) => e.action === "managed_certificate.names_changed")).toMatchObject({ target: { id: mc.id } });
  });

  test("proposed by an Owner with an ML-DSA CSR waits for Approval, and an Approver's approval issues it", async () => {
    const ca = await createCa("ml-dsa-65");
    const owner = await join("owner@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await mlDsaRequest("ml-dsa-44", ["app.internal.acme"])), ...fromCa(ca.issuing.id), owners: [{ type: "user", id: ((await h.api("/api/me", { cookie: owner })).body.user.id as string) }] } });
    expect(created.status).toBe(201);
    await ended(created.body.id);

    const proposed = await h.api(`${mcs()}/${created.body.id}/name-change`, { cookie: owner, body: { names: ["www.internal.acme"], csr: (await mlDsaRequest("ml-dsa-44", ["www.internal.acme"])).csr } });
    expect(proposed.status).toBe(201);
    expect(await certificateCount(created.body.id)).toBe(1);

    expect((await h.api(`${mcs()}/${created.body.id}/name-change/approve`, { cookie: approver, body: {} })).status).toBe(200);
    expect((await ended(created.body.id)).names).toEqual(["www.internal.acme"]);
    expect(algorithmIdentifiersIn((await leafOf(created.body.id)).rawData, "ml-dsa-44")).toBe(1);
  });

  test.each([
    ["an ML-DSA CSR of another ML-DSA algorithm", () => mlDsaRequest("ml-dsa-87", ["www.internal.acme"]).then((r) => r.csr), "ml-dsa-87, but the Managed Certificate's key algorithm is ml-dsa-65", undefined],
    ["an ECDSA CSR, which an ML-DSA Private CA would not take", () => ecdsaRequest(["www.internal.acme"]), "ecdsa-p256, but the Managed Certificate's key algorithm is ml-dsa-65", "weak link"],
  ])("is refused with a 422 for %s, and nothing changes", async (_, csr, reason, why) => {
    const { mc } = await issuedOnMlDsaCa("ml-dsa-65");
    const res = await h.api(`${mcs()}/${mc.id}/name-change`, { cookie: org.cookie, body: { names: ["www.internal.acme"], csr: await csr() } });
    expect(res.status).toBe(422);
    expect(res.body.error).toContain(reason);
    if (why) expect(res.body.error).toContain(why);
    expect((await h.api(`${mcs()}/${mc.id}`, { cookie: org.cookie })).body.names).toEqual(["app.internal.acme"]);
    expect(await certificateCount(mc.id)).toBe(1);
  });

  test("an ML-DSA CSR for an ECDSA Managed Certificate on an ECDSA Private CA is refused with a 422 that says why", async () => {
    const classic = await h.api(casOf(), { cookie: org.cookie, body: { ...NEW_CA, name: "Classic TLS", subject: "CN=Acme Classic TLS", keyAlgorithm: "ecdsa-p256" } });
    const created = await h.api(mcs(), { cookie: org.cookie, body: { names: ["app.internal.acme"], keyAlgorithm: "ecdsa-p256", csr: await ecdsaRequest(["app.internal.acme"]), ...fromCa(classic.body.issuingCas[0].id) } });
    expect(created.status).toBe(201);
    await ended(created.body.id);

    const res = await h.api(`${mcs()}/${created.body.id}/name-change`, { cookie: org.cookie, body: { names: ["www.internal.acme"], csr: (await mlDsaRequest("ml-dsa-65", ["www.internal.acme"])).csr } });
    expect(res.status).toBe(422);
    expect(res.body.error).toContain("gains no quantum resistance");
  });
});

describe("a Renewal of an ML-DSA Managed Certificate", () => {
  test("uses a new ML-DSA CSR of the same algorithm uploaded for it, and the Certificate issued has the new key", async () => {
    const { mc } = await issuedOnMlDsaCa("ml-dsa-65");
    const replacement = await mlDsaRequest("ml-dsa-65", ["app.internal.acme"]);

    const uploaded = await h.api(`${mcs()}/${mc.id}/csr`, { cookie: org.cookie, body: { csr: replacement.csr } });
    expect(uploaded.status).toBe(200);
    expect((await auditOf()).find((e) => e.action === "managed_certificate.csr_uploaded")).toMatchObject({ target: { id: mc.id } });

    const renewing = await h.api(`${mcs()}/${mc.id}/renewals`, { cookie: org.cookie, method: "POST", body: {} });
    expect(renewing.status).toBe(202);
    expect((await ended(mc.id)).issuance.status).toBe("succeeded");
    expect(await certificateCount(mc.id)).toBe(2);

    const leaf = await leafOf(mc.id);
    expect(Buffer.from(leaf.publicKey.rawData)).toEqual(Buffer.from(new x509.Pkcs10CertificateRequest(replacement.csr).publicKey.rawData));
    expect(algorithmIdentifiersIn(leaf.rawData, "ml-dsa-65")).toBe(3);
  });

  test.each([
    ["an ML-DSA CSR of another ML-DSA algorithm", () => mlDsaRequest("ml-dsa-44", ["app.internal.acme"]).then((r) => r.csr), "ml-dsa-44, but the Managed Certificate's key algorithm is ml-dsa-65", undefined],
    ["an ECDSA CSR, which an ML-DSA Private CA would not take", () => ecdsaRequest(["app.internal.acme"]), "ecdsa-p256, but the Managed Certificate's key algorithm is ml-dsa-65", "weak link"],
  ])("refuses %s with a 422 that says why, and keeps the CSR it has", async (_, csr, reason, why) => {
    const { mc } = await issuedOnMlDsaCa("ml-dsa-65");
    const before = (await h.api(`${mcs()}/${mc.id}`, { cookie: org.cookie })).body;

    const res = await h.api(`${mcs()}/${mc.id}/csr`, { cookie: org.cookie, body: { csr: await csr() } });
    expect(res.status).toBe(422);
    expect(res.body.error).toContain(reason);
    if (why) expect(res.body.error).toContain(why);
    expect((await h.api(`${mcs()}/${mc.id}`, { cookie: org.cookie })).body.csr).toEqual(before.csr);
  });
});

describe("a Renewal of an ECDSA Managed Certificate on an ECDSA Private CA", () => {
  test("refuses an uploaded ML-DSA CSR with a 422 that says why, and keeps the CSR it has", async () => {
    const classic = await h.api(casOf(), { cookie: org.cookie, body: { ...NEW_CA, name: "Classic TLS", subject: "CN=Acme Classic TLS", keyAlgorithm: "ecdsa-p256" } });
    const csr = await ecdsaRequest(["app.internal.acme"]);
    const created = await h.api(mcs(), { cookie: org.cookie, body: { names: ["app.internal.acme"], keyAlgorithm: "ecdsa-p256", csr, ...fromCa(classic.body.issuingCas[0].id) } });
    expect(created.status).toBe(201);
    const before = (await ended(created.body.id)).csr;

    const res = await h.api(`${mcs()}/${created.body.id}/csr`, { cookie: org.cookie, body: { csr: (await mlDsaRequest("ml-dsa-65", ["app.internal.acme"])).csr } });
    expect(res.status).toBe(422);
    expect(res.body.error).toContain("gains no quantum resistance");
    expect((await h.api(`${mcs()}/${created.body.id}`, { cookie: org.cookie })).body.csr).toEqual(before);
  });
});

describe("the inventory", () => {
  test("filters by the three ML-DSA key algorithms, one or several at once", async () => {
    const ca = await createCa("ml-dsa-65");
    const ids: Record<MlDsa, string> = { "ml-dsa-44": "", "ml-dsa-65": "", "ml-dsa-87": "" };
    for (const algorithm of Object.keys(ids) as MlDsa[]) {
      const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await mlDsaRequest(algorithm, [`${algorithm}.internal.acme`])), ...fromCa(ca.issuing.id) } });
      expect(created.status).toBe(201);
      ids[algorithm] = created.body.id;
    }
    const classic = await h.api(casOf(), { cookie: org.cookie, body: { ...NEW_CA, name: "Classic TLS", subject: "CN=Acme Classic TLS", keyAlgorithm: "ecdsa-p256" } });
    expect((await h.api(mcs(), { cookie: org.cookie, body: { names: ["classic.internal.acme"], keyAlgorithm: "ecdsa-p256", csr: await ecdsaRequest(["classic.internal.acme"]), ...fromCa(classic.body.issuingCas[0].id) } })).status).toBe(201);

    const listed = async (keyAlgorithm: string) => ((await h.api(`${mcs()}?keyAlgorithm=${keyAlgorithm}`, { cookie: org.cookie })).body.items as { id: string }[]).map((m) => m.id).sort();
    for (const algorithm of Object.keys(ids) as MlDsa[]) expect(await listed(algorithm)).toEqual([ids[algorithm]]);
    expect(await listed("ml-dsa-44,ml-dsa-87")).toEqual([ids["ml-dsa-44"], ids["ml-dsa-87"]].sort());
    expect((await listed("ml-dsa-44,ml-dsa-65,ml-dsa-87")).length).toBe(3);
  });
});

const DAY_MS = 86_400_000;
const START = Date.parse("2026-01-01T00:00:00Z");

/** A CA's CRL, fetched as a relying party does: from its public URL, with no credentials. */
async function publishedCrl(kind: "issuing-cas" | "roots", id: string) {
  const res = await h.app.request(`${PKI_BASE_URL}/pki/${kind}/${id}/ca.crl`);
  expect(res.status).toBe(200);
  expect(res.headers.get("content-type")).toBe("application/pkix-crl");
  return new x509.X509Crl(new Uint8Array(await res.arrayBuffer()));
}

const CRL_NUMBER = "2.5.29.20";
const crlNumberOf = (crl: x509.X509Crl) => {
  const value = new Uint8Array(crl.extensions.find((e) => e.type === CRL_NUMBER)!.value);
  return Number(BigInt(`0x${Buffer.from(value.subarray(2, 2 + value[1]!)).toString("hex")}`));
};

/** The size of what a CRL's issuer signed (its TBSCertList, the first element of the CRL's SEQUENCE), header included. */
function signedSizeOf(crl: x509.X509Crl) {
  const bytes = new Uint8Array(crl.rawData);
  const headerSize = (at: number) => (bytes[at + 1]! & 0x80 ? 2 + (bytes[at + 1]! & 0x7f) : 2);
  const at = headerSize(0);
  const length = bytes[at + 1]! & 0x80 ? Number(BigInt(`0x${Buffer.from(bytes.subarray(at + 2, at + headerSize(at))).toString("hex")}`)) : bytes[at + 1]!;
  return headerSize(at) + length;
}

const revoke = (mcId: string, certificateId: string, reason: string) => h.api(`${mcs()}/${mcId}/certificates/${certificateId}/revocation`, { cookie: org.cookie, body: { reason } });

describe.each(["ml-dsa-65", "ml-dsa-87"] as const)("the CRLs of an %s Private CA", (caAlgorithm) => {
  test("revoking an ML-DSA Certificate reissues its Issuing CA's CRL, signed with ML-DSA and listing it, which the X.509 library verifies", async () => {
    const ca = await createCa(caAlgorithm);
    const [issuing, root] = await download(`${casOf()}/${ca.id}/issuing-cas/${ca.issuing.id}/chain`);
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await mlDsaRequest("ml-dsa-44", ["app.internal.acme"])), ...fromCa(ca.issuing.id) } });
    const mc = await ended(created.body.id);
    const before = await publishedCrl("issuing-cas", ca.issuing.id);
    expect(before.entries).toEqual([]);

    h.setNow(new Date(START + 60_000));
    expect((await revoke(mc.id, mc.currentCertificate.id, "keyCompromise")).status).toBe(200);

    const crl = await publishedCrl("issuing-cas", ca.issuing.id);
    expect(await crl.verify({ publicKey: issuing! })).toBe(true);
    // The signature field of its TBS and its own signature algorithm.
    expect(algorithmIdentifiersIn(crl.rawData, caAlgorithm)).toBe(2);
    expect(crl.entries.map((e) => ({ serial: e.serialNumber.toUpperCase(), reason: e.reason }))).toEqual([{ serial: mc.currentCertificate.serial, reason: x509.X509CrlReason.keyCompromise }]);
    expect(crlNumberOf(crl)).toBeGreaterThan(crlNumberOf(before));

    // The root's CRL of its Issuing CAs is signed with ML-DSA too.
    const rootCrl = await publishedCrl("roots", ca.id);
    expect(await rootCrl.verify({ publicKey: root! })).toBe(true);
    expect(algorithmIdentifiersIn(rootCrl.rawData, caAlgorithm)).toBe(2);
  });

  test("revoking the Issuing CA puts it on its root's CRL, signed with ML-DSA", async () => {
    const ca = await createCa(caAlgorithm);
    const [issuing, root] = await download(`${casOf()}/${ca.id}/issuing-cas/${ca.issuing.id}/chain`);

    const res = await h.api(`${casOf()}/${ca.id}/issuing-cas/${ca.issuing.id}/revocation`, { cookie: org.cookie, body: { reason: "keyCompromise" } });
    expect(res.status).toBe(200);

    const rootCrl = await publishedCrl("roots", ca.id);
    expect(await rootCrl.verify({ publicKey: root! })).toBe(true);
    expect(rootCrl.entries.map((e) => e.serialNumber.toUpperCase())).toEqual([issuing!.serialNumber.toUpperCase()]);
  });
});

describe("a revocation the KMS cannot sign an ML-DSA CRL for", () => {
  test("is refused with 502 for a Certificate and for an Issuing CA, and nothing is revoked", async () => {
    const { ca, mc } = await issuedOnMlDsaCa();
    const certificate = mc.currentCertificate;

    h.kms.failing = true;
    const revokedCertificate = await revoke(mc.id, certificate.id, "keyCompromise");
    const revokedIssuingCa = await h.api(`${casOf()}/${ca.id}/issuing-cas/${ca.issuing.id}/revocation`, { cookie: org.cookie, body: { reason: "keyCompromise" } });
    h.kms.failing = false;

    expect(revokedCertificate.status).toBe(502);
    expect(revokedIssuingCa.status).toBe(502);
    expect((await publishedCrl("issuing-cas", ca.issuing.id)).entries).toEqual([]);
    expect((await publishedCrl("roots", ca.id)).entries).toEqual([]);
    expect((await h.api(`${mcs()}/${mc.id}`, { cookie: org.cookie })).body.currentCertificate.revocation).toBeNull();
    expect((await h.api(`${casOf()}/${ca.id}`, { cookie: org.cookie })).body.issuingCas[0].status).toBe("active");
    expect((await revoke(mc.id, certificate.id, "keyCompromise")).status).toBe(200);
  });
});

describe("the scheduled reissue of an ML-DSA Private CA's CRLs", () => {
  test("reissues a CRL over 4 KB, which no KMS limit on a message stops, and it still verifies", async () => {
    const ca = await createCa("ml-dsa-65");
    const [issuing, root] = await download(`${casOf()}/${ca.id}/issuing-cas/${ca.issuing.id}/chain`);
    // One entry takes about 50 bytes, so this many is a CRL whose TBS alone is over 4 KB.
    const ids: string[] = [];
    for (let i = 0; i < 100; i++) {
      const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await mlDsaRequest("ml-dsa-44", [`host${i}.internal.acme`])), ...fromCa(ca.issuing.id) } });
      expect(created.status).toBe(201);
      ids.push(created.body.id);
    }
    await h.settleIssuances();
    for (const id of ids) {
      const mc = (await h.api(`${mcs()}/${id}`, { cookie: org.cookie })).body;
      expect(mc.issuance.status).toBe("succeeded");
      expect((await revoke(id, mc.currentCertificate.id, "cessationOfOperation")).status).toBe(200);
    }
    const first = await publishedCrl("issuing-cas", ca.issuing.id);
    const firstRoot = await publishedCrl("roots", ca.id);
    expect(first.entries).toHaveLength(100);
    expect(signedSizeOf(first)).toBeGreaterThan(4096);
    expect(await first.verify({ publicKey: issuing! })).toBe(true);

    h.setNow(new Date(first.nextUpdate!.getTime() - 3 * DAY_MS));
    expect(await h.runCrlScheduler()).toBe(2);
    const secondRoot = await publishedCrl("roots", ca.id);
    expect(crlNumberOf(secondRoot)).toBeGreaterThan(crlNumberOf(firstRoot));
    expect(await secondRoot.verify({ publicKey: root! })).toBe(true);
    expect(algorithmIdentifiersIn(secondRoot.rawData, "ml-dsa-65")).toBe(2);
    const second = await publishedCrl("issuing-cas", ca.issuing.id);
    expect(crlNumberOf(second)).toBeGreaterThan(crlNumberOf(first));
    expect(second.entries).toHaveLength(100);
    expect(signedSizeOf(second)).toBeGreaterThan(4096);
    expect(await second.verify({ publicKey: issuing! })).toBe(true);
  }, 120_000);
});

describe("adding an Issuing CA under an ML-DSA root", () => {
  test.each(["ml-dsa-65", "ml-dsa-87"] as const)("%s: gets a new ML-DSA key of the root's algorithm, and a Managed Certificate issued from it verifies to the same root", async (caAlgorithm) => {
    const ca = await createCa(caAlgorithm);
    const [first, root] = await download(`${casOf()}/${ca.id}/issuing-cas/${ca.issuing.id}/chain`);

    const added = await h.api(`${casOf()}/${ca.id}/issuing-cas`, { cookie: org.cookie, body: { subject: "CN=Acme Quantum Devices, O=Acme", permittedNames: { exact: [], zones: ["internal.acme"] } } });
    expect(added.status).toBe(201);
    const [second, sameRoot] = await download(`${casOf()}/${ca.id}/issuing-cas/${added.body.id}/chain`);
    expect(sameRoot!.equal(root!)).toBe(true);
    expect(algorithmIdentifiersIn(second!.rawData, caAlgorithm)).toBe(3);
    expect(await second!.verify({ publicKey: root!.publicKey, signatureOnly: true })).toBe(true);
    expect(Buffer.from(second!.publicKey.rawData).equals(Buffer.from(first!.publicKey.rawData))).toBe(false);

    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await mlDsaRequest("ml-dsa-65", ["app.internal.acme"])), ...fromCa(added.body.id) } });
    expect(created.status).toBe(201);
    const mc = await ended(created.body.id);
    expect(mc.issuance.status).toBe("succeeded");
    const [leaf, ...above] = await download(`${mcs()}/${mc.id}/certificate?chain=with-root`);
    expect(await leaf!.verify({ publicKey: second!.publicKey, signatureOnly: true })).toBe(true);
    const path = await new x509.X509ChainBuilder({ certificates: above }).build(leaf!);
    expect(path.at(-1)!.equal(root!)).toBe(true);

    // It publishes its own CRL at once, signed with ML-DSA.
    const crl = await publishedCrl("issuing-cas", added.body.id);
    expect(await crl.verify({ publicKey: second! })).toBe(true);
    expect(algorithmIdentifiersIn(crl.rawData, caAlgorithm)).toBe(2);
  });

  test("rolls a Managed Certificate over: repointed to the new Issuing CA, its Renewal comes from it, verifies to the same root, and the retired one still publishes its CRL", async () => {
    const { ca, mc } = await issuedOnMlDsaCa();
    const [old, root] = await download(`${casOf()}/${ca.id}/issuing-cas/${ca.issuing.id}/chain`);
    const added = await h.api(`${casOf()}/${ca.id}/issuing-cas`, { cookie: org.cookie, body: { subject: "CN=Acme Quantum TLS 2, O=Acme", permittedNames: { exact: [], zones: ["internal.acme"] } } });
    expect(added.status).toBe(201);

    expect((await h.api(`${mcs()}/${mc.id}/issuer`, { method: "PUT", cookie: org.cookie, body: fromCa(added.body.id) })).status).toBe(200);
    expect((await h.api(`${casOf()}/${ca.id}/issuing-cas/${ca.issuing.id}/retire`, { cookie: org.cookie, method: "POST", body: {} })).status).toBe(200);
    expect((await h.api(`${mcs()}/${mc.id}/renewals`, { cookie: org.cookie, method: "POST", body: {} })).status).toBe(202);
    const renewed = await ended(mc.id);
    expect(renewed.issuance).toMatchObject({ kind: "renewal", status: "succeeded" });
    expect(renewed.currentCertificate.issuingCaId).toBe(added.body.id);

    const [leaf, ...above] = await download(`${mcs()}/${mc.id}/certificate?chain=with-root`);
    const [next] = await download(`${casOf()}/${ca.id}/issuing-cas/${added.body.id}/chain`);
    expect(await leaf!.verify({ publicKey: next!.publicKey, signatureOnly: true })).toBe(true);
    expect((await new x509.X509ChainBuilder({ certificates: above }).build(leaf!)).at(-1)!.equal(root!)).toBe(true);
    expect(await (await publishedCrl("issuing-cas", ca.issuing.id)).verify({ publicKey: old! })).toBe(true);
  });
});
