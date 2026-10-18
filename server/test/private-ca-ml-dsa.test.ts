// ML-DSA Private CAs: an Organization Administrator creates one whose root and Issuing CA have ML-DSA-65 or ML-DSA-87
// keys in the (local) KMS, and a Managed Certificate (Key Custody: Owner) created or proposed on it from an ML-DSA CSR
// is issued with a chain that verifies to its root. What is checked is what an outside party sees: the API's answers
// and the certificates, verified with the X.509 library.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { webcrypto } from "node:crypto";
import { PASSWORD, createHarness, type Harness } from "./support/harness";

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

  test("is refused under the Organization's own root for now, which nothing yet checks is ML-DSA too", async () => {
    const res = await h.api(casOf(), { cookie: org.cookie, body: { ...NEW_CA, kind: "organization_root", lifetimeYears: undefined, keyAlgorithm: "ml-dsa-65" } });
    expect(res.status).toBe(422);
    expect(res.body.error).toContain("platform-made root");
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
        organization_root: ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"],
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
