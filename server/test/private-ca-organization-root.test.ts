// Private CAs under an Organization's own root: the platform makes only the Issuing CAs, each key in the (local) KMS,
// and gives out each one's CSR; the Organization signs it with its own (here, a test's) root and uploads the result, with
// the root and anything between, once for the Private CA. What is checked is what an outside party sees: the API's
// answers, the CSR, and the certificates issued.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import acme from "acme-client";
import { webcrypto } from "node:crypto";
import { PASSWORD, createHarness, type Harness } from "./harness";

let h: Harness;
/** The harness's clock, which the Organization's own certificates here are dated by. */
const NOW = new Date("2026-01-01T00:00:00Z");
let operator: string;
let org: { orgId: string; cookie: string };

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  h.setNow(NOW);
  operator = await h.createOperator("op@platform.test", PASSWORD);
  org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
});
afterAll(async () => {
  await h.close();
});

const cas = (orgId = org.orgId) => `/api/organizations/${orgId}/private-cas`;
const mcs = (orgId = org.orgId) => `/api/organizations/${orgId}/managed-certificates`;
const auditOf = async (target = org) => (await h.api(`/api/organizations/${target.orgId}/audit-events`, { cookie: target.cookie })).body.items as { action: string; target: any; detail: any }[];

const NEW_CA = {
  name: "Corp PKI",
  kind: "organization_root",
  subject: "CN=Acme Issuing CA 1, O=Acme",
  keyAlgorithm: "ecdsa-p256",
  permittedNames: { exact: [], zones: ["internal.acme"] },
};

type IssuingCa = {
  id: string;
  subject: string;
  status: string;
  notAfter: string | null;
  permittedNames: { exact: string[]; zones: string[] };
  nameConstraints: { permitted: string[]; excluded: string[] } | null;
};
type PrivateCa = { id: string; name: string; status: string; kind: string; root: { subject: string; notAfter: string } | null; issuingCas: IssuingCa[] };

async function createCa(body: Record<string, unknown> = NEW_CA, target = org) {
  const res = await h.api(cas(target.orgId), { cookie: target.cookie, body });
  expect(res.status).toBe(201);
  const ca = res.body as PrivateCa;
  return { ...ca, issuing: ca.issuingCas[0]! };
}

const issuingCaPath = (ca: { id: string }, issuing: { id: string }, orgId = org.orgId) => `${cas(orgId)}/${ca.id}/issuing-cas/${issuing.id}`;

const certificatesIn = (pem: string) => (pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map((one) => new x509.X509Certificate(one));

/** The Issuing CA's CSR, as downloaded. */
async function csrOf(ca: { id: string }, issuing: { id: string }, cookie = org.cookie) {
  const res = await h.app.request(`http://localhost${issuingCaPath(ca, issuing)}/csr`, { headers: { cookie } });
  return { status: res.status, csr: res.status === 200 ? new x509.Pkcs10CertificateRequest(await res.text()) : null };
}

async function download(path: string, cookie = org.cookie) {
  const res = await h.app.request(`http://localhost${path}`, { headers: { cookie } });
  return { status: res.status, certificates: res.status === 200 ? certificatesIn(await res.text()) : [] };
}

const signedBy = (cert: x509.X509Certificate, by: x509.X509Certificate) => cert.verify({ publicKey: by.publicKey, signatureOnly: true });

const ALGORITHM = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
const YEAR_MS = 365 * 24 * 60 * 60 * 1000;

/** A CA of the Organization's own, outside the platform: a key and its certificate, which signs what it is asked to. */
interface OwnCa {
  keys: CryptoKeyPair;
  certificate: x509.X509Certificate;
}

/** The Organization's own self-signed root. */
async function ownRoot(subject = "CN=Acme Offline Root, O=Acme", notAfter = new Date(NOW.getTime() + 20 * YEAR_MS)): Promise<OwnCa> {
  const keys = (await webcrypto.subtle.generateKey(ALGORITHM, false, ["sign", "verify"])) as CryptoKeyPair;
  const certificate = await x509.X509CertificateGenerator.createSelfSigned(
    {
      serialNumber: "01",
      name: subject,
      notBefore: new Date(NOW.getTime() - 60_000),
      notAfter,
      keys,
      signingAlgorithm: ALGORITHM,
      extensions: [new x509.BasicConstraintsExtension(true, undefined, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)],
    },
    webcrypto as unknown as Crypto,
  );
  return { keys, certificate };
}

/** A certificate `by` signs for `publicKey` and `subject`: a CA one unless `ca` is false, with whatever `extensions` are added. */
async function sign(by: OwnCa, publicKey: x509.PublicKey, subject: string, { ca = true, extensions = [] as x509.Extension[], notBefore = new Date(NOW.getTime() - 60_000), notAfter = new Date(NOW.getTime() + 5 * YEAR_MS) } = {}) {
  return x509.X509CertificateGenerator.create(
    {
      serialNumber: Buffer.from(webcrypto.getRandomValues(new Uint8Array(8))).toString("hex").replace(/^./, "1"),
      subject,
      issuer: by.certificate.subject,
      notBefore,
      notAfter,
      publicKey,
      signingKey: by.keys.privateKey,
      signingAlgorithm: ALGORITHM,
      extensions: [
        new x509.BasicConstraintsExtension(ca, ca ? 0 : undefined, true),
        new x509.KeyUsagesExtension(ca ? x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign : x509.KeyUsageFlags.digitalSignature, true),
        ...extensions,
      ],
    },
    webcrypto as unknown as Crypto,
  );
}

/** An intermediate CA of the Organization's, under `by`. */
async function ownIntermediate(by: OwnCa, subject = "CN=Acme Policy CA, O=Acme"): Promise<OwnCa> {
  const keys = (await webcrypto.subtle.generateKey(ALGORITHM, false, ["sign", "verify"])) as CryptoKeyPair;
  const publicKey = await x509.PublicKey.create(keys.publicKey, webcrypto as unknown as Crypto);
  const certificate = await x509.X509CertificateGenerator.create(
    {
      serialNumber: "02",
      subject,
      issuer: by.certificate.subject,
      notBefore: new Date(NOW.getTime() - 60_000),
      notAfter: new Date(NOW.getTime() + 10 * YEAR_MS),
      publicKey,
      signingKey: by.keys.privateKey,
      signingAlgorithm: ALGORITHM,
      extensions: [new x509.BasicConstraintsExtension(true, 1, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)],
    },
    webcrypto as unknown as Crypto,
  );
  return { keys, certificate };
}

/** Uploads the Issuing CA's signed certificate, with the root and chain above when given; the answer as it came. */
const upload = (ca: { id: string }, issuing: { id: string }, body: { certificate: string; root?: string; chain?: string }, cookie = org.cookie) =>
  h.api(`${issuingCaPath(ca, issuing)}/certificate`, { cookie, body });

/** Has `by` sign the Issuing CA's CSR as its root would, and uploads it with `root` (and `chain`). */
async function signAndUpload(ca: { id: string }, issuing: { id: string }, by: OwnCa, root?: OwnCa, chain: OwnCa[] = []) {
  const { csr } = await csrOf(ca, issuing);
  const certificate = await sign(by, csr!.publicKey, csr!.subject);
  return upload(ca, issuing, { certificate: certificate.toString("pem"), ...(root && { root: root.certificate.toString("pem") }), ...(chain.length > 0 && { chain: chain.map((c) => c.certificate.toString("pem")).join("\n") }) });
}

async function request(names: string[]) {
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() };
}

const fromCa = (issuingCaId: string) => ({ issuer: { kind: "private_ca", issuingCaId } });

describe("creating a Private CA under the Organization's own root", () => {
  test("makes only its first Issuing CA's key, awaiting signature, and offers its CSR", async () => {
    const ca = await createCa();

    expect(ca).toMatchObject({ name: "Corp PKI", kind: "organization_root", status: "active", root: null });
    expect(ca.issuingCas).toHaveLength(1);
    expect(ca.issuing).toMatchObject({ subject: "CN=Acme Issuing CA 1, O=Acme", status: "awaiting_signature", notAfter: null, permittedNames: NEW_CA.permittedNames, nameConstraints: null });

    const { status, csr } = await csrOf(ca, ca.issuing);
    expect(status).toBe(200);
    expect(csr!.subject).toBe("CN=Acme Issuing CA 1, O=Acme");
    expect(await csr!.verify()).toBe(true);
    expect(csr!.publicKey.algorithm.name).toBe("ECDSA");
  });
});

describe("uploading an Issuing CA's signed certificate", () => {
  test("with the root makes it active, shows the root, and it issues Certificates whose chain verifies to that root", async () => {
    const ca = await createCa();
    const root = await ownRoot();

    const uploaded = await signAndUpload(ca, ca.issuing, root, root);

    expect(uploaded.status).toBe(200);
    expect(uploaded.body).toMatchObject({ id: ca.issuing.id, status: "active", subject: "CN=Acme Issuing CA 1, O=Acme" });
    const listed = (await h.api(`${cas()}/${ca.id}`, { cookie: org.cookie })).body as PrivateCa;
    expect(listed.root).toEqual({ subject: "CN=Acme Offline Root, O=Acme", notAfter: root.certificate.notAfter.toISOString() });
    expect(listed.issuingCas[0]!.notAfter).not.toBeNull();

    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.internal.acme"])), ...fromCa(ca.issuing.id) } });
    expect(created.status).toBe(201);
    await h.settleIssuances();
    const mc = (await h.api(`${mcs()}/${created.body.id}`, { cookie: org.cookie })).body;
    expect(mc.issuance).toMatchObject({ status: "succeeded" });
    const res = await h.app.request(`http://localhost${mcs()}/${mc.id}/certificate?chain=with-root`, { headers: { cookie: org.cookie } });
    const [leaf, issuing, top, ...rest] = certificatesIn(await res.text());
    expect(rest).toEqual([]);
    expect(top!.equal(root.certificate)).toBe(true);
    expect(await signedBy(leaf!, issuing!)).toBe(true);
    expect(await signedBy(issuing!, root.certificate)).toBe(true);
  });

  test("is an Audit Event naming the Issuing CA", async () => {
    const ca = await createCa();
    const root = await ownRoot();
    await signAndUpload(ca, ca.issuing, root, root);

    const signed = (await auditOf()).filter((e) => e.action === "private_ca.csr_signed");
    expect(signed).toMatchObject([{ target: { type: "private_ca", id: ca.id }, detail: { name: "Corp PKI", issuingCa: { id: ca.issuing.id, subject: "CN=Acme Issuing CA 1, O=Acme" } } }]);
  });

  test("with an intermediate between it and the root, serves the whole chain", async () => {
    const ca = await createCa();
    const root = await ownRoot();
    const policy = await ownIntermediate(root);

    expect((await signAndUpload(ca, ca.issuing, policy, root, [policy])).status).toBe(200);

    const { certificates } = await download(`${issuingCaPath(ca, ca.issuing)}/chain`);
    expect(certificates.map((c) => c.subject)).toEqual(["CN=Acme Issuing CA 1, O=Acme", "CN=Acme Policy CA, O=Acme", "CN=Acme Offline Root, O=Acme"]);
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.internal.acme"])), ...fromCa(ca.issuing.id) } });
    await h.settleIssuances();
    const res = await h.app.request(`http://localhost${mcs()}/${created.body.id}/certificate?chain=with-root`, { headers: { cookie: org.cookie } });
    const chain = certificatesIn(await res.text());
    expect(chain.slice(1).map((c) => c.subject)).toEqual(["CN=Acme Issuing CA 1, O=Acme", "CN=Acme Policy CA, O=Acme", "CN=Acme Offline Root, O=Acme"]);
  });
});

describe("an upload that would leave a broken CA is refused", () => {
  /** A fresh key's public key: one the Issuing CA's CSR is not for. */
  const otherKey = async () => x509.PublicKey.create(((await webcrypto.subtle.generateKey(ALGORITHM, true, ["sign", "verify"])) as CryptoKeyPair).publicKey, webcrypto as unknown as Crypto);

  async function refused(ca: { id: string }, issuing: { id: string }, body: { certificate: string; root?: string; chain?: string }, pattern: RegExp) {
    const res = await upload(ca, issuing, body);
    expect(res.status).toBe(422);
    expect(res.body.message ?? res.body.error).toMatch(pattern);
    const listed = (await h.api(`${cas()}/${ca.id}`, { cookie: org.cookie })).body as PrivateCa;
    expect(listed.issuingCas.find((i) => i.id === issuing.id)!.status).toBe("awaiting_signature");
  }

  test("a certificate for another key than the CSR's", async () => {
    const ca = await createCa();
    const root = await ownRoot();
    const certificate = await sign(root, await otherKey(), ca.issuing.subject);
    await refused(ca, ca.issuing, { certificate: certificate.toString("pem"), root: root.certificate.toString("pem") }, /not for the Issuing CA's key/);
  });

  test("a certificate that is not a CA certificate", async () => {
    const ca = await createCa();
    const root = await ownRoot();
    const { csr } = await csrOf(ca, ca.issuing);
    const certificate = await sign(root, csr!.publicKey, csr!.subject, { ca: false });
    await refused(ca, ca.issuing, { certificate: certificate.toString("pem"), root: root.certificate.toString("pem") }, /not a CA certificate/);
  });

  test("a certificate that does not verify against the root and chain", async () => {
    const ca = await createCa();
    const root = await ownRoot();
    const impostor = await ownRoot();
    const { csr } = await csrOf(ca, ca.issuing);
    const certificate = await sign(impostor, csr!.publicKey, csr!.subject);
    await refused(ca, ca.issuing, { certificate: certificate.toString("pem"), root: root.certificate.toString("pem") }, /does not verify against the root and chain/);

    // Nor when the intermediate that signed it is left out.
    const policy = await ownIntermediate(root);
    const viaPolicy = await sign(policy, csr!.publicKey, csr!.subject);
    await refused(ca, ca.issuing, { certificate: viaPolicy.toString("pem"), root: root.certificate.toString("pem") }, /does not verify against the root and chain/);
  });

  test("a certificate not valid yet", async () => {
    const ca = await createCa();
    const root = await ownRoot();
    const { csr } = await csrOf(ca, ca.issuing);
    const certificate = await sign(root, csr!.publicKey, csr!.subject, { notBefore: new Date(NOW.getTime() + YEAR_MS) });
    await refused(ca, ca.issuing, { certificate: certificate.toString("pem"), root: root.certificate.toString("pem") }, /not valid yet/);
  });

  test("the first one without its root", async () => {
    const ca = await createCa();
    const root = await ownRoot();
    const { csr } = await csrOf(ca, ca.issuing);
    const certificate = await sign(root, csr!.publicKey, csr!.subject);
    await refused(ca, ca.issuing, { certificate: certificate.toString("pem") }, /needs its root/);
  });

  test("one under a platform-made root, or one already signed", async () => {
    const platform = await createCa({ name: "Platform", subject: "CN=Acme Platform TLS, O=Acme", permittedNames: { exact: [], zones: ["internal.acme"] } });
    const root = await ownRoot();
    const anything = await sign(root, await otherKey(), "CN=Anything");
    expect((await upload(platform, platform.issuing, { certificate: anything.toString("pem"), root: root.certificate.toString("pem") })).status).toBe(422);
    expect((await csrOf(platform, platform.issuing)).status).toBe(422);

    const ca = await createCa();
    expect((await signAndUpload(ca, ca.issuing, root, root)).status).toBe(200);
    expect((await signAndUpload(ca, ca.issuing, root)).status).toBe(422);
  });

  test("what cannot be read as a certificate is a 400", async () => {
    const ca = await createCa();
    expect((await upload(ca, ca.issuing, { certificate: "not a certificate" })).status).toBe(400);
  });
});

describe("adding an Issuing CA under the Organization's own root", () => {
  const SECOND = { subject: "CN=Acme Issuing CA 2, O=Acme", permittedNames: { exact: [], zones: ["devices.acme"] } };

  test("makes only its key, awaiting signature, with its own CSR, and its upload reuses the root and chain", async () => {
    const ca = await createCa();
    const root = await ownRoot();
    const policy = await ownIntermediate(root);
    await signAndUpload(ca, ca.issuing, policy, root, [policy]);

    const added = await h.api(`${cas()}/${ca.id}/issuing-cas`, { cookie: org.cookie, body: SECOND });
    expect(added.status).toBe(201);
    expect(added.body).toMatchObject({ subject: SECOND.subject, status: "awaiting_signature", notAfter: null });
    const first = (await csrOf(ca, ca.issuing)).csr!;
    const second = (await csrOf(ca, added.body)).csr!;
    expect(second.subject).toBe(SECOND.subject);
    expect(Buffer.from(second.publicKey.rawData).equals(Buffer.from(first.publicKey.rawData))).toBe(false);

    // Neither the root nor the chain again; another root is refused.
    const other = await ownRoot("CN=Another Root");
    const certificate = (await sign(policy, second.publicKey, second.subject)).toString("pem");
    expect((await upload(ca, added.body, { certificate, root: other.certificate.toString("pem") })).status).toBe(422);
    const uploaded = await upload(ca, added.body, { certificate });
    expect(uploaded.status).toBe(200);
    expect(uploaded.body.status).toBe("active");
    const { certificates } = await download(`${issuingCaPath(ca, added.body)}/chain`);
    expect(certificates.map((c) => c.subject)).toEqual([SECOND.subject, "CN=Acme Policy CA, O=Acme", "CN=Acme Offline Root, O=Acme"]);

    expect((await auditOf()).filter((e) => e.action === "private_ca.issuing_ca_added")).toMatchObject([{ target: { id: ca.id }, detail: { issuingCa: { id: added.body.id, subject: SECOND.subject } } }]);
  });

  test("takes no lifetime: the root decides it", async () => {
    const ca = await createCa();
    expect((await h.api(`${cas()}/${ca.id}/issuing-cas`, { cookie: org.cookie, body: { ...SECOND, lifetimeYears: 2 } })).status).toBe(422);
    expect((await h.api(cas(), { cookie: org.cookie, body: { ...NEW_CA, name: "Other", lifetimeYears: 2 } })).status).toBe(422);
  });
});

describe("an Issuing CA awaiting its signature", () => {
  test("issues nothing: a Managed Certificate on it is refused", async () => {
    const ca = await createCa();
    const res = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.internal.acme"])), ...fromCa(ca.issuing.id) } });
    expect(res.status).toBe(422);
    expect(res.body.message ?? res.body.error).toMatch(/awaiting_signature/);
  });
});

/** The DER of name constraints (RFC 5280, 4.2.1.10) permitting the dNSNames and excluding the IPv4 range 10.0.0.0/8. */
function nameConstraints(permittedDns: string[]) {
  const der = (tag: number, ...content: Uint8Array[]) => {
    const body = Buffer.concat(content);
    return Buffer.concat([Uint8Array.of(tag, body.length), body]);
  };
  const subtree = (tag: number, value: Uint8Array) => der(0x30, der(tag, value));
  const permitted = permittedDns.map((name) => subtree(0x82, Buffer.from(name)));
  const excluded = [subtree(0x87, Uint8Array.of(10, 0, 0, 0, 255, 0, 0, 0))];
  return new x509.Extension("2.5.29.30", true, der(0x30, der(0xa0, ...permitted), der(0xa1, ...excluded)));
}

describe("the name constraints the Organization's root put in an Issuing CA", () => {
  test("are shown, while the platform still enforces the Issuing CA's own permitted name rules", async () => {
    const ca = await createCa();
    const root = await ownRoot();
    const { csr } = await csrOf(ca, ca.issuing);
    const certificate = await sign(root, csr!.publicKey, csr!.subject, { extensions: [nameConstraints(["acme", "acme.example"])] });
    const uploaded = await upload(ca, ca.issuing, { certificate: certificate.toString("pem"), root: root.certificate.toString("pem") });

    expect(uploaded.status).toBe(200);
    expect(uploaded.body.nameConstraints).toEqual({ permitted: ["dns:acme", "dns:acme.example"], excluded: ["ip:10.0.0.0/8"] });

    // Within the root's constraints but outside the Issuing CA's rules (internal.acme): refused by the platform.
    const outside = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["www.acme.example"])), ...fromCa(ca.issuing.id) } });
    expect(outside.status).toBe(422);
    expect(outside.body.message ?? outside.body.error).toMatch(/outside the permitted names/);
  });

  test("are none when the root put none", async () => {
    const ca = await createCa();
    const root = await ownRoot();
    expect((await signAndUpload(ca, ca.issuing, root, root)).body.nameConstraints).toBeNull();
  });
});

async function join(email: string, role: string, target = org) {
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: target.cookie, body: { email, role, organizationId: target.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}

describe("who may", () => {
  test.each(["approver", "member"])("an %s may see an Organization-root Private CA, but not create one, download a CSR or upload a certificate", async (role) => {
    const cookie = await join(`${role}@acme.test`, role);
    expect((await h.api(cas(), { cookie, body: NEW_CA })).status).toBe(403);
    const ca = await createCa();
    expect((await h.api(`${cas()}/${ca.id}`, { cookie })).status).toBe(200);
    expect((await csrOf(ca, ca.issuing, cookie)).status).toBe(403);
    const root = await ownRoot();
    const { csr } = await csrOf(ca, ca.issuing);
    const certificate = await sign(root, csr!.publicKey, csr!.subject);
    expect((await upload(ca, ca.issuing, { certificate: certificate.toString("pem"), root: root.certificate.toString("pem") }, cookie)).status).toBe(403);
  });

  test("another Organization's administrator can neither download its CSR nor upload for it", async () => {
    const ca = await createCa();
    const globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    const asGlobex = (path: string) => path.replace(org.orgId, globex.orgId);
    const csr = await h.app.request(`http://localhost${asGlobex(issuingCaPath(ca, ca.issuing))}/csr`, { headers: { cookie: globex.cookie } });
    expect(csr.status).toBe(404);
    const root = await ownRoot();
    const anything = await sign(root, root.certificate.publicKey, "CN=Anything");
    const res = await h.api(`${asGlobex(issuingCaPath(ca, ca.issuing))}/certificate`, { cookie: globex.cookie, body: { certificate: anything.toString("pem"), root: root.certificate.toString("pem") } });
    expect(res.status).toBe(404);
  });
});

describe("an Organization-root Issuing CA's CRL", () => {
  test("is published once its certificate is accepted, signed by its own key, and not before", async () => {
    const ca = await createCa();
    const crl = () => h.app.request(`http://localhost/pki/issuing-cas/${ca.issuing.id}/ca.crl`);
    expect((await crl()).status).toBe(404);

    const root = await ownRoot();
    const uploaded = await signAndUpload(ca, ca.issuing, root, root);

    const res = await crl();
    expect(res.status).toBe(200);
    const list = new x509.X509Crl(new Uint8Array(await res.arrayBuffer()));
    const issuing = new x509.X509Certificate((await download(`${issuingCaPath(ca, uploaded.body)}/chain`)).certificates[0]!.rawData);
    expect(list.issuer).toBe(issuing.subject);
    expect(await list.verify({ publicKey: issuing.publicKey })).toBe(true);
  });
});

describe("what an Organization-root Issuing CA issues", () => {
  test("never outlives the root, even when the root signed the Issuing CA for longer than itself", async () => {
    const DAY_MS = 24 * 60 * 60 * 1000;
    const rootEnd = new Date(NOW.getTime() + 30 * DAY_MS);
    const root = await ownRoot("CN=Acme Short Root, O=Acme", rootEnd);
    const ca = await createCa();
    const { csr } = await csrOf(ca, ca.issuing);
    const certificate = await sign(root, csr!.publicKey, csr!.subject, { notAfter: new Date(NOW.getTime() + YEAR_MS) });
    expect((await upload(ca, ca.issuing, { certificate: certificate.toString("pem"), root: root.certificate.toString("pem") })).status).toBe(200);

    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.internal.acme"])), ...fromCa(ca.issuing.id) } });
    await h.settleIssuances();
    const res = await h.app.request(`http://localhost${mcs()}/${created.body.id}/certificate?chain=leaf`, { headers: { cookie: org.cookie } });
    const [leaf] = certificatesIn(await res.text());
    expect(leaf!.notAfter.getTime()).toBeLessThanOrEqual(root.certificate.notAfter.getTime());
  });
});
