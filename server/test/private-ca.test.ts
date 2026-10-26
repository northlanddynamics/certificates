// Private CAs: an Organization Administrator creates one with a platform-made root and Issuing CA, both keys in the
// (local) KMS, and anyone in the Organization downloads its chain. A Managed Certificate (Key Custody: Owner) created or
// proposed against it is issued with no ACME order and no DCV, and its chain verifies to the Private CA's root. There is
// no Pebble and no DNS here: what is checked is what an outside party sees, the API's answers and the certificates.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import acme from "acme-client";
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

const cas = (orgId = org.orgId) => `/api/organizations/${orgId}/private-cas`;
const mcs = (orgId = org.orgId) => `/api/organizations/${orgId}/managed-certificates`;
const auditOf = async (target = org) => (await h.api(`/api/organizations/${target.orgId}/audit-events`, { cookie: target.cookie })).body.items as { action: string; target: any; detail: any }[];

const NEW_CA = { name: "Internal TLS", subject: "CN=Acme Internal TLS, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["internal.acme"] } };

type IssuingCa = { id: string; subject: string; status: string; notAfter: string; permittedNames: { exact: string[]; zones: string[] }; validity: { maximumDays: number; defaultDays: number } };
type PrivateCa = { id: string; name: string; status: string; kind: string; keyAlgorithm: string; root: { subject: string; notAfter: string } | null; issuingCas: IssuingCa[] };

/** A new Private CA, and its first Issuing CA as `issuing`. */
async function createCa(body: Record<string, unknown> = NEW_CA, target = org) {
  const res = await h.api(cas(target.orgId), { cookie: target.cookie, body });
  expect(res.status).toBe(201);
  const ca = res.body as PrivateCa;
  return { ...ca, issuing: ca.issuingCas[0]! };
}

/** Where an Issuing CA of the Private CA is. */
const issuingCaPath = (ca: { id: string; issuing: { id: string } }, orgId = org.orgId) => `${cas(orgId)}/${ca.id}/issuing-cas/${ca.issuing.id}`;

/** The certificates of a PEM bundle, in order. */
const certificatesIn = (pem: string) => (pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map((one) => new x509.X509Certificate(one));

async function download(path: string, cookie: string) {
  const res = await h.app.request(`http://localhost${path}`, { headers: { cookie } });
  return { status: res.status, certificates: res.status === 200 ? certificatesIn(await res.text()) : [] };
}

/** The chain of the Private CA's first Issuing CA (or of `ca.issuing`): the Issuing CA, then the root. */
const chainOf = (ca: { id: string; issuing: { id: string } }, cookie = org.cookie, orgId = org.orgId) => download(`${issuingCaPath(ca, orgId)}/chain`, cookie);

/** The Private CA's own download: its root. */
const rootOf = (id: string, cookie = org.cookie, orgId = org.orgId) => download(`${cas(orgId)}/${id}/chain`, cookie);

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
    const { status, certificates } = await chainOf(ca);
    expect(status).toBe(200);
    const [issuing, root] = certificates;
    expect(certificates).toHaveLength(2);

    expect(await signedBy(root!, root!)).toBe(true);
    expect(await signedBy(issuing!, root!)).toBe(true);
    expect(root!.subject).not.toBe(issuing!.subject);
    expect(issuing!.issuer).toBe(root!.subject);
    expect(Buffer.from(issuing!.publicKey.rawData).equals(Buffer.from(root!.publicKey.rawData))).toBe(false);
    expect(issuing!.subject).toBe("CN=Acme Internal TLS, O=Acme");
    expect(new Date(ca.issuing.notAfter).getTime()).toBe(issuing!.notAfter.getTime());
    expect(ca.root).toEqual({ subject: "CN=Acme Internal TLS Root, O=Acme", notAfter: root!.notAfter.toISOString() });

    const issuingConstraints = issuing!.getExtension(x509.BasicConstraintsExtension)!;
    expect(issuingConstraints).toMatchObject({ ca: true, pathLength: 0, critical: true });
    expect(root!.getExtension(x509.BasicConstraintsExtension)).toMatchObject({ ca: true, critical: true });
    expect(issuing!.getExtension(x509.KeyUsagesExtension)!.usages & x509.KeyUsageFlags.keyCertSign).toBeTruthy();
  });

  test.each(["ecdsa-p384", "rsa-2048"])("makes the CA keys of the algorithm asked for: %s", async (keyAlgorithm) => {
    const ca = await createCa({ ...NEW_CA, keyAlgorithm });

    const [issuing, root] = (await chainOf(ca)).certificates;
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

/** The DER elements in `bytes`, one after another: each one's tag and content. */
function derElements(bytes: Uint8Array) {
  const elements: { tag: number; content: Uint8Array }[] = [];
  for (let i = 0; i < bytes.length; ) {
    const tag = bytes[i++]!;
    let length = bytes[i++]!;
    if (length & 0x80) {
      const octets = length & 0x7f;
      length = 0;
      for (let k = 0; k < octets; k++) length = (length << 8) | bytes[i++]!;
    }
    elements.push({ tag, content: bytes.subarray(i, i + length) });
    i += length;
  }
  return elements;
}

/** The Issuing CA's name constraints (RFC 5280, 4.2.1.10): whether critical, and each subtree's base as the dNSName or the iPAddress range it is. */
function nameConstraintsOf(cert: x509.X509Certificate) {
  const extension = cert.extensions.find((e) => e.type === "2.5.29.30");
  if (!extension) return null;
  const [sequence] = derElements(new Uint8Array(extension.value));
  const subtrees = (tag: number) =>
    derElements(derElements(sequence!.content).find((e) => e.tag === tag)?.content ?? new Uint8Array()).map((subtree) => {
      const [base] = derElements(subtree.content);
      return base!.tag === 0x82 ? `dns:${new TextDecoder().decode(base!.content)}` : base!.tag === 0x87 ? `ip:${Buffer.from(base!.content).toString("hex")}` : `tag ${base!.tag}`;
    });
  return { critical: extension.critical, permitted: subtrees(0xa0), excluded: subtrees(0xa1) };
}

describe("a platform-made Issuing CA's name constraints", () => {
  test("are its permitted name rules, critical, as dNSName subtrees, with no IP address permitted", async () => {
    const ca = await createCa({ ...NEW_CA, permittedNames: { exact: ["app.corp.example", "*.svc.corp.example"], zones: ["internal.acme"] } });

    const [issuing, root] = (await chainOf(ca)).certificates;
    expect(nameConstraintsOf(issuing!)).toEqual({
      critical: true,
      permitted: ["dns:app.corp.example", "dns:svc.corp.example", "dns:internal.acme"],
      excluded: ["ip:0000000000000000", `ip:${"00".repeat(32)}`],
    });
    expect(nameConstraintsOf(root!)).toBeNull();
    expect(await signedBy(issuing!, root!)).toBe(true);
  });

  test("stay as they were made when the rules change", async () => {
    const ca = await createCa();
    const before = (await chainOf(ca)).certificates[0]!;
    await h.api(issuingCaPath(ca), { cookie: org.cookie, method: "PATCH", body: { permittedNames: { exact: [], zones: ["lab.acme"] } } });

    const after = (await chainOf(ca)).certificates[0]!;
    expect(after.equal(before)).toBe(true);
    expect(nameConstraintsOf(after)!.permitted).toEqual(["dns:internal.acme"]);
  });
});

/** Adds an Issuing CA under the Private CA's root; the answer as it came. */
const addIssuingCa = (ca: { id: string }, body: Record<string, unknown>, cookie = org.cookie, orgId = org.orgId) => h.api(`${cas(orgId)}/${ca.id}/issuing-cas`, { cookie, body });

const DEVICES = { subject: "CN=Acme Devices, O=Acme", permittedNames: { exact: ["vpn.corp.example"], zones: ["devices.acme"] }, validity: { maximumDays: 90, defaultDays: 30 } };

/** The key of a certificate, as bytes to compare. */
const keyOf = (cert: x509.X509Certificate) => Buffer.from(cert.publicKey.rawData).toString("hex");

describe("adding an Issuing CA under a platform-made root", () => {
  test("makes one with its own key, signed by the root with pathLen 0 and its rules as name constraints, listed with the Private CA", async () => {
    const ca = await createCa();

    const added = await addIssuingCa(ca, DEVICES);

    expect(added.status).toBe(201);
    expect(added.body).toMatchObject({ subject: "CN=Acme Devices, O=Acme", status: "active", permittedNames: DEVICES.permittedNames, validity: DEVICES.validity });
    const listed = (await h.api(`${cas()}/${ca.id}`, { cookie: org.cookie })).body as PrivateCa;
    expect(listed.issuingCas.map((i) => i.subject)).toEqual(["CN=Acme Internal TLS, O=Acme", "CN=Acme Devices, O=Acme"]);
    expect(listed.issuingCas[1]).toEqual(added.body);

    const [devices, root, ...rest] = (await chainOf({ id: ca.id, issuing: added.body })).certificates;
    expect(rest).toEqual([]);
    const [first] = (await chainOf(ca)).certificates;
    const [onlyRoot, ...more] = (await rootOf(ca.id)).certificates;
    expect(more).toEqual([]);
    expect(root!.equal(onlyRoot!)).toBe(true);
    expect(await signedBy(devices!, root!)).toBe(true);
    expect(devices!.issuer).toBe(root!.subject);
    expect(devices!.subject).toBe("CN=Acme Devices, O=Acme");
    expect(new Set([keyOf(devices!), keyOf(root!), keyOf(first!)]).size).toBe(3);
    expect(devices!.getExtension(x509.BasicConstraintsExtension)).toMatchObject({ ca: true, pathLength: 0, critical: true });
    expect(nameConstraintsOf(devices!)).toEqual({ critical: true, permitted: ["dns:vpn.corp.example", "dns:devices.acme"], excluded: ["ip:0000000000000000", `ip:${"00".repeat(32)}`] });
    expect(devices!.notBefore.toISOString()).toBe("2026-01-01T00:00:00.000Z");
    expect(added.body.notAfter).toBe(devices!.notAfter.toISOString());
  });

  test("is valid until the root ends unless a shorter lifetime is asked, and never past the root", async () => {
    const ca = await createCa({ ...NEW_CA, lifetimeYears: 5 });

    const until = async (subject: string, lifetimeYears?: number) => (await addIssuingCa(ca, { ...DEVICES, subject, ...(lifetimeYears && { lifetimeYears }) })).body.notAfter;

    expect(await until("CN=Until the root")).toBe(ca.root!.notAfter);
    expect(await until("CN=Two years", 2)).toBe("2028-01-01T00:00:00.000Z");
    expect(await until("CN=Longer than the root", 20)).toBe(ca.root!.notAfter);
  });

  test("is an Audit Event naming the Issuing CA", async () => {
    const ca = await createCa();

    const added = await addIssuingCa(ca, DEVICES);

    const [devices] = (await chainOf({ id: ca.id, issuing: added.body })).certificates;
    expect((await auditOf()).filter((e) => e.action === "private_ca.issuing_ca_added")).toMatchObject([
      {
        target: { type: "private_ca", id: ca.id },
        detail: {
          name: "Internal TLS",
          issuingCa: { id: added.body.id, subject: "CN=Acme Devices, O=Acme", notAfter: added.body.notAfter, permittedNames: DEVICES.permittedNames, validity: DEVICES.validity, serial: devices!.serialNumber },
        },
      },
    ]);
  });

  test("refuses a subject another Issuing CA of the Private CA has, but not one under another Private CA", async () => {
    const ca = await createCa();
    const other = await createCa({ ...NEW_CA, name: "Other" });

    for (const subject of ["CN=Acme Internal TLS, O=Acme", "CN=Acme Internal TLS,O=Acme"]) {
      const res = await addIssuingCa(ca, { ...DEVICES, subject });
      expect(res.status).toBe(422);
      expect(res.body.error).toContain("CN=Acme Internal TLS");
    }
    expect((await addIssuingCa(ca, DEVICES)).status).toBe(201);
    expect((await addIssuingCa(ca, DEVICES)).status).toBe(422);
    expect((await addIssuingCa(other, DEVICES)).status).toBe(201);

    expect(((await h.api(`${cas()}/${ca.id}`, { cookie: org.cookie })).body as PrivateCa).issuingCas).toHaveLength(2);
    expect((await auditOf()).filter((e) => e.action === "private_ca.issuing_ca_added")).toHaveLength(2);
  });

  test("refuses what could not be one: no common name, no rules, a default above the maximum", async () => {
    const ca = await createCa();

    expect((await addIssuingCa(ca, { ...DEVICES, subject: "O=Acme" })).status).toBe(400);
    expect((await addIssuingCa(ca, { ...DEVICES, permittedNames: { exact: [], zones: [] } })).status).toBe(400);
    expect((await addIssuingCa(ca, { ...DEVICES, validity: { maximumDays: 30, defaultDays: 90 } })).status).toBe(422);
    expect(((await h.api(`${cas()}/${ca.id}`, { cookie: org.cookie })).body as PrivateCa).issuingCas).toHaveLength(1);
  });

  test("only an Organization Administrator may, and only under the Organization's own Private CAs", async () => {
    const ca = await createCa();
    const globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");

    for (const role of ["member", "approver"]) {
      const cookie = await join(`${role}@acme.test`, role);
      expect((await addIssuingCa(ca, DEVICES, cookie)).status).toBe(403);
    }
    expect((await addIssuingCa(ca, DEVICES, globex.cookie, globex.orgId)).status).toBe(404);
    expect((await addIssuingCa({ id: "not-an-id" }, DEVICES)).status).toBe(404);

    expect(((await h.api(`${cas()}/${ca.id}`, { cookie: org.cookie })).body as PrivateCa).issuingCas).toHaveLength(1);
    expect((await auditOf()).filter((e) => e.action === "private_ca.issuing_ca_added")).toEqual([]);
  });

  test("an Issuing CA is found only under its own Private CA", async () => {
    const ca = await createCa();
    const other = await createCa({ ...NEW_CA, name: "Other" });
    const misplaced = { id: other.id, issuing: ca.issuing };

    expect((await chainOf(misplaced)).status).toBe(404);
    expect((await h.api(issuingCaPath(misplaced), { cookie: org.cookie, method: "PATCH", body: { validity: { maximumDays: 30, defaultDays: 30 } } })).status).toBe(404);
  });
});

describe("who may see and create Private CAs", () => {
  test.each(["member", "approver"])("a %s lists them and downloads their chains, and may not create one", async (role) => {
    const ca = await createCa();
    const cookie = await join(`${role}@acme.test`, role);

    const listed = await h.api(cas(), { cookie });
    expect(listed.status).toBe(200);
    expect(listed.body.items.map((i: { id: string }) => i.id)).toEqual([ca.id]);
    expect((await chainOf(ca, cookie)).certificates).toHaveLength(2);

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
    expect((await chainOf(theirs)).status).toBe(404);
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

const fromCa = (issuingCaId: string) => ({ issuer: { kind: "private_ca", issuingCaId } });

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
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.internal.acme", "*.svc.internal.acme"])), ...fromCa(ca.issuing.id) } });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ issuer: { kind: "private_ca", issuingCa: { id: ca.issuing.id, subject: "CN=Acme Internal TLS, O=Acme" }, privateCa: { id: ca.id, name: "Internal TLS" } }, acmeCaId: null, approval: { status: "not_required" } });

    const mc = await ended(created.body.id);
    expect(mc.issuance).toMatchObject({ status: "succeeded", failure: null });
    expect(mc.currentCertificate).toMatchObject({ ca: "Internal TLS", issuingCaId: ca.issuing.id, acmeCaId: null, acmeAccountId: null, names: ["app.internal.acme", "*.svc.internal.acme"] });

    const [leaf, issuing, root, ...rest] = await downloaded(mc.id);
    expect(rest).toEqual([]);
    const [caIssuing, caRoot] = (await chainOf(ca)).certificates;
    expect(issuing!.equal(caIssuing!)).toBe(true);
    expect(root!.equal(caRoot!)).toBe(true);
    expect(await signedBy(leaf!, issuing!)).toBe(true);
    expect(await signedBy(issuing!, root!)).toBe(true);
    const path = await new x509.X509ChainBuilder({ certificates: [issuing!, root!] }).build(leaf!);
    expect(path.map((c) => c.subject)).toEqual([leaf!.subject, issuing!.subject, root!.subject]);
  });

  test("the Certificate is a TLS server certificate for the approved names, with a 20-byte random serial", async () => {
    const ca = await createCa();
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.internal.acme", "api.internal.acme"])), ...fromCa(ca.issuing.id) } });
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

    const other = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["other.internal.acme"])), ...fromCa(ca.issuing.id) } });
    expect((await ended(other.body.id)).currentCertificate.serial).not.toBe(leaf!.serialNumber.toUpperCase());
  });

  test("a name too long for a common name is left out of the subject, and only in the subject alternative names, then critical", async () => {
    const ca = await createCa();
    const long = `${"a".repeat(60)}.internal.acme`;
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request([long, "app.internal.acme"])), ...fromCa(ca.issuing.id) } });
    const mc = await ended(created.body.id);

    const [leaf] = await downloaded(mc.id, "leaf");
    expect(leaf!.subject).toBe("CN=app.internal.acme");
    const [onlyLong] = await downloaded((await ended((await h.api(mcs(), { cookie: org.cookie, body: { ...(await request([long])), ...fromCa(ca.issuing.id) } })).body.id)).id, "leaf");
    expect(onlyLong!.subject).toBe("");
    expect(onlyLong!.getExtension(x509.SubjectAlternativeNameExtension)).toMatchObject({ critical: true });
  });

  test("a CSR that asks for clientAuth gets it besides serverAuth", async () => {
    const ca = await createCa();
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await requestWithUsages(["app.internal.acme"], [x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth])), ...fromCa(ca.issuing.id) } });
    const mc = await ended(created.body.id);

    const [leaf] = await downloaded(mc.id, "leaf");
    expect(leaf!.getExtension(x509.ExtendedKeyUsageExtension)!.usages).toEqual([x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth]);
  });

  test("its Issuance is audited with the existing actions, the issuer in their detail", async () => {
    const ca = await createCa();
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.internal.acme"])), ...fromCa(ca.issuing.id) } });
    await ended(created.body.id);

    const events = (await auditOf()).filter((e) => e.target?.id === created.body.id);
    const issuer = { kind: "private_ca", issuingCaId: ca.issuing.id };
    expect(events.find((e) => e.action === "managed_certificate.created")!.detail).toMatchObject({ issuer });
    expect(events.find((e) => e.action === "issuance.started")!.detail).toMatchObject({ issuer });
    expect(events.find((e) => e.action === "issuance.succeeded")!.detail).toMatchObject({ issuer });
  });
});

describe("two Issuing CAs under one root with different rules", () => {
  /** The Private CA with its first Issuing CA for internal.acme (397 days at most) and a second for devices.acme (90 days at most). */
  async function twoUnderOneRoot() {
    const ca = await createCa();
    const added = await addIssuingCa(ca, DEVICES);
    expect(added.status).toBe(201);
    return { ca, tls: ca.issuing, devices: added.body as IssuingCa };
  }

  test("each issues for its own names, signed with its own key, and the chain is that Issuing CA then the root", async () => {
    const { ca, tls, devices } = await twoUnderOneRoot();
    const [tlsCert, root] = (await chainOf({ id: ca.id, issuing: tls })).certificates;
    const [devicesCert] = (await chainOf({ id: ca.id, issuing: devices })).certificates;

    for (const [issuing, issuingCert, name] of [[tls, tlsCert, "app.internal.acme"], [devices, devicesCert, "laptop-1.devices.acme"]] as const) {
      const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request([name])), ...fromCa(issuing.id) } });
      expect(created.status).toBe(201);
      expect(created.body.issuer).toEqual({ kind: "private_ca", issuingCa: { id: issuing.id, subject: issuing.subject }, privateCa: { id: ca.id, name: "Internal TLS" } });
      const mc = await ended(created.body.id);
      expect(mc.issuance.status).toBe("succeeded");
      expect(mc.currentCertificate.issuingCaId).toBe(issuing.id);

      const [leaf, chainIssuing, chainRoot, ...rest] = await downloaded(mc.id);
      expect(rest).toEqual([]);
      expect(chainIssuing!.equal(issuingCert!)).toBe(true);
      expect(chainRoot!.equal(root!)).toBe(true);
      expect(await signedBy(leaf!, issuingCert!)).toBe(true);
      expect(leaf!.issuer).toBe(issuing.subject);
    }
  });

  test("a Managed Certificate's names and validity are checked against its own Issuing CA when it is created or proposed", async () => {
    const { tls, devices } = await twoUnderOneRoot();
    const member = await join("member@acme.test", "member");

    for (const cookie of [org.cookie, member]) {
      const wrongNames = await h.api(mcs(), { cookie, body: { ...(await request(["app.internal.acme"])), ...fromCa(devices.id) } });
      expect(wrongNames.status).toBe(422);
      expect(wrongNames.body.error).toContain("Acme Devices");
      const tooLong = await h.api(mcs(), { cookie, body: { ...(await request(["laptop-1.devices.acme"])), ...fromCa(devices.id), validityDays: 200 } });
      expect(tooLong.status).toBe(422);
      expect(tooLong.body.error).toContain("90 days");
      expect((await h.api(mcs(), { cookie, body: { ...(await request(["app.internal.acme"])), ...fromCa(tls.id), validityDays: 200 } })).status).toBe(201);
    }
  });

  test("a Name Change is checked against the Managed Certificate's own Issuing CA", async () => {
    const { devices } = await twoUnderOneRoot();
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["laptop-1.devices.acme"])), ...fromCa(devices.id) } });
    await ended(created.body.id);

    const outside = await request(["laptop-1.devices.acme", "app.internal.acme"]);
    const refused = await h.api(`${mcs()}/${created.body.id}/name-change`, { cookie: org.cookie, body: { names: outside.names, csr: outside.csr } });
    expect(refused.status).toBe(422);
    expect(refused.body.error).toContain("app.internal.acme");
    const inside = await request(["laptop-1.devices.acme", "laptop-2.devices.acme"]);
    expect((await h.api(`${mcs()}/${created.body.id}/name-change`, { cookie: org.cookie, body: { names: inside.names, csr: inside.csr, validityDays: 91 } })).status).toBe(422);
    expect((await h.api(`${mcs()}/${created.body.id}/name-change`, { cookie: org.cookie, body: { names: inside.names, csr: inside.csr, validityDays: 90 } })).status).toBe(201);
  });

  test("changing one's rules or validity leaves the other's as it was", async () => {
    const { ca, tls, devices } = await twoUnderOneRoot();

    const res = await h.api(issuingCaPath({ id: ca.id, issuing: devices }), { cookie: org.cookie, method: "PATCH", body: { permittedNames: { exact: [], zones: ["lab.acme"] }, validity: { maximumDays: 30, defaultDays: 7 } } });

    expect(res.status).toBe(200);
    const listed = ((await h.api(`${cas()}/${ca.id}`, { cookie: org.cookie })).body as PrivateCa).issuingCas;
    expect(listed.map((i) => [i.id, i.permittedNames, i.validity])).toEqual([
      [tls.id, NEW_CA.permittedNames, { maximumDays: 397, defaultDays: 397 }],
      [devices.id, { exact: [], zones: ["lab.acme"] }, { maximumDays: 30, defaultDays: 7 }],
    ]);
    expect((await auditOf()).find((e) => e.action === "private_ca.updated")!.detail.issuingCa).toEqual({ id: devices.id, subject: "CN=Acme Devices, O=Acme" });
  });
});

describe("proposing a Managed Certificate from a Private CA", () => {
  test("a Member proposes one, an Approver sees which Private CA it is and approves it, and only then is it issued", async () => {
    const ca = await createCa();
    const member = await join("member@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");

    const proposed = await h.api(mcs(), { cookie: member, body: { ...(await request(["app.internal.acme"])), ...fromCa(ca.issuing.id) } });
    expect(proposed.status).toBe(201);
    expect(proposed.body).toMatchObject({ approval: { status: "pending" }, issuance: null });

    const queue = await h.api(`/api/organizations/${org.orgId}/approvals`, { cookie: approver });
    expect(queue.body.items).toMatchObject([{ id: proposed.body.id, issuer: { kind: "private_ca", issuingCa: { id: ca.issuing.id, subject: "CN=Acme Internal TLS, O=Acme" }, privateCa: { id: ca.id, name: "Internal TLS" } } }]);
    expect((await auditOf()).find((e) => e.action === "managed_certificate.proposed")!.detail).toMatchObject({ issuer: { kind: "private_ca", issuingCaId: ca.issuing.id } });

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

    const res = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.internal.acme"])), ...fromCa(theirs.issuing.id) } });

    expect(res.status).toBe(422);
    expect((await h.api(mcs(), { cookie: org.cookie })).body.items).toEqual([]);
    expect((await h.api(mcs(globex.orgId), { cookie: globex.cookie })).body.items).toEqual([]);
  });

  test("not one that does not exist, and not both a Private CA and an ACME CA", async () => {
    const ca = await createCa();
    const body = await request(["app.internal.acme"]);

    expect((await h.api(mcs(), { cookie: org.cookie, body: { ...body, ...fromCa("00000000-0000-0000-0000-000000000000") } })).status).toBe(422);
    expect((await h.api(mcs(), { cookie: org.cookie, body: { ...body, ...fromCa("not-an-id") } })).status).toBe(422);
    expect((await h.api(mcs(), { cookie: org.cookie, body: { ...body, ...fromCa(ca.issuing.id), acmeCaId: "letsencrypt-staging" } })).status).toBe(400);
  });
});

describe("a Private CA's permitted name rules", () => {
  test("are set when it is created, normalised and without repeats, and shown to everyone in the Organization", async () => {
    const ca = await createCa({ ...NEW_CA, permittedNames: { exact: ["App.Corp.Example.", "*.svc.corp.example", "app.corp.example"], zones: ["Internal.Acme"] } });

    const rules = { exact: ["app.corp.example", "*.svc.corp.example"], zones: ["internal.acme"] };
    expect(ca.issuing.permittedNames).toEqual(rules);
    const member = await join("member@acme.test", "member");
    expect((await h.api(`${cas()}/${ca.id}`, { cookie: member })).body.issuingCas[0].permittedNames).toEqual(rules);
    expect((await h.api(cas(), { cookie: member })).body.items[0].issuingCas[0].permittedNames).toEqual(rules);
    expect((await auditOf()).find((e) => e.action === "private_ca.created")!.detail.permittedNames).toEqual(rules);
  });

  test("an Organization Administrator changes them later, for what is issued from then on, as an Audit Event", async () => {
    const ca = await createCa();
    const res = await h.api(issuingCaPath(ca), { cookie: org.cookie, method: "PATCH", body: { permittedNames: { exact: ["App.Corp.Example"], zones: ["internal.acme", "lab.acme"] } } });

    expect(res.status).toBe(200);
    const rules = { exact: ["app.corp.example"], zones: ["internal.acme", "lab.acme"] };
    expect(res.body.permittedNames).toEqual(rules);
    expect((await h.api(`${cas()}/${ca.id}`, { cookie: org.cookie })).body.issuingCas[0].permittedNames).toEqual(rules);
    expect((await auditOf()).filter((e) => e.action === "private_ca.updated")).toMatchObject([
      { target: { type: "private_ca", id: ca.id }, detail: { permittedNames: { from: { exact: [], zones: ["internal.acme"] }, to: rules } } },
    ]);

    expect((await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.corp.example", "x.lab.acme"])), ...fromCa(ca.issuing.id) } })).status).toBe(201);
  });

  test("only an Organization Administrator may change them, and only for the Organization's own Private CAs, and never to none", async () => {
    const ca = await createCa();
    const globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    const change = { permittedNames: { exact: [], zones: ["other.acme"] } };

    for (const role of ["member", "approver"]) {
      const cookie = await join(`${role}@acme.test`, role);
      expect((await h.api(issuingCaPath(ca), { cookie, method: "PATCH", body: change })).status).toBe(403);
    }
    expect((await h.api(issuingCaPath(ca, globex.orgId), { cookie: globex.cookie, method: "PATCH", body: change })).status).toBe(404);
    expect((await h.api(issuingCaPath(ca), { cookie: org.cookie, method: "PATCH", body: { permittedNames: { exact: [], zones: [] } } })).status).toBe(400);

    expect((await h.api(`${cas()}/${ca.id}`, { cookie: org.cookie })).body.issuingCas[0].permittedNames).toEqual(NEW_CA.permittedNames);
    expect((await auditOf()).filter((e) => e.action === "private_ca.updated")).toEqual([]);
  });

  test("must have at least one rule, each a name that could be issued for, and a zone is never a wildcard", async () => {
    for (const permittedNames of [{ exact: [], zones: [] }, { exact: ["10.0.0.1"], zones: [] }, { exact: ["not a name"], zones: [] }, { exact: [], zones: ["*.internal.acme"] }]) {
      const res = await h.api(cas(), { cookie: org.cookie, body: { ...NEW_CA, permittedNames } });
      expect(res.status).toBe(400);
    }
    expect((await h.api(cas(), { cookie: org.cookie })).body.items).toEqual([]);
  });
});

describe("names outside a Private CA's permitted name rules", () => {
  const RULES = { exact: ["app.corp.example", "*.svc.corp.example"], zones: ["internal.acme"] };

  test("are refused when an Organization Administrator creates a Managed Certificate, naming them, and nothing is created", async () => {
    const ca = await createCa({ ...NEW_CA, permittedNames: RULES });

    const res = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.internal.acme", "db.corp.example", "*.corp.example", "*.corp.acme"])), ...fromCa(ca.issuing.id) } });

    expect(res.status).toBe(422);
    expect(res.body.error).toContain("db.corp.example, *.corp.example, *.corp.acme");
    expect(res.body.error).not.toContain("app.internal.acme");
    expect((await h.api(mcs(), { cookie: org.cookie })).body.items).toEqual([]);
  });

  test("are refused when a Member proposes one, so no Approver sees it", async () => {
    const ca = await createCa({ ...NEW_CA, permittedNames: RULES });
    const member = await join("member@acme.test", "member");

    const res = await h.api(mcs(), { cookie: member, body: { ...(await request(["other.example"])), ...fromCa(ca.issuing.id) } });

    expect(res.status).toBe(422);
    expect(res.body.error).toContain("other.example");
    expect((await h.api(`/api/organizations/${org.orgId}/approvals`, { cookie: org.cookie })).body.items).toEqual([]);
  });

  test("are refused when an Organization Administrator changes a Managed Certificate's names, or an Owner proposes the change", async () => {
    const ca = await createCa({ ...NEW_CA, permittedNames: RULES });
    const member = await join("member@acme.test", "member");
    const memberId = (await h.api("/api/me", { cookie: member })).body.user.id;
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.internal.acme"])), ...fromCa(ca.issuing.id), owners: [{ type: "user", id: memberId }] } });
    await ended(created.body.id);
    const { csr } = await request(["app.internal.acme", "other.example"]);

    for (const cookie of [org.cookie, member]) {
      const res = await h.api(`${mcs()}/${created.body.id}/name-change`, { cookie, body: { names: ["app.internal.acme", "other.example"], csr } });
      expect(res.status).toBe(422);
      expect(res.body.error).toContain("other.example");
    }
    const mc = await h.api(`${mcs()}/${created.body.id}`, { cookie: org.cookie });
    expect(mc.body).toMatchObject({ names: ["app.internal.acme"], pendingNameChange: null });

    const inside = await request(["app.internal.acme", "api.internal.acme"]);
    expect((await h.api(`${mcs()}/${created.body.id}/name-change`, { cookie: org.cookie, body: { names: inside.names, csr: inside.csr } })).status).toBe(201);
  });

  test("fail the Issuance when the rules changed after they were proposed, and nothing is issued", async () => {
    const ca = await createCa({ ...NEW_CA, permittedNames: { exact: [], zones: ["internal.acme", "lab.acme"] } });
    const member = await join("member@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");
    const proposed = await h.api(mcs(), { cookie: member, body: { ...(await request(["app.internal.acme", "app.lab.acme"])), ...fromCa(ca.issuing.id) } });
    expect(proposed.status).toBe(201);
    expect((await h.api(issuingCaPath(ca), { cookie: org.cookie, method: "PATCH", body: { permittedNames: { exact: [], zones: ["internal.acme"] } } })).status).toBe(200);

    expect((await h.api(`${mcs()}/${proposed.body.id}/approve`, { cookie: approver, body: {} })).status).toBe(200);

    const mc = await ended(proposed.body.id);
    expect(mc.issuance).toMatchObject({ status: "failed", failure: { code: "name_not_permitted" } });
    expect(mc.issuance.failure.message).toContain("app.lab.acme");
    expect(mc.issuance.failure.message).not.toContain("app.internal.acme");
    expect(mc.currentCertificate).toBeNull();
  });

  test("exact names and every name in a zone, wildcards included, are permitted", async () => {
    const ca = await createCa({ ...NEW_CA, permittedNames: RULES });
    const names = ["app.corp.example", "*.svc.corp.example", "internal.acme", "a.b.internal.acme", "*.internal.acme", "*.x.internal.acme"];

    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(names)), ...fromCa(ca.issuing.id) } });

    expect(created.status).toBe(201);
    expect((await ended(created.body.id)).issuance.status).toBe("succeeded");
  });
});

describe("a Private CA's validity limits", () => {
  test("are 397 days for both its maximum and its default unless set, and shown to everyone in the Organization", async () => {
    const ca = await createCa();

    expect(ca.issuing).toMatchObject({ validity: { maximumDays: 397, defaultDays: 397 } });
    const member = await join("member@acme.test", "member");
    expect((await h.api(`${cas()}/${ca.id}`, { cookie: member })).body.issuingCas[0].validity).toEqual({ maximumDays: 397, defaultDays: 397 });
  });

  test("are set when it is created, as an Audit Event, and a default above the maximum is refused", async () => {
    const ca = await createCa({ ...NEW_CA, validity: { maximumDays: 825, defaultDays: 90 } });

    expect(ca.issuing).toMatchObject({ validity: { maximumDays: 825, defaultDays: 90 } });
    expect((await auditOf()).find((e) => e.action === "private_ca.created")!.detail.validity).toEqual({ maximumDays: 825, defaultDays: 90 });

    const refused = await h.api(cas(), { cookie: org.cookie, body: { ...NEW_CA, name: "Too long", validity: { maximumDays: 30, defaultDays: 90 } } });
    expect(refused.status).toBe(422);
    expect((await h.api(cas(), { cookie: org.cookie })).body.items).toHaveLength(1);
  });

  test("may be at most 3650 days (ten years), whatever the Issuing CA's lifetime", async () => {
    const tenYears = await createCa({ ...NEW_CA, validity: { maximumDays: 3650, defaultDays: 3650 } });
    expect(tenYears.issuing.validity).toEqual({ maximumDays: 3650, defaultDays: 3650 });

    expect((await h.api(cas(), { cookie: org.cookie, body: { ...NEW_CA, name: "Longer", validity: { maximumDays: 3651, defaultDays: 397 } } })).status).toBe(400);
    expect((await h.api(issuingCaPath(tenYears), { cookie: org.cookie, method: "PATCH", body: { validity: { maximumDays: 3651, defaultDays: 3651 } } })).status).toBe(400);
    expect((await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.internal.acme"])), ...fromCa(tenYears.issuing.id), validityDays: 3651 } })).status).toBe(400);
    expect((await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.internal.acme"])), ...fromCa(tenYears.issuing.id), validityDays: 3650 } })).status).toBe(201);
  });

  test("an Organization Administrator changes them later, each field changed in the Audit Event, and a default above the maximum is refused", async () => {
    const ca = await createCa();
    const patch = (body: unknown, cookie = org.cookie) => h.api(issuingCaPath(ca), { cookie, method: "PATCH", body });

    const res = await patch({ validity: { maximumDays: 825, defaultDays: 397 } });
    expect(res.status).toBe(200);
    expect(res.body.validity).toEqual({ maximumDays: 825, defaultDays: 397 });
    expect((await auditOf()).filter((e) => e.action === "private_ca.updated").map((e) => e.detail)).toEqual([
      { name: "Internal TLS", issuingCa: { id: ca.issuing.id, subject: "CN=Acme Internal TLS, O=Acme" }, validity: { maximumDays: { from: 397, to: 825 } } },
    ]);

    expect((await patch({ validity: { maximumDays: 30, defaultDays: 90 } })).status).toBe(422);
    expect((await patch({ validity: { maximumDays: 825, defaultDays: 397 } })).status).toBe(200);
    expect((await patch({ validity: { maximumDays: 0, defaultDays: 0 } })).status).toBe(400);
    const member = await join("member@acme.test", "member");
    expect((await patch({ validity: { maximumDays: 90, defaultDays: 90 } }, member)).status).toBe(403);

    expect((await h.api(`${cas()}/${ca.id}`, { cookie: org.cookie })).body.issuingCas[0].validity).toEqual({ maximumDays: 825, defaultDays: 397 });
    expect((await auditOf()).filter((e) => e.action === "private_ca.updated")).toHaveLength(1);
  });

  test("change with the permitted name rules in one Audit Event", async () => {
    const ca = await createCa();

    const res = await h.api(issuingCaPath(ca), { cookie: org.cookie, method: "PATCH", body: { permittedNames: { exact: [], zones: ["lab.acme"] }, validity: { maximumDays: 397, defaultDays: 30 } } });

    expect(res.status).toBe(200);
    expect((await auditOf()).filter((e) => e.action === "private_ca.updated").map((e) => e.detail)).toEqual([
      { name: "Internal TLS", issuingCa: { id: ca.issuing.id, subject: "CN=Acme Internal TLS, O=Acme" }, permittedNames: { from: NEW_CA.permittedNames, to: { exact: [], zones: ["lab.acme"] } }, validity: { defaultDays: { from: 397, to: 30 } } },
    ]);
  });
});

describe("the validity of a Certificate from a Private CA", () => {
  const JAN_1 = Date.parse("2026-01-01T00:00:00Z");
  const days = (n: number) => new Date(JAN_1 + n * 86_400_000).toISOString();
  const leafOf = async (body: Record<string, unknown>) => {
    const created = await h.api(mcs(), { cookie: org.cookie, body });
    expect(created.status).toBe(201);
    const mc = await ended(created.body.id);
    expect(mc.issuance.status).toBe("succeeded");
    return { mc, leaf: (await downloaded(mc.id, "leaf"))[0]! };
  };
  const onCa = (issuingCaId: string, validityDays?: number) => ({ issuer: { kind: "private_ca", issuingCaId }, ...(validityDays && { validityDays }) });

  test("is the Private CA's default when the Managed Certificate chooses none", async () => {
    const ca = await createCa({ ...NEW_CA, validity: { maximumDays: 397, defaultDays: 90 } });

    const { mc, leaf } = await leafOf({ ...(await request(["app.internal.acme"])), ...onCa(ca.issuing.id) });

    expect(mc.validityDays).toBeNull();
    expect(leaf.notBefore.toISOString()).toBe(days(0));
    expect(leaf.notAfter.toISOString()).toBe(days(90));
  });

  test("is what the Managed Certificate chooses, at or below the maximum, which is shown and audited", async () => {
    const ca = await createCa();

    const { mc, leaf } = await leafOf({ ...(await request(["app.internal.acme"])), ...onCa(ca.issuing.id, 7) });

    expect(mc).toMatchObject({ issuer: { kind: "private_ca", issuingCa: { id: ca.issuing.id }, privateCa: { id: ca.id } }, validityDays: 7 });
    expect(leaf.notAfter.toISOString()).toBe(days(7));
    expect((await auditOf()).find((e) => e.action === "managed_certificate.created")!.detail).toMatchObject({ validityDays: 7 });
    expect((await leafOf({ ...(await request(["max.internal.acme"])), ...onCa(ca.issuing.id, 397) })).leaf.notAfter.toISOString()).toBe(days(397));
  });

  test("can be chosen only for a Managed Certificate issued from a Private CA", async () => {
    const res = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.example.com"])), issuer: { kind: "acme", acmeCaId: "letsencrypt-staging" }, validityDays: 30 } });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("Private CA");
    expect((await h.api(mcs(), { cookie: org.cookie })).body.items).toEqual([]);
  });

  test("above the Private CA's maximum is refused when a Managed Certificate is created or proposed, and nothing is created", async () => {
    const ca = await createCa({ ...NEW_CA, validity: { maximumDays: 90, defaultDays: 30 } });
    const member = await join("member@acme.test", "member");

    for (const cookie of [org.cookie, member]) {
      const res = await h.api(mcs(), { cookie, body: { ...(await request(["app.internal.acme"])), ...onCa(ca.issuing.id, 91) } });
      expect(res.status).toBe(422);
      expect(res.body.error).toContain("90 days");
    }
    expect((await h.api(mcs(), { cookie: org.cookie })).body.items).toEqual([]);
  });

  test("is the maximum when the maximum was lowered below what the Managed Certificate chose", async () => {
    const ca = await createCa();
    const member = await join("member@acme.test", "member");
    const proposed = await h.api(mcs(), { cookie: member, body: { ...(await request(["app.internal.acme"])), ...onCa(ca.issuing.id, 200) } });
    expect(proposed.status).toBe(201);
    expect((await h.api(issuingCaPath(ca), { cookie: org.cookie, method: "PATCH", body: { validity: { maximumDays: 100, defaultDays: 30 } } })).status).toBe(200);

    expect((await h.api(`${mcs()}/${proposed.body.id}/approve`, { cookie: org.cookie, body: {} })).status).toBe(200);

    const mc = await ended(proposed.body.id);
    expect(mc.issuance.status).toBe("succeeded");
    expect((await downloaded(mc.id, "leaf"))[0]!.notAfter.toISOString()).toBe(days(100));
  });

  test("never outlives the Issuing CA: it ends when the Issuing CA ends", async () => {
    const ca = await createCa({ ...NEW_CA, lifetimeYears: 1, validity: { maximumDays: 825, defaultDays: 825 } });

    const { leaf } = await leafOf({ ...(await request(["app.internal.acme"])), ...onCa(ca.issuing.id, 500) });

    expect(leaf.notAfter.toISOString()).toBe("2027-01-01T00:00:00.000Z");
    expect(leaf.notAfter.toISOString()).toBe(ca.issuing.notAfter);
  });

  test("is renewed under the Renewal Policy as any Certificate is: its days before the end, but not in the first tenth of its life", async () => {
    const ca = await createCa();
    const { mc } = await leafOf({ ...(await request(["app.internal.acme"])), ...onCa(ca.issuing.id, 10) });
    expect(mc.renewal).toMatchObject({ policy: { mode: "automatic", daysBeforeExpiry: 30 }, dueAt: days(1), dueBecause: "policy" });

    h.setNow(new Date(JAN_1 + 86_400_000 - 60_000));
    expect(await h.runRenewalScheduler()).toBe(0);
    h.setNow(new Date(days(1)));
    expect(await h.runRenewalScheduler()).toBe(1);

    const renewed = await ended(mc.id);
    expect(renewed.issuance).toMatchObject({ kind: "renewal", status: "succeeded" });
    expect(renewed.currentCertificate).toMatchObject({ notBefore: days(1), notAfter: days(11) });
  });
});


describe("a Name Change's validity", () => {
  const JAN_1 = Date.parse("2026-01-01T00:00:00Z");
  const days = (n: number) => new Date(JAN_1 + n * 86_400_000).toISOString();

  /** A Managed Certificate on the Private CA, issued, with the member as its Owner. */
  async function owned(ca: { issuing: { id: string } }, member: string, validityDays?: number) {
    const memberId = (await h.api("/api/me", { cookie: member })).body.user.id;
    const created = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.internal.acme"])), ...fromCa(ca.issuing.id), ...(validityDays && { validityDays }), owners: [{ type: "user", id: memberId }] } });
    expect(created.status).toBe(201);
    return ended(created.body.id);
  }
  const nameChange = async (id: string, cookie: string, extra: Record<string, unknown>) => {
    const { names, csr } = await request(["app.internal.acme", "api.internal.acme"]);
    return h.api(`${mcs()}/${id}/name-change`, { cookie, body: { names, csr, ...extra } });
  };

  test("an Owner proposes one with the names, an Approver sees it, and once approved it is the Managed Certificate's and the new Certificate's", async () => {
    const ca = await createCa();
    const member = await join("member@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");
    const mc = await owned(ca, member);

    const proposed = await nameChange(mc.id, member, { validityDays: 30 });
    expect(proposed.status).toBe(201);
    expect(proposed.body).toMatchObject({ validityDays: null, pendingNameChange: { names: ["app.internal.acme", "api.internal.acme"], validityDays: 30 } });
    const queue = await h.api(`/api/organizations/${org.orgId}/approvals`, { cookie: approver });
    expect(queue.body.nameChanges).toMatchObject([{ managedCertificateId: mc.id, validityDays: 30 }]);
    expect((await auditOf()).find((e) => e.action === "name_change.proposed")!.detail).toMatchObject({ validityDays: { from: null, to: 30 } });

    expect((await h.api(`${mcs()}/${mc.id}/name-change/approve`, { cookie: approver, body: {} })).status).toBe(200);

    const after = await ended(mc.id);
    expect(after).toMatchObject({ validityDays: 30, commonName: "app.internal.acme", issuance: { status: "succeeded" }, currentCertificate: { notBefore: days(0), notAfter: days(30) } });
    expect((await auditOf()).find((e) => e.action === "name_change.approved")!.detail).toMatchObject({ validityDays: { from: null, to: 30 } });
  });

  test("an Organization Administrator's applies at once; without one the validity stays as it was, and null goes back to the default", async () => {
    const ca = await createCa({ ...NEW_CA, validity: { maximumDays: 397, defaultDays: 90 } });
    const member = await join("member@acme.test", "member");
    const mc = await owned(ca, member, 14);

    expect((await nameChange(mc.id, org.cookie, {})).status).toBe(201);
    expect(await ended(mc.id)).toMatchObject({ validityDays: 14, currentCertificate: { notAfter: days(14) } });
    expect((await auditOf()).find((e) => e.action === "managed_certificate.names_changed")!.detail.validityDays).toBeUndefined();

    const { names, csr } = await request(["app.internal.acme"]);
    expect((await h.api(`${mcs()}/${mc.id}/name-change`, { cookie: org.cookie, body: { names, csr, validityDays: null } })).status).toBe(201);
    expect(await ended(mc.id)).toMatchObject({ validityDays: null, currentCertificate: { notAfter: days(90) } });
    expect((await auditOf()).find((e) => e.action === "managed_certificate.names_changed" && e.detail.validityDays)!.detail.validityDays).toEqual({ from: 14, to: null });
  });

  test("above the Private CA's maximum is refused, and so is one for a Managed Certificate from an ACME CA", async () => {
    const ca = await createCa({ ...NEW_CA, validity: { maximumDays: 90, defaultDays: 90 } });
    const member = await join("member@acme.test", "member");
    const mc = await owned(ca, member);

    for (const cookie of [org.cookie, member]) {
      const res = await nameChange(mc.id, cookie, { validityDays: 91 });
      expect(res.status).toBe(422);
      expect(res.body.error).toContain("90 days");
    }
    expect((await h.api(`${mcs()}/${mc.id}`, { cookie: org.cookie })).body).toMatchObject({ names: ["app.internal.acme"], validityDays: null, pendingNameChange: null });

    const acmeMc = await h.api(mcs(), { cookie: org.cookie, body: { ...(await request(["app.example.com"])), acmeCaId: "letsencrypt-staging" } });
    expect(acmeMc.status).toBe(201);
    await h.settleIssuances();
    const { names, csr } = await request(["app.example.com", "www.example.com"]);
    const refused = await h.api(`${mcs()}/${acmeMc.body.id}/name-change`, { cookie: org.cookie, body: { names, csr, validityDays: 30 } });
    expect(refused.status).toBe(400);
  });
});

// Kept last: the second harness shares the database with the first.
describe("where the Private CAs publish", () => {
  test("the list says the PKI base URL every Certificate names, and that the operator set it", async () => {
    const res = await h.api(cas(), { cookie: org.cookie });

    expect(res.status).toBe(200);
    expect(res.body.publication).toEqual({ baseUrl: PKI_BASE_URL, configured: true });
  });

  test("without PKI_BASE_URL it is the address the API is served at, and says it was not set", async () => {
    const unset = await createHarness({ pkiBaseURL: undefined });
    try {
      const op = await unset.createOperator("op2@platform.test", PASSWORD);
      const other = await unset.createOrgWithAdmin(op, "initech", "admin@initech.test");

      const res = await unset.api(cas(other.orgId), { cookie: other.cookie });

      expect(res.status).toBe(200);
      expect(res.body.publication).toEqual({ baseUrl: "http://localhost", configured: false });
    } finally {
      await unset.close();
    }
  });
});
