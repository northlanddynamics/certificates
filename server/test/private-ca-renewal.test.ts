// Renewal from a Private CA, and Key Custody: Agent with one. A Private CA offers no ACME Renewal Information, so a
// Managed Certificate on one renews by its Renewal Policy alone (its days before expiry, never in the first tenth of its
// life), and the scheduler asks it nothing. "Renew now" and a Name Change renew it as they do one from an ACME CA, and a
// Deployment's Agent obtains and deploys its Certificates with their chain as it does a public one. No Pebble and no
// DNS: the CA is the platform's own, with its keys in the (local) KMS; time is the harness's clock.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import acme from "acme-client";
import { createHash, createPublicKey } from "node:crypto";
import { TestAgent } from "./agent-double";
import { PASSWORD, createHarness, type Harness } from "./harness";

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
const days = (n: number) => new Date(JAN_1 + n * DAY).toISOString();

const api = (path: string, body?: unknown, method?: string, target = org) => h.api(`/api/organizations/${target.orgId}${path}`, { cookie: target.cookie, body, method });
const auditOf = async (target = org) => (await api("/audit-events", undefined, undefined, target)).body.items as { action: string; actor: any; target: any; detail: any }[];

const NEW_CA = { name: "Internal TLS", subject: "CN=Acme Internal TLS, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["internal.acme"] } };

/** A new Private CA with a platform-made root, and its first Issuing CA as `issuing`. */
async function createCa(target = org) {
  const res = await api("/private-cas", NEW_CA, undefined, target);
  expect(res.status).toBe(201);
  return { ...res.body, issuing: res.body.issuingCas[0] } as { id: string; issuing: { id: string; subject: string } };
}

/** The certificates of a PEM bundle, in order. */
const certificatesIn = (pem: string) => (pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map((one) => new x509.X509Certificate(one));

/** The root of the Private CA, as anyone in the Organization downloads it. */
async function rootOf(ca: { id: string }) {
  const res = await h.app.request(`http://localhost/api/organizations/${org.orgId}/private-cas/${ca.id}/chain`, { headers: { cookie: org.cookie } });
  expect(res.status).toBe(200);
  return certificatesIn(await res.text())[0]!;
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
  expect(res.status).toBe(200);
  expect(res.body.issuance.status).not.toBe("running");
  return res.body;
}

/** A Managed Certificate (Key Custody: Owner) on the Issuing CA, issued, valid for `validityDays`. */
async function issued(ca: { issuing: { id: string } }, validityDays: number, names = ["app.internal.acme"]) {
  const created = await api("/managed-certificates", { ...(await request(names)), issuer: { kind: "private_ca", issuingCaId: ca.issuing.id }, validityDays });
  expect(created.status).toBe(201);
  const mc = await ended(created.body.id);
  expect(mc.issuance.status).toBe("succeeded");
  return mc;
}

describe("automatic Renewal from a Private CA", () => {
  test("is by the Renewal Policy's days alone: the scheduler asks the Private CA for no renewal window", async () => {
    const ca = await createCa();
    const mc = await issued(ca, 90);
    // Due 30 days before it ends.
    expect(mc.renewal).toMatchObject({ policy: { mode: "automatic", daysBeforeExpiry: 30 }, dueAt: days(60), dueBecause: "policy", ari: null });

    h.setNow(new Date(JAN_1 + 60 * DAY - 60_000));
    expect(await h.runRenewalScheduler()).toBe(0);
    // Nothing was asked of the Private CA: there is nothing it said, and nothing to ask it again.
    expect((await api(`/managed-certificates/${mc.id}`)).body.renewal).toMatchObject({ dueAt: days(60), dueBecause: "policy", ari: null });

    h.setNow(new Date(days(60)));
    expect(await h.runRenewalScheduler()).toBe(1);
    const renewed = await ended(mc.id);
    expect(renewed.issuance).toMatchObject({ kind: "renewal", status: "succeeded" });
    expect(renewed.currentCertificate).toMatchObject({ issuingCaId: ca.issuing.id, notBefore: days(60), notAfter: days(150) });
    expect(renewed.renewal).toMatchObject({ dueAt: days(120), dueBecause: "policy", ari: null });
  });
});

describe("renewing from a Private CA by hand", () => {
  test("renewing now issues a new Certificate from the same Issuing CA for the stored CSR, and is the person's", async () => {
    const ca = await createCa();
    const mc = await issued(ca, 90);
    h.setNow(new Date(days(5)));

    const renewing = await api(`/managed-certificates/${mc.id}/renewals`, {}, "POST");
    expect(renewing.status).toBe(202);
    const renewed = await ended(mc.id);
    expect(renewed.issuance).toMatchObject({ id: renewing.body.id, kind: "renewal", status: "succeeded" });
    expect(renewed.currentCertificate).toMatchObject({ issuingCaId: ca.issuing.id, notBefore: days(5), notAfter: days(95) });
    expect(renewed.currentCertificate.fingerprint).not.toBe(mc.currentCertificate.fingerprint);
    expect((await auditOf()).filter((e) => e.action === "issuance.started").at(-1)).toMatchObject({
      actor: { email: "admin@acme.test" },
      detail: { renewal: "requested", issuer: { kind: "private_ca", issuingCaId: ca.issuing.id } },
    });
  });

  test("a Name Change is issued at once from the same Issuing CA for the new names", async () => {
    const ca = await createCa();
    const mc = await issued(ca, 90);
    h.setNow(new Date(days(5)));

    const changed = await api(`/managed-certificates/${mc.id}/name-change`, await request(["app.internal.acme", "api.internal.acme"]));
    expect(changed.status).toBe(201);
    const renewed = await ended(mc.id);
    expect(renewed.issuance).toMatchObject({ status: "succeeded" });
    expect(renewed.currentCertificate).toMatchObject({ issuingCaId: ca.issuing.id, names: ["app.internal.acme", "api.internal.acme"], notBefore: days(5), notAfter: days(95) });
  });
});

describe("a Deployment whose Agent holds the key, from a Private CA", () => {
  const INSTALL = "#!/usr/bin/env bash\ncp \"$CERT_FULLCHAIN_FILE\" /etc/ssl/site.pem\n";

  async function script() {
    const created = await api("/deployment-scripts", { name: "install", interpreter: "bash", content: INSTALL });
    expect(created.status).toBe(201);
    return created.body as { id: string };
  }
  /** The Agent takes its work, the Issuance that follows settles, and the Agent takes what that made. */
  async function untilDeployed(agent: TestAgent) {
    await agent.work();
    await h.settleIssuances();
    await agent.work();
  }
  const fingerprintOf = (cert: x509.X509Certificate) => createHash("sha256").update(Buffer.from(cert.rawData)).digest("hex");
  const spkiOf = (cert: x509.X509Certificate) => Buffer.from(cert.publicKey.rawData);
  const keySpki = (pem: string) => createPublicKey(pem).export({ type: "spki", format: "der" });

  test("the Agent makes the key, the Certificate is issued from the Issuing CA with no DCV, and the script is given it with its chain", async () => {
    const ca = await createCa();
    const agent = await TestAgent.registered(h, org.cookie, org.orgId, { hostName: "web-1" });
    const s = await script();

    const created = await api("/deployments", {
      agentId: agent.id,
      scriptId: s.id,
      names: ["app.internal.acme"],
      keyAlgorithm: "ecdsa-p256",
      issuer: { kind: "private_ca", issuingCaId: ca.issuing.id },
      validityDays: 30,
      renewalPolicy: { mode: "automatic", daysBeforeExpiry: 10 },
    });
    expect(created.status).toBe(201);
    const mcId = created.body.managedCertificateId;
    expect((await api(`/managed-certificates/${mcId}`)).body).toMatchObject({
      keyCustody: "agent",
      issuer: { kind: "private_ca", issuingCa: { id: ca.issuing.id }, privateCa: { id: ca.id } },
      environment: null,
      validityDays: 30,
    });
    expect((await auditOf()).find((e) => e.action === "managed_certificate.created")!.detail).toMatchObject({
      keyCustody: "agent",
      issuer: { kind: "private_ca", issuingCaId: ca.issuing.id },
      validityDays: 30,
    });

    // No ACME account and no DNS Provider: only the Private CA could have issued it.
    await untilDeployed(agent);
    expect(agent.executed.map((i) => i.type)).toEqual(["deployment.generate_key", "deployment.run"]);
    const mc = (await api(`/managed-certificates/${mcId}`)).body;
    expect(mc.issuance).toMatchObject({ status: "succeeded" });
    expect(mc.currentCertificate).toMatchObject({ issuingCaId: ca.issuing.id, notBefore: days(0), notAfter: days(30) });

    // The script is given the Certificate for the Agent's key and the Issuing CA above it, which chains to the root.
    const [run] = agent.deployed;
    const [leaf, issuing, ...rest] = certificatesIn(run!.item.payload.certificate.chainPem);
    expect(rest).toEqual([]);
    expect(fingerprintOf(leaf!)).toBe(mc.currentCertificate.fingerprint);
    expect(spkiOf(leaf!)).toEqual(keySpki(run!.keyPem!));
    expect(issuing!.subject).toBe(ca.issuing.subject);
    const root = await rootOf(ca);
    const path = await new x509.X509ChainBuilder({ certificates: [issuing!, root] }).build(leaf!);
    expect(path.map((c) => c.subject)).toEqual([leaf!.subject, issuing!.subject, root.subject]);
    expect(await leaf!.verify({ publicKey: issuing!.publicKey, signatureOnly: true })).toBe(true);
    expect(await issuing!.verify({ publicKey: root.publicKey, signatureOnly: true })).toBe(true);
    expect(await api(`/deployments/${created.body.id}`)).toMatchObject({ body: { state: "deployed", lastRun: { status: "succeeded" } } });
  });

  test("renews by its Renewal Policy: the Agent makes a new key and the new Certificate is deployed", async () => {
    const ca = await createCa();
    const agent = await TestAgent.registered(h, org.cookie, org.orgId, { hostName: "web-1" });
    const s = await script();
    const created = await api("/deployments", {
      agentId: agent.id,
      scriptId: s.id,
      names: ["app.internal.acme"],
      keyAlgorithm: "ecdsa-p256",
      issuer: { kind: "private_ca", issuingCaId: ca.issuing.id },
      validityDays: 30,
      renewalPolicy: { mode: "automatic", daysBeforeExpiry: 10 },
    });
    await untilDeployed(agent);
    const first = (await api(`/managed-certificates/${created.body.managedCertificateId}`)).body.currentCertificate;

    h.setNow(new Date(days(20)));
    expect(await h.runRenewalScheduler()).toBe(1);
    await untilDeployed(agent);

    const renewed = (await api(`/managed-certificates/${created.body.managedCertificateId}`)).body;
    expect(renewed.issuance).toMatchObject({ kind: "renewal", status: "succeeded" });
    expect(renewed.currentCertificate).toMatchObject({ issuingCaId: ca.issuing.id, notBefore: days(20), notAfter: days(50) });
    expect(renewed.renewal.ari).toBeNull();
    const [firstRun, renewalRun] = agent.deployed;
    const [renewedLeaf] = certificatesIn(renewalRun!.item.payload.certificate.chainPem);
    expect(fingerprintOf(renewedLeaf!)).toBe(renewed.currentCertificate.fingerprint);
    expect(spkiOf(renewedLeaf!)).toEqual(keySpki(renewalRun!.keyPem!));
    expect(spkiOf(renewedLeaf!)).not.toEqual(spkiOf(certificatesIn(firstRun!.item.payload.certificate.chainPem)[0]!));
    expect(renewed.currentCertificate.fingerprint).not.toBe(first.fingerprint);
  });

  test("is refused for names outside the Issuing CA's permitted names, and for another Organization's Issuing CA", async () => {
    const ca = await createCa();
    const theirs = await createCa(globex);
    const agent = await TestAgent.registered(h, org.cookie, org.orgId, { hostName: "web-1" });
    const s = await script();
    const setUp = (names: string[], issuingCaId: string) =>
      api("/deployments", { agentId: agent.id, scriptId: s.id, names, keyAlgorithm: "ecdsa-p256", issuer: { kind: "private_ca", issuingCaId } });

    const outside = await setUp(["app.example.com"], ca.issuing.id);
    expect(outside.status).toBe(422);
    expect(outside.body.error).toContain("app.example.com");
    expect((await setUp(["app.internal.acme"], theirs.issuing.id)).status).toBe(422);
    expect((await api("/deployments")).body.items).toEqual([]);
    expect((await api("/managed-certificates")).body.items).toEqual([]);
  });
});
