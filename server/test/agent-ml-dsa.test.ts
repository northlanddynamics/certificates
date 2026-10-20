// A Deployment's Agent makes the ML-DSA key and CSR for a Managed Certificate on an ML-DSA Private CA. The Go Agent's
// side is tested in agent/ (Seam B); here the platform's: it accepts the three ML-DSA algorithms for a Deployment on an
// ML-DSA Private CA and refuses them (and the other algorithms there) elsewhere, asks the Agent for the key, issues from
// the CSR that comes back, and has the Agent deploy the Certificate with its chain. The Agent here is a stand-in; a CSR
// the real Agent made is kept as a fixture, which the platform's CSR parser must accept, so that the two ends stay in step.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { createHash, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { parseCsr, type MlDsaKeyAlgorithm } from "../src/pki/csr";
import { TestAgent } from "./support/agent-double";
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

const api = (path: string, body?: unknown, method?: string) => h.api(`/api/organizations/${org.orgId}${path}`, { cookie: org.cookie, body, method });
const ML_DSA = ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"] as const satisfies readonly MlDsaKeyAlgorithm[];

describe("a CSR the real Agent made", () => {
  test.each([...ML_DSA])("is accepted by the CSR parser as %s with its names", async (algorithm) => {
    const pem = readFileSync(new URL(`./fixtures/agent/${algorithm}.csr.pem`, import.meta.url), "utf8");
    const parsed = await parseCsr(pem);
    expect(parsed.keyAlgorithm).toBe(algorithm);
    expect(parsed.names).toEqual(["app.example.test", "*.wild.example.test"]);
  });
});

describe("a Deployment on a Private CA", () => {
  const INSTALL = "#!/usr/bin/env bash\ncp \"$CERT_FULLCHAIN_FILE\" /etc/ssl/site.pem\n";
  const NEW_CA = { name: "Internal TLS", subject: "CN=Acme Internal TLS, O=Acme", lifetimeYears: 5, permittedNames: { exact: [], zones: ["internal.acme"] } };

  async function createCa(keyAlgorithm: string) {
    const res = await api("/private-cas", { ...NEW_CA, name: `Internal TLS ${keyAlgorithm}`, keyAlgorithm });
    expect(res.status).toBe(201);
    return { ...res.body, issuing: res.body.issuingCas[0] } as { id: string; issuing: { id: string; subject: string } };
  }
  /** The Organization's script, uploaded if it is not there yet. */
  async function script() {
    const existing = (await api("/deployment-scripts")).body.items[0];
    if (existing) return existing as { id: string };
    const created = await api("/deployment-scripts", { name: "install", interpreter: "bash", content: INSTALL });
    expect(created.status).toBe(201);
    return created.body as { id: string };
  }
  async function setUp(keyAlgorithm: string, ca: { issuing: { id: string } }, agent: TestAgent) {
    return api("/deployments", {
      agentId: agent.id,
      scriptId: (await script()).id,
      names: ["app.internal.acme"],
      keyAlgorithm,
      issuer: { kind: "private_ca", issuingCaId: ca.issuing.id },
      validityDays: 30,
      renewalPolicy: { mode: "automatic", daysBeforeExpiry: 10 },
    });
  }
  const certificatesIn = (pem: string) => (pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map((one) => new x509.X509Certificate(one));
  const spkiOf = (cert: x509.X509Certificate) => Buffer.from(cert.publicKey.rawData);
  async function untilDeployed(agent: TestAgent) {
    await agent.work();
    await h.settleIssuances();
    await agent.work();
  }

  test.each([...ML_DSA])("has the Agent make an %s key, and the Certificate for it is issued and deployed with its chain", async (algorithm) => {
    const ca = await createCa("ml-dsa-65");
    const agent = await TestAgent.registered(h, org.cookie, org.orgId, { hostName: "web-1" });

    const created = await setUp(algorithm, ca, agent);
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ keyAlgorithm: algorithm, state: "awaiting_key" });
    const mcId = created.body.managedCertificateId;
    const auditOf = async () => (await api("/audit-events")).body.items as { action: string; detail: any }[];
    expect((await auditOf()).find((e) => e.action === "managed_certificate.created")!.detail).toMatchObject({ keyCustody: "agent", keyAlgorithm: algorithm });

    await untilDeployed(agent);
    expect((await auditOf()).find((e) => e.action === "deployment.key_generated")!.detail).toMatchObject({ keyAlgorithm: algorithm });
    // The Agent was asked for a key of that algorithm, and it is the only thing it was told of the key.
    expect(agent.executed.map((i) => i.type)).toEqual(["deployment.generate_key", "deployment.run"]);
    expect(agent.executed[0]!.payload).toMatchObject({ managedCertificateId: mcId, names: ["app.internal.acme"], keyAlgorithm: algorithm });
    expect((await api(`/deployments/${created.body.id}`)).body).toMatchObject({ state: "deployed", keyAlgorithm: algorithm, lastRun: { status: "succeeded" } });
    expect((await api(`/managed-certificates/${mcId}`)).body).toMatchObject({ keyAlgorithm: algorithm, keyCustody: "agent", issuance: { status: "succeeded" } });

    // The script is given a Certificate for the Agent's own key, signed by the Issuing CA above it.
    const [run] = agent.deployed;
    const [leaf, issuing, ...rest] = certificatesIn(run!.item.payload.certificate.chainPem);
    expect(rest).toEqual([]);
    expect(createHash("sha256").update(Buffer.from(leaf!.rawData)).digest("hex")).toBe(run!.item.payload.certificate.fingerprint);
    expect(spkiOf(leaf!)).toEqual(createPublicKey(run!.keyPem!).export({ type: "spki", format: "der" }));
    expect(await leaf!.verify({ publicKey: issuing!.publicKey, signatureOnly: true })).toBe(true);
  });

  test("renews with a new ML-DSA key that the Agent makes", async () => {
    const ca = await createCa("ml-dsa-65");
    const agent = await TestAgent.registered(h, org.cookie, org.orgId, { hostName: "web-1" });
    const created = await setUp("ml-dsa-44", ca, agent);
    expect(created.status).toBe(201);
    await untilDeployed(agent);

    h.setNow(new Date(Date.parse("2026-01-21T00:00:00Z")));
    expect(await h.runRenewalScheduler()).toBe(1);
    await untilDeployed(agent);

    const [first, renewal] = agent.deployed;
    expect(agent.executed.map((i) => i.type)).toEqual(["deployment.generate_key", "deployment.run", "deployment.generate_key", "deployment.run"]);
    expect(agent.executed[2]!.payload).toMatchObject({ keyAlgorithm: "ml-dsa-44" });
    const [renewedLeaf] = certificatesIn(renewal!.item.payload.certificate.chainPem);
    expect(spkiOf(renewedLeaf!)).toEqual(createPublicKey(renewal!.keyPem!).export({ type: "spki", format: "der" }));
    expect(spkiOf(renewedLeaf!)).not.toEqual(spkiOf(certificatesIn(first!.item.payload.certificate.chainPem)[0]!));
  });

  test("is refused, with the reason and before the Agent is asked, for a key the CA does not take", async () => {
    const mlDsaCa = await createCa("ml-dsa-65");
    const ecdsaCa = await createCa("ecdsa-p256");
    const agent = await TestAgent.registered(h, org.cookie, org.orgId, { hostName: "web-1" });

    const classicalOnMlDsa = await setUp("ecdsa-p256", mlDsaCa, agent);
    expect(classicalOnMlDsa.status).toBe(422);
    expect(classicalOnMlDsa.body.error).toContain("ml-dsa-44, ml-dsa-65, ml-dsa-87");
    const mlDsaOnEcdsa = await setUp("ml-dsa-65", ecdsaCa, agent);
    expect(mlDsaOnEcdsa.status).toBe(422);
    expect(mlDsaOnEcdsa.body.error).toContain("ml-dsa-65");
    const mlDsaOnAcme = await api("/deployments", { agentId: agent.id, scriptId: (await script()).id, names: ["app.example.com"], keyAlgorithm: "ml-dsa-65" });
    expect(mlDsaOnAcme.status).toBe(422);
    expect(mlDsaOnAcme.body.error).toContain("ACME");

    expect((await api("/deployments")).body.items).toEqual([]);
    expect((await api("/managed-certificates")).body.items).toEqual([]);
    expect((await agent.poll()).body.items).toEqual([]);
  });
});
