// Renewal of a Managed Certificate whose key an Agent holds, through the platform's HTTP API: each Renewal has the Agent
// make a new key and send a CSR for it, and the Certificate issued for it is deployed as the first one was. An Agent that
// is away when Renewal is due holds the Renewal up until it is back, and the inventory says so. The Agent is the stand-in
// (agent-double.ts); Certificates are issued by Pebble for real; time is the harness's clock.
import * as acme from "acme-client";
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { X509Certificate, createPublicKey, randomBytes } from "node:crypto";
import { BIND, PASSWORD, createHarness, type Harness } from "./support/harness";
import { TestAgent } from "./support/agent-double";

setDefaultTimeout(60_000);

let h: Harness;
let operator: string;
let acmeOrg: { orgId: string; cookie: string };
type Org = typeof acmeOrg;

beforeAll(async () => {
  // The clock jumps months ahead to a Renewal, past an Agent credential's life; the Agent would have replaced it on the way, which is not what these tests are about.
  h = await createHarness({ agentGateway: { credentialValidityDays: 3650 } });
});
beforeEach(async () => {
  await h.reset();
  operator = await h.createOperator("op@platform.test", PASSWORD);
  acmeOrg = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
});
afterAll(async () => {
  await h.close();
});

const DAY = 86_400_000;
/** How many days before its Certificate ends a Deployment's Managed Certificate is due, here: inside any Certificate's life Pebble gives. */
const DUE_DAYS = 2;

const api = (path: string, body?: unknown, method?: string, org: Org = acmeOrg) => h.api(`/api/organizations/${org.orgId}${path}`, { cookie: org.cookie, body, method });
const agentIn = () => TestAgent.registered(h, acmeOrg.cookie, acmeOrg.orgId, { hostName: `host-${randomBytes(3).toString("hex")}` });
const auditOf = async () => (await api("/audit-events")).body.items as { action: string; actor: any; target: any; detail: any }[];
const host = () => `t${randomBytes(5).toString("hex")}.${BIND.zone}`;

async function readyToIssue() {
  expect((await api("/acme-accounts", { termsOfServiceAgreed: true })).status).toBe(201);
  const created = await api("/dns-providers", {
    name: "BIND",
    type: "rfc2136",
    settings: { server: BIND.server, port: BIND.port, zone: BIND.zone, keyName: BIND.keyName },
    secret: BIND.keySecret,
  });
  expect(created.status).toBe(201);
}

/** A Deployment taken through to its first Deployment Run, due for Renewal `DUE_DAYS` before its Certificate ends. */
async function deployed(agent: TestAgent, over: Record<string, unknown> = {}) {
  const script = await api("/deployment-scripts", { name: `install-${randomBytes(3).toString("hex")}`, interpreter: "bash", content: "#!/usr/bin/env bash\ntrue\n" });
  expect(script.status).toBe(201);
  const created = await api("/deployments", {
    agentId: agent.id,
    scriptId: script.body.id,
    names: [host()],
    keyAlgorithm: "ecdsa-p256",
    renewalPolicy: { mode: "automatic", daysBeforeExpiry: DUE_DAYS },
    ...over,
  });
  expect(created.status).toBe(201);
  await agent.work();
  await h.settleIssuances();
  await agent.work();
  expect((await deployment(created.body.id)).state).toBe("deployed");
  return created.body as { id: string; managedCertificateId: string };
}

const managed = async (id: string) => (await api(`/managed-certificates/${id}`)).body;
const deployment = async (id: string) => (await api(`/deployments/${id}`)).body;
const runsOf = async (id: string) => (await api(`/deployments/${id}/runs`)).body.items as any[];
const certificatesOf = async (id: string) => (await api(`/managed-certificates/${id}/certificates`)).body.items as { id: string; fingerprint: string; chainPem?: string }[];
const leafKey = (chainPem: string) => new X509Certificate(chainPem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/)![0]).publicKey.export({ type: "spki", format: "der" });
const pemKey = (keyPem: string) => createPublicKey(keyPem).export({ type: "spki", format: "der" });

/** The moment the Managed Certificate's current Certificate is due under the Deployment's Renewal Policy. */
const dueOf = async (managedCertificateId: string) => new Date(Date.parse((await managed(managedCertificateId)).currentCertificate.notAfter) - DUE_DAYS * DAY);

/** One pass of the scheduler, and whatever it started that can run to its end without the Agent. */
async function schedule() {
  const started = await h.runRenewalScheduler();
  await h.settleIssuances();
  return started;
}

/** The Agent takes its work, the Issuance that follows settles, and the Agent takes what that made. */
async function agentWorks(agent: TestAgent) {
  await agent.work();
  await h.settleIssuances();
  await agent.work();
}

describe("Renewal when an Agent holds the key", () => {
  test("the scheduler has the Agent make a new key, the Certificate is issued for it, and the Deployment Script runs with it", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const d = await deployed(agent);
    const first = (await managed(d.managedCertificateId)).currentCertificate;
    const firstKey = agent.keys.get(d.managedCertificateId)!;

    h.setNow(await dueOf(d.managedCertificateId));
    expect(await schedule()).toBe(1);
    await agentWorks(agent);

    // It asked the Agent for a key again, then had it deploy what was issued for that key.
    expect(agent.executed.map((i) => i.type)).toEqual(["deployment.generate_key", "deployment.run", "deployment.generate_key", "deployment.run"]);
    const renewed = await managed(d.managedCertificateId);
    expect(renewed.issuance).toMatchObject({ status: "succeeded", failure: null });
    expect(renewed.currentCertificate.fingerprint).not.toBe(first.fingerprint);
    expect(await certificatesOf(d.managedCertificateId)).toHaveLength(2);

    // A new key: the renewed Certificate's public key is not the first one's, and is the one the Agent now holds.
    const newKey = agent.keys.get(d.managedCertificateId)!;
    expect(newKey).not.toBe(firstKey);
    const [, renewalRun] = agent.deployed;
    const issuedKey = leafKey(renewalRun!.item.payload.certificate.chainPem);
    expect(issuedKey).toEqual(pemKey(newKey));
    expect(issuedKey).not.toEqual(pemKey(firstKey));
    expect(leafKey(agent.deployed[0]!.item.payload.certificate.chainPem)).toEqual(pemKey(firstKey));

    // The renewed Certificate was deployed and recorded as a Deployment Run.
    const runs = await runsOf(d.id);
    expect(runs.map((r) => [r.trigger, r.status, r.certificate.fingerprint])).toEqual([
      ["issuance", "succeeded", renewed.currentCertificate.fingerprint],
      ["issuance", "succeeded", first.fingerprint],
    ]);
    expect(await deployment(d.id)).toMatchObject({ state: "deployed", lastRun: { certificate: { id: renewed.currentCertificate.id } } });

    // The Renewal, the new key and the run are audited; the scheduler's Renewal has no actor.
    const actions = (await auditOf()).map((e) => e.action);
    expect(actions.filter((a) => a === "deployment.key_generated")).toHaveLength(2);
    expect(actions.filter((a) => a === "deployment_run.succeeded")).toHaveLength(2);
    const started = (await auditOf()).filter((e) => e.action === "issuance.started");
    expect(started.at(-1)).toMatchObject({ actor: { id: null }, detail: { renewal: "scheduled" } });
  });
});

describe("an Agent that is offline when Renewal is due", () => {
  const listed = async (filter: string) => ((await api(`/managed-certificates?${filter}`)).body.items as { id: string }[]).map((m) => m.id);

  test("the Renewal waits, the Managed Certificate shows the Agent offline, and it completes once the Agent is back", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const d = await deployed(agent);
    const other = await deployed(await agentIn());
    const first = (await managed(d.managedCertificateId)).currentCertificate;
    expect((await managed(d.managedCertificateId)).agent).toEqual({ id: agent.id, hostName: expect.any(String), status: "online" });
    expect(await listed("agentOffline=true")).toEqual([]);

    // Due, and the Agent has not been in touch for days.
    const due = await dueOf(d.managedCertificateId);
    h.setNow(due);
    expect(await schedule()).toBeGreaterThanOrEqual(1);
    const waiting = await managed(d.managedCertificateId);
    expect(waiting.agent).toMatchObject({ id: agent.id, status: "offline" });
    expect(waiting.issuance).toMatchObject({ status: "running", awaitingKey: true, failure: null });
    expect(waiting.renewal.failing).toBeNull();
    expect(await listed("agentOffline=true")).toContain(d.managedCertificateId);
    expect(await listed("renewalFailing=true")).toEqual([]);

    // It waits as long as the Agent is away: no second request, nothing issued, nothing given up.
    h.setNow(new Date(due.getTime() + 6 * 3_600_000));
    await schedule();
    await h.failInterruptedIssuances();
    expect(await certificatesOf(d.managedCertificateId)).toHaveLength(1);
    expect((await managed(d.managedCertificateId)).issuance).toMatchObject({ status: "running", awaitingKey: true });

    // Back: it is given the one request it missed, and the Renewal goes on to its Deployment Run.
    await agentWorks(agent);
    expect(agent.executed.filter((i) => i.type === "deployment.generate_key")).toHaveLength(2);
    const renewed = await managed(d.managedCertificateId);
    expect(renewed.issuance).toMatchObject({ status: "succeeded", awaitingKey: false });
    expect(renewed.currentCertificate.fingerprint).not.toBe(first.fingerprint);
    expect(renewed.agent.status).toBe("online");
    expect((await runsOf(d.id))[0]).toMatchObject({ trigger: "issuance", status: "succeeded", certificate: { id: renewed.currentCertificate.id } });
    expect(await listed("agentOffline=true")).not.toContain(d.managedCertificateId);
    // The other Deployment's Agent is still away.
    expect(await listed("agentOffline=true")).toContain(other.managedCertificateId);
  });

  test("a Managed Certificate whose key the Owner holds has no Agent, and is never listed as Agent offline", async () => {
    await readyToIssue();
    const name = host();
    const key = await acme.crypto.createPrivateEcdsaKey("P-256");
    const [, csr] = await acme.crypto.createCsr({ commonName: name, altNames: [name] }, key);
    const created = await api("/managed-certificates", { names: [name], keyAlgorithm: "ecdsa-p256", csr: csr.toString() });
    expect(created.status).toBe(201);
    await h.settleIssuances();
    expect((await managed(created.body.id)).agent).toBeNull();
    h.setNow(new Date(Date.now() + 30 * DAY));
    expect(await listed("agentOffline=true")).toEqual([]);
  });
});

describe("renewing now", () => {
  test("has the Agent make a new key too, and the Renewal is the person's", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const d = await deployed(agent);
    const firstKey = agent.keys.get(d.managedCertificateId)!;

    const renewing = await api(`/managed-certificates/${d.managedCertificateId}/renewals`, {}, "POST");
    expect(renewing.status).toBe(202);
    expect(renewing.body).toMatchObject({ status: "running", awaitingKey: true });
    // One at a time, as for any Renewal.
    expect((await api(`/managed-certificates/${d.managedCertificateId}/renewals`, {}, "POST")).status).toBe(409);

    await agentWorks(agent);
    const renewed = await managed(d.managedCertificateId);
    expect(renewed.issuance).toMatchObject({ id: renewing.body.id, status: "succeeded" });
    expect(leafKey(agent.deployed[1]!.item.payload.certificate.chainPem)).toEqual(pemKey(agent.keys.get(d.managedCertificateId)!));
    expect(agent.keys.get(d.managedCertificateId)).not.toBe(firstKey);
    expect((await auditOf()).filter((e) => e.action === "issuance.started").at(-1)).toMatchObject({ actor: { email: "admin@acme.test" }, detail: { renewal: "requested" } });
  });
});

describe("parameter values", () => {
  test("a Renewal gives the Agent the Deployment's values, as its first run had them", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const content = ["#!/usr/bin/env bash", "# deploy-params:begin", '# [{ "name": "SITE_ID", "required": true }, { "name": "PORT", "default": "443" }]', "# deploy-params:end", "true", ""].join("\n");
    const script = await api("/deployment-scripts", { name: "bind-site", interpreter: "bash", content });
    expect(script.status).toBe(201);
    const d = await deployed(agent, { scriptId: script.body.id, parameters: { SITE_ID: "site-7" } });

    h.setNow(await dueOf(d.managedCertificateId));
    expect(await schedule()).toBe(1);
    await agentWorks(agent);

    expect(agent.deployed.map((r) => r.item.payload.parameters)).toEqual([
      { SITE_ID: "site-7", PORT: "443" },
      { SITE_ID: "site-7", PORT: "443" },
    ]);
    expect((await runsOf(d.id)).map((r) => r.status)).toEqual(["succeeded", "succeeded"]);
  });
});

describe("a new key the Agent cannot make", () => {
  test("fails the Renewal, which is then failing and tried again after its backoff", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const d = await deployed(agent);
    const due = await dueOf(d.managedCertificateId);
    h.setNow(due);
    await schedule();

    const [item] = ((await agent.poll()).body.items as { id: string; type: string }[]).filter((i) => i.type === "deployment.generate_key");
    expect((await agent.report(item!.id, { ok: false, error: "the key store is full" })).status).toBe(200);
    await h.settleIssuances();

    const failed = await managed(d.managedCertificateId);
    expect(failed.issuance).toMatchObject({ status: "failed", awaitingKey: false, failure: { code: "agent_key_failed", message: "the key store is full" } });
    expect(failed.renewal.failing).toMatchObject({ failures: 1, lastFailure: { code: "agent_key_failed" } });
    expect(((await api("/managed-certificates?renewalFailing=true")).body.items as { id: string }[]).map((m) => m.id)).toEqual([d.managedCertificateId]);
    expect((await auditOf()).filter((e) => e.action === "deployment.key_failed").at(-1)).toMatchObject({ target: { id: d.id }, detail: { message: "the key store is full" } });
    // The Deployment still has its Certificate in use: the failure is the Renewal's.
    expect(await deployment(d.id)).toMatchObject({ state: "deployed", keyFailure: null });

    // Not before the backoff; after it, the Agent is asked again and the Renewal goes through.
    expect(await schedule()).toBe(0);
    h.setNow(new Date(Date.parse(failed.renewal.failing.nextAttemptAt)));
    expect(await schedule()).toBe(1);
    await agentWorks(agent);
    const renewed = await managed(d.managedCertificateId);
    expect(renewed.issuance).toMatchObject({ status: "succeeded" });
    expect(renewed.renewal.failing).toBeNull();
    expect(await certificatesOf(d.managedCertificateId)).toHaveLength(2);
  });

  test("a CSR that is not for the Managed Certificate's names fails the Renewal, and nothing is issued for it", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const d = await deployed(agent);
    h.setNow(await dueOf(d.managedCertificateId));
    await schedule();

    const [item] = ((await agent.poll()).body.items as { id: string; type: string }[]).filter((i) => i.type === "deployment.generate_key");
    const key = await acme.crypto.createPrivateEcdsaKey("P-256");
    const [, csr] = await acme.crypto.createCsr({ commonName: "elsewhere.rfc2136.test", altNames: ["elsewhere.rfc2136.test"] }, key);
    expect((await agent.report(item!.id, { ok: true, csr: csr.toString() })).status).toBe(200);
    await h.settleIssuances();

    const failed = await managed(d.managedCertificateId);
    expect(failed.issuance).toMatchObject({ status: "failed", failure: { code: "agent_key_failed", message: expect.stringContaining("names") } });
    expect(await certificatesOf(d.managedCertificateId)).toHaveLength(1);
  });
});

describe("archiving while a Renewal waits for the Agent's key", () => {
  test("ends the Renewal, and the Agent is not asked for the key when it is back", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const d = await deployed(agent);
    h.setNow(await dueOf(d.managedCertificateId));
    await schedule();

    expect((await api(`/managed-certificates/${d.managedCertificateId}/archive`, {}, "POST")).status).toBe(200);
    const archived = await managed(d.managedCertificateId);
    expect(archived.issuance).toMatchObject({ status: "failed", awaitingKey: false, failure: { code: "archived" } });

    await agentWorks(agent);
    expect(agent.executed.filter((i) => i.type === "deployment.generate_key")).toHaveLength(1);
    expect(await certificatesOf(d.managedCertificateId)).toHaveLength(1);
  });
});

describe("an Agent that is revoked", () => {
  test("cannot make a new key: Renewal is refused rather than left waiting, and the Managed Certificate says why", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const d = await deployed(agent);
    expect((await api(`/agents/${agent.id}/revoke`, {}, "POST")).status).toBe(200);

    const renewing = await api(`/managed-certificates/${d.managedCertificateId}/renewals`, {}, "POST");
    expect(renewing.status).toBe(409);
    expect(renewing.body.error).toContain("revoked");
    h.setNow(await dueOf(d.managedCertificateId));
    expect(await schedule()).toBe(0);
    const mc = await managed(d.managedCertificateId);
    expect(mc.agent).toMatchObject({ id: agent.id, status: "revoked" });
    expect(mc.issuance).toMatchObject({ status: "succeeded" });
  });

  test("while a Renewal waits for its key ends the Renewal", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const d = await deployed(agent);
    h.setNow(await dueOf(d.managedCertificateId));
    expect(await schedule()).toBe(1);

    expect((await api(`/agents/${agent.id}/revoke`, {}, "POST")).status).toBe(200);
    expect((await managed(d.managedCertificateId)).issuance).toMatchObject({ status: "failed", awaitingKey: false, failure: { code: "agent_key_failed", message: expect.stringContaining("revoked") } });
  });
});
