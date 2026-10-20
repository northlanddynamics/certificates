// The first Deployment, through the platform's HTTP API: an Organization Administrator sets up one in a single call (the
// Agent, the Managed Certificate's names and key algorithm, a Deployment Script version, the Renewal Policy); the Agent
// makes the key and a CSR (ADR 0002: only the CSR reaches the platform), the platform issues the Certificate for real
// (Pebble, DCV through BIND), and the Agent is then told to run the script, which it reports as a Deployment Run. Here the
// Agent is a stand-in (agent-double.ts) that does what the Go Agent does without running the script; the Go Agent proper,
// including running it, is tested in agent/ (Seam B).
import * as acme from "acme-client";
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { X509Certificate, createHash, createPublicKey, randomBytes } from "node:crypto";
import { BIND, PASSWORD, createHarness, type Harness } from "./support/harness";
import { TestAgent } from "./support/agent-double";

setDefaultTimeout(60_000);

let h: Harness;
let operator: string;
let acmeOrg: { orgId: string; cookie: string };
let globex: { orgId: string; cookie: string };
type Org = typeof acmeOrg;

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  operator = await h.createOperator("op@platform.test", PASSWORD);
  acmeOrg = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
  globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
});
afterAll(async () => {
  await h.close();
});

const api = (org: Org, path: string, body?: unknown, method?: string) => h.api(`/api/organizations/${org.orgId}${path}`, { cookie: org.cookie, body, method });
const agentIn = (org: Org = acmeOrg, hostName = `host-${randomBytes(3).toString("hex")}`) => TestAgent.registered(h, org.cookie, org.orgId, { hostName });
const auditOf = async (org: Org = acmeOrg) => (await api(org, "/audit-events")).body.items as { action: string; actor: any; target: any; detail: any }[];

/** A host name of its own inside the zone BIND serves, so tests never share challenge records. */
const host = () => `t${randomBytes(5).toString("hex")}.${BIND.zone}`;

const INSTALL = "#!/usr/bin/env bash\ncp \"$CERT_FULLCHAIN_FILE\" /etc/ssl/site.pem\n";
const sha256 = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");

/** What issuing needs in the Organization: an ACME account in staging, and a DNS Provider for the zone BIND serves. */
async function readyToIssue(org: Org = acmeOrg) {
  expect((await api(org, "/acme-accounts", { termsOfServiceAgreed: true })).status).toBe(201);
  const created = await api(org, "/dns-providers", {
    name: "BIND",
    type: "rfc2136",
    settings: { server: BIND.server, port: BIND.port, zone: BIND.zone, keyName: BIND.keyName },
    secret: BIND.keySecret,
  });
  expect(created.status).toBe(201);
}

/** The Organization's script of that name, uploaded if it is not there yet. */
async function script(org: Org = acmeOrg, name = "install", content = INSTALL, interpreter = "bash") {
  const existing = (await api(org, "/deployment-scripts")).body.items.find((s: any) => s.name === name);
  if (existing) return existing as { id: string };
  const created = await api(org, "/deployment-scripts", { name, interpreter, content });
  expect(created.status).toBe(201);
  return created.body as { id: string };
}

/** The request that sets up a Deployment; what a test does not say is a valid default. */
async function deploymentRequest(agent: TestAgent, over: Record<string, unknown> = {}) {
  const s = await script();
  return { agentId: agent.id, scriptId: s.id, names: [host()], keyAlgorithm: "ecdsa-p256", ...over };
}
const setUp = (org: Org, body: unknown) => api(org, "/deployments", body);
const deployment = async (id: string, org: Org = acmeOrg) => (await api(org, `/deployments/${id}`)).body;
const runsOf = async (id: string, org: Org = acmeOrg) => (await api(org, `/deployments/${id}/runs`)).body.items as any[];

/** The Agent takes its work, the Issuance that follows settles, and the Agent takes what that made. */
async function untilDeployed(agent: TestAgent) {
  await agent.work();
  await h.settleIssuances();
  await agent.work();
}

describe("setting up the first Deployment", () => {
  test("the Agent makes the key, the Certificate is issued for its CSR, and the script runs and is recorded as a Deployment Run", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const request = await deploymentRequest(agent);

    const created = await setUp(acmeOrg, request);
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({
      agent: { id: agent.id },
      script: { id: request.scriptId, name: "install", interpreter: "bash", version: 1, hash: sha256(INSTALL) },
      // The script declares no parameters, so it is given none.
      parameters: {},
      state: "awaiting_key",
      lastRun: null,
    });

    // No Approval is needed, and the Managed Certificate's key is the Agent's, through this one Deployment.
    const mc = await api(acmeOrg, `/managed-certificates/${created.body.managedCertificateId}`);
    expect(mc.body).toMatchObject({
      names: request.names,
      keyAlgorithm: "ecdsa-p256",
      keyCustody: "agent",
      approval: { status: "not_required" },
      issuance: null,
    });

    await untilDeployed(agent);

    // The Agent was asked to make the key, then to run the script for the Certificate that was issued for the CSR it sent.
    expect(agent.executed.map((i) => i.type)).toEqual(["deployment.generate_key", "deployment.run"]);
    const issued = (await api(acmeOrg, `/managed-certificates/${created.body.managedCertificateId}`)).body;
    expect(issued.issuance).toMatchObject({ status: "succeeded" });
    const [run] = agent.deployed;
    expect(run!.hashMatched).toBe(true);
    expect(run!.item.payload).toMatchObject({
      deploymentId: created.body.id,
      managedCertificateId: created.body.managedCertificateId,
      names: request.names,
      certificate: { id: issued.currentCertificate.id, fingerprint: issued.currentCertificate.fingerprint },
      script: { name: "install", interpreter: "bash", version: 1, hash: sha256(INSTALL), content: INSTALL },
      parameters: {},
    });
    // The Certificate it was given is the one issued, for the key the Agent holds.
    const leaf = new X509Certificate(run!.item.payload.certificate.chainPem);
    expect(createHash("sha256").update(leaf.raw).digest("hex")).toBe(issued.currentCertificate.fingerprint);
    expect(leaf.publicKey.export({ type: "spki", format: "der" })).toEqual(createPublicKey(run!.keyPem!).export({ type: "spki", format: "der" }));

    // The Deployment Run: when, which Certificate, what the script said.
    expect(await runsOf(created.body.id)).toEqual([
      {
        id: expect.any(String),
        deploymentId: created.body.id,
        status: "succeeded",
        trigger: "issuance",
        startedAt: expect.any(String),
        finishedAt: expect.any(String),
        exitCode: 0,
        output: "installed",
        outputTruncated: false,
        certificate: { id: issued.currentCertificate.id, fingerprint: issued.currentCertificate.fingerprint },
        script: { version: 1, hash: sha256(INSTALL) },
      },
    ]);
    expect(await deployment(created.body.id)).toMatchObject({ state: "deployed", lastRun: { status: "succeeded", exitCode: 0 } });
  });
});

/** A Deployment taken through to its first Deployment Run. */
async function deployed(agent: TestAgent, over: Record<string, unknown> = {}) {
  const created = await setUp(acmeOrg, await deploymentRequest(agent, over));
  expect(created.status).toBe(201);
  await untilDeployed(agent);
  return created.body as { id: string; managedCertificateId: string; names: string[] };
}

/** A Member, Approver or the like invited into the Acme Organization and signed in. */
async function join(role: string) {
  const email = `${role}@acme.test`;
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: acmeOrg.cookie, body: { email, role, organizationId: acmeOrg.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}

describe("what the Deployment Run records", () => {
  test("a script that fails is a failed run with its exit code and output, and the state says so", async () => {
    await readyToIssue();
    const agent = await agentIn();
    agent.scriptOutcome = { exitCode: 3, output: "cp: cannot create /etc/ssl/site.pem" };
    const d = await deployed(agent);

    const [run] = await runsOf(d.id);
    expect(run).toMatchObject({ status: "failed", exitCode: 3, output: "cp: cannot create /etc/ssl/site.pem", trigger: "issuance" });
    expect(await deployment(d.id)).toMatchObject({ state: "deployment_failed", lastRun: { id: run.id } });
  });

  test("a script that did not match its hash was not run: the run is failed, has no exit code and says why", async () => {
    await readyToIssue();
    const agent = await agentIn();
    // The stand-in checks what it was given against the hash, as the Agent does; here what it is given has been altered.
    agent.corruptScripts = true;
    const d = await deployed(agent);

    const [run] = await runsOf(d.id);
    expect(agent.deployed[0]!.hashMatched).toBe(false);
    expect(run).toMatchObject({ status: "failed", exitCode: null, script: { hash: sha256(INSTALL) } });
    expect(run.output).toContain("hash");
  });

  test("output is kept up to a limit, whatever the Agent sends", async () => {
    await readyToIssue();
    const agent = await agentIn();
    agent.scriptOutcome = { exitCode: 0, output: "é".repeat(30_000) }; // 60 000 bytes
    const d = await deployed(agent);

    const [run] = await runsOf(d.id);
    expect(Buffer.byteLength(run.output, "utf8")).toBeLessThanOrEqual(32 * 1024);
    expect(run.output.startsWith("éé")).toBe(true);
    expect(run.outputTruncated).toBe(true);
  });
});

describe("running a Deployment again", () => {
  test("an Organization Administrator has the Agent run the script again for the current Certificate, without renewing", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const d = await deployed(agent);
    const before = (await api(acmeOrg, `/managed-certificates/${d.managedCertificateId}`)).body;

    agent.scriptOutcome = { exitCode: 0, output: "installed again" };
    h.setNow(new Date("2026-01-01T01:00:00Z"));
    const again = await api(acmeOrg, `/deployments/${d.id}/runs`, {}, "POST");
    expect(again.status).toBe(202);
    expect(again.body.runPending).toBe(true);
    // Only one waits at a time.
    expect((await api(acmeOrg, `/deployments/${d.id}/runs`, {}, "POST")).status).toBe(409);

    await agent.work();
    await h.settleIssuances();

    const runs = await runsOf(d.id);
    expect(runs.map((r) => [r.trigger, r.output])).toEqual([["rerun", "installed again"], ["issuance", "installed"]]);
    // The same Certificate as before: nothing was issued.
    expect(runs[0].certificate).toEqual(runs[1].certificate);
    const after = (await api(acmeOrg, `/managed-certificates/${d.managedCertificateId}`)).body;
    expect(after.currentCertificate.id).toBe(before.currentCertificate.id);
    expect((await api(acmeOrg, `/managed-certificates/${d.managedCertificateId}/certificates`)).body.items).toHaveLength(1);
    expect(await deployment(d.id)).toMatchObject({ runPending: false, state: "deployed" });
  });

  test("it is refused before there is a Certificate, once the Managed Certificate is archived, and for an Agent that is revoked", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const created = (await setUp(acmeOrg, await deploymentRequest(agent))).body;
    expect((await api(acmeOrg, `/deployments/${created.id}/runs`, {}, "POST")).status).toBe(409);

    await untilDeployed(agent);
    expect((await api(acmeOrg, `/managed-certificates/${created.managedCertificateId}/archive`, {}, "POST")).status).toBe(200);
    expect((await api(acmeOrg, `/deployments/${created.id}/runs`, {}, "POST")).status).toBe(409);

    const other = await agentIn();
    const second = await deployed(other);
    expect((await api(acmeOrg, `/agents/${other.id}/revoke`, {}, "POST")).status).toBe(200);
    expect((await api(acmeOrg, `/deployments/${second.id}/runs`, {}, "POST")).status).toBe(409);
  });
});

describe("one Agent serves many Deployments", () => {
  test("each has its own Managed Certificate, key and runs, all on the one Agent", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const first = await deployed(agent);
    const second = await deployed(agent);

    expect(first.managedCertificateId).not.toBe(second.managedCertificateId);
    expect(agent.keys.size).toBe(2);
    expect(agent.keys.get(first.managedCertificateId)).not.toBe(agent.keys.get(second.managedCertificateId));
    const list = await api(acmeOrg, "/deployments");
    expect(list.body.total).toBe(2);
    expect(list.body.items.map((d: any) => [d.agent.id, d.state])).toEqual([[agent.id, "deployed"], [agent.id, "deployed"]]);
    // Each Agent run is for its own Certificate.
    expect(agent.deployed.map((r) => r.item.payload.deploymentId).sort()).toEqual([first.id, second.id].sort());
  });
});

describe("narrowing the Deployments", () => {
  test("by where each has got to, its Agent and its script, the filters combining and the total counting what matches", async () => {
    await readyToIssue();
    const [web, mail] = [await agentIn(acmeOrg, "web"), await agentIn(acmeOrg, "mail")];
    const other = await script(acmeOrg, "other", "#!/usr/bin/env bash\ntrue\n");
    const failed = (await setUp(acmeOrg, await deploymentRequest(web))).body;
    const onWebOther = (await setUp(acmeOrg, await deploymentRequest(web, { scriptId: other.id }))).body;
    const onMail = (await setUp(acmeOrg, await deploymentRequest(mail))).body;
    const item = ((await web.poll()).body.items as { id: string; payload: { deploymentId: string } }[]).find((i) => i.payload.deploymentId === failed.id)!;
    expect((await web.report(item.id, { ok: false, error: "the key store is not writable" })).status).toBe(200);
    // Set up at the same moment, so in no order of their own: compare the ids as sets.
    const listed = async (query: string) => {
      const res = await api(acmeOrg, `/deployments?${query}`);
      expect(res.status).toBe(200);
      return { total: res.body.total, ids: (res.body.items as { id: string }[]).map((d) => d.id).sort() };
    };
    const ids = (...ds: { id: string }[]) => ds.map((d) => d.id).sort();

    expect(await listed("state=key_failed")).toEqual({ total: 1, ids: [failed.id] });
    expect(await listed("state=awaiting_key,key_failed")).toEqual({ total: 3, ids: ids(onMail, onWebOther, failed) });
    expect(await listed(`agentId=${web.id}`)).toEqual({ total: 2, ids: ids(onWebOther, failed) });
    expect(await listed(`scriptId=${other.id}`)).toEqual({ total: 1, ids: [onWebOther.id] });
    expect(await listed(`agentId=${web.id},${mail.id}&state=awaiting_key`)).toEqual({ total: 2, ids: ids(onMail, onWebOther) });
    const [first, second] = [await listed("state=awaiting_key&pageSize=1"), await listed("state=awaiting_key&pageSize=1&page=2")];
    expect([first.total, second.total]).toEqual([2, 2]);
    expect([...first.ids, ...second.ids].sort()).toEqual(ids(onMail, onWebOther));
    expect(await listed("state=deployed")).toEqual({ total: 0, ids: [] });
    for (const query of ["state=lost", "agentId=not-an-id", "scriptId="]) expect((await api(acmeOrg, `/deployments?${query}`)).status).toBe(400);
  });
});

describe("who may set up Deployments, and with what", () => {
  test("only an Organization Administrator may set up, see or run one", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const d = await deployed(agent);
    const request = await deploymentRequest(agent);
    for (const role of ["approver", "member"]) {
      const cookie = await join(role);
      const as = (path: string, body?: unknown, method?: string) => h.api(`/api/organizations/${acmeOrg.orgId}${path}`, { cookie, body, method });
      expect((await as("/deployments", request)).status).toBe(403);
      expect((await as("/deployments")).status).toBe(403);
      expect((await as(`/deployments/${d.id}`)).status).toBe(403);
      expect((await as(`/deployments/${d.id}/runs`)).status).toBe(403);
      expect((await as(`/deployments/${d.id}/runs`, {}, "POST")).status).toBe(403);
    }
    expect((await h.api(`/api/organizations/${acmeOrg.orgId}/deployments`, { body: request })).status).toBe(401);
  });

  test("the Agent and the script must be the Organization's own, and the Agent not revoked", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const foreignAgent = await agentIn(globex);
    const foreignScript = await script(globex);
    const request = await deploymentRequest(agent);

    expect((await setUp(acmeOrg, { ...request, agentId: foreignAgent.id })).status).toBe(400);
    expect((await setUp(acmeOrg, { ...request, agentId: "not-an-id" })).status).toBe(400);
    expect((await setUp(acmeOrg, { ...request, scriptId: foreignScript.id })).status).toBe(400);
    expect((await setUp(acmeOrg, { ...request, scriptVersion: 9 })).status).toBe(400);
    expect((await setUp(acmeOrg, { ...request, names: ["not a name"] })).status).toBe(400);
    expect((await setUp(acmeOrg, { ...request, keyAlgorithm: "dsa" })).status).toBe(400);
    expect((await setUp(acmeOrg, { ...request, renewalPolicy: { mode: "automatic", daysBeforeExpiry: 0 } })).status).toBe(400);
    expect((await api(acmeOrg, `/agents/${agent.id}/revoke`, {}, "POST")).status).toBe(200);
    expect((await setUp(acmeOrg, request)).status).toBe(400);
    // Nothing was made by any of them.
    expect((await api(acmeOrg, "/managed-certificates")).body.total).toBe(0);
    expect((await api(acmeOrg, "/deployments")).body.total).toBe(0);
  });

  test("the Renewal Policy and key algorithm chosen are the Managed Certificate's, and a version of the script can be picked", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const s = await script();
    const v2 = "#!/usr/bin/env bash\necho second\n";
    expect((await api(acmeOrg, `/deployment-scripts/${s.id}/versions`, { content: v2 })).status).toBe(201);

    const latest = await setUp(acmeOrg, { agentId: agent.id, scriptId: s.id, names: [host()], keyAlgorithm: "rsa-2048", renewalPolicy: { mode: "manual", daysBeforeExpiry: 14 } });
    expect(latest.body.script).toMatchObject({ version: 2, hash: sha256(v2) });
    expect((await api(acmeOrg, `/managed-certificates/${latest.body.managedCertificateId}`)).body).toMatchObject({
      keyAlgorithm: "rsa-2048",
      renewal: { policy: { mode: "manual", daysBeforeExpiry: 14 } },
    });
    const pinned = await setUp(acmeOrg, { agentId: agent.id, scriptId: s.id, scriptVersion: 1, names: [host()], keyAlgorithm: "ecdsa-p384" });
    expect(pinned.body.script).toMatchObject({ version: 1, hash: sha256(INSTALL) });
  });

  test("an Organization's Deployments are not seen or run from another", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const d = await deployed(agent);
    expect((await api(globex, `/deployments/${d.id}`)).status).toBe(404);
    expect((await api(globex, `/deployments/${d.id}/runs`)).status).toBe(404);
    expect((await api(globex, `/deployments/${d.id}/runs`, {}, "POST")).status).toBe(404);
    expect((await api(globex, "/deployments")).body.total).toBe(0);
  });
});

describe("the private key stays with the Agent", () => {
  test("nothing the platform stores or serves holds the key the Agent made, and the platform never asks for one", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const d = await deployed(agent);
    const keyBody = agent.keys.get(d.managedCertificateId)!.replace(/-----[A-Z ]+-----|\s/g, "");
    expect(keyBody.length).toBeGreaterThan(40);

    const tables = await h.pool.query(`select table_name from information_schema.tables where table_schema = 'public' and table_type = 'BASE TABLE'`);
    for (const { table_name } of tables.rows) {
      const dump = await h.pool.query(`select t::text as row from "${table_name}" t`);
      for (const { row } of dump.rows) expect(row).not.toContain(keyBody);
    }
    for (const path of [`/deployments/${d.id}`, `/deployments/${d.id}/runs`, `/managed-certificates/${d.managedCertificateId}`, `/audit-events`]) {
      const res = await h.app.request(`http://localhost/api/organizations/${acmeOrg.orgId}${path}`, { headers: { cookie: acmeOrg.cookie } });
      const text = await res.text();
      expect(text).not.toContain(keyBody);
      expect(text).not.toContain("PRIVATE KEY");
    }
    // What the Agent was given to make the key is names and an algorithm, and what it was given to deploy is the Certificate: no key either way.
    for (const item of [...agent.received]) expect(JSON.stringify(item)).not.toContain("PRIVATE KEY");
  });
});

describe("a CSR the platform cannot use", () => {
  test("the Agent's CSR must be for the names and key algorithm: otherwise nothing is issued and the Deployment says why", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const created = (await setUp(acmeOrg, await deploymentRequest(agent))).body;

    const polled = (await agent.poll()).body.items as { id: string; payload: any }[];
    const item = polled.find((i) => (i as any).type === "deployment.generate_key")!;
    // A CSR for other names than the Managed Certificate's.
    const other = await acmeCsr(["someone-else.rfc2136.test"]);
    expect((await agent.report(item.id, { ok: true, csr: other })).status).toBe(200);
    await h.settleIssuances();

    expect(await deployment(created.id)).toMatchObject({ state: "key_failed", keyFailure: expect.stringContaining("names") });
    const mc = (await api(acmeOrg, `/managed-certificates/${created.managedCertificateId}`)).body;
    expect(mc.issuance).toBeNull();
    expect((await auditOf()).map((e) => e.action)).toContain("deployment.key_failed");
  });

  test("an Agent that cannot make the key says so, and the Deployment shows it", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const created = (await setUp(acmeOrg, await deploymentRequest(agent))).body;
    const item = ((await agent.poll()).body.items as { id: string }[])[0]!;
    expect((await agent.report(item.id, { ok: false, error: "the key store is not writable" })).status).toBe(200);

    expect(await deployment(created.id)).toMatchObject({ state: "key_failed", keyFailure: "the key store is not writable" });
  });
});

/** What an Owner submits for a Managed Certificate of their own key. */
async function ownerRequest() {
  const name = host();
  return { names: [name], keyAlgorithm: "ecdsa-p256", csr: await acmeCsr([name]) };
}

/** A CSR, as some other Agent or an Owner might make one, under a fresh P-256 key. */
async function acmeCsr(names: string[]) {
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return csr.toString();
}

describe("recovering from a key that could not be made", () => {
  test("running the Deployment again asks the Agent for the key again, and the Deployment then goes on as usual", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const created = (await setUp(acmeOrg, await deploymentRequest(agent))).body;
    const item = ((await agent.poll()).body.items as { id: string }[])[0]!;
    await agent.report(item.id, { ok: false, error: "the key store is not writable" });
    expect(await deployment(created.id)).toMatchObject({ state: "key_failed" });

    const again = await api(acmeOrg, `/deployments/${created.id}/runs`, {}, "POST");
    expect(again.status).toBe(202);
    expect(again.body).toMatchObject({ state: "awaiting_key", keyFailure: null });
    // Only once while the Agent has not answered.
    expect((await api(acmeOrg, `/deployments/${created.id}/runs`, {}, "POST")).status).toBe(409);

    await untilDeployed(agent);
    expect(await deployment(created.id)).toMatchObject({ state: "deployed" });
    expect((await auditOf()).map((e) => e.action)).toContain("deployment.key_requested");
  });

  test("a late failure report for a key that was made does not undo it", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const created = (await setUp(acmeOrg, await deploymentRequest(agent))).body;
    // A second request for the key, as redelivery after a stop can leave, is answered late with a failure.
    await agent.work();
    await h.settleIssuances();
    await db_enqueueKeyItem(created.id, agent.id);
    const second = ((await agent.poll()).body.items as { id: string; type: string }[]).find((i) => i.type === "deployment.generate_key")!;
    expect((await agent.report(second.id, { ok: false, error: "late" })).status).toBe(200);
    expect(await deployment(created.id)).not.toMatchObject({ state: "key_failed" });
  });
});

/** Puts a second request for the key in front of the Agent, as a redelivery after a stop can. */
async function db_enqueueKeyItem(deploymentId: string, agentId: string) {
  await h.pool.query(
    `insert into work_item (organization_id, agent_id, type, payload, status, created_at) values ($1, $2, 'deployment.generate_key', $3, 'pending', now())`,
    [acmeOrg.orgId, agentId, JSON.stringify({ deploymentId })],
  );
}

describe("an Agent that is away, or stops partway", () => {
  test("work waits for an Agent however long it is away, and one it was given but never reported is given again", async () => {
    await readyToIssue();
    const agent = await agentIn();
    await setUp(acmeOrg, await deploymentRequest(agent));

    // Away for a week: the request for the key has not expired.
    h.setNow(new Date("2026-01-08T00:00:00Z"));
    const first = (await agent.poll("0.1.0")).body.items as { id: string; type: string }[];
    expect(first.map((i) => i.type)).toEqual(["deployment.generate_key"]);
    // It stopped before reporting: a poll soon after has nothing, one long after is given it again.
    expect(((await agent.poll()).body.items as unknown[]).length).toBe(0);
    h.setNow(new Date("2026-01-08T00:20:00Z"));
    const again = (await agent.poll()).body.items as { id: string; type: string }[];
    expect(again.map((i) => [i.id, i.type])).toEqual([[first[0]!.id, "deployment.generate_key"]]);
  });
});

describe("what is audited", () => {
  test("setting up, the key, and each Deployment Run are Audit Events, with the hash and fingerprint but no key", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const d = await deployed(agent);
    await api(acmeOrg, `/deployments/${d.id}/runs`, {}, "POST");
    await agent.work();

    const events = (await auditOf()).filter((e) => /^deployment[._]/.test(e.action) && e.action !== "deployment_script.uploaded" || e.action === "managed_certificate.created");
    expect(events.map((e) => e.action)).toEqual([
      "managed_certificate.created",
      "deployment.created",
      "deployment.key_generated",
      "deployment_run.succeeded",
      "deployment.run_requested",
      "deployment_run.succeeded",
    ]);
    const issued = (await api(acmeOrg, `/managed-certificates/${d.managedCertificateId}`)).body.currentCertificate;
    const [, created, keyed, firstRun, requested, secondRun] = events;
    expect(created).toMatchObject({
      actor: { email: "admin@acme.test" },
      target: { type: "deployment", id: d.id },
      detail: { managedCertificateId: d.managedCertificateId, agentId: agent.id, scriptName: "install", scriptVersion: 1, scriptHash: sha256(INSTALL), keyAlgorithm: "ecdsa-p256" },
    });
    expect(keyed!.detail).toMatchObject({ agentId: agent.id, csrFingerprint: expect.stringMatching(/^[0-9a-f]{64}$/) });
    expect(firstRun!.detail).toMatchObject({ trigger: "issuance", fingerprint: issued.fingerprint, scriptHash: sha256(INSTALL), exitCode: 0, agentId: agent.id });
    expect(requested).toMatchObject({ actor: { email: "admin@acme.test" }, detail: { fingerprint: issued.fingerprint } });
    expect(secondRun!.detail).toMatchObject({ trigger: "rerun", exitCode: 0 });
  });

  test("a setup that is refused leaves nothing, not even an Audit Event", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const request = await deploymentRequest(agent);
    const before = (await auditOf()).length;
    expect((await setUp(acmeOrg, { ...request, scriptVersion: 9 })).status).toBe(400);
    expect((await auditOf()).length).toBe(before);
  });
});

describe("Managed Certificates whose key an Agent holds", () => {
  test("their names and CSR are not changed by upload or name change, which would put in a key the Agent does not hold", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const d = await deployed(agent);
    const csr = await acmeCsr(["other.rfc2136.test"]);
    expect((await api(acmeOrg, `/managed-certificates/${d.managedCertificateId}/csr`, { csr })).status).toBe(409);
    expect((await api(acmeOrg, `/managed-certificates/${d.managedCertificateId}/name-change`, { names: ["other.rfc2136.test"], csr })).status).toBe(409);
  });

  test("the inventory can be narrowed to the ones an Agent holds the key of", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const d = await deployed(agent);
    const owner = await h.api(`/api/organizations/${acmeOrg.orgId}/managed-certificates`, { cookie: acmeOrg.cookie, body: { ...(await ownerRequest()) } });
    expect(owner.status).toBe(201);

    const agentHeld = await api(acmeOrg, "/managed-certificates?keyCustody=agent");
    expect(agentHeld.body.items.map((m: any) => m.id)).toEqual([d.managedCertificateId]);
    const ownerHeld = await api(acmeOrg, "/managed-certificates?keyCustody=owner");
    expect(ownerHeld.body.items.map((m: any) => m.id)).toEqual([owner.body.id]);
    await h.settleIssuances();
  });

  test("trying issuance again before the Agent has made the key is refused", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const created = (await setUp(acmeOrg, await deploymentRequest(agent))).body;
    expect((await api(acmeOrg, `/managed-certificates/${created.managedCertificateId}/issuances`, {}, "POST")).status).toBe(409);
  });

  test("a failed Issuance leaves the Deployment awaiting a new one, and nothing is deployed", async () => {
    await readyToIssue();
    const agent = await agentIn();
    // No DNS Provider serves the name, so DCV cannot be done.
    const created = (await setUp(acmeOrg, await deploymentRequest(agent, { names: ["no-zone.example.invalid"] }))).body;
    await agent.work();
    await h.settleIssuances();
    expect(await deployment(created.id)).toMatchObject({ state: "issuance_failed" });
    expect(agent.executed.map((i) => i.type)).toEqual(["deployment.generate_key"]);
  });
});

describe("parameter values", () => {
  /** A script declaring a required site id, a port with a default, and a pool that may be left unset. */
  const BIND_SITE = [
    "#!/usr/bin/env bash",
    "# deploy-params:begin",
    "# [",
    '#   { "name": "SITE_ID", "label": "Site id", "required": true },',
    '#   { "name": "PORT", "default": "443" },',
    '#   { "name": "POOL" }',
    "# ]",
    "# deploy-params:end",
    'bind-site "$DEPLOY_PARAM_SITE_ID" "${DEPLOY_PARAM_PORT}" "${DEPLOY_PARAM_POOL:-}"',
    "",
  ].join("\n");
  const SITE = "site-7f3a9c";
  const bindSite = () => script(acmeOrg, "bind-site", BIND_SITE);
  const withParameters = async (agent: TestAgent, parameters: unknown) => deploymentRequest(agent, { scriptId: (await bindSite()).id, parameters });

  test("the values are kept on the Deployment, defaults filled in and blanks left out, and given to the Agent with the script", async () => {
    await readyToIssue();
    const agent = await agentIn();

    const created = await setUp(acmeOrg, await withParameters(agent, { SITE_ID: SITE, POOL: "" }));

    expect(created.status).toBe(201);
    const values = { SITE_ID: SITE, PORT: "443" };
    expect(created.body.parameters).toEqual(values);
    expect((await deployment(created.body.id)).parameters).toEqual(values);
    expect((await api(acmeOrg, "/deployments")).body.items[0].parameters).toEqual(values);

    await untilDeployed(agent);
    expect(agent.deployed[0]!.item.payload.parameters).toEqual(values);
  });

  test("running the Deployment again gives the Agent the same values", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const created = await setUp(acmeOrg, await withParameters(agent, { SITE_ID: SITE, PORT: "8443" }));
    await untilDeployed(agent);

    expect((await api(acmeOrg, `/deployments/${created.body.id}/runs`, {}, "POST")).status).toBe(202);
    await agent.work();

    expect(agent.deployed.map((r) => [r.item.payload.trigger, r.item.payload.parameters])).toEqual([
      ["issuance", { SITE_ID: SITE, PORT: "8443" }],
      ["rerun", { SITE_ID: SITE, PORT: "8443" }],
    ]);
  });

  test("a run the Agent was given and never reported is given again with the values", async () => {
    await readyToIssue();
    const agent = await agentIn();
    await setUp(acmeOrg, await withParameters(agent, { SITE_ID: SITE }));
    await agent.work();
    await h.settleIssuances();

    const runItem = async () => ((await agent.poll()).body.items as { id: string; type: string; payload: any }[]).find((i) => i.type === "deployment.run");
    const first = await runItem();
    expect(first!.payload.parameters).toEqual({ SITE_ID: SITE, PORT: "443" });
    // It stopped before reporting, and is given the run again later.
    h.setNow(new Date("2026-01-01T00:20:00Z"));
    const again = await runItem();
    expect(again).toMatchObject({ id: first!.id, payload: { parameters: { SITE_ID: SITE, PORT: "443" } } });
  });

  test.each([
    ["a required parameter with no value", {}, "SITE_ID", "required"],
    ["a required parameter left blank", { SITE_ID: "  " }, "SITE_ID", "required"],
    ["a parameter the version does not declare", { SITE_ID: SITE, SITEID: "7" }, "SITEID", "not a parameter"],
    ["a value over 1 KiB", { SITE_ID: "x".repeat(1025) }, "SITE_ID", "KiB"],
    ["a value with a NUL in it", { SITE_ID: "a\u0000b" }, "SITE_ID", "NUL"],
    ["a value with a newline in it", { SITE_ID: SITE, POOL: "a\nb" }, "POOL", "newline"],
    ["a value with a carriage return in it", { SITE_ID: "a\rb" }, "SITE_ID", "newline"],
  ])("%s is refused with 400 naming the parameter, and nothing is set up", async (_what, parameters, name, problem) => {
    await readyToIssue();
    const request = await withParameters(await agentIn(), parameters);
    const before = (await auditOf()).length;

    const refused = await setUp(acmeOrg, request);

    expect(refused.status).toBe(400);
    expect(refused.body.error).toContain(name);
    expect(Object.keys(refused.body.parameters)).toEqual([name]);
    expect(refused.body.parameters[name]).toContain(problem);
    expect((await api(acmeOrg, "/deployments")).body.total).toBe(0);
    expect((await api(acmeOrg, "/managed-certificates")).body.total).toBe(0);
    expect((await auditOf()).length).toBe(before);
  });

  test("every parameter at fault is named at once", async () => {
    await readyToIssue();
    const refused = await setUp(acmeOrg, await withParameters(await agentIn(), { PORT: "a\nb", NOPE: "1" }));

    expect(refused.status).toBe(400);
    expect(Object.keys(refused.body.parameters).sort()).toEqual(["NOPE", "PORT", "SITE_ID"]);
  });

  test("values for a script that declares no parameters are refused", async () => {
    await readyToIssue();
    const refused = await setUp(acmeOrg, await deploymentRequest(await agentIn(), { parameters: { SITE_ID: SITE } }));

    expect(refused.status).toBe(400);
    expect(refused.body.parameters).toEqual({ SITE_ID: expect.stringContaining("not a parameter") });
  });

  test("values are checked against the version chosen, not the latest", async () => {
    await readyToIssue();
    const agent = await agentIn();
    const s = await bindSite();
    expect((await api(acmeOrg, `/deployment-scripts/${s.id}/versions`, { content: INSTALL })).status).toBe(201);

    expect((await setUp(acmeOrg, await deploymentRequest(agent, { scriptId: s.id, parameters: { SITE_ID: SITE } }))).status).toBe(400);
    const pinned = await setUp(acmeOrg, await deploymentRequest(agent, { scriptId: s.id, scriptVersion: 1, parameters: { SITE_ID: SITE } }));
    expect(pinned.status).toBe(201);
    expect(pinned.body).toMatchObject({ script: { version: 1 }, parameters: { SITE_ID: SITE, PORT: "443" } });
  });

  test("the Audit Event of setting it up names the parameters set and holds none of their values", async () => {
    await readyToIssue();
    const created = await setUp(acmeOrg, await withParameters(await agentIn(), { SITE_ID: SITE, PORT: "8443-tls" }));
    expect(created.status).toBe(201);

    const events = await auditOf();
    expect(events.find((e) => e.action === "deployment.created")!.detail.parameters).toEqual(["SITE_ID", "PORT"]);
    for (const value of [SITE, "8443-tls"]) expect(JSON.stringify(events)).not.toContain(value);
  });

  test("only an Organization Administrator sees the values", async () => {
    await readyToIssue();
    const created = await setUp(acmeOrg, await withParameters(await agentIn(), { SITE_ID: SITE }));
    for (const role of ["approver", "member"]) {
      const cookie = await join(role);
      const read = (path: string) => h.app.request(`http://localhost/api/organizations/${acmeOrg.orgId}${path}`, { headers: { cookie } });
      for (const path of ["/deployments", `/deployments/${created.body.id}`]) expect((await read(path)).status).toBe(403);
      // The Managed Certificate an Approver may see does not carry them.
      expect(await (await read(`/managed-certificates/${created.body.managedCertificateId}`)).text()).not.toContain(SITE);
    }
  });
});
