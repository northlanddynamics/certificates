// TLS Managed Certificates from an ADCS CA, through the platform's HTTP API and the Agent protocol: a Managed Certificate's
// issuer is an ADCS CA and one of its TLS templates; an Organization Administrator creates one outright, a Member proposes
// one and an Approver approves it. The platform checks the CA's Permitted Name Rules and the template's key requirements
// before anything is submitted, then an online assigned Agent submits the CSR (`adcs.submit`) and the Issuance waits for
// its report. Here the Agents are stand-ins (agent-double.ts) and ADCS an in-memory double (adcs-double.ts).
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import acme from "acme-client";
import { randomBytes } from "node:crypto";
import { PASSWORD, createHarness, type Harness } from "./support/harness";
import { TestAgent } from "./support/agent-double";
import { AdcsDouble, AdcsDoubleError, defaultTemplates } from "./support/adcs-double";
import { FIRST_CHECK_AFTER_MS, LONGEST_CHECK_WAIT_MS, NO_AGENT_TIMEOUT_MS, PENDING_TIMEOUT_MS } from "../src/adcs/adcs-issuance";

setDefaultTimeout(60_000);

let h: Harness;
let operator: string;
let acmeOrg: { orgId: string; cookie: string };
let globex: { orgId: string; cookie: string };
let adcs: AdcsDouble;
type Org = typeof acmeOrg;

const CONFIG = "ca01.corp.example\\Corp Issuing CA";
const DAY_MS = 24 * 3600_000;
const SUBMIT_TIMEOUT_MS = 10 * 60_000;
/** The harness's clock after a reset; an Agent's credential lasts 30 days from it. */
const START = new Date("2026-01-01T00:00:00Z");
const after = (ms: number) => new Date(START.getTime() + ms);
let current = START;
/** Sets the clock of the platform and of ADCS. */
function setNow(d: Date) {
  current = d;
  h.setNow(d);
}

beforeAll(async () => {
  h = await createHarness({ adcsRelay: { attemptTimeoutMs: 1500 }, adcsSubmit: { submitTimeoutMs: SUBMIT_TIMEOUT_MS }, dnsRelay: { pollMs: 10 } });
  adcs = await AdcsDouble.create(CONFIG);
});
beforeEach(async () => {
  await h.reset();
  adcs.failure = null;
  adcs.templates = defaultTemplates();
  adcs.issued.length = 0;
  adcs.hold = false;
  adcs.denyWith = null;
  adcs.pending.clear();
  adcs.denied.clear();
  adcs.checks = 0;
  current = START;
  adcs.now = () => current;
  operator = await h.createOperator("op@platform.test", PASSWORD);
  acmeOrg = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
  globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
});
afterAll(async () => {
  await h.close();
});

const api = (org: Org, path: string, body?: unknown, method?: string, cookie = org.cookie) => h.api(`/api/organizations/${org.orgId}${path}`, { cookie, body, method });
const auditOf = async (org: Org = acmeOrg) => (await api(org, "/audit-events")).body.items as { action: string; detail: any; target: any }[];

/** A registered Agent on a Windows host that reaches `reaches` (the ADCS double unless given none). */
async function windowsAgent(org: Org = acmeOrg, reaches: AdcsDouble | null = adcs) {
  const agent = await TestAgent.registered(h, org.cookie, org.orgId, { hostName: `win-${randomBytes(3).toString("hex")}`, os: "windows" });
  agent.adcs = reaches;
  return agent;
}

type Template = { id: string; name: string };
type Ca = { id: string; name: string; templates: Template[]; permittedNames: { exact: string[]; zones: string[] } | null };

/** An ADCS CA added with the Agents (a Windows one that reaches the double unless given), and its TLS template. */
async function adcsCa(agents?: TestAgent[], body: Record<string, unknown> = {}, org: Org = acmeOrg) {
  const assigned = agents ?? [await windowsAgent(org)];
  const stops = assigned.map((a) => a.startWorking());
  let res;
  try {
    res = await api(org, "/adcs-cas", { name: "Corp", configString: CONFIG, agentIds: assigned.map((a) => a.id), ...body });
  } finally {
    for (const stop of stops) await stop();
  }
  expect(res.status).toBe(201);
  const ca = res.body as Ca;
  const template = (name: string) => ca.templates.find((t) => t.name === name)!;
  return { ca, agents: assigned, tls: template("CorpWebServer"), device: template("CorpDevice"), directory: template("Workstation") };
}

/** A key and a CSR for the names: RSA 2048 unless asked otherwise. */
async function csrFor(names: string[], keyAlgorithm: "rsa-2048" | "rsa-3072" | "ecdsa-p256" | "ecdsa-p384" = "rsa-2048") {
  const key =
    keyAlgorithm === "ecdsa-p256"
      ? await acme.crypto.createPrivateEcdsaKey("P-256")
      : keyAlgorithm === "ecdsa-p384"
        ? await acme.crypto.createPrivateEcdsaKey("P-384")
        : await acme.crypto.createPrivateRsaKey(keyAlgorithm === "rsa-3072" ? 3072 : 2048);
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return { csr: csr.toString(), keyAlgorithm };
}

const issuerOf = (ca: Ca, template: Template) => ({ kind: "adcs", adcsCaId: ca.id, templateId: template.id });

/** Creates (as the Organization Administrator, unless a cookie says otherwise) a Managed Certificate on the ADCS CA and template. */
async function create(ca: Ca, template: Template, names = ["web.corp.example"], over: Record<string, unknown> = {}, cookie = acmeOrg.cookie) {
  return api(acmeOrg, "/managed-certificates", { names, ...(await csrFor(names)), issuer: issuerOf(ca, template), ...over }, undefined, cookie);
}

/** The Managed Certificate as it is now. */
const mcOf = async (id: string, org: Org = acmeOrg) => (await api(org, `/managed-certificates/${id}`)).body;

/** Has the Agents take their work once each, after the Issuances started so far have had their say. */
async function work(...agents: TestAgent[]) {
  await h.settleIssuances();
  for (const agent of agents) await agent.work();
}

/** A member of the Organization in the role, signed in. */
async function memberWithRole(role: string, email = `${role}@acme.test`) {
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: acmeOrg.cookie, body: { email, role, organizationId: acmeOrg.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return await h.signIn(email, PASSWORD);
}

const certificatesIn = (pem: string) => (pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map((one) => new x509.X509Certificate(one));

describe("creating a Managed Certificate on an ADCS CA", () => {
  test("an assigned Agent submits the CSR under the template, and the Certificate ADCS issued is stored, with its request ID", async () => {
    const { ca, agents, tls } = await adcsCa();
    const created = await create(ca, tls);
    expect(created.status).toBe(201);
    expect(created.body.issuer).toEqual({ kind: "adcs", adcsCa: { id: ca.id, name: "Corp" }, template: { id: tls.id, name: "CorpWebServer", displayName: "Corp Web Server" } });
    expect(created.body.validityDays).toBeNull();

    await h.settleIssuances();
    // Waiting at the platform until the Agent takes it: it has been given to the Agent.
    const waiting = await mcOf(created.body.id);
    expect(waiting.issuance).toMatchObject({ status: "running", adcs: { status: "submitted", agent: { id: agents[0]!.id }, requestId: null } });

    await work(agents[0]!);
    const submitted = agents[0]!.executed.find((i) => i.type === "adcs.submit")!;
    // The config string, the template's ADCS name and the CSR: nothing secret, and nothing of the platform's own.
    expect(Object.keys(submitted.payload).sort()).toEqual(["configString", "csr", "template"]);
    expect(submitted.payload).toMatchObject({ configString: CONFIG, template: "CorpWebServer" });

    const mc = await mcOf(created.body.id);
    const [issued] = adcs.issued;
    expect(mc.issuance).toMatchObject({ status: "succeeded", adcs: { status: "issued", requestId: issued!.requestId } });
    expect(mc.currentCertificate).toMatchObject({ names: ["web.corp.example"], ca: "Corp", adcs: { adcsCaId: ca.id, templateId: tls.id, requestId: issued!.requestId } });
    // The template decides validity: a year, as it says.
    const lifetime = new Date(mc.currentCertificate.notAfter).getTime() - new Date(mc.currentCertificate.notBefore).getTime();
    expect(Math.round(lifetime / DAY_MS)).toBe(365);

    const certificate = await api(acmeOrg, `/managed-certificates/${mc.id}/certificates/${mc.currentCertificate.id}`);
    expect(certificate.body.chain.map((c: any) => c.subject)).toEqual(["CN=web.corp.example", "CN=Corp Issuing CA, DC=corp, DC=example"]);
  });

  test("the request ID is in the Issuance's Audit Events, with adcs_ca.request_submitted", async () => {
    const { ca, agents, tls } = await adcsCa();
    const created = await create(ca, tls);
    await work(agents[0]!);
    const requestId = adcs.issued[0]!.requestId;
    const events = (await auditOf()).filter((e) => e.target?.id === created.body.id);
    const issuanceId = (await mcOf(created.body.id)).issuance.id;

    const submitted = events.find((e) => e.action === "adcs_ca.request_submitted")!;
    expect(submitted.detail).toEqual({
      issuanceId,
      adcsCa: { id: ca.id, name: "Corp" },
      template: { id: tls.id, name: "CorpWebServer" },
      agent: { id: agents[0]!.id, hostName: expect.stringMatching(/^win-/) },
      adcsRequestId: requestId,
      disposition: "issued",
    });
    expect(events.find((e) => e.action === "issuance.started")!.detail.issuer).toEqual({ kind: "adcs", adcsCaId: ca.id, templateId: tls.id });
    expect(events.find((e) => e.action === "issuance.succeeded")!.detail.issuer).toEqual({ kind: "adcs", adcsCaId: ca.id, templateId: tls.id, adcsRequestId: requestId });
    expect(events.find((e) => e.action === "managed_certificate.created")!.detail.issuer).toEqual({ kind: "adcs", adcsCaId: ca.id, templateId: tls.id });
  });

  test("its Certificate exports with the ADCS chain, up to the root", async () => {
    const { ca, agents, tls } = await adcsCa();
    const created = await create(ca, tls);
    await work(agents[0]!);
    const download = async (chain: string) => {
      const res = await h.app.request(`http://localhost/api/organizations/${acmeOrg.orgId}/managed-certificates/${created.body.id}/certificate?chain=${chain}`, { headers: { cookie: acmeOrg.cookie } });
      expect(res.status).toBe(200);
      return certificatesIn(await res.text()).map((c) => c.subject);
    };
    expect(await download("leaf")).toEqual(["CN=web.corp.example"]);
    expect(await download("with-intermediates")).toEqual(["CN=web.corp.example", "CN=Corp Issuing CA, DC=corp, DC=example"]);
    expect(await download("with-root")).toEqual(["CN=web.corp.example", "CN=Corp Issuing CA, DC=corp, DC=example", "CN=Corp Root CA, DC=corp, DC=example"]);
  });

  test("a validity is refused: the template decides it", async () => {
    const { ca, tls } = await adcsCa();
    const res = await create(ca, tls, undefined, { validityDays: 90 });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("Certificate Template decides it");
  });

  test("only an available, unhidden template with Server Authentication can be chosen", async () => {
    const { ca, tls, device, directory } = await adcsCa();
    const deviceOnly = await create(ca, device);
    expect(deviceOnly.status).toBe(422);
    expect(deviceOnly.body.error).toContain("not offered for TLS: It has no Server Authentication EKU");
    const fromDirectory = await create(ca, directory);
    expect(fromDirectory.status).toBe(422);
    expect(fromDirectory.body.error).toContain("builds the subject from Active Directory");

    expect((await api(acmeOrg, `/adcs-cas/${ca.id}/templates/${tls.id}/hide`, {}, "POST")).status).toBe(200);
    const hidden = await create(ca, tls);
    expect(hidden.status).toBe(422);
    expect(hidden.body.error).toContain("an Organization Administrator hid it");

    const unknown = await create(ca, { id: crypto.randomUUID(), name: "Nope" });
    expect(unknown.status).toBe(422);
    expect(unknown.body.error).toBe("the ADCS CA Corp has no such Certificate Template");
    const otherCa = await api(acmeOrg, "/managed-certificates", { names: ["web.corp.example"], ...(await csrFor(["web.corp.example"])), issuer: { kind: "adcs", adcsCaId: crypto.randomUUID(), templateId: tls.id } });
    expect(otherCa.status).toBe(422);
    expect(otherCa.body.error).toBe("the Organization has no such ADCS CA");
  });

  test("another Organization's ADCS CA cannot be named", async () => {
    const theirs = await adcsCa(undefined, {}, globex);
    const res = await create(theirs.ca, theirs.tls);
    expect(res.status).toBe(422);
    expect(res.body.error).toBe("the Organization has no such ADCS CA");
  });

  test("a CSR whose key does not meet the template's requirements is refused before anything is submitted", async () => {
    const { ca, agents, tls } = await adcsCa();
    // The template takes RSA of 2048 bits or more, and ECDSA P-256.
    const p384 = await create(ca, tls, undefined, await csrFor(["web.corp.example"], "ecdsa-p384"));
    expect(p384.status).toBe(422);
    expect(p384.body.error).toBe("the Certificate Template CorpWebServer takes keys of RSA, ECDSA P-256, not ecdsa-p384");

    adcs.templates = defaultTemplates().map((t) => (t.name === "CorpWebServer" ? { ...t, minimumKeySize: 3072 } : t));
    await refresh(ca, agents[0]!);
    const small = await create(ca, tls);
    expect(small.status).toBe(422);
    expect(small.body.error).toBe("the Certificate Template CorpWebServer takes RSA keys of at least 3072 bits, not rsa-2048");
    expect((await create(ca, tls, undefined, await csrFor(["web.corp.example"], "rsa-3072"))).status).toBe(201);
    expect((await create(ca, tls, ["api.corp.example"], await csrFor(["api.corp.example"], "ecdsa-p256"))).status).toBe(201);
    expect(adcs.issued).toHaveLength(0);
  });
});

/** Has the Agent discover the CA again. */
async function refresh(ca: Ca, agent: TestAgent) {
  const stop = agent.startWorking();
  try {
    expect((await api(acmeOrg, `/adcs-cas/${ca.id}/refresh`, {}, "POST")).status).toBe(200);
  } finally {
    await stop();
  }
}

describe("Permitted Name Rules on an ADCS CA", () => {
  test("an Organization Administrator sets and changes them, as Audit Events; none relies on Approval alone", async () => {
    const { ca } = await adcsCa();
    expect(ca.permittedNames).toBeNull();
    const set = await api(acmeOrg, `/adcs-cas/${ca.id}`, { permittedNames: { exact: ["Portal.Corp.Example"], zones: ["internal.corp.example"] } }, "PATCH");
    expect(set.status).toBe(200);
    expect(set.body.permittedNames).toEqual({ exact: ["portal.corp.example"], zones: ["internal.corp.example"] });
    const cleared = await api(acmeOrg, `/adcs-cas/${ca.id}`, { permittedNames: null }, "PATCH");
    expect(cleared.body.permittedNames).toBeNull();

    const updates = (await auditOf()).filter((e) => e.action === "adcs_ca.updated").map((e) => e.detail.changes.permittedNames);
    expect(updates).toEqual([
      { from: null, to: { exact: ["portal.corp.example"], zones: ["internal.corp.example"] } },
      { from: { exact: ["portal.corp.example"], zones: ["internal.corp.example"] }, to: null },
    ]);
    expect((await api(acmeOrg, `/adcs-cas/${ca.id}`, { permittedNames: { exact: ["*.*.bad"], zones: [] } }, "PATCH")).status).toBe(400);
    // Only an Organization Administrator may.
    const member = await memberWithRole("member");
    expect((await api(acmeOrg, `/adcs-cas/${ca.id}`, { permittedNames: null }, "PATCH", member)).status).toBe(403);
  });

  test("they are enforced at proposal, at Name Change, and at Issuance", async () => {
    const { ca, agents, tls } = await adcsCa(undefined, { permittedNames: { exact: [], zones: ["corp.example"] } });
    const member = await memberWithRole("member");
    const outside = await create(ca, tls, ["www.example.org"], {}, member);
    expect(outside.status).toBe(422);
    expect(outside.body.error).toBe("www.example.org is outside the Permitted Name Rules of the ADCS CA Corp");

    const created = await create(ca, tls);
    expect(created.status).toBe(201);
    await work(agents[0]!);
    const renamed = await api(acmeOrg, `/managed-certificates/${created.body.id}/name-change`, { names: ["web.example.org"], ...(await csrFor(["web.example.org"])) });
    expect(renamed.status).toBe(422);
    expect(renamed.body.error).toContain("outside the Permitted Name Rules");

    // Narrowed after it was created: its next Issuance fails before anything is submitted.
    await api(acmeOrg, `/adcs-cas/${ca.id}`, { permittedNames: { exact: ["other.corp.example"], zones: [] } }, "PATCH");
    const again = await api(acmeOrg, `/managed-certificates/${created.body.id}/renewals`, {}, "POST");
    expect(again.status).toBe(202);
    await work(agents[0]!);
    expect((await mcOf(created.body.id)).issuance).toMatchObject({ status: "failed", failure: { code: "name_not_permitted" }, adcs: null });
    expect(adcs.issued).toHaveLength(1);
  });
});

describe("proposing and approving", () => {
  test("a Member proposes on an ADCS CA; an Approver sees the CA and template, and approving issues it", async () => {
    const { ca, agents, tls } = await adcsCa();
    const member = await memberWithRole("member");
    const proposed = await create(ca, tls, undefined, {}, member);
    expect(proposed.status).toBe(201);
    expect(proposed.body.approval.status).toBe("pending");

    const approver = await memberWithRole("approver");
    const queue = await api(acmeOrg, "/approvals", undefined, undefined, approver);
    expect(queue.body.items[0].issuer).toEqual({ kind: "adcs", adcsCa: { id: ca.id, name: "Corp" }, template: { id: tls.id, name: "CorpWebServer", displayName: "Corp Web Server" } });

    expect((await api(acmeOrg, `/managed-certificates/${proposed.body.id}/approve`, {}, "POST", approver)).status).toBe(200);
    await work(agents[0]!);
    expect((await mcOf(proposed.body.id)).issuance.status).toBe("succeeded");
  });

  test("a proposal whose template was hidden since is not approved", async () => {
    const { ca, tls } = await adcsCa();
    const proposed = await create(ca, tls, undefined, {}, await memberWithRole("member"));
    await api(acmeOrg, `/adcs-cas/${ca.id}/templates/${tls.id}/hide`, {}, "POST");
    const approver = await memberWithRole("approver");
    const approved = await api(acmeOrg, `/managed-certificates/${proposed.body.id}/approve`, {}, "POST", approver);
    expect(approved.status).toBe(422);
    expect(approved.body.error).toContain("an Organization Administrator hid it");
    expect((await mcOf(proposed.body.id)).approval.status).toBe("pending");
  });
});

describe("Name Changes", () => {
  test("a Name Change is issued under the same template", async () => {
    const { ca, agents, tls } = await adcsCa();
    const created = await create(ca, tls);
    await work(agents[0]!);
    const changed = await api(acmeOrg, `/managed-certificates/${created.body.id}/name-change`, { names: ["portal.corp.example"], ...(await csrFor(["portal.corp.example"])) });
    expect(changed.status).toBe(201);
    await work(agents[0]!);
    const mc = await mcOf(created.body.id);
    expect(mc.issuance).toMatchObject({ kind: "name_change", status: "succeeded" });
    expect(mc.currentCertificate.names).toEqual(["portal.corp.example"]);
    expect(adcs.issued.map((i) => i.template)).toEqual(["CorpWebServer", "CorpWebServer"]);
  });

  test("a validity is refused for a Name Change too", async () => {
    const { ca, agents, tls } = await adcsCa();
    const created = await create(ca, tls);
    await work(agents[0]!);
    const changed = await api(acmeOrg, `/managed-certificates/${created.body.id}/name-change`, { names: ["portal.corp.example"], ...(await csrFor(["portal.corp.example"])), validityDays: 30 });
    expect(changed.status).toBe(400);
  });
});

describe("the Agents that submit", () => {
  test("while no assigned Agent is online the Issuance waits for one, and is submitted once one is", async () => {
    const { ca, agents, tls } = await adcsCa();
    // The Agent's last contact is now an hour in the past: it is offline.
    setNow(after(3600_000));
    const created = await create(ca, tls);
    await h.settleIssuances();
    expect((await mcOf(created.body.id)).issuance).toMatchObject({ status: "running", adcs: { status: "waiting", agent: null } });

    // It polls again, and the next pass gives it the request.
    await agents[0]!.poll();
    await h.runAdcsRequests();
    expect((await mcOf(created.body.id)).issuance.adcs).toMatchObject({ status: "submitted", agent: { id: agents[0]!.id } });
    await work(agents[0]!);
    expect((await mcOf(created.body.id)).issuance.status).toBe("succeeded");
  });

  test("after 7 days with no Agent online it fails as no Agent available", async () => {
    const { ca, tls } = await adcsCa();
    const start = after(3600_000);
    setNow(start);
    const created = await create(ca, tls);
    await h.settleIssuances();
    setNow(new Date(start.getTime() + NO_AGENT_TIMEOUT_MS - 60_000));
    await h.runAdcsRequests();
    expect((await mcOf(created.body.id)).issuance.status).toBe("running");
    setNow(new Date(start.getTime() + NO_AGENT_TIMEOUT_MS));
    await h.runAdcsRequests();
    const failed = (await mcOf(created.body.id)).issuance;
    expect(failed).toMatchObject({ status: "failed", failure: { code: "no_agent_available" }, adcs: { status: "failed" } });
    expect(failed.failure.message).toContain("no Agent assigned to the ADCS CA Corp submitted the request within 7 days");
  });

  test("an Agent that cannot reach the CA passes the request to another assigned Agent", async () => {
    const cut = await AdcsDouble.create(CONFIG);
    cut.failure = new AdcsDoubleError("unreachable", "the RPC server is unavailable");
    const connected = await windowsAgent();
    const isolated = await windowsAgent(acmeOrg, cut);
    const { ca, tls } = await adcsCa([connected, isolated]);
    // The isolated one is the most recently heard from, so it is given the request first.
    setNow(after(60_000));
    await isolated.poll();
    const created = await create(ca, tls);
    await work(isolated);
    expect((await mcOf(created.body.id)).issuance.adcs).toMatchObject({ status: "submitted", agent: { id: connected.id } });
    await work(connected);
    expect((await mcOf(created.body.id)).issuance.status).toBe("succeeded");
    expect(isolated.executed.map((i) => i.type)).toContain("adcs.submit");
  });

  test("when no assigned Agent can reach the CA, the Issuance fails as unreachable", async () => {
    const { ca, agents, tls } = await adcsCa();
    const created = await create(ca, tls);
    adcs.failure = new AdcsDoubleError("unreachable", "the RPC server is unavailable");
    await work(agents[0]!);
    const failed = (await mcOf(created.body.id)).issuance;
    expect(failed).toMatchObject({ status: "failed", failure: { code: "ca_unreachable" } });
    expect(failed.failure.message).toContain("could reach it");
  });

  test("ADCS refusing the request fails the Issuance with its reason", async () => {
    const { ca, agents, tls } = await adcsCa();
    const created = await create(ca, tls);
    adcs.templates = defaultTemplates().map((t) => (t.name === "CorpWebServer" ? { ...t, enrollable: false } : t));
    await work(agents[0]!);
    const failed = (await mcOf(created.body.id)).issuance;
    expect(failed).toMatchObject({ status: "failed", failure: { code: "ca_rejected" } });
    expect(failed.failure.message).toContain("Access is denied");
  });

  test("an Agent given the request that does not take it in time is given up on for another", async () => {
    const slow = await windowsAgent();
    const quick = await windowsAgent();
    const { ca, tls } = await adcsCa([slow, quick]);
    setNow(after(60_000));
    await slow.poll();
    const created = await create(ca, tls);
    await h.settleIssuances();
    expect((await mcOf(created.body.id)).issuance.adcs.agent.id).toBe(slow.id);

    // It does not poll for the item; the other is online.
    setNow(after(60_000 + SUBMIT_TIMEOUT_MS));
    await quick.poll();
    await h.runAdcsRequests();
    expect((await mcOf(created.body.id)).issuance.adcs.agent.id).toBe(quick.id);
    await work(quick);
    expect((await mcOf(created.body.id)).issuance.status).toBe("succeeded");
    // It is not given the item it was given up on.
    await slow.work();
    expect(slow.received.filter((i) => i.type === "adcs.submit")).toEqual([]);
  });

  test("an Agent that took the request is waited for, never given up on for a second submission", async () => {
    const slow = await windowsAgent();
    const quick = await windowsAgent();
    const { ca, tls } = await adcsCa([slow, quick]);
    setNow(after(60_000));
    await slow.poll();
    slow.stalled = true;
    const created = await create(ca, tls);
    await work(slow);
    setNow(after(60_000 + 2 * SUBMIT_TIMEOUT_MS));
    await quick.poll();
    await h.runAdcsRequests();
    expect((await mcOf(created.body.id)).issuance.adcs).toMatchObject({ status: "submitted", agent: { id: slow.id } });
    expect(quick.received.filter((i) => i.type === "adcs.submit")).toEqual([]);
    // It reports at last, and that is the Certificate.
    slow.stalled = false;
    const item = slow.received.find((i) => i.type === "adcs.submit")!;
    expect((await slow.report(item.id, { ok: true, submission: await adcs.submit(item.payload.configString, item.payload.template, item.payload.csr) })).status).toBe(200);
    expect((await mcOf(created.body.id)).issuance.status).toBe("succeeded");
  });

  test("a template that became unavailable while the request waited fails it with that cause", async () => {
    const { ca, agents, tls } = await adcsCa();
    setNow(after(3600_000));
    const created = await create(ca, tls);
    await h.settleIssuances();
    adcs.templates = defaultTemplates().map((t) => (t.name === "CorpWebServer" ? { ...t, enrollable: false } : t));
    await refresh(ca, agents[0]!);
    await h.runAdcsRequests();
    expect((await mcOf(created.body.id)).issuance).toMatchObject({ status: "failed", failure: { code: "template_unavailable" } });
    expect(agents[0]!.received.filter((i) => i.type === "adcs.submit")).toEqual([]);
  });

  test("a template unavailable at submission fails the Issuance with that cause", async () => {
    const { ca, agents, tls } = await adcsCa();
    const created = await create(ca, tls);
    await work(agents[0]!);
    adcs.templates = defaultTemplates().filter((t) => t.name !== "CorpWebServer");
    await refresh(ca, agents[0]!);
    expect((await api(acmeOrg, `/managed-certificates/${created.body.id}/renewals`, {}, "POST")).status).toBe(202);
    await h.settleIssuances();
    const failed = (await mcOf(created.body.id)).issuance;
    expect(failed).toMatchObject({ status: "failed", failure: { code: "template_unavailable" } });
    expect(failed.failure.message).toContain("The CA no longer reports it.");
  });
});

describe("requests pending at ADCS", () => {
  /** At `at`, the Agents are heard from, the pass over the requests runs, and they carry out what it gave them. */
  async function passAt(at: Date, ...agents: TestAgent[]) {
    setNow(at);
    for (const agent of agents) await agent.poll();
    await h.runAdcsRequests();
    for (const agent of agents) await agent.work();
  }
  const checksBy = (agent: TestAgent) => agent.executed.filter((i) => i.type === "adcs.check");

  test("a request ADCS holds for a CA manager is pending at ADCS, checked again, and issued once approved", async () => {
    // The template needs a CA manager's approval, as ADCS reports it.
    adcs.templates = defaultTemplates().map((t) => (t.name === "CorpWebServer" ? { ...t, managerApproval: true } : t));
    const { ca, agents, tls } = await adcsCa();
    expect(ca.templates.find((t) => t.id === tls.id)).toMatchObject({ managerApproval: true });
    const [agent] = agents as [TestAgent];
    const created = await create(ca, tls);
    await work(agent);

    const [requestId] = [...adcs.pending.keys()];
    const pending = (await mcOf(created.body.id)).issuance;
    expect(pending).toMatchObject({ status: "running", adcs: { status: "pending", requestId, pendingUntil: after(PENDING_TIMEOUT_MS).toISOString() } });
    expect(adcs.issued).toHaveLength(0);

    // Not checked before the first wait is over; then checked, and still pending.
    await passAt(after(FIRST_CHECK_AFTER_MS - 1000), agent);
    expect(checksBy(agent)).toHaveLength(0);
    await passAt(after(FIRST_CHECK_AFTER_MS), agent);
    expect(checksBy(agent)).toHaveLength(1);
    // The Agent is asked by ADCS's ID of the request, with nothing of the platform's own.
    expect(checksBy(agent)[0]!.payload).toEqual({ configString: CONFIG, requestId });
    expect((await mcOf(created.body.id)).issuance).toMatchObject({ status: "running", adcs: { status: "pending" } });

    adcs.approve(requestId!);
    await passAt(after(FIRST_CHECK_AFTER_MS * 3), agent);
    const mc = await mcOf(created.body.id);
    expect(mc.issuance).toMatchObject({ status: "succeeded", adcs: { status: "issued", requestId, pendingUntil: null } });
    expect(mc.currentCertificate).toMatchObject({ names: ["web.corp.example"], adcs: { requestId } });
    expect(mc.currentCertificate.fingerprint).toBeString();

    const events = (await auditOf()).filter((e) => e.target?.id === created.body.id);
    expect(events.find((e) => e.action === "adcs_ca.request_submitted")!.detail).toMatchObject({ adcsRequestId: requestId, disposition: "pending" });
    expect(events.find((e) => e.action === "adcs_ca.request_pending")!.detail).toEqual({
      issuanceId: mc.issuance.id,
      adcsCa: { id: ca.id, name: "Corp" },
      template: { id: tls.id, name: "CorpWebServer" },
      agent: { id: agent.id, hostName: expect.stringMatching(/^win-/) },
      adcsRequestId: requestId,
      pendingUntil: after(PENDING_TIMEOUT_MS).toISOString(),
    });
    expect(events.filter((e) => e.action === "adcs_ca.request_pending")).toHaveLength(1);
    expect(events.find((e) => e.action === "issuance.succeeded")!.detail.issuer.adcsRequestId).toBe(requestId);
  });

  test("it is checked on a backoff that grows to once every 15 minutes", async () => {
    adcs.hold = true;
    const { ca, agents, tls } = await adcsCa();
    const [agent] = agents as [TestAgent];
    await create(ca, tls);
    await work(agent);
    // Every minute for two hours, the pass runs: the checks are 1, 2, 4, 8 minutes apart, then 15.
    const checkedAt: number[] = [];
    for (let minute = 1; minute <= 120; minute++) {
      const before = checksBy(agent).length;
      await passAt(after(minute * 60_000), agent);
      if (checksBy(agent).length > before) checkedAt.push(minute);
    }
    const waits = checkedAt.map((m, i) => m - (checkedAt[i - 1] ?? 0));
    expect(waits.slice(0, 5)).toEqual([1, 2, 4, 8, 15]);
    expect(new Set(waits.slice(4))).toEqual(new Set([LONGEST_CHECK_WAIT_MS / 60_000]));
    expect(adcs.checks).toBe(checkedAt.length);
  });

  test("a request a CA manager denies fails the Issuance with ADCS's disposition message", async () => {
    adcs.hold = true;
    const { ca, agents, tls } = await adcsCa();
    const [agent] = agents as [TestAgent];
    const created = await create(ca, tls);
    await work(agent);
    const [requestId] = [...adcs.pending.keys()];
    adcs.deny(requestId!, "Denied by CORP\\pki-manager: not an approved host");
    await passAt(after(FIRST_CHECK_AFTER_MS), agent);

    const failed = (await mcOf(created.body.id)).issuance;
    expect(failed).toMatchObject({ status: "failed", failure: { code: "request_denied" }, adcs: { status: "failed", requestId } });
    expect(failed.failure.message).toBe(`the ADCS CA Corp denied the request (ADCS request ${requestId}): Denied by CORP\\pki-manager: not an approved host`);
    const denied = (await auditOf()).find((e) => e.action === "adcs_ca.request_denied")!;
    expect(denied.target).toEqual({ type: "managed_certificate", id: created.body.id });
    expect(denied.detail).toMatchObject({ adcsRequestId: requestId, agent: { id: agent.id }, message: "Denied by CORP\\pki-manager: not an approved host" });
    // Nothing more is asked of ADCS for it.
    await passAt(after(60 * 60_000), agent);
    expect(checksBy(agent)).toHaveLength(1);
  });

  test("a request ADCS denies at submission fails at once", async () => {
    adcs.denyWith = "The request was denied by the policy module";
    const { ca, agents, tls } = await adcsCa();
    const created = await create(ca, tls);
    await work(agents[0]!);
    const failed = (await mcOf(created.body.id)).issuance;
    expect(failed).toMatchObject({ status: "failed", failure: { code: "request_denied" }, adcs: { requestId: [...adcs.denied.keys()][0] } });
    expect(failed.failure.message).toContain("The request was denied by the policy module");
    const events = await auditOf();
    expect(events.find((e) => e.action === "adcs_ca.request_submitted")!.detail.disposition).toBe("denied");
    expect(events.find((e) => e.action === "adcs_ca.request_denied")!.detail.message).toBe("The request was denied by the policy module");
    expect(events.some((e) => e.action === "adcs_ca.request_pending")).toBe(false);
  });

  test("a request pending 7 days after its submission fails as pending too long, though it waited for an Agent first", async () => {
    adcs.hold = true;
    const { ca, agents, tls } = await adcsCa();
    const [agent] = agents as [TestAgent];
    // Two days with no Agent online, then submitted.
    setNow(after(3600_000));
    const created = await create(ca, tls);
    await h.settleIssuances();
    const submittedAt = after(2 * DAY_MS);
    await passAt(submittedAt, agent);
    expect((await mcOf(created.body.id)).issuance.adcs).toMatchObject({ status: "pending", pendingUntil: new Date(submittedAt.getTime() + PENDING_TIMEOUT_MS).toISOString() });

    // Past the 7 days the Issuance first had, it still waits: ADCS holds it.
    setNow(after(8 * DAY_MS));
    expect(await h.timeOutIssuances()).toBe(0);
    await passAt(new Date(submittedAt.getTime() + PENDING_TIMEOUT_MS - 60_000), agent);
    expect((await mcOf(created.body.id)).issuance.status).toBe("running");
    await passAt(new Date(submittedAt.getTime() + PENDING_TIMEOUT_MS), agent);
    const failed = (await mcOf(created.body.id)).issuance;
    expect(failed).toMatchObject({ status: "failed", failure: { code: "pending_too_long" } });
    expect(failed.failure.message).toContain("for a CA manager's approval for 7 days");
    // Approved too late, it is not taken.
    adcs.approve([...adcs.pending.keys()][0]!);
    await passAt(new Date(submittedAt.getTime() + PENDING_TIMEOUT_MS + 3600_000), agent);
    expect((await mcOf(created.body.id)).issuance.status).toBe("failed");
  });

  test("any online assigned Agent checks it, and one that cannot reach the CA, or does not answer, passes the check on", async () => {
    adcs.hold = true;
    const first = await windowsAgent();
    const second = await windowsAgent();
    const { ca, tls } = await adcsCa([first, second]);
    setNow(after(60_000));
    await first.poll();
    const created = await create(ca, tls);
    await work(first);
    const [requestId] = [...adcs.pending.keys()];

    // The Agent that submitted it is away: the other checks it.
    await passAt(after(2 * 60_000), second);
    expect(checksBy(second)).toHaveLength(1);
    expect(first.received.filter((i) => i.type === "adcs.check")).toHaveLength(0);

    // The next is given to the one heard from last, which cannot reach the CA: the other is asked at once.
    const cut = await AdcsDouble.create(CONFIG);
    cut.failure = new AdcsDoubleError("unreachable", "the RPC server is unavailable");
    second.adcs = cut;
    setNow(after(4 * 60_000 - 10_000));
    await first.poll();
    setNow(after(4 * 60_000));
    await second.poll();
    await h.runAdcsRequests();
    await second.work();
    expect(checksBy(second)).toHaveLength(2);
    expect((await mcOf(created.body.id)).issuance.adcs).toMatchObject({ status: "pending", agent: { id: first.id } });
    await first.work();
    expect(checksBy(first)).toHaveLength(1);

    // A check not answered in time is asked of another.
    adcs.approve(requestId!);
    second.adcs = adcs;
    first.stalled = true;
    setNow(after(8 * 60_000 - 10_000));
    await second.poll();
    setNow(after(8 * 60_000));
    await first.poll();
    await h.runAdcsRequests();
    await first.work();
    expect((await mcOf(created.body.id)).issuance.adcs.agent.id).toBe(first.id);
    await passAt(after(8 * 60_000 + SUBMIT_TIMEOUT_MS), second);
    expect((await mcOf(created.body.id)).issuance).toMatchObject({ status: "succeeded", adcs: { status: "issued", requestId, agent: { id: second.id } } });
  });

  test("ADCS refusing to say where it stands fails the Issuance", async () => {
    adcs.hold = true;
    const { ca, agents, tls } = await adcsCa();
    const [agent] = agents as [TestAgent];
    const created = await create(ca, tls);
    await work(agent);
    // ADCS lost the request (it was deleted from its database).
    adcs.pending.clear();
    await passAt(after(FIRST_CHECK_AFTER_MS), agent);
    const failed = (await mcOf(created.body.id)).issuance;
    expect(failed).toMatchObject({ status: "failed", failure: { code: "ca_rejected" } });
    expect(failed.failure.message).toContain("the CA has no request");
  });
});

describe("Renewal and Deployments", () => {
  test("it renews by its Renewal Policy alone, and the CA is never asked when to renew", async () => {
    const { ca, agents, tls } = await adcsCa();
    const created = await create(ca, tls, undefined, { renewalPolicy: { mode: "automatic", daysBeforeExpiry: 330 } });
    await work(agents[0]!);
    const first = await mcOf(created.body.id);
    expect(first.renewal).toMatchObject({ dueBecause: "policy", ari: null });
    const due = new Date(first.renewal.dueAt);
    // Not before a tenth of its life, whatever the policy says.
    expect(due.getTime()).toBe(new Date(first.currentCertificate.notBefore).getTime() + (new Date(first.currentCertificate.notAfter).getTime() - new Date(first.currentCertificate.notBefore).getTime()) / 10);

    // The Agent keeps its credential current meanwhile, as it does.
    setNow(after(20 * DAY_MS));
    expect((await agents[0]!.rotate()).status).toBe(200);

    setNow(new Date(due.getTime() - 60_000));
    expect(await h.runRenewalScheduler()).toBe(0);
    setNow(due);
    // The Agent is heard from, so it is online to submit.
    await agents[0]!.poll();
    expect(await h.runRenewalScheduler()).toBe(1);
    await work(agents[0]!);
    const renewed = await mcOf(created.body.id);
    expect(renewed.issuance).toMatchObject({ kind: "renewal", status: "succeeded" });
    expect(renewed.currentCertificate.id).not.toBe(first.currentCertificate.id);
    expect(h.ari.asked).toEqual([]);
  });

  test("a Deployment's Agent makes the key, an ADCS Agent submits its CSR, and the Certificate is deployed", async () => {
    const { ca, agents, tls } = await adcsCa();
    const deployer = await TestAgent.registered(h, acmeOrg.cookie, acmeOrg.orgId, { hostName: "web-1" });
    const script = await api(acmeOrg, "/deployment-scripts", { name: "install", interpreter: "bash", content: "echo installed" });
    const set = await api(acmeOrg, "/deployments", { agentId: deployer.id, scriptId: script.body.id, names: ["web.corp.example"], keyAlgorithm: "rsa-2048", issuer: issuerOf(ca, tls) });
    expect(set.status).toBe(201);

    await deployer.work();
    await work(agents[0]!);
    await deployer.work();
    expect(deployer.executed.map((i) => i.type)).toEqual(["deployment.generate_key", "deployment.run"]);
    const mc = await mcOf(set.body.managedCertificateId);
    expect(mc.currentCertificate.adcs.templateId).toBe(tls.id);
    expect(deployer.deployed[0]!.item.payload.certificate.id).toBe(mc.currentCertificate.id);
  });

  test("a Deployment's key must meet the template's requirements", async () => {
    const { ca, tls } = await adcsCa();
    const deployer = await TestAgent.registered(h, acmeOrg.cookie, acmeOrg.orgId, { hostName: "web-1" });
    const script = await api(acmeOrg, "/deployment-scripts", { name: "install", interpreter: "bash", content: "echo installed" });
    const set = await api(acmeOrg, "/deployments", { agentId: deployer.id, scriptId: script.body.id, names: ["web.corp.example"], keyAlgorithm: "ecdsa-p384", issuer: issuerOf(ca, tls) });
    expect(set.status).toBe(422);
    expect(set.body.error).toContain("takes keys of RSA, ECDSA P-256, not ecdsa-p384");
  });
});

describe("removing the ADCS CA", () => {
  test("is refused while a Managed Certificate names it", async () => {
    const { ca, tls } = await adcsCa();
    await create(ca, tls);
    const removed = await api(acmeOrg, `/adcs-cas/${ca.id}`, undefined, "DELETE");
    expect(removed.status).toBe(409);
  });
});
