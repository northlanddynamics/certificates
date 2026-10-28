// ADCS CAs, through the platform's HTTP API: an Organization Administrator adds one by its name and config string and
// assigns it Windows Agents of the Organization; an online assigned Agent discovers it (its chain and its Certificate
// Templates) as it is added, and nothing is saved if none can. Here the Agent is the stand-in (agent-double.ts) and ADCS
// an in-memory double (adcs-double.ts); the Go Agent proper is tested in agent/ (Seam B).
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { randomBytes } from "node:crypto";
import { PASSWORD, createHarness, type Harness } from "./support/harness";
import { TestAgent } from "./support/agent-double";
import { AdcsDouble, AdcsDoubleError, CDP_URL } from "./support/adcs-double";

setDefaultTimeout(60_000);

let h: Harness;
let operator: string;
let acmeOrg: { orgId: string; cookie: string };
let globex: { orgId: string; cookie: string };
let adcs: AdcsDouble;
type Org = typeof acmeOrg;

const CONFIG = "ca01.corp.example\\Corp Issuing CA";

beforeAll(async () => {
  // An Agent has 1.5 seconds to answer before another is tried.
  h = await createHarness({ adcsRelay: { attemptTimeoutMs: 1500 }, dnsRelay: { pollMs: 10 } });
  adcs = await AdcsDouble.create(CONFIG);
});
beforeEach(async () => {
  await h.reset();
  adcs.failure = null;
  operator = await h.createOperator("op@platform.test", PASSWORD);
  acmeOrg = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
  globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
});
afterAll(async () => {
  await h.close();
});

const api = (org: Org, path: string, body?: unknown, method?: string) => h.api(`/api/organizations/${org.orgId}${path}`, { cookie: org.cookie, body, method });
const auditOf = async (org: Org = acmeOrg) => (await api(org, "/audit-events")).body.items as { action: string; detail: any; target: any }[];

/** A registered Agent on a Windows host that reaches `reaches` (the ADCS double unless given none). */
async function windowsAgent(org: Org = acmeOrg, reaches: AdcsDouble | null = adcs) {
  const agent = await TestAgent.registered(h, org.cookie, org.orgId, { hostName: `win-${randomBytes(3).toString("hex")}`, os: "windows" });
  agent.adcs = reaches;
  return agent;
}

/** Adds an ADCS CA while the Agents work, as they would be. */
async function add(agents: TestAgent[], over: { name?: string; configString?: string } = {}, org: Org = acmeOrg) {
  const stops = agents.map((a) => a.startWorking());
  try {
    return await api(org, "/adcs-cas", { name: over.name ?? "Corp", configString: over.configString ?? CONFIG, agentIds: agents.map((a) => a.id) });
  } finally {
    for (const stop of stops) await stop();
  }
}

async function added(agents: TestAgent[], over: Parameters<typeof add>[1] = {}) {
  const res = await add(agents, over);
  expect(res.status).toBe(201);
  return res.body;
}

/** A member of the Organization in the role, signed in. */
async function memberWithRole(role: string) {
  const email = `${role}@acme.test`;
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: acmeOrg.cookie, body: { email, role, organizationId: acmeOrg.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return await h.signIn(email, PASSWORD);
}

describe("adding an ADCS CA", () => {
  test("an assigned Agent discovers the CA: its chain, the CDP URLs of its certificate and its templates with their facts", async () => {
    const agent = await windowsAgent();
    const ca = await added([agent]);

    expect(ca).toMatchObject({ name: "Corp", configString: CONFIG, agentIds: [agent.id], cdpUrls: [CDP_URL] });
    expect(ca.caCertificate.subject).toBe("CN=Corp Issuing CA, DC=corp, DC=example");
    expect(ca.chain.map((c: any) => c.subject)).toEqual(["CN=Corp Issuing CA, DC=corp, DC=example", "CN=Corp Root CA, DC=corp, DC=example"]);
    expect(ca.templates.map((t: any) => [t.name, t.available])).toEqual([
      ["CorpDevice", true],
      ["CorpWebServer", true],
      // It builds the subject from Active Directory, so the platform cannot use it.
      ["Workstation", false],
    ]);
    expect(ca.templates[1]).toMatchObject({
      oid: "1.3.6.1.4.1.311.21.8.1.1",
      displayName: "Corp Web Server",
      extendedKeyUsages: ["1.3.6.1.5.5.7.3.1"],
      validityDays: 365,
      minimumKeySize: 2048,
      keyAlgorithms: ["rsa", "ecdsa-p256"],
      managerApproval: false,
      subjectFromRequest: true,
      enrollable: true,
      published: true,
    });
    expect(ca.templates[0].managerApproval).toBe(true);

    // The Agent was asked for the CA by its config string and nothing else: it reaches ADCS as its own account.
    expect(agent.executed.map((i) => [i.type, i.payload])).toEqual([["adcs.discover", { configString: CONFIG }]]);
    expect((await api(acmeOrg, `/adcs-cas/${ca.id}`)).body).toEqual(ca);
    expect((await api(acmeOrg, "/adcs-cas")).body.items).toEqual([ca]);
  });

  test("adding it and its discovery are Audit Events", async () => {
    const agent = await windowsAgent();
    const ca = await added([agent]);
    const events = await auditOf();
    const created = events.find((e) => e.action === "adcs_ca.created")!;
    expect(created.target).toEqual({ type: "adcs_ca", id: ca.id });
    expect(created.detail).toEqual({ name: "Corp", configString: CONFIG, agentIds: [agent.id] });
    const discovered = events.find((e) => e.action === "adcs_ca.discovered")!;
    expect(discovered.detail).toMatchObject({
      name: "Corp",
      agent: { id: agent.id, hostName: expect.stringMatching(/^win-/) },
      caCertificate: { subject: "CN=Corp Issuing CA, DC=corp, DC=example", fingerprint: ca.caCertificate.fingerprint },
      cdpUrls: [CDP_URL],
      templates: { available: ["CorpWebServer", "CorpDevice"], unavailable: ["Workstation"] },
    });
  });

  test("its chain can be downloaded, the CA certificate first", async () => {
    const ca = await added([await windowsAgent()]);
    const res = await h.app.request(`http://localhost/api/organizations/${acmeOrg.orgId}/adcs-cas/${ca.id}/chain`, { headers: { cookie: acmeOrg.cookie } });
    expect(res.status).toBe(200);
    const pems = (await res.text()).match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g)!;
    expect(pems.map((pem) => new x509.X509Certificate(pem).subject)).toEqual(["CN=Corp Issuing CA, DC=corp, DC=example", "CN=Corp Root CA, DC=corp, DC=example"]);
  });

  test("a CA no Agent can reach saves nothing, and says why", async () => {
    const agent = await windowsAgent();
    const res = await add([agent], { configString: "ca99.corp.example\\Corp Issuing CA" });
    expect(res.status).toBe(502);
    expect(res.body.error).toContain("the RPC server is unavailable at ca99.corp.example");
    expect((await api(acmeOrg, "/adcs-cas")).body.items).toEqual([]);
    expect((await auditOf()).filter((e) => e.action.startsWith("adcs_ca."))).toEqual([]);
  });

  test("a CA that ADCS refuses saves nothing, and gives the Agent's reason", async () => {
    const agent = await windowsAgent();
    const res = await add([agent], { configString: "ca01.corp.example\\No Such CA" });
    expect(res.status).toBe(422);
    expect(res.body.error).toContain("ca01.corp.example has no CA named No Such CA");

    adcs.failure = new AdcsDoubleError("rejected", "access is denied");
    const denied = await add([agent]);
    expect(denied.status).toBe(422);
    expect(denied.body.error).toContain("access is denied");
    expect((await api(acmeOrg, "/adcs-cas")).body.items).toEqual([]);
  });

  test("an Agent that cannot reach ADCS refuses, saying so", async () => {
    // As an Agent built for another system answers: it reports Windows here only to be assignable.
    const res = await add([await windowsAgent(acmeOrg, null)]);
    expect(res.status).toBe(422);
    expect(res.body.error).toContain("this Agent cannot reach ADCS");
  });

  test("an Agent that cannot reach the CA passes it to another assigned Agent", async () => {
    const cut = await AdcsDouble.create(CONFIG);
    cut.failure = new AdcsDoubleError("unreachable", "the RPC server is unavailable");
    const isolated = await windowsAgent(acmeOrg, cut);
    const connected = await windowsAgent();
    const ca = await added([isolated, connected]);
    expect(ca.templates).toHaveLength(3);
    expect(connected.executed.map((i) => i.type)).toEqual(["adcs.discover"]);
  });

  test("with no assigned Agent online, or none answering, nothing is saved", async () => {
    const stalled = await windowsAgent();
    stalled.stalled = true;
    const res = await add([stalled]);
    expect(res.status).toBe(502);
    expect(res.body.error).toMatch(/did not answer within 1.5 seconds/);

    h.setNow(new Date(Date.now() + 365 * 24 * 3600_000));
    const offline = await api(acmeOrg, "/adcs-cas", { name: "Corp", configString: CONFIG, agentIds: [stalled.id] });
    expect(offline.status).toBe(502);
    expect(offline.body.error).toMatch(/no Agent that is assigned to this ADCS CA is online/);
    expect((await api(acmeOrg, "/adcs-cas")).body.items).toEqual([]);
  });

  test("names and config strings are unique within the Organization, and another Organization may use the same", async () => {
    const agent = await windowsAgent();
    await added([agent]);
    expect((await add([agent], { configString: "ca02.corp.example\\Other" })).status).toBe(409);
    expect((await add([agent], { name: "Other" })).status).toBe(409);
    // Refused before any Agent was asked.
    expect(agent.executed).toHaveLength(1);
    expect((await add([await windowsAgent(globex)], {}, globex)).status).toBe(201);
  });

  test("a config string must be host\\CA Name", async () => {
    const agent = await windowsAgent();
    for (const configString of ["ca01.corp.example", "\\Corp", "ca01\\", "a\\b\\c", ""]) {
      expect((await api(acmeOrg, "/adcs-cas", { name: "Corp", configString, agentIds: [agent.id] })).status).toBe(400);
    }
    expect(agent.received).toEqual([]);
  });
});

describe("assigning Agents", () => {
  test("only Windows Agents of the Organization that are not revoked can be assigned, each once, and at least one", async () => {
    const linux = await TestAgent.registered(h, acmeOrg.cookie, acmeOrg.orgId, { hostName: "lin-01", os: "linux" });
    const theirs = await windowsAgent(globex);
    const revoked = await windowsAgent();
    await api(acmeOrg, `/agents/${revoked.id}/revoke`, {}, "POST");
    const mine = await windowsAgent();

    const linuxRefused = await api(acmeOrg, "/adcs-cas", { name: "Corp", configString: CONFIG, agentIds: [linux.id] });
    expect(linuxRefused.status).toBe(400);
    expect(linuxRefused.body.error).toBe("the Agent lin-01 runs on linux, not Windows, so it cannot reach ADCS");
    for (const agentIds of [[theirs.id], [revoked.id], [mine.id, "not-an-agent"], [crypto.randomUUID()], [mine.id, mine.id], []]) {
      expect((await api(acmeOrg, "/adcs-cas", { name: "Corp", configString: CONFIG, agentIds })).status).toBe(400);
    }
    expect(mine.received).toEqual([]);
    expect((await api(acmeOrg, "/adcs-cas")).body.items).toEqual([]);
  });

  test("the Agents can be changed and the CA renamed, which is an Audit Event with the changes; its config string stays", async () => {
    const first = await windowsAgent();
    const second = await windowsAgent();
    const ca = await added([first]);

    const changed = await api(acmeOrg, `/adcs-cas/${ca.id}`, { name: "Corp Issuing", agentIds: [second.id, first.id], configString: "other\\CA" }, "PATCH");
    expect(changed.status).toBe(200);
    expect(changed.body).toMatchObject({ name: "Corp Issuing", configString: CONFIG, agentIds: [first.id, second.id].sort() });

    const event = (await auditOf()).find((e) => e.action === "adcs_ca.updated")!;
    expect(event.target).toEqual({ type: "adcs_ca", id: ca.id });
    expect(event.detail).toEqual({ name: "Corp Issuing", changes: { name: { from: "Corp", to: "Corp Issuing" }, agentIds: { from: [first.id], to: [first.id, second.id].sort() } } });

    // Nothing changed, nothing recorded.
    expect((await api(acmeOrg, `/adcs-cas/${ca.id}`, { name: "Corp Issuing" }, "PATCH")).status).toBe(200);
    expect((await auditOf()).filter((e) => e.action === "adcs_ca.updated")).toHaveLength(1);
  });

  test("changing the Agents is refused for an Agent that cannot be assigned", async () => {
    const agent = await windowsAgent();
    const ca = await added([agent]);
    const linux = await TestAgent.registered(h, acmeOrg.cookie, acmeOrg.orgId, { os: "linux" });
    expect((await api(acmeOrg, `/adcs-cas/${ca.id}`, { agentIds: [linux.id] }, "PATCH")).status).toBe(400);
    expect((await api(acmeOrg, `/adcs-cas/${ca.id}`, { agentIds: [] }, "PATCH")).status).toBe(400);
    expect((await api(acmeOrg, `/adcs-cas/${ca.id}`)).body.agentIds).toEqual([agent.id]);
  });
});

describe("removing an ADCS CA", () => {
  test("an ADCS CA nothing refers to can be removed, which is an Audit Event", async () => {
    const ca = await added([await windowsAgent()]);
    expect((await api(acmeOrg, `/adcs-cas/${ca.id}`, undefined, "DELETE")).status).toBe(204);
    expect((await api(acmeOrg, "/adcs-cas")).body.items).toEqual([]);
    expect((await api(acmeOrg, `/adcs-cas/${ca.id}`)).status).toBe(404);
    expect((await api(acmeOrg, `/adcs-cas/${ca.id}`, undefined, "DELETE")).status).toBe(404);
    const event = (await auditOf()).find((e) => e.action === "adcs_ca.deleted")!;
    expect(event).toMatchObject({ target: { type: "adcs_ca", id: ca.id }, detail: { name: "Corp", configString: CONFIG } });
  });
});

describe("who may see and manage ADCS CAs", () => {
  test("/api/me reports the permissions: everyone reads, Organization Administrators manage", async () => {
    const permissions = async (cookie: string) => (await h.api("/api/me", { cookie })).body.organizations[0].permissions;
    expect((await permissions(acmeOrg.cookie)).adcsCa).toEqual(["read", "create", "update", "delete"]);
    expect((await permissions(await memberWithRole("member"))).adcsCa).toEqual(["read"]);
    expect((await permissions(await memberWithRole("approver"))).adcsCa).toEqual(["read"]);
  });

  test("a Member sees the ADCS CAs and downloads their chains, and changes nothing", async () => {
    const agent = await windowsAgent();
    const ca = await added([agent]);
    const cookie = await memberWithRole("member");
    const as = (path: string, body?: unknown, method?: string) => h.api(`/api/organizations/${acmeOrg.orgId}${path}`, { cookie, body, method });

    expect((await as("/adcs-cas")).body.items.map((c: any) => c.id)).toEqual([ca.id]);
    expect((await as(`/adcs-cas/${ca.id}`)).body.templates).toHaveLength(3);
    expect((await h.app.request(`http://localhost/api/organizations/${acmeOrg.orgId}/adcs-cas/${ca.id}/chain`, { headers: { cookie } })).status).toBe(200);
    expect((await as("/adcs-cas", { name: "Mine", configString: "ca02.corp.example\\X", agentIds: [agent.id] })).status).toBe(403);
    expect((await as(`/adcs-cas/${ca.id}`, { name: "Mine" }, "PATCH")).status).toBe(403);
    expect((await as(`/adcs-cas/${ca.id}`, undefined, "DELETE")).status).toBe(403);
  });

  test("an Organization sees, changes and removes none of another's ADCS CAs", async () => {
    const ca = await added([await windowsAgent()]);
    expect((await api(globex, "/adcs-cas")).body.items).toEqual([]);
    expect((await api(globex, `/adcs-cas/${ca.id}`)).status).toBe(404);
    expect((await api(globex, `/adcs-cas/${ca.id}`, { name: "Taken" }, "PATCH")).status).toBe(404);
    expect((await api(globex, `/adcs-cas/${ca.id}`, undefined, "DELETE")).status).toBe(404);
    expect((await api(acmeOrg, `/adcs-cas/${ca.id}`)).body.name).toBe("Corp");
  });
});
