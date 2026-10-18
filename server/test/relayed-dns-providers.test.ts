// Relayed DNS Providers, through the platform's HTTP API: an Organization Administrator has some of the Organization's
// Agents relay a DNS Provider, so that DNS the hosted platform cannot reach (on-prem BIND or Infoblox) still serves
// DCV. The operations (publish, remove, test) reach an online relay Agent as work items, and the Agent carries them out
// with its own provider code. Here the Agent is a stand-in (agent-double.ts) that runs the platform's provider code
// against the real BIND, so that issuing through a relay is real; the Go Agent proper is tested in agent/ (Seam B).
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import acme from "acme-client";
import { randomBytes } from "node:crypto";
import { BIND, PASSWORD, createHarness, type Harness } from "./support/harness";
import { TestAgent } from "./support/agent-double";

setDefaultTimeout(60_000);

let h: Harness;
let operator: string;
let acmeOrg: { orgId: string; cookie: string };
let globex: { orgId: string; cookie: string };
type Org = typeof acmeOrg;

beforeAll(async () => {
  // Work items wait 1.5 seconds for an Agent to answer before another is tried.
  h = await createHarness({ dnsRelay: { attemptTimeoutMs: 1500, pollMs: 10 } });
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
const auditOf = async (org: Org = acmeOrg) => (await api(org, "/audit-events")).body.items as { action: string; detail: any; target: any }[];

const bind = (over: { name?: string; secret?: string; relayAgentIds?: string[] } = {}) => ({
  name: over.name ?? "BIND",
  type: "rfc2136",
  settings: { server: BIND.server, port: BIND.port, zone: BIND.zone, keyName: BIND.keyName },
  secret: over.secret ?? BIND.keySecret,
  ...(over.relayAgentIds ? { relayAgentIds: over.relayAgentIds } : {}),
});
async function connect(over: Parameters<typeof bind>[0] = {}, org: Org = acmeOrg) {
  const created = await api(org, "/dns-providers", bind(over));
  expect(created.status).toBe(201);
  return created.body as { id: string; relayAgentIds: string[] };
}
const testConnection = async (providerId: string, org: Org = acmeOrg) => (await api(org, `/dns-providers/${providerId}/test`, {}, "POST")).body as { ok: boolean; error?: string };
const relay = (providerId: string, agentIds: unknown, org: Org = acmeOrg) => api(org, `/dns-providers/${providerId}/relay`, { agentIds }, "PUT");

/** A member of the Organization in the role, signed in. */
async function memberWithRole(role: string) {
  const email = `${role}@acme.test`;
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: acmeOrg.cookie, body: { email, role, organizationId: acmeOrg.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return await h.signIn(email, PASSWORD);
}

describe("assigning relay Agents", () => {
  test("a DNS Provider runs directly until Agents are assigned, and directly again when none are", async () => {
    const provider = await connect();
    expect(provider.relayAgentIds).toEqual([]);
    const a = await agentIn();
    const b = await agentIn();

    const assigned = await relay(provider.id, [a.id, b.id]);
    expect(assigned.status).toBe(200);
    expect([...assigned.body.relayAgentIds].sort()).toEqual([a.id, b.id].sort());
    expect([...(await api(acmeOrg, "/dns-providers")).body.items[0].relayAgentIds].sort()).toEqual([a.id, b.id].sort());

    const direct = await relay(provider.id, []);
    expect(direct.body.relayAgentIds).toEqual([]);
    // Back to direct: the platform itself reaches BIND.
    expect(await testConnection(provider.id)).toEqual({ ok: true });
  });

  test("Agents can be assigned when the provider is connected", async () => {
    const a = await agentIn();
    const provider = await connect({ relayAgentIds: [a.id] });
    expect(provider.relayAgentIds).toEqual([a.id]);
  });

  test("changing the assignment is an Audit Event, and the provider's other settings are untouched", async () => {
    const provider = await connect();
    const a = await agentIn();
    await relay(provider.id, [a.id]);
    const event = (await auditOf()).find((e) => e.action === "dns_provider.relay_changed")!;
    expect(event.target).toEqual({ type: "dns_provider", id: provider.id });
    expect(event.detail).toMatchObject({ agentIds: [a.id], previousAgentIds: [] });
    const listed = (await api(acmeOrg, "/dns-providers")).body.items[0];
    expect(listed).toMatchObject({ name: "BIND", type: "rfc2136", settings: { zone: BIND.zone } });
  });

  test("only the Organization's own Agents that are not revoked can be assigned, and only by an Organization Administrator", async () => {
    const provider = await connect();
    const mine = await agentIn();
    const theirs = await agentIn(globex);
    const revoked = await agentIn();
    await api(acmeOrg, `/agents/${revoked.id}/revoke`, {}, "POST");

    for (const agentIds of [[theirs.id], [revoked.id], [mine.id, "not-an-agent"], [crypto.randomUUID()], [mine.id, mine.id]]) {
      expect((await relay(provider.id, agentIds)).status).toBe(400);
    }
    expect((await api(acmeOrg, "/dns-providers", bind({ name: "Other", relayAgentIds: [theirs.id] }))).status).toBe(400);
    expect((await api(acmeOrg, "/dns-providers")).body.items.map((p: any) => p.relayAgentIds)).toEqual([[]]);

    for (const role of ["approver", "member"]) {
      const cookie = await memberWithRole(role);
      expect((await h.api(`/api/organizations/${acmeOrg.orgId}/dns-providers/${provider.id}/relay`, { cookie, method: "PUT", body: { agentIds: [mine.id] } })).status).toBe(403);
    }
    expect((await relay(provider.id, [mine.id], globex)).status).toBe(404);
    expect((await auditOf()).filter((e) => e.action === "dns_provider.relay_changed")).toEqual([]);
  });
});

describe("work items for relay Agents", () => {
  test("testing the connection becomes a work item for an assigned online Agent, which carries it out and reports", async () => {
    const a = await agentIn();
    const provider = await connect({ relayAgentIds: [a.id] });
    const stop = a.startWorking();
    const outcome = await testConnection(provider.id);
    await stop();

    expect(outcome).toEqual({ ok: true });
    expect(a.executed.map((i) => i.type)).toEqual(["dns.test"]);
    expect(a.executed[0]!.payload.provider).toEqual({
      type: "rfc2136",
      settings: { server: BIND.server, port: BIND.port, zone: BIND.zone, keyName: BIND.keyName, algorithm: "hmac-sha256" },
      secret: BIND.keySecret,
    });
  });

  test("an Agent that is not assigned is given nothing, and an item is given once", async () => {
    const relaying = await agentIn();
    const bystander = await agentIn();
    const provider = await connect({ relayAgentIds: [relaying.id] });
    const stopBystander = bystander.startWorking();
    const stop = relaying.startWorking();
    await testConnection(provider.id);
    await stop();
    await stopBystander();

    expect(bystander.received).toEqual([]);
    expect(relaying.received.map((i) => i.type)).toEqual(["dns.test"]);
    expect((await relaying.poll()).body.items).toEqual([]);
  });

  test("the credentials reach the Agent only inside the work item for the operation, and are shown nowhere", async () => {
    const a = await agentIn();
    const provider = await connect({ relayAgentIds: [a.id] });
    const stop = a.startWorking();
    await testConnection(provider.id);
    await stop();

    const shown = JSON.stringify([
      (await api(acmeOrg, "/dns-providers")).body,
      (await api(acmeOrg, "/agents")).body,
      await auditOf(),
      await relay(provider.id, [a.id]),
      (await a.poll()).body,
    ]);
    expect(shown).not.toContain(BIND.keySecret);
    // The Agent's own report of a failure does not carry them either: BIND refusing a key says which, not what.
    const wrong = await connect({ name: "Wrong key", secret: Buffer.from("not-the-servers-key").toString("base64"), relayAgentIds: [a.id] });
    const stopAgain = a.startWorking();
    const failed = await testConnection(wrong.id);
    await stopAgain();
    expect(failed.ok).toBe(false);
    expect(JSON.stringify([failed, await auditOf()])).not.toContain(Buffer.from("not-the-servers-key").toString("base64"));
  });

  test("an Agent reports only on the items it was given, once, and a revoked Agent not at all", async () => {
    const a = await agentIn();
    const other = await agentIn();
    const provider = await connect({ relayAgentIds: [a.id] });
    a.stalled = true;
    const pending = testConnection(provider.id);
    let item: any;
    while (!(item = a.received[0])) await a.work();

    expect((await other.report(item.id, { ok: true })).status).toBe(404);
    expect((await a.report(crypto.randomUUID(), { ok: true })).status).toBe(404);
    expect((await a.report("not-an-id", { ok: true })).status).toBe(404);
    expect((await a.report(item.id, { ok: true })).status).toBe(200);
    expect((await a.report(item.id, { ok: false, error: "changed my mind" })).status).toBe(409);
    expect(await pending).toEqual({ ok: true });

    await api(acmeOrg, `/agents/${a.id}/revoke`, {}, "POST");
    expect((await a.report(item.id, { ok: true })).status).toBe(401);
  });

  test("an item that waited too long to be given to its Agent is dropped, not carried out late", async () => {
    const a = await agentIn();
    const provider = await connect({ relayAgentIds: [a.id] });
    const pending = testConnection(provider.id);
    // The Agent was away for an hour (or the platform restarted): what was asked then is not wanted now.
    await new Promise((resolve) => setTimeout(resolve, 100));
    h.setNow(new Date("2026-01-01T01:00:00Z"));
    expect((await a.poll()).body.items).toEqual([]);
    expect((await pending).ok).toBe(false);
    expect((await a.poll()).body.items).toEqual([]);
  });

  test("a poll waits for work when the platform is set to long-poll, and returns as soon as there is some", async () => {
    const longPolling = await createHarness({ agentGateway: { longPollSeconds: 5 }, dnsRelay: { pollMs: 10 } });
    try {
      const op = await longPolling.createOperator("op2@platform.test", PASSWORD);
      const org = await longPolling.createOrgWithAdmin(op, "initech", "admin@initech.test");
      const agent = await TestAgent.registered(longPolling, org.cookie, org.orgId);
      const provider = await longPolling.api(`/api/organizations/${org.orgId}/dns-providers`, { cookie: org.cookie, body: bind({ relayAgentIds: [agent.id] }) });

      const started = Date.now();
      const polling = agent.work();
      await new Promise((resolve) => setTimeout(resolve, 300));
      const tested = longPolling.api(`/api/organizations/${org.orgId}/dns-providers/${provider.body.id}/test`, { cookie: org.cookie, method: "POST", body: {} });
      const items = await polling;
      expect(items.map((i) => i.type)).toEqual(["dns.test"]);
      expect(Date.now() - started).toBeLessThan(3000);
      expect((await tested).body).toEqual({ ok: true });
    } finally {
      await longPolling.close();
    }
  });
});

describe("which relay Agent is used", () => {
  test("an offline Agent is passed over for an online one", async () => {
    const gone = await agentIn(acmeOrg, "gone");
    const here = await agentIn(acmeOrg, "here");
    const provider = await connect({ relayAgentIds: [gone.id, here.id] });
    // `gone` last made contact ten minutes before `here` did.
    h.setNow(new Date("2026-01-01T00:10:00Z"));
    await here.poll();
    // `gone` does not poll: an Agent that is offline does not.
    const stopHere = here.startWorking();
    expect(await testConnection(provider.id)).toEqual({ ok: true });
    await stopHere();

    expect(gone.received).toEqual([]);
    expect(here.executed.map((i) => i.type)).toEqual(["dns.test"]);
  });

  test("when none is online the operation fails, saying which Agents were not", async () => {
    const a = await agentIn(acmeOrg, "web-01");
    const b = await agentIn(acmeOrg, "web-02");
    const provider = await connect({ name: "Internal DNS", relayAgentIds: [a.id, b.id] });
    await api(acmeOrg, `/agents/${b.id}/revoke`, {}, "POST");
    h.setNow(new Date("2026-01-01T00:10:00Z"));

    const outcome = await testConnection(provider.id);
    expect(outcome.ok).toBe(false);
    expect(outcome.error).toMatch(/no Agent that relays this DNS Provider is online/);
    expect(outcome.error).toContain("web-01");
    expect(outcome.error).toContain("web-02");
    expect(outcome.error).toMatch(/revoked/);
    expect(a.received).toEqual([]);
  });

  test("an Agent that takes an item and does not answer is given up on, and another online Agent does it", async () => {
    const stalled = await agentIn(acmeOrg, "stalled");
    const working = await agentIn(acmeOrg, "working");
    const provider = await connect({ relayAgentIds: [stalled.id, working.id] });
    // The stalled one made contact last, so it is tried first.
    h.setNow(new Date("2026-01-01T00:00:30Z"));
    await stalled.poll();
    stalled.stalled = true;
    const pending = testConnection(provider.id);
    while (stalled.received.length === 0) await stalled.work();
    const stopWorking = working.startWorking();
    const outcome = await pending;
    await stopWorking();

    expect(outcome).toEqual({ ok: true });
    expect(stalled.received.map((i) => i.type)).toEqual(["dns.test"]);
    expect(working.executed.map((i) => i.type)).toEqual(["dns.test"]);
    // What it was too late with is refused.
    expect((await stalled.report(stalled.received[0]!.id, { ok: true })).status).toBe(409);
  });

  test("when every online Agent stalls, the operation fails with that cause", async () => {
    const stalled = await agentIn(acmeOrg, "stalled");
    const provider = await connect({ relayAgentIds: [stalled.id] });
    stalled.stalled = true;
    const stop = stalled.startWorking();
    const outcome = await testConnection(provider.id);
    await stop();
    expect(outcome.ok).toBe(false);
    expect(outcome.error).toMatch(/stalled.*1\.5 seconds/);
  });

  test("what the Agent says went wrong is what the operation says, and a provider that cannot be used by the Agent fails the same way as directly", async () => {
    const a = await agentIn(acmeOrg, "web-01");
    const provider = await connect({ secret: Buffer.from("not-the-servers-key").toString("base64"), relayAgentIds: [a.id] });
    const stop = a.startWorking();
    const outcome = await testConnection(provider.id);
    await stop();
    expect(outcome.ok).toBe(false);
    expect(outcome.error).toMatch(/web-01/);
    expect(outcome.error).toMatch(/TSIG|BADSIG|signature/i);
  });
});

describe("issuing through a relayed DNS Provider", () => {
  const direct = () => `t${randomBytes(5).toString("hex")}.${BIND.zone}`;

  async function create(org: Org, names: string[]) {
    const key = await acme.crypto.createPrivateEcdsaKey("P-256");
    const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
    const created = await api(org, "/managed-certificates", { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() });
    expect(created.status).toBe(201);
    await h.settleIssuances();
    return (await api(org, `/managed-certificates/${created.body.id}`)).body;
  }

  test("a Certificate is issued with Direct DCV whose challenge record the Agent published and removed", async () => {
    expect((await api(acmeOrg, "/acme-accounts", { termsOfServiceAgreed: true })).status).toBe(201);
    const a = await agentIn();
    await connect({ relayAgentIds: [a.id] });
    const name = direct();
    const stop = a.startWorking();
    const issued = await create(acmeOrg, [name]);
    await stop();

    expect(issued.issuance).toMatchObject({ status: "succeeded", failure: null });
    expect(issued.currentCertificate.names).toEqual([name]);
    expect(a.executed.map((i) => [i.type, i.payload.record.name])).toEqual([
      ["dns.present", `_acme-challenge.${name}`],
      ["dns.cleanup", `_acme-challenge.${name}`],
    ]);
    // Cleaned up: nothing is left at the name.
    expect(await h.bindTxt.lookupTxt(`_acme-challenge.${name}`)).toEqual([]);
  });

  test("with no relay Agent online the Issuance fails with the DNS Provider unreachable and why", async () => {
    expect((await api(acmeOrg, "/acme-accounts", { termsOfServiceAgreed: true })).status).toBe(201);
    const a = await agentIn(acmeOrg, "web-01");
    await connect({ relayAgentIds: [a.id] });
    h.setNow(new Date("2026-01-01T01:00:00Z"));

    const issued = await create(acmeOrg, [direct()]);
    expect(issued.issuance).toMatchObject({ status: "failed", failure: { code: "dns_provider_unreachable" } });
    expect(issued.issuance.failure.message).toContain('through DNS Provider "BIND" failed');
    expect(issued.issuance.failure.message).toMatch(/no Agent that relays this DNS Provider is online.*web-01/);
  });

  test("when the Agent's DNS refuses the record the Issuance fails as it does for a direct provider", async () => {
    expect((await api(acmeOrg, "/acme-accounts", { termsOfServiceAgreed: true })).status).toBe(201);
    const a = await agentIn();
    await connect({ secret: Buffer.from("not-the-servers-key").toString("base64"), relayAgentIds: [a.id] });
    const stop = a.startWorking();
    const issued = await create(acmeOrg, [direct()]);
    await stop();
    expect(issued.issuance).toMatchObject({ status: "failed", failure: { code: "dns_update_rejected" } });
  });
});
