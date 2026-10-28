// Revoking a Certificate from an ADCS CA, through the platform's HTTP API and the Agent protocol: an Owner or an
// Organization Administrator asks, with an RFC 5280 reason; an online Agent assigned to the CA carries out `adcs.revoke`,
// and the Revocation is recorded only once ADCS confirms it. A refusal or an unreachable CA fails the request with its
// cause and leaves the Certificate unrevoked. Here the Agents are stand-ins (agent-double.ts) and ADCS an in-memory double
// (adcs-double.ts).
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import acme from "acme-client";
import { randomBytes } from "node:crypto";
import { PASSWORD, createHarness, type Harness } from "./support/harness";
import { TestAgent } from "./support/agent-double";
import { AdcsDouble, AdcsDoubleError, CDP_URL, defaultTemplates } from "./support/adcs-double";

setDefaultTimeout(60_000);

let h: Harness;
let operator: string;
let org: { orgId: string; cookie: string };
let adcs: AdcsDouble;

const CONFIG = "ca01.corp.example\\Corp Issuing CA";
const START = new Date("2026-01-01T00:00:00Z");
const HOUR_MS = 3600_000;

beforeAll(async () => {
  h = await createHarness({ adcsRelay: { attemptTimeoutMs: 1500 }, dnsRelay: { pollMs: 10 } });
  adcs = await AdcsDouble.create(CONFIG);
});
beforeEach(async () => {
  await h.reset();
  adcs.failure = null;
  adcs.templates = defaultTemplates();
  adcs.issued.length = 0;
  adcs.revoked.clear();
  adcs.now = () => START;
  operator = await h.createOperator("op@platform.test", PASSWORD);
  org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
});
afterAll(async () => {
  await h.close();
});

const api = (path: string, body?: unknown, method?: string, cookie = org.cookie) => h.api(`/api/organizations/${org.orgId}${path}`, { cookie, body, method });
const auditOf = async () => (await api("/audit-events")).body.items as { action: string; actor: any; detail: any; target: any }[];

/** A registered Agent on a Windows host that reaches `reaches` (the ADCS double unless given another). */
async function windowsAgent(reaches: AdcsDouble = adcs) {
  const agent = await TestAgent.registered(h, org.cookie, org.orgId, { hostName: `win-${randomBytes(3).toString("hex")}`, os: "windows" });
  agent.adcs = reaches;
  return agent;
}

/** A Managed Certificate issued from an ADCS CA, with the Agents assigned to it (one that reaches the double unless given), and its Certificate. */
async function issued(agents?: TestAgent[]) {
  const assigned = agents ?? [await windowsAgent()];
  const stops = assigned.map((a) => a.startWorking());
  let added;
  try {
    added = await api("/adcs-cas", { name: "Corp", configString: CONFIG, agentIds: assigned.map((a) => a.id) });
  } finally {
    for (const stop of stops) await stop();
  }
  expect(added.status).toBe(201);
  const tls = added.body.templates.find((t: { name: string }) => t.name === "CorpWebServer");
  const key = await acme.crypto.createPrivateRsaKey(2048);
  const [, csr] = await acme.crypto.createCsr({ commonName: "web.corp.example", altNames: ["web.corp.example"] }, key);
  const created = await api("/managed-certificates", { names: ["web.corp.example"], keyAlgorithm: "rsa-2048", csr: csr.toString(), issuer: { kind: "adcs", adcsCaId: added.body.id, templateId: tls.id } });
  expect(created.status).toBe(201);
  await h.settleIssuances();
  // Twice over: one that cannot reach the CA passes the request to another, which may have worked already.
  for (const agent of [...assigned, ...assigned]) await agent.work();
  const mc = (await api(`/managed-certificates/${created.body.id}`)).body;
  expect(mc.currentCertificate).not.toBeNull();
  return { mcId: mc.id as string, certificate: mc.currentCertificate as { id: string; serial: string }, agents: assigned };
}

const revoke = (mcId: string, certificateId: string, reason = "keyCompromise", cookie = org.cookie) => api(`/managed-certificates/${mcId}/certificates/${certificateId}/revocation`, { reason }, undefined, cookie);
const certificateOf = async (mcId: string, certificateId: string) => (await api(`/managed-certificates/${mcId}/certificates/${certificateId}`)).body;

describe("revoking a Certificate from an ADCS CA", () => {
  test("an assigned Agent carries out adcs.revoke, and the Revocation is recorded once ADCS confirms it", async () => {
    const { mcId, certificate, agents } = await issued();

    const asked = await revoke(mcId, certificate.id);
    expect(asked.status).toBe(202);
    expect(asked.body.revocation).toBeNull();
    expect(asked.body.revocationRequest).toMatchObject({ reason: "keyCompromise", status: "pending" });
    // Nothing is revoked at ADCS nor recorded until the Agent has done it.
    expect(adcs.revoked.size).toBe(0);
    expect((await auditOf()).map((e) => e.action)).not.toContain("certificate.revoked");

    await agents[0]!.work();
    const item = agents[0]!.executed.find((i) => i.type === "adcs.revoke")!;
    // The config string, the serial and the RFC 5280 reason code: nothing secret.
    expect(item.payload).toEqual({ configString: CONFIG, serialNumber: certificate.serial.toLowerCase(), reason: 1 });
    expect(adcs.revoked.get(certificate.serial.toLowerCase())).toBe(1);

    const revoked = await certificateOf(mcId, certificate.id);
    expect(revoked.revocation).toMatchObject({ reason: "keyCompromise", revokedBy: { email: "admin@acme.test" } });
    expect(revoked.revocationRequest).toBeNull();
    const event = (await auditOf()).find((e) => e.action === "certificate.revoked")!;
    expect(event.actor.email).toBe("admin@acme.test");
    expect(event.detail).toMatchObject({ certificateId: certificate.id, reason: "keyCompromise", issuer: { kind: "adcs" } });
  });

  test("ADCS refusing fails the request with its reason, and the Certificate stays unrevoked and may be revoked again", async () => {
    const { mcId, certificate, agents } = await issued();
    await revoke(mcId, certificate.id);
    adcs.failure = new AdcsDoubleError("rejected", "Access is denied: the account may not issue and manage certificates");
    await agents[0]!.work();

    const refused = await certificateOf(mcId, certificate.id);
    expect(refused.revocation).toBeNull();
    expect(refused.revocationRequest).toMatchObject({ status: "failed", failure: { code: "rejected" } });
    expect(refused.revocationRequest.failure.message).toContain("Access is denied");
    expect((await auditOf()).map((e) => e.action)).toContain("certificate.revocation_failed");
    expect((await auditOf()).map((e) => e.action)).not.toContain("certificate.revoked");

    adcs.failure = null;
    expect((await revoke(mcId, certificate.id)).status).toBe(202);
    await agents[0]!.work();
    expect((await certificateOf(mcId, certificate.id)).revocation).toMatchObject({ reason: "keyCompromise" });
  });

  test("an Agent that cannot reach the CA passes the revocation to another assigned Agent", async () => {
    const cut = await AdcsDouble.create(CONFIG);
    cut.failure = new AdcsDoubleError("unreachable", "the RPC server is unavailable");
    const connected = await windowsAgent();
    const isolated = await windowsAgent(cut);
    const { mcId, certificate } = await issued([connected, isolated]);
    // The isolated one is the most recently heard from, so it is asked first.
    h.setNow(new Date(START.getTime() + 60_000));
    await isolated.poll();
    await revoke(mcId, certificate.id);
    await isolated.work();
    expect(isolated.executed.map((i) => i.type)).toContain("adcs.revoke");
    expect((await certificateOf(mcId, certificate.id)).revocationRequest).toMatchObject({ status: "pending" });
    await connected.work();
    expect((await certificateOf(mcId, certificate.id)).revocation).toMatchObject({ reason: "keyCompromise" });
  });

  test("when no assigned Agent can reach the CA, the request fails as unreachable", async () => {
    const { mcId, certificate, agents } = await issued();
    await revoke(mcId, certificate.id);
    adcs.failure = new AdcsDoubleError("unreachable", "the RPC server is unavailable");
    await agents[0]!.work();
    const failed = await certificateOf(mcId, certificate.id);
    expect(failed.revocation).toBeNull();
    expect(failed.revocationRequest).toMatchObject({ status: "failed", failure: { code: "unreachable" } });
    expect(failed.revocationRequest.failure.message).toContain("the RPC server is unavailable");
  });

  test("with no assigned Agent online, nothing is asked: 502, and nothing is recorded", async () => {
    const { mcId, certificate } = await issued();
    h.setNow(new Date(START.getTime() + 2 * HOUR_MS));
    const res = await revoke(mcId, certificate.id);
    expect(res.status).toBe(502);
    expect(res.body.error).toContain("no Agent assigned to the ADCS CA Corp is online");
    const after = await certificateOf(mcId, certificate.id);
    expect(after.revocation).toBeNull();
    expect(after.revocationRequest).toBeNull();
  });

  test("an Agent that does not report by the deadline leaves the request timed out; its late confirmation is still recorded", async () => {
    const { mcId, certificate, agents } = await issued();
    await revoke(mcId, certificate.id);
    // It takes the work item and is not heard from again in time.
    agents[0]!.stalled = true;
    const [item] = await agents[0]!.work();
    h.setNow(new Date(START.getTime() + 2 * HOUR_MS));
    expect(await h.timeOutRevocations()).toBe(1);
    expect((await certificateOf(mcId, certificate.id)).revocationRequest).toMatchObject({ status: "failed", failure: { code: "timed_out" } });
    // ADCS did revoke it, and the Agent says so at last.
    expect((await agents[0]!.report(item!.id, { ok: true, revocation: { status: "revoked" } })).status).toBe(200);
    expect((await certificateOf(mcId, certificate.id)).revocation).toMatchObject({ reason: "keyCompromise" });
  });

  test("the reasons ADCS takes map one to one to their RFC 5280 codes; privilegeWithdrawn is refused", async () => {
    const { mcId, certificate, agents } = await issued();
    const refused = await revoke(mcId, certificate.id, "privilegeWithdrawn");
    expect(refused.status).toBe(422);
    expect(adcs.revoked.size).toBe(0);
    expect((await revoke(mcId, certificate.id, "cessationOfOperation")).status).toBe(202);
    await agents[0]!.work();
    expect(agents[0]!.executed.find((i) => i.type === "adcs.revoke")!.payload.reason).toBe(5);
    expect(adcs.revoked.get(certificate.serial.toLowerCase())).toBe(5);
  });

  test("an Owner may revoke, even once an Organization Administrator archived the Managed Certificate", async () => {
    const { mcId, certificate, agents } = await issued();
    const email = "owner@acme.test";
    const invited = await h.api("/api/auth/organization/invite-member", { cookie: org.cookie, body: { email, role: "member", organizationId: org.orgId } });
    await h.api("/api/auth/organization/accept-invitation", { cookie: await h.signUp(email, PASSWORD), body: { invitationId: invited.body.id } });
    const owner = await h.signIn(email, PASSWORD);
    const userId = (await h.api("/api/me", { cookie: owner })).body.user.id;
    expect((await api(`/managed-certificates/${mcId}/owners`, { type: "user", id: userId })).status).toBe(200);
    expect((await api(`/managed-certificates/${mcId}/archive`, {}, "POST")).status).toBe(200);

    expect((await revoke(mcId, certificate.id, "superseded", owner)).status).toBe(202);
    await agents[0]!.work();
    expect((await certificateOf(mcId, certificate.id)).revocation).toMatchObject({ reason: "superseded", revokedBy: { email } });
  });
});

describe("a Certificate from an ADCS CA", () => {
  test("shows the CRL Distribution Point URLs from its own extension, revoked or not", async () => {
    const { mcId, certificate, agents } = await issued();
    expect((await certificateOf(mcId, certificate.id)).crlDistributionPoints).toEqual([CDP_URL]);
    await revoke(mcId, certificate.id);
    await agents[0]!.work();
    const revoked = await certificateOf(mcId, certificate.id);
    expect(revoked.revocation).not.toBeNull();
    expect(revoked.crlDistributionPoints).toEqual([CDP_URL]);
  });
});
