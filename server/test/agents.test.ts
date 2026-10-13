// Agent Registration and authentication, through the platform's HTTP API: an Organization Administrator makes a single-use
// token, an Agent registers with it and is given a credential (ADR 0006), authenticates with that from then on, rotates it
// before it ends, and is listed with its status until it is revoked. The Agent here is a double (agent-double.ts); the real one runs against a stub of this API in agent/ (Seam B).
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { PASSWORD, createHarness, type Harness } from "./harness";
import { TestAgent, asBearer } from "./agent-double";

let h: Harness;
let operator: string;
let acmeOrg: { orgId: string; cookie: string };
let globex: { orgId: string; cookie: string };

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

const DAY = 24 * 3600_000;
const tokens = (org = acmeOrg) => `/api/organizations/${org.orgId}/agent-registration-tokens`;
const agentsOf = (org = acmeOrg) => `/api/organizations/${org.orgId}/agents`;
const makeToken = (org = acmeOrg) => h.api(tokens(org), { cookie: org.cookie, method: "POST", body: {} });
const listAgents = async (org = acmeOrg) => (await h.api(agentsOf(org), { cookie: org.cookie })).body.items as any[];
const registerAgent = (org = acmeOrg, reg = {}) => TestAgent.registered(h, org.cookie, org.orgId, reg);
const auditOf = async (org = acmeOrg) =>
  (await h.api(`/api/organizations/${org.orgId}/audit-events`, { cookie: org.cookie })).body.items as { action: string; actor: any; target: any; detail: any }[];

/** A member of the Organization in the role, signed in. */
async function memberWithRole(role: string, email = `${role}@acme.test`) {
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: acmeOrg.cookie, body: { email, role, organizationId: acmeOrg.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return await h.signIn(email, PASSWORD);
}

describe("registration tokens", () => {
  test("an Organization Administrator makes one, shown once, that expires", async () => {
    const made = await makeToken();
    expect(made.status).toBe(201);
    expect(made.body).toEqual({ token: expect.stringMatching(/^agt_/), expiresAt: new Date(Date.parse("2026-01-01T00:00:00Z") + 7 * DAY).toISOString() });
    // Nothing the platform lists shows it again.
    expect(JSON.stringify([await listAgents(), await auditOf()])).not.toContain(made.body.token);
  });

  test("making one is an Audit Event", async () => {
    await makeToken();
    const event = (await auditOf()).find((e) => e.action === "agent_registration_token.created")!;
    expect(event.actor.email).toBe("admin@acme.test");
    expect(event.target.type).toBe("agent_registration_token");
  });

  test("only an Organization Administrator may, and other Organizations' people find nothing", async () => {
    for (const role of ["approver", "member"]) {
      const cookie = await memberWithRole(role);
      expect((await h.api(tokens(), { cookie, method: "POST", body: {} })).status).toBe(403);
      expect((await h.api(agentsOf(), { cookie })).status).toBe(403);
    }
    expect((await h.api(tokens(), { cookie: globex.cookie, method: "POST", body: {} })).status).toBe(404);
    expect((await h.api(tokens(), { method: "POST", body: {} })).status).toBe(401);
    expect((await auditOf()).filter((e) => e.action === "agent_registration_token.created")).toEqual([]);
  });

  test("an Organization Administrator is told they may, and others that they may not", async () => {
    const me = await h.api("/api/me", { cookie: acmeOrg.cookie });
    expect(me.body.organizations[0].permissions.agent).toEqual(["read", "register", "revoke"]);
    const member = await h.api("/api/me", { cookie: await memberWithRole("member") });
    expect(member.body.organizations[0].permissions.agent).toBeUndefined();
  });
});

describe("Agent Registration", () => {
  test("an Agent registers with the token and is given a credential, of which the platform keeps only the hash", async () => {
    const { token } = (await makeToken()).body;
    const { res } = await TestAgent.register(h, { token, hostName: "web-01", os: "windows", arch: "arm64", version: "0.1.0" });
    expect(res.status).toBe(201);
    expect(res.body).toEqual({ agentId: expect.any(String), credential: expect.stringMatching(/^agk_[A-Za-z0-9_-]{43}$/), expiresAt: "2026-01-31T00:00:00.000Z", pollAfterSeconds: 30 });
    const [row] = await h.pool.query("select credential_hash from agent where id = $1", [res.body.agentId]).then((r) => r.rows);
    expect(row.credential_hash).toBe(new Bun.CryptoHasher("sha256").update(res.body.credential).digest("hex"));
    // Two Agents never share one.
    const second = await TestAgent.register(h, { token: (await makeToken()).body.token });
    expect(second.res.body.credential).not.toBe(res.body.credential);
  });

  test("an Agent on macOS registers, and is listed as such", async () => {
    const agent = await registerAgent(acmeOrg, { hostName: "mac-01", os: "macos", arch: "arm64" });
    expect(await listAgents()).toMatchObject([{ id: agent.id, hostName: "mac-01", os: "macos", arch: "arm64" }]);
  });

  test("the Agent is listed in its Organization, with what it said about its host, and the registration is an Audit Event", async () => {
    const agent = await registerAgent(acmeOrg, { hostName: "web-01", os: "windows", arch: "arm64", version: "0.1.0" });
    expect(await listAgents()).toEqual([
      {
        id: agent.id,
        hostName: "web-01",
        os: "windows",
        arch: "arm64",
        version: "0.1.0",
        outdated: false,
        status: "online",
        registeredAt: "2026-01-01T00:00:00.000Z",
        lastContactAt: "2026-01-01T00:00:00.000Z",
        revokedAt: null,
      },
    ]);
    const event = (await auditOf()).find((e) => e.action === "agent.registered")!;
    expect(event.target).toEqual({ type: "agent", id: agent.id });
    expect(event.detail).toMatchObject({ hostName: "web-01", os: "windows", arch: "arm64", version: "0.1.0" });
  });

  test("a token registers one Agent, once: reuse is refused, and nothing more is registered", async () => {
    const { token } = (await makeToken()).body;
    expect((await TestAgent.register(h, { token })).res.status).toBe(201);
    const again = await TestAgent.register(h, { token, hostName: "other-host" });
    expect(again.res.status).toBe(401);
    expect(await listAgents()).toHaveLength(1);
    expect((await auditOf()).filter((e) => e.action === "agent.registered")).toHaveLength(1);
  });

  test("two registrations with one token at once register one", async () => {
    const { token } = (await makeToken()).body;
    const results = await Promise.all([1, 2, 3].map((n) => TestAgent.register(h, { token, hostName: `host-${n}` })));
    expect(results.map((r) => r.res.status).sort()).toEqual([201, 401, 401]);
    expect(await listAgents()).toHaveLength(1);
  });

  test("an expired or unknown token is refused", async () => {
    const { token } = (await makeToken()).body;
    h.setNow(new Date(Date.parse("2026-01-01T00:00:00Z") + 7 * DAY + 1000));
    expect((await TestAgent.register(h, { token })).res.status).toBe(401);
    expect((await TestAgent.register(h, { token: "agt_not-a-token" })).res.status).toBe(401);
    expect(await listAgents()).toEqual([]);
  });

  test("a request that is not a good one is refused, and does not use the token up", async () => {
    const { token } = (await makeToken()).body;
    expect((await h.api("/api/agent/registration", { body: { token, hostName: "h", os: "darwin", arch: "amd64", version: "1" } })).status).toBe(400);
    expect((await h.api("/api/agent/registration", { body: { token, hostName: "", os: "linux", arch: "amd64", version: "1" } })).status).toBe(400);
    expect((await TestAgent.register(h, { token })).res.status).toBe(201);
  });

  test("each Agent belongs to the one Organization whose token it used, and only its administrators see it", async () => {
    const acmeAgent = await registerAgent(acmeOrg, { hostName: "acme-host" });
    const globexAgent = await registerAgent(globex, { hostName: "globex-host" });
    expect((await listAgents(acmeOrg)).map((a) => a.hostName)).toEqual(["acme-host"]);
    expect((await listAgents(globex)).map((a) => a.hostName)).toEqual(["globex-host"]);
    expect((await h.api(`/api/organizations/${acmeOrg.orgId}/agents`, { cookie: globex.cookie })).status).toBe(404);
    expect((await auditOf(acmeOrg)).filter((e) => e.action === "agent.registered").map((e) => e.target.id)).toEqual([acmeAgent.id]);
    expect((await auditOf(globex)).filter((e) => e.action === "agent.registered").map((e) => e.target.id)).toEqual([globexAgent.id]);
  });
});

describe("authenticating with the credential", () => {
  test("an Agent with its credential polls and is given its work (none yet) and when to poll again", async () => {
    const agent = await registerAgent();
    const polled = await agent.poll();
    expect(polled.status).toBe(200);
    expect(polled.body).toEqual({ items: [], pollAfterSeconds: 30 });
  });

  test("a call without a credential, or with one that is not an Agent's, is refused", async () => {
    const agent = await registerAgent();
    expect((await agent.poll("0.1.0", null)).status).toBe(401);
    expect((await agent.poll("0.1.0", "agk_" + "A".repeat(43))).status).toBe(401);
    expect((await agent.poll("0.1.0", "not a credential")).status).toBe(401);
    // Not the registration token it came with, nor the scheme's absence.
    expect((await h.api("/api/agent/poll", { body: { version: "0.1.0" }, headers: { authorization: agent.credential } })).status).toBe(401);
    expect((await h.api("/api/agent/poll", { body: { version: "0.1.0" }, headers: { authorization: "Bearer" } })).status).toBe(401);
    // Nothing but the Agent's credential: a signed-in administrator is not an Agent.
    expect((await h.api("/api/agent/poll", { body: { version: "0.1.0" }, cookie: acmeOrg.cookie })).status).toBe(401);
  });

  test("a credential that has ended is refused", async () => {
    const agent = await registerAgent();
    h.setNow(new Date(Date.parse(agent.expiresAt) + 1000));
    expect((await agent.poll()).status).toBe(401);
  });

  test("an Agent's credential opens nothing outside the Agent protocol", async () => {
    const agent = await registerAgent();
    const res = await h.api(`/api/organizations/${acmeOrg.orgId}/agents`, { headers: asBearer(agent.credential) });
    expect(res.status).toBe(401);
  });

  test("an Agent's polls are its contact: its last contact and version are as it last reported", async () => {
    const agent = await registerAgent(acmeOrg, { version: "0.1.0" });
    h.setNow(new Date("2026-01-01T00:01:00Z"));
    await agent.poll("0.2.0");
    expect(await listAgents()).toMatchObject([{ version: "0.2.0", lastContactAt: "2026-01-01T00:01:00.000Z", status: "online" }]);
  });
});

describe("online and offline, and outdated versions", () => {
  test("an Agent is offline once it has been silent for two minutes, and online again when it polls", async () => {
    const agent = await registerAgent();
    h.setNow(new Date("2026-01-01T00:02:00Z"));
    expect((await listAgents())[0].status).toBe("online");
    h.setNow(new Date("2026-01-01T00:02:01Z"));
    expect((await listAgents())[0].status).toBe("offline");
    await agent.poll();
    expect((await listAgents())[0].status).toBe("online");
  });

  test("an Agent older than the latest version is flagged, and not once it reports the latest", async () => {
    const agent = await registerAgent(acmeOrg, { version: "0.0.9" });
    const listed = await h.api(agentsOf(), { cookie: acmeOrg.cookie });
    expect(listed.body.latestVersion).toBe("0.1.0");
    expect(listed.body.items[0]).toMatchObject({ version: "0.0.9", outdated: true });
    await agent.poll("0.1.0");
    expect((await listAgents())[0].outdated).toBe(false);
    await agent.poll("0.1.0-dev");
    expect((await listAgents())[0].outdated).toBe(true);
    await agent.poll("not-a-version");
    expect((await listAgents())[0].outdated).toBe(true);
    await agent.poll("1.0.0");
    expect((await listAgents())[0].outdated).toBe(false);
  });
});

describe("listing Agents a page at a time", () => {
  test("they are paged, counted in all, and narrowed by status, operating system and version, which combine", async () => {
    // Registered at the start; `silent` then goes quiet while the others keep in touch.
    // A second apart, so they are listed in the order they registered.
    const registerAt = (second: number, reg: object) => {
      h.setNow(new Date(Date.parse("2026-01-01T00:00:00Z") + second * 1000));
      return registerAgent(acmeOrg, reg);
    };
    const silent = await registerAt(0, { hostName: "silent", os: "linux", version: "0.1.0" });
    const old = await registerAt(1, { hostName: "old", os: "windows", version: "0.0.9" });
    const revoked = await registerAt(2, { hostName: "revoked", os: "linux", version: "0.1.0" });
    const live = await registerAt(3, { hostName: "live", os: "linux", version: "0.1.0" });
    await h.api(`${agentsOf()}/${revoked.id}/revoke`, { cookie: acmeOrg.cookie, method: "POST", body: {} });
    h.setNow(new Date("2026-01-01T00:02:01Z"));
    await old.poll("0.0.9");
    await live.poll("0.1.0");
    expect(silent.id).toBeString();

    const hosts = async (query: string) => {
      const res = await h.api(`${agentsOf()}${query}`, { cookie: acmeOrg.cookie });
      expect(res.status).toBe(200);
      return [res.body.total, res.body.items.map((a: any) => a.hostName)];
    };
    expect(await hosts("")).toEqual([4, ["silent", "old", "revoked", "live"]]);
    expect(await hosts("?pageSize=3&page=2")).toEqual([4, ["live"]]);
    expect(await hosts("?status=offline")).toEqual([1, ["silent"]]);
    expect(await hosts("?status=online")).toEqual([2, ["old", "live"]]);
    expect(await hosts("?status=offline,revoked")).toEqual([2, ["silent", "revoked"]]);
    expect(await hosts("?os=windows")).toEqual([1, ["old"]]);
    expect(await hosts("?os=linux&status=online")).toEqual([1, ["live"]]);
    expect(await hosts("?outdated=true")).toEqual([1, ["old"]]);
    expect(await hosts("?outdated=true&os=linux")).toEqual([0, []]);
    expect(await hosts("?os=macos")).toEqual([0, []]);
    for (const query of ["?status=gone", "?os=darwin", "?outdated=yes", "?page=0", "?pageSize=101"]) {
      expect((await h.api(`${agentsOf()}${query}`, { cookie: acmeOrg.cookie })).status).toBe(400);
    }
  });
});

describe("rotating the credential", () => {
  test("an Agent gets a new credential, which works, and the old one only until the new one is used", async () => {
    const agent = await registerAgent();
    const before = agent.credential;
    h.setNow(new Date("2026-01-21T00:00:00Z"));
    const rotated = await agent.rotate();
    expect(rotated.status).toBe(200);
    expect(agent.credential).not.toBe(before);
    expect(rotated.body.expiresAt).toBe(new Date(Date.parse("2026-01-21T00:00:00Z") + 30 * DAY).toISOString());

    // The response may have been lost: the old credential still works until the new one has.
    expect((await agent.poll("0.1.0", before)).status).toBe(200);
    expect((await agent.poll()).status).toBe(200);
    expect((await agent.poll("0.1.0", before)).status).toBe(401);
    expect((await agent.poll()).status).toBe(200);
    expect((await auditOf()).filter((e) => e.action === "agent.credential_rotated").map((e) => e.target.id)).toEqual([agent.id]);
  });

  test("an Agent that never received the new credential rotates again with the old one", async () => {
    const agent = await registerAgent();
    const old = agent.credential;
    await agent.rotate();
    const again = await agent.rotate(old);
    expect(again.status).toBe(200);
    expect((await agent.poll()).status).toBe(200);
  });

  test("the credential it replaced is not accepted past its own end", async () => {
    const agent = await registerAgent();
    const old = agent.credential;
    h.setNow(new Date("2026-01-21T00:00:00Z"));
    await agent.rotate();
    h.setNow(new Date(Date.parse("2026-01-01T00:00:00Z") + 30 * DAY + 1000));
    expect((await agent.poll("0.1.0", old)).status).toBe(401);
    expect((await agent.poll()).status).toBe(200);
  });

  test("rotation needs the credential", async () => {
    const agent = await registerAgent();
    expect((await agent.call("/api/agent/credential", undefined, null)).status).toBe(401);
    expect((await agent.poll()).status).toBe(200);
  });

  test("an Agent whose credential has ended can no longer rotate, and registers again", async () => {
    const agent = await registerAgent();
    h.setNow(new Date(Date.parse(agent.expiresAt) + 1000));
    expect((await agent.rotate()).status).toBe(401);
  });
});

describe("revoking an Agent", () => {
  test("an Organization Administrator revokes it, and it can no longer authenticate", async () => {
    const agent = await registerAgent();
    const revoked = await h.api(`${agentsOf()}/${agent.id}/revoke`, { cookie: acmeOrg.cookie, method: "POST", body: {} });
    expect(revoked.status).toBe(200);
    expect(revoked.body).toMatchObject({ id: agent.id, status: "revoked", revokedAt: "2026-01-01T00:00:00.000Z" });
    expect((await agent.poll()).status).toBe(401);
    expect((await agent.rotate()).status).toBe(401);
    expect((await listAgents())[0].status).toBe("revoked");
  });

  test("a revoked Agent's credential stays refused, even though it has not ended, and the token it used does not register another", async () => {
    const { token } = (await makeToken()).body;
    const { agent } = await TestAgent.register(h, { token });
    await h.api(`${agentsOf()}/${agent!.id}/revoke`, { cookie: acmeOrg.cookie, method: "POST", body: {} });
    h.setNow(new Date("2026-01-10T00:00:00Z"));
    expect((await agent!.poll()).status).toBe(401);
    expect((await TestAgent.register(h, { token })).res.status).toBe(401);
  });

  test("it is an Audit Event, by the administrator who did it", async () => {
    const agent = await registerAgent(acmeOrg, { hostName: "web-01" });
    await h.api(`${agentsOf()}/${agent.id}/revoke`, { cookie: acmeOrg.cookie, method: "POST", body: {} });
    const event = (await auditOf()).find((e) => e.action === "agent.revoked")!;
    expect(event.actor.email).toBe("admin@acme.test");
    expect(event.target).toEqual({ type: "agent", id: agent.id });
    expect(event.detail).toEqual({ hostName: "web-01" });
  });

  test("it cannot be done twice, by others in the Organization, or from another Organization", async () => {
    const agent = await registerAgent();
    const revoke = (cookie: string, orgId = acmeOrg.orgId) => h.api(`/api/organizations/${orgId}/agents/${agent.id}/revoke`, { cookie, method: "POST", body: {} });
    expect((await revoke(await memberWithRole("approver"))).status).toBe(403);
    expect((await revoke(globex.cookie)).status).toBe(404);
    expect((await revoke(globex.cookie, globex.orgId)).status).toBe(404);
    expect((await agent.poll()).status).toBe(200);
    expect((await revoke(acmeOrg.cookie)).status).toBe(200);
    expect((await revoke(acmeOrg.cookie)).status).toBe(409);
    expect((await auditOf()).filter((e) => e.action === "agent.revoked")).toHaveLength(1);
  });

  test("revoking one Agent leaves the others", async () => {
    const one = await registerAgent(acmeOrg, { hostName: "one" });
    const two = await registerAgent(acmeOrg, { hostName: "two" });
    await h.api(`${agentsOf()}/${one.id}/revoke`, { cookie: acmeOrg.cookie, method: "POST", body: {} });
    expect((await one.poll()).status).toBe(401);
    expect((await two.poll()).status).toBe(200);
  });
});
