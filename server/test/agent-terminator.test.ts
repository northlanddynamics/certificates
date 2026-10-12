// When the platform is told the secret its TLS terminator sends (ADR 0005), the client certificate in the header is trusted
// only with it: a request that did not come through the terminator is refused even with a genuine Agent certificate.
import { afterAll, beforeAll, beforeEach, expect, test } from "bun:test";
import { PASSWORD, createHarness, type Harness } from "./harness";
import { TestAgent, asHeader } from "./agent-double";

const SECRET = "terminator-secret-terminator-secret";
let h: Harness;
let org: { orgId: string; cookie: string };

beforeAll(async () => {
  h = await createHarness({ agentGateway: { terminatorSecret: SECRET } });
});
beforeEach(async () => {
  await h.reset();
  org = await h.createOrgWithAdmin(await h.createOperator("op@platform.test", PASSWORD), "acme", "admin@acme.test");
});
afterAll(async () => {
  await h.close();
});

test("a genuine Agent certificate is accepted only with the terminator's secret", async () => {
  const agent = await TestAgent.registered(h, org.cookie, org.orgId);
  const poll = (headers: Record<string, string>) => h.api("/api/agent/poll", { body: { version: "0.1.0" }, headers });
  expect((await poll(asHeader(agent.certificate))).status).toBe(401);
  expect((await poll({ ...asHeader(agent.certificate), "x-agent-gateway-secret": "wrong" })).status).toBe(401);
  expect((await poll({ ...asHeader(agent.certificate), "x-agent-gateway-secret": SECRET })).status).toBe(200);
});

test("Agent Registration needs no certificate, so no secret either", async () => {
  const made = await h.api(`/api/organizations/${org.orgId}/agent-registration-tokens`, { cookie: org.cookie, method: "POST", body: {} });
  expect((await TestAgent.register(h, { token: made.body.token })).res.status).toBe(201);
});
