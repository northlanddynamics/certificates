// The Agent is built against agent/contract/openapi.json, and the stub platform that its Seam B tests run against is built
// from it: this fails when the protocol the platform serves has moved on from that copy. `bun run contract:export` updates it.
import { afterAll, beforeAll, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { agentContract, serializeContract } from "../src/agents/agent-contract";
import { createHarness, type Harness } from "./support/harness";

let h: Harness;
beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => {
  await h.close();
});

test("the contract the Agent is built against is the one the platform serves", () => {
  const committed = readFileSync(new URL("../../agent/contract/openapi.json", import.meta.url), "utf8");
  expect(serializeContract(agentContract(h.app))).toBe(committed);
});

test("the contract holds the Agent protocol and nothing else", () => {
  const paths = Object.keys(agentContract(h.app).paths);
  expect(paths.length).toBeGreaterThan(0);
  expect(paths.every((p) => p.startsWith("/api/agent/"))).toBe(true);
});

test("the contract gives the Agent `adcs.discover` and takes its discovery: the chain, and the templates with their facts", () => {
  const contract = agentContract(h.app) as any;
  const poll = contract.paths["/api/agent/poll"].post.responses["200"].content["application/json"].schema;
  expect(JSON.stringify(poll)).toContain("`adcs.discover`");
  const result = contract.paths["/api/agent/work-items/{id}/result"].post.requestBody.content["application/json"].schema;
  const discovery = result.properties.discovery;
  expect(discovery.required).toEqual(["chain", "templates"]);
  expect(Object.keys(discovery.properties.templates.items.properties).sort()).toEqual(
    ["displayName", "enrollable", "extendedKeyUsages", "keyAlgorithms", "managerApproval", "minimumKeySize", "name", "oid", "published", "subjectFromRequest", "validityDays"].sort(),
  );
  expect(discovery.properties.templates.items.properties.keyAlgorithms.items.enum).toEqual(["rsa", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"]);
});

test("the contract gives the Agent `adcs.submit` and `adcs.check`, and takes what ADCS answered: issued with the Certificate, pending, or denied with its message", () => {
  const contract = agentContract(h.app) as any;
  const poll = contract.paths["/api/agent/poll"].post.responses["200"].content["application/json"].schema;
  expect(JSON.stringify(poll)).toContain("`adcs.submit`");
  expect(JSON.stringify(poll)).toContain("`adcs.check`");
  const result = contract.paths["/api/agent/work-items/{id}/result"].post.requestBody.content["application/json"].schema;
  const answers = result.properties.submission.oneOf ?? result.properties.submission.anyOf;
  const byStatus = Object.fromEntries(answers.map((a: any) => [a.properties.status.enum?.[0] ?? a.properties.status.const, a.required.sort()]));
  expect(byStatus).toEqual({ issued: ["certificate", "requestId", "status"], pending: ["requestId", "status"], denied: ["message", "requestId", "status"] });
});

test("the contract gives the Agent `adcs.revoke` with the serial number and RFC 5280 reason code, and takes that ADCS revoked it", () => {
  const contract = agentContract(h.app) as any;
  const poll = contract.paths["/api/agent/poll"].post.responses["200"].content["application/json"].schema;
  expect(JSON.stringify(poll)).toContain("`adcs.revoke`");
  expect(JSON.stringify(poll)).toContain("`serialNumber`");
  const result = contract.paths["/api/agent/work-items/{id}/result"].post.requestBody.content["application/json"].schema;
  expect(result.properties.revocation.required).toEqual(["status"]);
  expect(result.properties.revocation.properties.status.enum ?? [result.properties.revocation.properties.status.const]).toEqual(["revoked"]);
  expect(result.properties.kind.enum).toEqual(["rejected", "unreachable"]);
});
