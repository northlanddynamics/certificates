// Delegated DCV, end to end: a real ACME order against Pebble, whose DNS checks read BIND. The names under
// delegating.test have, in BIND, a CNAME from `_acme-challenge.<name>` into validation.rfc2136.test, as an Organization
// would create in its own DNS; the platform writes the challenge TXT into that Validation Zone through an RFC 2136 DNS
// Provider (docker/bind). Names under rfc2136.test are not delegated: DCV for them is Direct.
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import acme from "acme-client";
import { randomBytes } from "node:crypto";
import type { TxtResolver } from "../src/dcv";
import { BIND, PASSWORD, createHarness, type Harness } from "./harness";

setDefaultTimeout(60_000);

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

const VALIDATION_ZONE = "validation.rfc2136.test";
type Org = { orgId: string; cookie: string };

const api = (org: Org, path: string, body?: unknown, method?: string) => h.api(`/api/organizations/${org.orgId}${path}`, { cookie: org.cookie, body, method });

/** The Organization's ACME account and a DNS Provider for the BIND zone, which issuing needs; returns the provider. */
async function readyToIssue(org: Org = acmeOrg, over: { zone?: string } = {}) {
  expect((await api(org, "/acme-accounts", { termsOfServiceAgreed: true })).status).toBe(201);
  const provider = await api(org, "/dns-providers", {
    name: "BIND",
    type: "rfc2136",
    settings: { server: BIND.server, port: BIND.port, zone: over.zone ?? BIND.zone, keyName: BIND.keyName },
    secret: BIND.keySecret,
  });
  expect(provider.status).toBe(201);
  return provider.body as { id: string };
}

/** Delegated DCV for everything under delegating.test, through a Validation Zone on `providerId`. */
async function delegate(providerId: string, org: Org = acmeOrg, zone = VALIDATION_ZONE) {
  const created = await api(org, "/validation-zones", { name: zone, dnsProviderId: providerId });
  expect(created.status).toBe(201);
  const rule = await api(org, "/dcv-rules", { scope: "zone", domain: "delegating.test", method: "delegated", validationZoneId: created.body.id });
  expect(rule.status).toBe(201);
  return { zoneId: created.body.id as string, ruleId: rule.body.id as string };
}

/** A host name of its own inside the zone BIND serves for RFC 2136 updates, which is not delegated. */
const direct = () => `t${randomBytes(5).toString("hex")}.${BIND.zone}`;
const target = (name: string) => `${name}.${VALIDATION_ZONE}`;

async function create(org: Org, names: string[]) {
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  const created = await api(org, "/managed-certificates", { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() });
  expect(created.status).toBe(201);
  await h.settleIssuances();
  const read = await api(org, `/managed-certificates/${created.body.id}`);
  expect(read.body.issuance.status).not.toBe("running");
  return read.body;
}

const auditOf = async (org: Org = acmeOrg) => ((await h.api(`/api/organizations/${org.orgId}/audit-events`, { cookie: org.cookie })).body.items as any[]);

/** What the platform's DCV sees while it waits, and what BIND held at the Validation Zone's own name at that moment. */
function watching(records: { name: string; at: string[]; viaCname: string[] }[], watched: (name: string) => string): TxtResolver {
  return {
    async lookupTxt(name) {
      const seen = await h.bindTxt.lookupTxt(name);
      if (seen.length > 0) records.push({ name, at: seen, viaCname: await h.bindTxt.lookupTxt(watched(name)) });
      return seen;
    },
    lookupCname: (name) => h.bindTxt.lookupCname(name),
  };
}

describe("issuing through Delegated DCV", () => {
  test("a Certificate is issued for a name whose `_acme-challenge` is a CNAME into the Validation Zone, with the challenge written there", async () => {
    const provider = await readyToIssue();
    await delegate(provider.id);
    const name = "app.delegating.test";
    const seen: Parameters<typeof watching>[0] = [];
    h.dcvResolver.current = watching(seen, (challenge) => target(challenge.replace(/^_acme-challenge\./, "")));

    const issued = await create(acmeOrg, [name]);

    expect(issued.issuance).toMatchObject({ status: "succeeded", failure: null });
    expect(issued.currentCertificate.names).toEqual([name]);
    // The CA's view of `_acme-challenge.<name>` was the TXT record the platform wrote in the Validation Zone, under the target the CNAME points to.
    expect(seen).toEqual([{ name: `_acme-challenge.${name}`, at: [expect.any(String)], viaCname: seen[0]!.at }]);
    // Both are gone again, and the CNAME the Organization made was never touched.
    expect(await h.bindTxt.lookupTxt(`_acme-challenge.${name}`)).toEqual([]);
    expect(await h.bindTxt.lookupTxt(target(name))).toEqual([]);
    expect(await h.bindTxt.lookupCname(`_acme-challenge.${name}`)).toEqual([target(name)]);
  });

  test("a wildcard and its base name share one delegated record name, and both challenge values are removed", async () => {
    const provider = await readyToIssue();
    await delegate(provider.id);

    const issued = await create(acmeOrg, ["*.wild.delegating.test", "wild.delegating.test"]);

    expect(issued.issuance).toMatchObject({ status: "succeeded", failure: null });
    expect(await h.bindTxt.lookupTxt(target("wild.delegating.test"))).toEqual([]);
  });

  test("Delegated and Direct names are validated together in one Issuance", async () => {
    const provider = await readyToIssue();
    await delegate(provider.id);
    const plain = direct();

    const issued = await create(acmeOrg, ["app.delegating.test", plain]);

    expect(issued.issuance).toMatchObject({ status: "succeeded", failure: null });
    expect(issued.currentCertificate.names.sort()).toEqual(["app.delegating.test", plain].sort());
    expect(await h.bindTxt.lookupTxt(`_acme-challenge.${plain}`)).toEqual([]);
    expect(await h.bindTxt.lookupTxt(target("app.delegating.test"))).toEqual([]);
  });

  test("a Direct rule through a named DNS Provider validates as before", async () => {
    const provider = await readyToIssue();
    expect((await api(acmeOrg, "/dcv-rules", { scope: "zone", domain: BIND.zone, method: "direct", dnsProviderId: provider.id })).status).toBe(201);

    const issued = await create(acmeOrg, [direct()]);

    expect(issued.issuance).toMatchObject({ status: "succeeded", failure: null });
  });

  test("a change of the rules applies to the next Issuance: Delegated, then Direct again when the rule goes", async () => {
    const provider = await readyToIssue();
    const { ruleId } = await delegate(provider.id);
    expect((await create(acmeOrg, ["app.delegating.test"])).issuance.status).toBe("succeeded");

    await api(acmeOrg, `/dcv-rules/${ruleId}`, undefined, "DELETE");
    const direct2 = await create(acmeOrg, ["app.delegating.test"]);

    // No DNS Provider publishes records in delegating.test, so Direct DCV has nowhere to write.
    expect(direct2.issuance).toMatchObject({ status: "failed", failure: { code: "no_dns_provider", message: expect.stringContaining("_acme-challenge.app.delegating.test") } });
  });
});

describe("when the delegation is not in place", () => {
  test("no CNAME at all: the failure says which record to create, and the record written in the Validation Zone is removed", async () => {
    const provider = await readyToIssue();
    await delegate(provider.id);
    const name = "undelegated.delegating.test";

    const failed = await create(acmeOrg, [name]);

    expect(failed.issuance).toMatchObject({
      status: "failed",
      failure: { code: "cname_missing", message: expect.stringContaining(`create the CNAME _acme-challenge.${name} -> ${target(name)}`) },
    });
    expect(await h.bindTxt.lookupTxt(target(name))).toEqual([]);
  });

  test("a CNAME that points somewhere else is reported with where it points", async () => {
    const provider = await readyToIssue();
    await delegate(provider.id);

    const failed = await create(acmeOrg, ["elsewhere.delegating.test"]);

    expect(failed.issuance.failure).toMatchObject({
      code: "cname_missing",
      message: expect.stringContaining("it points to elsewhere.delegating.test.elsewhere.rfc2136.test instead"),
    });
    expect(await h.bindTxt.lookupTxt(target("elsewhere.delegating.test"))).toEqual([]);
  });

  test("a Validation Zone whose DNS Provider no longer publishes in it fails DCV in terms of the zone", async () => {
    const provider = await readyToIssue();
    await delegate(provider.id);
    const moved = await api(acmeOrg, `/dns-providers/${provider.id}`, { name: "BIND", settings: { server: BIND.server, port: BIND.port, zone: BIND.readonlyZone, keyName: BIND.keyName } }, "PUT");
    expect(moved.status).toBe(200);

    const failed = await create(acmeOrg, ["app.delegating.test"]);

    expect(failed.issuance.failure).toMatchObject({ code: "no_dns_provider", message: expect.stringContaining(`Validation Zone ${VALIDATION_ZONE}`) });
  });

  test("a DNS Provider that refuses the update is reported as such", async () => {
    await readyToIssue();
    // A zone on a provider for the zone that takes no updates.
    const readonly = await api(acmeOrg, "/dns-providers", {
      name: "Readonly",
      type: "rfc2136",
      settings: { server: BIND.server, port: BIND.port, zone: BIND.readonlyZone, keyName: BIND.keyName },
      secret: BIND.keySecret,
    });
    await delegate(readonly.body.id, acmeOrg, `validation.${BIND.readonlyZone}`);

    const failed = await create(acmeOrg, ["app.delegating.test"]);

    expect(failed.issuance.failure).toMatchObject({ code: "dns_update_rejected", message: expect.stringContaining(`app.delegating.test.validation.${BIND.readonlyZone}`) });
  });

  test("a Direct rule naming a DNS Provider that does not publish the name fails DCV in terms of the rule", async () => {
    await readyToIssue();
    const readonly = await api(acmeOrg, "/dns-providers", {
      name: "Readonly",
      type: "rfc2136",
      settings: { server: BIND.server, port: BIND.port, zone: BIND.readonlyZone, keyName: BIND.keyName },
      secret: BIND.keySecret,
    });
    await api(acmeOrg, "/dcv-rules", { scope: "zone", domain: BIND.zone, method: "direct", dnsProviderId: readonly.body.id });

    const failed = await create(acmeOrg, [direct()]);

    expect(failed.issuance.failure).toMatchObject({ code: "no_dns_provider", message: expect.stringContaining(`DCV Rule for ${BIND.zone}`) });
  });
});

describe("Organizations share no Validation Zone (ADR 0003)", () => {
  test("another Organization's names are not delegated through this one's zone, and its CNAMEs buy it nothing", async () => {
    const provider = await readyToIssue();
    await delegate(provider.id);
    // The other Organization has its own provider for the same BIND zone, and no Validation Zone or rule of its own.
    await readyToIssue(globex);

    const failed = await create(globex, ["app.delegating.test"]);

    expect(failed.issuance).toMatchObject({ status: "failed", failure: { code: "no_dns_provider" } });
    // And this one's own delegation keeps working.
    expect((await create(acmeOrg, ["app.delegating.test"])).issuance.status).toBe("succeeded");
  });
});

describe("audit of DCV configuration around an Issuance", () => {
  test("the configuration changes are audited before the Issuance that used them, and the Issuance's success records the names", async () => {
    const provider = await readyToIssue();
    const { zoneId, ruleId } = await delegate(provider.id);
    await create(acmeOrg, ["app.delegating.test"]);

    const actions = (await auditOf()).map((e) => e.action).filter((a) => /^(validation_zone|dcv_rule|issuance)\./.test(a));
    expect(actions).toEqual(["validation_zone.created", "dcv_rule.created", "issuance.started", "issuance.succeeded"]);
    const [zone, rule] = (await auditOf()).filter((e) => /^(validation_zone|dcv_rule)\./.test(e.action));
    expect(zone.target).toEqual({ type: "validation_zone", id: zoneId });
    expect(rule.target).toEqual({ type: "dcv_rule", id: ruleId });
  });
});
