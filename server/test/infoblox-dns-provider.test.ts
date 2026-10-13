// An Organization's Infoblox DNS Providers through the API, and used: for Direct DCV and to host a Validation
// Zone, in real Issuances against Pebble. Infoblox is the WAPI double (test/infoblox-double.ts), which here
// publishes what it is given to BIND, where the CA's DNS checks read.
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import acme from "acme-client";
import { randomBytes } from "node:crypto";
import { DNS_PROVIDER_KINDS } from "../src/dns-provider-kinds";
import { BIND, PASSWORD, createHarness, type Harness } from "./harness";
import { INFOBLOX, startInfobloxDouble, type InfobloxDouble } from "./infoblox-double";

setDefaultTimeout(60_000);

let h: Harness;
let wapi: InfobloxDouble;
let operator: string;
let acmeOrg: { orgId: string; cookie: string };
type Org = typeof acmeOrg;

beforeAll(async () => {
  h = await createHarness();
  wapi = await startInfobloxDouble();
});
beforeEach(async () => {
  await h.reset();
  wapi.zones.splice(0, wapi.zones.length, { name: BIND.zone, view: "default" });
  wapi.records.length = 0;
  wapi.requests.length = 0;
  wapi.failing = null;
  wapi.deletesFailing = false;
  wapi.mirror = DNS_PROVIDER_KINDS.rfc2136.create(
    DNS_PROVIDER_KINDS.rfc2136.settings.parse({ server: BIND.server, port: BIND.port, zone: BIND.zone, keyName: BIND.keyName }),
    BIND.keySecret,
  );
  operator = await h.createOperator("op@platform.test", PASSWORD);
  acmeOrg = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
});
afterAll(async () => {
  await wapi.close();
  await h.close();
});

const api = (org: Org, path: string, body?: unknown, method?: string) => h.api(`/api/organizations/${org.orgId}${path}`, { cookie: org.cookie, body, method });

/** An Infoblox DNS Provider request for the double's zone, with what is in `over` replacing the defaults. */
const infoblox = (over: { name?: string; settings?: object; secret?: string } = {}) => ({
  name: over.name ?? "Infoblox",
  type: "infoblox",
  settings: { url: wapi.url, zone: BIND.zone, caCertificate: wapi.caCertificate, ...over.settings },
  secret: over.secret ?? INFOBLOX.secret,
});
const connect = async (over: Parameters<typeof infoblox>[0] = {}) => {
  const created = await api(acmeOrg, "/dns-providers", infoblox(over));
  expect(created.status).toBe(201);
  return created.body as { id: string; settings: Record<string, unknown> };
};

describe("connecting an Infoblox DNS Provider", () => {
  test("an Organization Administrator adds one with WAPI URL, zone, view and credentials, and the credentials are not returned", async () => {
    const created = await api(acmeOrg, "/dns-providers", infoblox());
    expect(created.status).toBe(201);
    expect(created.body).toEqual({
      id: expect.any(String),
      name: "Infoblox",
      type: "infoblox",
      settings: { url: wapi.url, zone: BIND.zone, view: "default", caCertificate: wapi.caCertificate },
      relayAgentIds: [],
    });
    const listed = await api(acmeOrg, "/dns-providers");
    expect(listed.body.items).toEqual([created.body]);
    expect(JSON.stringify([created.body, listed.body])).not.toContain(INFOBLOX.password);
  });

  test("what cannot be an Infoblox DNS Provider is refused, and nothing is stored", async () => {
    for (const bad of [
      infoblox({ settings: { url: "http://gm.acme.test/wapi/v2.12" } }),
      infoblox({ settings: { url: "https://gm.acme.test/" } }),
      infoblox({ settings: { zone: "not a zone" } }),
      infoblox({ settings: { view: "" } }),
      infoblox({ settings: { caCertificate: "nope" } }),
      infoblox({ secret: "no-colon-here" }),
      infoblox({ secret: "user:" }),
    ])
      expect((await api(acmeOrg, "/dns-providers", bad)).status).toBe(400);
    expect((await api(acmeOrg, "/dns-providers")).body.items).toEqual([]);
  });

  test("a refusal does not repeat the credentials", async () => {
    const refused = await api(acmeOrg, "/dns-providers", infoblox({ secret: "justonepart" }));
    expect(refused.status).toBe(400);
    expect(JSON.stringify(refused.body)).not.toContain("justonepart");
  });

  test("the settings can be changed, and the view with them", async () => {
    const { id } = await connect();
    const changed = await api(acmeOrg, `/dns-providers/${id}`, { name: "Infoblox", settings: { url: wapi.url, zone: BIND.zone, view: "internal", caCertificate: wapi.caCertificate } }, "PUT");
    expect(changed.status).toBe(200);
    expect(changed.body.settings.view).toBe("internal");
  });
});

describe("testing the connection", () => {
  test("publishes a record through the WAPI and removes it again", async () => {
    const { id } = await connect();
    expect((await api(acmeOrg, `/dns-providers/${id}/test`, {}, "POST")).body).toEqual({ ok: true });
    expect(wapi.records).toEqual([]);
    expect(wapi.requests.map((r) => r.method)).toContain("POST");
    expect(wapi.requests.map((r) => r.method)).toContain("DELETE");
  });

  test("reports wrong credentials, which can be replaced on their own, without repeating them", async () => {
    const { id } = await connect({ secret: "wapi-user:not-the-password" });
    const failed = await api(acmeOrg, `/dns-providers/${id}/test`, {}, "POST");
    expect(failed.body).toEqual({ ok: false, error: expect.stringMatching(/credentials/) });
    expect(JSON.stringify(failed.body)).not.toContain("not-the-password");

    expect((await api(acmeOrg, `/dns-providers/${id}/secret`, { secret: INFOBLOX.secret }, "PUT")).status).toBe(200);
    expect((await api(acmeOrg, `/dns-providers/${id}/test`, {}, "POST")).body).toEqual({ ok: true });
    expect((await api(acmeOrg, `/dns-providers/${id}/secret`, { secret: "nocolon" }, "PUT")).status).toBe(400);
  });

  test("reports a view or zone Infoblox does not have, and a WAPI that is not there", async () => {
    const view = await connect({ name: "wrong view", settings: { view: "nonexistent" } });
    expect((await api(acmeOrg, `/dns-providers/${view.id}/test`, {}, "POST")).body).toEqual({ ok: false, error: expect.stringContaining("nonexistent") });

    const gone = await connect({ name: "gone", settings: { url: "https://127.0.0.1:1/wapi/v2.12" } });
    expect((await api(acmeOrg, `/dns-providers/${gone.id}/test`, {}, "POST")).body).toEqual({ ok: false, error: expect.stringContaining("could not be reached") });
  });

  test("is audited, and nothing audited or returned holds the credentials", async () => {
    const { id } = await connect();
    await api(acmeOrg, `/dns-providers/${id}/secret`, { secret: "wapi-user:replaced-password" }, "PUT");
    await api(acmeOrg, `/dns-providers/${id}/test`, {}, "POST");
    const events = ((await api(acmeOrg, "/audit-events")).body.items as any[]).filter((e) => e.action.startsWith("dns_provider."));
    expect(events.map((e) => e.action)).toEqual(["dns_provider.created", "dns_provider.secret_replaced", "dns_provider.tested"]);
    expect(events[0].detail).toMatchObject({ type: "infoblox" });
    expect(JSON.stringify(events)).not.toContain(INFOBLOX.password);
    expect(JSON.stringify(events)).not.toContain("replaced-password");
  });
});

// --- Used for DCV ------------------------------------------------------------------------------------------------

const VALIDATION_ZONE = "validation.rfc2136.test";
const direct = () => `t${randomBytes(5).toString("hex")}.${BIND.zone}`;

async function acmeAccount() {
  expect((await api(acmeOrg, "/acme-accounts", { termsOfServiceAgreed: true })).status).toBe(201);
}
async function create(names: string[]) {
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  const created = await api(acmeOrg, "/managed-certificates", { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() });
  expect(created.status).toBe(201);
  await h.settleIssuances();
  return (await api(acmeOrg, `/managed-certificates/${created.body.id}`)).body;
}

describe("Direct DCV through Infoblox", () => {
  test("a Certificate is issued for a name in the zone, the challenge published and removed through the WAPI", async () => {
    await acmeAccount();
    await connect();
    const name = direct();

    const issued = await create([name]);

    expect(issued.issuance).toMatchObject({ status: "succeeded", failure: null });
    expect(issued.currentCertificate.names).toEqual([name]);
    const posts = wapi.requests.filter((r) => r.method === "POST");
    expect(posts.map((r) => (r.body as any).name)).toEqual([`_acme-challenge.${name}`]);
    expect(wapi.requests.some((r) => r.method === "DELETE")).toBe(true);
    expect(wapi.records).toEqual([]);
    expect(await h.bindTxt.lookupTxt(`_acme-challenge.${name}`)).toEqual([]);
  });

  test("a name under a Direct rule for the provider is validated there too, with a wildcard and its base name together", async () => {
    await acmeAccount();
    const { id } = await connect();
    expect((await api(acmeOrg, "/dcv-rules", { scope: "zone", domain: BIND.zone, method: "direct", dnsProviderId: id })).status).toBe(201);
    const name = direct();

    const issued = await create([`*.${name}`, name]);

    expect(issued.issuance).toMatchObject({ status: "succeeded", failure: null });
    expect(wapi.records).toEqual([]);
  });

  test("an Issuance fails with the reason when Infoblox refuses the credentials", async () => {
    await acmeAccount();
    await connect({ secret: "wapi-user:wrong" });

    const issued = await create([direct()]);

    expect(issued.issuance.status).toBe("failed");
    expect(JSON.stringify(issued.issuance)).toMatch(/credentials/);
    expect(JSON.stringify(issued.issuance)).not.toContain(INFOBLOX.password);
  });
});

describe("a Validation Zone hosted on Infoblox", () => {
  test("names delegated into it are validated by the challenge written there through the WAPI", async () => {
    await acmeAccount();
    const { id } = await connect();
    const zone = await api(acmeOrg, "/validation-zones", { name: VALIDATION_ZONE, dnsProviderId: id });
    expect(zone.status).toBe(201);
    expect((await api(acmeOrg, "/dcv-rules", { scope: "zone", domain: "delegating.test", method: "delegated", validationZoneId: zone.body.id })).status).toBe(201);
    const name = "app.delegating.test";

    const issued = await create([name]);

    expect(issued.issuance).toMatchObject({ status: "succeeded", failure: null });
    // The challenge went to the Validation Zone, at the name the Organization's CNAME points to, and not to the domain's own.
    expect(wapi.requests.filter((r) => r.method === "POST").map((r) => (r.body as any).name)).toEqual([`${name}.${VALIDATION_ZONE}`]);
    expect(wapi.records).toEqual([]);
  });
});
