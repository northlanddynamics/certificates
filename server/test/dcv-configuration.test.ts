// How an Organization Administrator sets up Delegated DCV: Validation Zones on the Organization's own DNS Providers, and
// rules that say, per name or zone, whether DCV is Direct or Delegated and through which DNS Provider. Through the API,
// against a real Postgres; the Issuances that use these are in delegated-dcv.test.ts.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { BIND, PASSWORD, createHarness, type Harness } from "./support/harness";

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

const NOT_THERE = "00000000-0000-4000-8000-000000000000";
const VALIDATION_ZONE = "validation.rfc2136.test";

const configuration = (org: { orgId: string; cookie: string }) => {
  const base = `/api/organizations/${org.orgId}`;
  const call = (path: string, method: string, body?: unknown) => h.api(`${base}${path}`, { cookie: org.cookie, method, body: body ?? (method === "GET" ? undefined : {}) });
  return {
    provider: async (name = "BIND", zone = BIND.zone) => {
      const created = await h.api(`${base}/dns-providers`, {
        cookie: org.cookie,
        body: { name, type: "rfc2136", settings: { server: BIND.server, port: BIND.port, zone, keyName: BIND.keyName }, secret: BIND.keySecret },
      });
      expect(created.status).toBe(201);
      return created.body as { id: string; name: string };
    },
    zones: {
      list: () => call("/validation-zones", "GET"),
      create: (body: unknown) => call("/validation-zones", "POST", body),
      remove: (id: string) => call(`/validation-zones/${id}`, "DELETE"),
    },
    rules: {
      list: () => call("/dcv-rules", "GET"),
      create: (body: unknown) => call("/dcv-rules", "POST", body),
      change: (id: string, body: unknown) => call(`/dcv-rules/${id}`, "PUT", body),
      remove: (id: string) => call(`/dcv-rules/${id}`, "DELETE"),
    },
    preview: (name: string, { lookup = false } = {}) => call(`/dcv/preview?name=${encodeURIComponent(name)}${lookup ? "&lookup=true" : ""}`, "GET"),
  };
};
const admin = () => configuration(acmeOrg);

/** A Validation Zone on a fresh DNS Provider for the BIND zone. */
async function zoneOnBind(org = acmeOrg, name = VALIDATION_ZONE) {
  const provider = await configuration(org).provider();
  const zone = await configuration(org).zones.create({ name, dnsProviderId: provider.id });
  expect(zone.status).toBe(201);
  return { provider, zone: zone.body as { id: string; name: string; dnsProviderId: string } };
}

describe("Validation Zones", () => {
  test("an Organization Administrator defines one on a DNS Provider that can publish records in it", async () => {
    const provider = await admin().provider();

    const created = await admin().zones.create({ name: VALIDATION_ZONE, dnsProviderId: provider.id });

    expect(created.status).toBe(201);
    expect(created.body).toEqual({ id: expect.any(String), name: VALIDATION_ZONE, dnsProviderId: provider.id });
    expect((await admin().zones.list()).body.items).toEqual([created.body]);
  });

  test("the name is kept in lower case without a trailing dot, and the zone of the provider itself is allowed", async () => {
    const provider = await admin().provider();

    const created = await admin().zones.create({ name: "Validation.RFC2136.test.", dnsProviderId: provider.id });
    const own = await admin().zones.create({ name: BIND.zone, dnsProviderId: provider.id });

    expect(created.body.name).toBe(VALIDATION_ZONE);
    expect(own.status).toBe(201);
  });

  test("a zone the DNS Provider cannot publish in, and what is not a zone name, are refused", async () => {
    const provider = await admin().provider();
    for (const name of ["validation.example.test", "rfc2136.test.example.test", "notrfc2136.test", "", "not a zone", "http://validation.rfc2136.test"]) {
      expect((await admin().zones.create({ name, dnsProviderId: provider.id })).status).toBe(400);
    }
    expect((await admin().zones.list()).body.items).toEqual([]);
  });

  test("a zone is on a DNS Provider of the Organization, and no other's", async () => {
    const theirs = await configuration(globex).provider();
    expect((await admin().zones.create({ name: VALIDATION_ZONE, dnsProviderId: theirs.id })).status).toBe(404);
    expect((await admin().zones.create({ name: VALIDATION_ZONE, dnsProviderId: NOT_THERE })).status).toBe(404);
    expect((await admin().zones.create({ name: VALIDATION_ZONE, dnsProviderId: "not-a-uuid" })).status).toBe(404);
    expect((await admin().zones.create({ name: VALIDATION_ZONE })).status).toBe(400);
  });

  test("an Organization defines a zone once, and another Organization may define the same name on its own provider", async () => {
    const provider = await admin().provider();
    expect((await admin().zones.create({ name: VALIDATION_ZONE, dnsProviderId: provider.id })).status).toBe(201);
    expect((await admin().zones.create({ name: VALIDATION_ZONE, dnsProviderId: provider.id })).status).toBe(409);

    await zoneOnBind(globex);
    expect((await configuration(globex).zones.list()).body.items).toHaveLength(1);
  });

  test("a zone is removed, unless a rule delegates through it", async () => {
    const { zone } = await zoneOnBind();
    const rule = await admin().rules.create({ scope: "zone", domain: "delegating.test", method: "delegated", validationZoneId: zone.id });
    expect(rule.status).toBe(201);

    expect((await admin().zones.remove(zone.id)).status).toBe(409);
    expect((await admin().zones.list()).body.items).toHaveLength(1);

    await admin().rules.remove(rule.body.id);
    expect((await admin().zones.remove(zone.id)).status).toBe(200);
    expect((await admin().zones.list()).body.items).toEqual([]);
    expect((await admin().zones.remove(zone.id)).status).toBe(404);
  });
});

describe("DCV Rules", () => {
  test("a rule makes DCV Direct, through a DNS Provider or whichever publishes the name", async () => {
    const provider = await admin().provider();

    const through = await admin().rules.create({ scope: "zone", domain: "Example.test.", method: "direct", dnsProviderId: provider.id });
    const any = await admin().rules.create({ scope: "name", domain: "app.example.test", method: "direct" });

    expect(through.status).toBe(201);
    expect(through.body).toEqual({ id: expect.any(String), scope: "zone", domain: "example.test", method: "direct", dnsProviderId: provider.id, validationZoneId: null });
    expect(any.body).toEqual({ id: expect.any(String), scope: "name", domain: "app.example.test", method: "direct", dnsProviderId: null, validationZoneId: null });
    expect((await admin().rules.list()).body.items).toEqual([through.body, any.body]);
  });

  test("a rule makes DCV Delegated, through a Validation Zone", async () => {
    const { zone } = await zoneOnBind();

    const created = await admin().rules.create({ scope: "zone", domain: "delegating.test", method: "delegated", validationZoneId: zone.id });

    expect(created.status).toBe(201);
    expect(created.body).toEqual({ id: expect.any(String), scope: "zone", domain: "delegating.test", method: "delegated", dnsProviderId: null, validationZoneId: zone.id });
  });

  test("what does not make sense as a rule is refused, and nothing is stored", async () => {
    const { provider, zone } = await zoneOnBind();
    const theirs = await zoneOnBind(globex);
    const theirProvider = await configuration(globex).provider("Theirs");
    const bad = [
      { scope: "zone", domain: "delegating.test", method: "delegated" }, // no Validation Zone
      { scope: "zone", domain: "delegating.test", method: "delegated", validationZoneId: zone.id, dnsProviderId: provider.id }, // two ways at once
      { scope: "zone", domain: "delegating.test", method: "direct", validationZoneId: zone.id },
      { scope: "zone", domain: "*.delegating.test", method: "direct" }, // a rule for a name covers its wildcard already
      { scope: "zone", domain: "not a domain", method: "direct" },
      { scope: "zone", domain: "", method: "direct" },
      { scope: "domain", domain: "delegating.test", method: "direct" },
      { scope: "zone", domain: "delegating.test", method: "magic" },
    ];
    for (const body of bad) expect((await admin().rules.create(body)).status).toBe(400);
    // Another Organization's Validation Zone or provider is no one's to use, and an unknown one is not found.
    for (const body of [
      { scope: "zone", domain: "delegating.test", method: "delegated", validationZoneId: theirs.zone.id },
      { scope: "zone", domain: "delegating.test", method: "delegated", validationZoneId: NOT_THERE },
      { scope: "zone", domain: "delegating.test", method: "direct", dnsProviderId: theirProvider.id },
      { scope: "zone", domain: "delegating.test", method: "direct", dnsProviderId: NOT_THERE },
    ]) {
      expect((await admin().rules.create(body)).status).toBe(404);
    }
    expect((await admin().rules.list()).body.items).toEqual([]);
  });

  test("a name or zone has one rule, scope by scope", async () => {
    const { zone } = await zoneOnBind();
    const first = await admin().rules.create({ scope: "zone", domain: "delegating.test", method: "direct" });
    expect((await admin().rules.create({ scope: "zone", domain: "delegating.test", method: "delegated", validationZoneId: zone.id })).status).toBe(409);
    // The same domain as a name is another rule: the name's own.
    const name = await admin().rules.create({ scope: "name", domain: "delegating.test", method: "delegated", validationZoneId: zone.id });
    expect(name.status).toBe(201);
    expect((await admin().rules.list()).body.items).toEqual([first.body, name.body]);
  });

  test("a rule is changed to Delegated and back, and removed", async () => {
    const { zone } = await zoneOnBind();
    const created = await admin().rules.create({ scope: "zone", domain: "delegating.test", method: "direct" });

    const delegated = await admin().rules.change(created.body.id, { scope: "zone", domain: "delegating.test", method: "delegated", validationZoneId: zone.id });
    expect(delegated.status).toBe(200);
    expect(delegated.body).toEqual({ ...created.body, method: "delegated", validationZoneId: zone.id });

    const refused = await admin().rules.change(created.body.id, { scope: "zone", domain: "delegating.test", method: "delegated" });
    expect(refused.status).toBe(400);
    expect((await admin().rules.list()).body.items).toEqual([delegated.body]);

    const other = await admin().rules.create({ scope: "zone", domain: "other.test", method: "direct" });
    expect((await admin().rules.change(created.body.id, { scope: "zone", domain: "other.test", method: "direct" })).status).toBe(409);
    expect((await admin().rules.change(NOT_THERE, { scope: "zone", domain: "x.test", method: "direct" })).status).toBe(404);

    expect((await admin().rules.remove(created.body.id)).status).toBe(200);
    expect((await admin().rules.list()).body.items).toEqual([other.body]);
    expect((await admin().rules.remove(created.body.id)).status).toBe(404);
    expect((await admin().rules.remove("not-a-uuid")).status).toBe(404);
  });
});

describe("showing how DCV is done for a name, and the CNAME a Delegated name needs", () => {
  test("with no rule, DCV is Direct through the DNS Provider that publishes the name, and no CNAME is needed", async () => {
    const provider = await admin().provider();

    const shown = await admin().preview(`app.${BIND.zone}`);
    expect(shown.status).toBe(200);
    expect(shown.body).toEqual({
      name: `app.${BIND.zone}`,
      challengeName: `_acme-challenge.app.${BIND.zone}`,
      method: "direct",
      rule: null,
      dnsProvider: { id: provider.id, name: "BIND" },
      validationZone: null,
      cname: null,
    });

    // No provider publishes there: DCV has nowhere to write, and the preview says so instead of failing.
    expect((await admin().preview("app.nowhere.test")).body).toMatchObject({ method: "direct", rule: null, dnsProvider: null, cname: null });
  });

  test("for a Delegated name it shows the exact record to create: `_acme-challenge.<name>` as a CNAME into the Validation Zone", async () => {
    const { provider, zone } = await zoneOnBind();
    const rule = await admin().rules.create({ scope: "zone", domain: "delegating.test", method: "delegated", validationZoneId: zone.id });

    const shown = await admin().preview("app.delegating.test");

    expect(shown.body).toEqual({
      name: "app.delegating.test",
      challengeName: "_acme-challenge.app.delegating.test",
      method: "delegated",
      rule: { id: rule.body.id, scope: "zone", domain: "delegating.test" },
      dnsProvider: { id: provider.id, name: "BIND" },
      validationZone: { id: zone.id, name: VALIDATION_ZONE },
      cname: { name: "_acme-challenge.app.delegating.test", type: "CNAME", value: `app.delegating.test.${VALIDATION_ZONE}` },
    });
  });

  test("asked to look it up, it says what the CNAME points to now, and whether that is the record to create", async () => {
    const { zone } = await zoneOnBind();
    await admin().rules.create({ scope: "zone", domain: "delegating.test", method: "delegated", validationZoneId: zone.id });
    const target = `app.delegating.test.${VALIDATION_ZONE}`;
    const pointing: Record<string, string[]> = { "_acme-challenge.app.delegating.test": [target], "_acme-challenge.old.delegating.test": ["old.elsewhere.test"] };
    h.dcvResolver.current = { lookupTxt: async () => [], lookupCname: async (name) => pointing[name] ?? [] };

    expect((await admin().preview("app.delegating.test", { lookup: true })).body.dns).toEqual({ pointsTo: [target], matches: true });
    expect((await admin().preview("old.delegating.test", { lookup: true })).body.dns).toEqual({ pointsTo: ["old.elsewhere.test"], matches: false });
    expect((await admin().preview("new.delegating.test", { lookup: true })).body.dns).toEqual({ pointsTo: [], matches: false });
    // Not asked, it looks nothing up; a Direct name needs no CNAME, so there is nothing to look up.
    expect((await admin().preview("app.delegating.test")).body).not.toHaveProperty("dns");
    expect((await admin().preview(`app.${BIND.zone}`, { lookup: true })).body.dns).toBeNull();
  });

  test("a wildcard is challenged at its base name, so it shows the same record as the base name", async () => {
    const { zone } = await zoneOnBind();
    await admin().rules.create({ scope: "zone", domain: "delegating.test", method: "delegated", validationZoneId: zone.id });

    const wildcard = await admin().preview("*.Wild.Delegating.test");
    const base = await admin().preview("wild.delegating.test");

    expect(wildcard.body.cname).toEqual({ name: "_acme-challenge.wild.delegating.test", type: "CNAME", value: `wild.delegating.test.${VALIDATION_ZONE}` });
    expect({ ...wildcard.body, name: undefined }).toEqual({ ...base.body, name: undefined });
    expect(wildcard.body.name).toBe("*.wild.delegating.test");
  });

  test("the most specific rule decides: a name's own, then the longest zone", async () => {
    const { zone } = await zoneOnBind();
    const provider = await admin().provider("Direct");
    const broad = await admin().rules.create({ scope: "zone", domain: "rfc2136.test", method: "delegated", validationZoneId: zone.id });
    const narrow = await admin().rules.create({ scope: "zone", domain: "internal.rfc2136.test", method: "direct", dnsProviderId: provider.id });
    const own = await admin().rules.create({ scope: "name", domain: "special.internal.rfc2136.test", method: "delegated", validationZoneId: zone.id });

    const ruleOf = async (name: string) => (await admin().preview(name)).body.rule?.id;
    expect(await ruleOf("www.rfc2136.test")).toBe(broad.body.id);
    expect(await ruleOf("rfc2136.test")).toBe(broad.body.id);
    expect(await ruleOf("a.b.internal.rfc2136.test")).toBe(narrow.body.id);
    expect(await ruleOf("internal.rfc2136.test")).toBe(narrow.body.id);
    expect(await ruleOf("special.internal.rfc2136.test")).toBe(own.body.id);
    // A name's own rule is for that name only, not what is beneath it.
    expect(await ruleOf("x.special.internal.rfc2136.test")).toBe(narrow.body.id);
    // Not under any rule's zone: the default.
    expect(await ruleOf("other.test")).toBeUndefined();
    expect((await admin().preview("internal.rfc2136.test")).body).toMatchObject({ method: "direct", dnsProvider: { id: provider.id, name: "Direct" }, cname: null });
    // A rule that names a DNS Provider which cannot publish the name leaves DCV with none, which the preview shows.
    await admin().rules.create({ scope: "zone", domain: "other.test", method: "direct", dnsProviderId: provider.id });
    expect((await admin().preview("www.other.test")).body).toMatchObject({ method: "direct", dnsProvider: null });
  });

  test("something that cannot be a name is refused", async () => {
    for (const name of ["", "not a name", "1.2.3.4", "a_b.example.test"]) expect((await admin().preview(name)).status).toBe(400);
  });
});

describe("who may configure DCV", () => {
  async function join(email: string, role: string) {
    const invited = await h.api("/api/auth/organization/invite-member", { cookie: acmeOrg.cookie, body: { email, role, organizationId: acmeOrg.orgId } });
    const cookie = await h.signUp(email, PASSWORD);
    await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
    return h.signIn(email, PASSWORD);
  }

  test("only an Organization Administrator", async () => {
    const { zone } = await zoneOnBind();
    const rule = await admin().rules.create({ scope: "zone", domain: "delegating.test", method: "delegated", validationZoneId: zone.id });
    for (const role of ["approver", "member"]) {
      const as = configuration({ orgId: acmeOrg.orgId, cookie: await join(`${role}@acme.test`, role) });
      for (const response of [
        await as.zones.list(),
        await as.zones.create({ name: "x.rfc2136.test", dnsProviderId: zone.dnsProviderId }),
        await as.zones.remove(zone.id),
        await as.rules.list(),
        await as.rules.create({ scope: "zone", domain: "x.test", method: "direct" }),
        await as.rules.change(rule.body.id, { scope: "zone", domain: "x.test", method: "direct" }),
        await as.rules.remove(rule.body.id),
        await as.preview("app.delegating.test"),
      ]) {
        expect(response.status).toBe(403);
      }
    }
    const anon = configuration({ orgId: acmeOrg.orgId, cookie: "" });
    expect((await anon.zones.list()).status).toBe(401);
    expect((await anon.rules.list()).status).toBe(401);
    expect((await anon.preview("app.delegating.test")).status).toBe(401);
    expect((await admin().zones.list()).body.items).toHaveLength(1);
  });

  test("another Organization sees nothing of it, not even by id; neither does an Operator who was not invited", async () => {
    const { zone } = await zoneOnBind();
    const rule = await admin().rules.create({ scope: "zone", domain: "delegating.test", method: "delegated", validationZoneId: zone.id });

    for (const cookie of [globex.cookie, operator]) {
      const other = configuration({ orgId: acmeOrg.orgId, cookie });
      expect((await other.zones.list()).status).toBe(404);
      expect((await other.rules.list()).status).toBe(404);
      expect((await other.preview("app.delegating.test")).status).toBe(404);
    }
    const own = configuration(globex);
    expect((await own.zones.remove(zone.id)).status).toBe(404);
    expect((await own.rules.remove(rule.body.id)).status).toBe(404);
    expect((await own.rules.change(rule.body.id, { scope: "zone", domain: "x.test", method: "direct" })).status).toBe(404);
    expect((await own.zones.list()).body.items).toEqual([]);
    expect((await own.rules.list()).body.items).toEqual([]);
    // Nor does the other Organization's configuration decide how its own names are validated.
    expect((await own.preview("app.delegating.test")).body).toMatchObject({ method: "direct", rule: null, cname: null });
    expect((await admin().zones.list()).body.items).toHaveLength(1);
  });

  test("an Organization Administrator holds the permissions, which /api/me reports", async () => {
    const me = await h.api("/api/me", { cookie: acmeOrg.cookie });
    const held = me.body.organizations.find((o: any) => o.id === acmeOrg.orgId).permissions;
    expect(held.validationZone).toEqual(["read", "create", "delete"]);
    expect(held.dcvRule).toEqual(["read", "create", "update", "delete"]);
  });
});

describe("audit", () => {
  const dcvEvents = async () =>
    ((await h.api(`/api/organizations/${acmeOrg.orgId}/audit-events`, { cookie: acmeOrg.cookie })).body.items as any[]).filter((e) =>
      /^(validation_zone|dcv_rule)\./.test(e.action),
    );

  test("defining and removing a Validation Zone, and creating, changing and removing a rule, are audited with what changed", async () => {
    const { provider, zone } = await zoneOnBind();
    const rule = await admin().rules.create({ scope: "zone", domain: "delegating.test", method: "delegated", validationZoneId: zone.id });
    await admin().rules.change(rule.body.id, { scope: "zone", domain: "delegating.test", method: "direct", dnsProviderId: provider.id });
    await admin().rules.remove(rule.body.id);
    await admin().zones.remove(zone.id);

    const actor = { id: expect.any(String), email: "admin@acme.test" };
    expect(await dcvEvents()).toEqual([
      expect.objectContaining({ action: "validation_zone.created", actor, target: { type: "validation_zone", id: zone.id }, detail: { name: VALIDATION_ZONE, dnsProviderId: provider.id } }),
      expect.objectContaining({
        action: "dcv_rule.created",
        actor,
        target: { type: "dcv_rule", id: rule.body.id },
        detail: { scope: "zone", domain: "delegating.test", method: "delegated", validationZoneId: zone.id, dnsProviderId: null },
      }),
      expect.objectContaining({
        action: "dcv_rule.changed",
        actor,
        target: { type: "dcv_rule", id: rule.body.id },
        detail: {
          scope: "zone",
          domain: "delegating.test",
          method: "direct",
          validationZoneId: null,
          dnsProviderId: provider.id,
          previous: { scope: "zone", domain: "delegating.test", method: "delegated", validationZoneId: zone.id, dnsProviderId: null },
        },
      }),
      expect.objectContaining({
        action: "dcv_rule.deleted",
        actor,
        target: { type: "dcv_rule", id: rule.body.id },
        detail: { scope: "zone", domain: "delegating.test", method: "direct", validationZoneId: null, dnsProviderId: provider.id },
      }),
      expect.objectContaining({ action: "validation_zone.deleted", actor, target: { type: "validation_zone", id: zone.id }, detail: { name: VALIDATION_ZONE, dnsProviderId: provider.id } }),
    ]);
  });

  test("a change that is refused leaves no Audit Event", async () => {
    const { zone } = await zoneOnBind();
    await admin().zones.create({ name: VALIDATION_ZONE, dnsProviderId: zone.dnsProviderId }); // the name is taken
    await admin().zones.create({ name: "elsewhere.test", dnsProviderId: zone.dnsProviderId });
    await admin().rules.create({ scope: "zone", domain: "x.test", method: "delegated" });
    const rule = await admin().rules.create({ scope: "zone", domain: "x.test", method: "delegated", validationZoneId: zone.id });
    await admin().rules.create({ scope: "zone", domain: "x.test", method: "direct" }); // the zone has its rule
    await admin().zones.remove(zone.id); // a rule uses it
    await admin().rules.change(rule.body.id, { scope: "zone", domain: "x.test", method: "delegated" });

    expect((await dcvEvents()).map((e) => e.action)).toEqual(["validation_zone.created", "dcv_rule.created"]);
  });
});
