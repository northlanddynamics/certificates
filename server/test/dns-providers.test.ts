// An Organization's RFC 2136 DNS Providers: connected, changed and tested through the API, with the TSIG key a
// write-only secret (ADR 0002). The DNS server is BIND (docker-compose); the provider code is the real one.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { BIND, PASSWORD, createHarness, type Harness } from "./harness";

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

const base = (orgId: string) => `/api/organizations/${orgId}/dns-providers`;
const providers = (cookie: string, orgId: string) => ({
  list: () => h.api(base(orgId), { cookie }),
  create: (body: unknown = rfc2136()) => h.api(base(orgId), { cookie, body }),
  change: (id: string, body: unknown) => h.api(`${base(orgId)}/${id}`, { cookie, method: "PUT", body }),
  replaceSecret: (id: string, secret: unknown) => h.api(`${base(orgId)}/${id}/secret`, { cookie, method: "PUT", body: { secret } }),
  test: (id: string) => h.api(`${base(orgId)}/${id}/test`, { cookie, method: "POST", body: {} }),
});
const admin = () => providers(acmeOrg.cookie, acmeOrg.orgId);

/** A DNS Provider request for the BIND zone, with the settings in `settings` and the TSIG key's secret in `secret` overriding the defaults. */
const rfc2136 = (over: { name?: string; settings?: object; secret?: string } = {}) => ({
  name: over.name ?? "BIND",
  type: "rfc2136",
  settings: { server: BIND.server, port: BIND.port, zone: BIND.zone, keyName: BIND.keyName, ...over.settings },
  secret: over.secret ?? BIND.keySecret,
});

describe("connecting an RFC 2136 DNS Provider", () => {
  test("an Organization Administrator adds one with server, zone and TSIG key, and the key is not returned", async () => {
    const created = await admin().create();
    expect(created.status).toBe(201);
    expect(created.body).toEqual({
      id: expect.any(String),
      name: "BIND",
      type: "rfc2136",
      settings: { server: BIND.server, port: BIND.port, zone: BIND.zone, keyName: BIND.keyName, algorithm: "hmac-sha256" },
    });

    const listed = await admin().list();
    expect(listed.status).toBe(200);
    expect(listed.body.items).toEqual([created.body]);
    expect(JSON.stringify([created.body, listed.body])).not.toContain(BIND.keySecret);
  });

  test("settings are normalised, and the port defaults to 53 and the algorithm to hmac-sha256", async () => {
    const created = await admin().create({
      name: "Defaults",
      type: "rfc2136",
      settings: { server: "DNS.Acme.Test", zone: "Acme.Test.", keyName: "Key.Acme.Test." },
      secret: BIND.keySecret,
    });
    expect(created.status).toBe(201);
    expect(created.body.settings).toEqual({ server: "dns.acme.test", port: 53, zone: "acme.test", keyName: "key.acme.test", algorithm: "hmac-sha256" });
  });

  test("what cannot be a DNS Provider is refused, and nothing is stored", async () => {
    const bad = (over: object) => admin().create({ ...rfc2136(), ...over });
    const settings = (over: object) => ({ ...rfc2136().settings, ...over });
    for (const refused of [
      await bad({ settings: settings({ server: "http://dns.acme.test" }) }),
      await bad({ settings: settings({ server: "" }) }),
      await bad({ settings: settings({ zone: "not a zone" }) }),
      await bad({ settings: settings({ keyName: "" }) }),
      await bad({ settings: settings({ port: 0 }) }),
      await bad({ settings: settings({ port: 70000 }) }),
      await bad({ settings: settings({ algorithm: "rot13" }) }),
      await bad({ settings: { server: BIND.server } }),
      await bad({ secret: "not base64!" }),
      await bad({ secret: "" }),
      await bad({ type: "carrier-pigeon" }),
      await bad({ name: " " }),
    ]) {
      expect(refused.status).toBe(400);
    }
    expect((await admin().list()).body.items).toEqual([]);
  });

  test("a refused secret is not quoted back", async () => {
    const res = await admin().create(rfc2136({ secret: "definitely-not-base64-but-secret!" }));
    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).not.toContain("definitely-not-base64");
  });

  test("names are unique within an Organization, and only there", async () => {
    expect((await admin().create(rfc2136({ name: "Primary" }))).status).toBe(201);
    expect((await admin().create(rfc2136({ name: "Primary" }))).status).toBe(409);
    expect((await admin().create(rfc2136({ name: "Secondary" }))).status).toBe(201);
    expect((await providers(globex.cookie, globex.orgId).create(rfc2136({ name: "Primary" }))).status).toBe(201);
    expect((await admin().list()).body.items.map((p: any) => p.name)).toEqual(["Primary", "Secondary"]);
  });
});

describe("testing the connection", () => {
  test("succeeds when the server accepts the TSIG key's updates in the zone", async () => {
    const { body } = await admin().create();
    const tested = await admin().test(body.id);
    expect(tested.status).toBe(200);
    expect(tested.body).toEqual({ ok: true });
  });

  test("reports a wrong secret in words", async () => {
    const { body } = await admin().create(rfc2136({ secret: Buffer.from("not the key at all").toString("base64") }));
    const tested = await admin().test(body.id);
    expect(tested.status).toBe(200);
    expect(tested.body).toEqual({ ok: false, error: expect.stringMatching(/TSIG/) });
  });

  test("reports a zone that refuses updates, and a server that is not there", async () => {
    const readonly = await admin().create(rfc2136({ name: "Readonly", settings: { zone: BIND.readonlyZone } }));
    expect((await admin().test(readonly.body.id)).body).toEqual({ ok: false, error: expect.stringMatching(/refused/i) });

    const gone = await admin().create(rfc2136({ name: "Gone", settings: { port: 1 } }));
    expect((await admin().test(gone.body.id)).body).toEqual({ ok: false, error: expect.stringContaining(`${BIND.server}:1`) });
  });
});

describe("a provider that cannot be used at all", () => {
  test("is reported by the test, and audited like any other result", async () => {
    const { body } = await admin().create();
    // Settings that no longer parse, as after a release that tightened them.
    await h.pool.query(`update dns_provider set settings = '{"server": 7}'::jsonb where id = $1`, [body.id]);

    const tested = await admin().test(body.id);
    expect(tested.status).toBe(200);
    expect(tested.body).toEqual({ ok: false, error: expect.any(String) });
    const events = (await h.api(`/api/organizations/${acmeOrg.orgId}/audit-events`, { cookie: acmeOrg.cookie })).body.items;
    expect(events.at(-1)).toMatchObject({ action: "dns_provider.tested", detail: { ok: false } });
  });
});

describe("changing a DNS Provider", () => {
  test("settings and name change, the secret stays, and the test then reflects the change", async () => {
    const { body } = await admin().create(rfc2136({ settings: { zone: BIND.readonlyZone } }));
    expect((await admin().test(body.id)).body.ok).toBe(false);

    const changed = await admin().change(body.id, {
      name: "BIND (fixed)",
      settings: { server: BIND.server, port: BIND.port, zone: BIND.zone, keyName: BIND.keyName },
    });
    expect(changed.status).toBe(200);
    expect(changed.body).toEqual({
      id: body.id,
      name: "BIND (fixed)",
      type: "rfc2136",
      settings: { server: BIND.server, port: BIND.port, zone: BIND.zone, keyName: BIND.keyName, algorithm: "hmac-sha256" },
    });
    expect((await admin().list()).body.items).toEqual([changed.body]);
    expect((await admin().test(body.id)).body).toEqual({ ok: true });
  });

  test("invalid settings and a name already taken are refused, and nothing changes", async () => {
    const first = await admin().create(rfc2136({ name: "First" }));
    await admin().create(rfc2136({ name: "Second" }));
    expect((await admin().change(first.body.id, { name: "First", settings: { server: "" } })).status).toBe(400);
    expect((await admin().change(first.body.id, { name: "Second", settings: first.body.settings })).status).toBe(409);
    expect((await admin().list()).body.items[0]).toEqual(first.body);
  });

  test("the secret is replaced on its own", async () => {
    const { body } = await admin().create(rfc2136({ secret: Buffer.from("the wrong key").toString("base64") }));
    expect((await admin().test(body.id)).body.ok).toBe(false);

    const replaced = await admin().replaceSecret(body.id, BIND.keySecret);
    expect(replaced.status).toBe(200);
    expect(replaced.body).toEqual(body);
    expect((await admin().test(body.id)).body).toEqual({ ok: true });

    expect((await admin().replaceSecret(body.id, "not base64!")).status).toBe(400);
    expect((await admin().replaceSecret(body.id, 42)).status).toBe(400);
    expect((await admin().test(body.id)).body).toEqual({ ok: true });
  });

  test("an unknown DNS Provider is a 404", async () => {
    const id = "00000000-0000-4000-8000-000000000000";
    expect((await admin().test(id)).status).toBe(404);
    expect((await admin().replaceSecret(id, BIND.keySecret)).status).toBe(404);
    expect((await admin().change(id, { name: "x", settings: rfc2136().settings })).status).toBe(404);
    expect((await admin().test("not-a-uuid")).status).toBe(404);
  });
});

describe("who may manage DNS Providers", () => {
  async function join(email: string, role: string) {
    const invited = await h.api("/api/auth/organization/invite-member", { cookie: acmeOrg.cookie, body: { email, role, organizationId: acmeOrg.orgId } });
    const cookie = await h.signUp(email, PASSWORD);
    await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
    return h.signIn(email, PASSWORD);
  }

  test("only an Organization Administrator", async () => {
    const { body } = await admin().create();
    for (const role of ["approver", "member"]) {
      const as = providers(await join(`${role}@acme.test`, role), acmeOrg.orgId);
      expect((await as.list()).status).toBe(403);
      expect((await as.create()).status).toBe(403);
      expect((await as.change(body.id, { name: "x", settings: rfc2136().settings })).status).toBe(403);
      expect((await as.replaceSecret(body.id, BIND.keySecret)).status).toBe(403);
      expect((await as.test(body.id)).status).toBe(403);
    }
    const anon = providers("", acmeOrg.orgId);
    expect((await anon.list()).status).toBe(401);
    expect((await anon.create()).status).toBe(401);
  });

  test("another Organization sees nothing: not the list, and not the provider by its id", async () => {
    const { body } = await admin().create();
    const other = providers(globex.cookie, acmeOrg.orgId);
    expect((await other.list()).status).toBe(404);
    expect((await other.create()).status).toBe(404);
    expect((await other.test(body.id)).status).toBe(404);

    // Naming one's own Organization with another's provider id finds nothing either.
    const own = providers(globex.cookie, globex.orgId);
    expect((await own.test(body.id)).status).toBe(404);
    expect((await own.replaceSecret(body.id, BIND.keySecret)).status).toBe(404);
    expect((await own.change(body.id, { name: "mine", settings: rfc2136().settings })).status).toBe(404);
    expect((await own.list()).body.items).toEqual([]);
  });

  test("a Platform Operator who was not invited into the Organization sees nothing", async () => {
    const { body } = await admin().create();
    const op = providers(operator, acmeOrg.orgId);
    expect((await op.list()).status).toBe(404);
    expect((await op.create()).status).toBe(404);
    expect((await op.test(body.id)).status).toBe(404);
  });
});

describe("the TSIG key is write-only", () => {
  /** Every response the platform's own API gives about the Organization, as one string. */
  async function everythingReadable(cookie: string, orgId: string) {
    const spec = (await h.api("/api/openapi.json")).body;
    const found: string[] = [];
    for (const [path, ops] of Object.entries<any>(spec.paths)) {
      if (!ops.get) continue;
      const url = path.replace("{orgId}", orgId);
      if (url.includes("{")) continue; // needs an id this sweep does not have
      found.push(JSON.stringify((await h.api(url, { cookie })).body));
    }
    return found.join("\n");
  }

  test("no response, to anyone, contains the key; neither does the audit log; an impersonating Platform Operator reads no more", async () => {
    const created = await admin().create();
    const replacement = Buffer.from("a replacement key, also secret").toString("base64");
    const replaced = await admin().replaceSecret(created.body.id, replacement);
    const changed = await admin().change(created.body.id, { name: "renamed", settings: created.body.settings });
    const tested = await admin().test(created.body.id);

    const me = await h.api("/api/me", { cookie: acmeOrg.cookie });
    const impersonated = await h.api("/api/auth/admin/impersonate-user", { cookie: operator, body: { userId: me.body.user.id } });
    expect(impersonated.status).toBe(200);

    const seen = [
      ...[created, replaced, changed, tested].map((r) => JSON.stringify(r.body)),
      await everythingReadable(acmeOrg.cookie, acmeOrg.orgId),
      await everythingReadable(impersonated.cookie, acmeOrg.orgId),
    ].join("\n");
    expect(seen).toContain("renamed"); // the sweep did read the provider
    for (const secret of [BIND.keySecret, replacement]) expect(seen).not.toContain(secret.replace(/=+$/, ""));
  });
});

describe("audit", () => {
  const dnsEvents = async () =>
    ((await h.api(`/api/organizations/${acmeOrg.orgId}/audit-events`, { cookie: acmeOrg.cookie })).body.items as any[]).filter((e) =>
      e.action.startsWith("dns_provider."),
    );

  test("adding, changing, replacing the secret of and testing a provider are audited, without the secret", async () => {
    const { body } = await admin().create();
    const replacement = Buffer.from("another key worth hiding").toString("base64");
    await admin().replaceSecret(body.id, replacement);
    await admin().change(body.id, { name: "BIND 2", settings: { ...body.settings, port: 1 } });
    await admin().test(body.id);

    const target = { type: "dns_provider", id: body.id };
    const actor = { id: expect.any(String), email: "admin@acme.test" };
    expect(await dnsEvents()).toEqual([
      expect.objectContaining({ action: "dns_provider.created", target, actor, detail: { name: "BIND", type: "rfc2136", settings: body.settings } }),
      expect.objectContaining({ action: "dns_provider.secret_replaced", target, actor, detail: {} }),
      expect.objectContaining({
        action: "dns_provider.changed",
        target,
        actor,
        detail: {
          name: "BIND 2",
          type: "rfc2136",
          settings: { ...body.settings, port: 1 },
          previous: { name: "BIND", settings: body.settings },
        },
      }),
      expect.objectContaining({ action: "dns_provider.tested", target, actor, detail: { ok: false, error: expect.stringContaining(`${BIND.server}:1`) } }),
    ]);
    const log = JSON.stringify(await dnsEvents());
    expect(log).not.toContain(BIND.keySecret.replace(/=+$/, ""));
    expect(log).not.toContain(replacement.replace(/=+$/, ""));
  });

  test("a passing test is audited as such", async () => {
    const { body } = await admin().create();
    await admin().test(body.id);
    expect((await dnsEvents()).at(-1)).toMatchObject({ action: "dns_provider.tested", detail: { ok: true } });
  });

  test("a change that is refused leaves no Audit Event", async () => {
    const { body } = await admin().create();
    await admin().change(body.id, { name: "x", settings: { server: "" } });
    await admin().replaceSecret(body.id, "not base64!");
    await admin().create(rfc2136()); // the name is taken
    expect((await dnsEvents()).map((e) => e.action)).toEqual(["dns_provider.created"]);
  });
});
