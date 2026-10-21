// The ACME CAs an Organization can use, its ACME account with each, and the write-only secret behind it. The CA is Pebble and the
// ACME client is the real one; the account's key is a secret that no API returns (ADR 0002).
import { afterAll, beforeAll, beforeEach, describe, expect, spyOn, test } from "bun:test";
import acme from "acme-client";
import { PASSWORD, PEBBLE_DIRECTORY, PEBBLE_EAB_DIRECTORY, PEBBLE_MANAGEMENT, PEBBLE_EAB_KEY, createHarness, type Harness } from "./support/harness";

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

const base = (orgId: string) => `/api/organizations/${orgId}/acme-accounts`;
const accounts = (cookie: string, orgId: string) => ({
  list: () => h.api(base(orgId), { cookie }),
  create: (body: unknown = { termsOfServiceAgreed: true }) => h.api(base(orgId), { cookie, body }),
  replaceKey: (id: string, privateKey: string) => h.api(`${base(orgId)}/${id}/key`, { cookie, method: "PUT", body: { privateKey } }),
  test: (id: string) => h.api(`${base(orgId)}/${id}/test`, { cookie, method: "POST", body: {} }),
});
const admin = () => accounts(acmeOrg.cookie, acmeOrg.orgId);
const customCa = (body: Record<string, unknown> = {}, cookie = acmeOrg.cookie, orgId = acmeOrg.orgId) =>
  h.api(`/api/organizations/${orgId}/acme-cas`, { cookie, body: { name: "Internal CA", directoryUrl: PEBBLE_DIRECTORY, tag: "staging", termsOfServiceAgreed: true, ...body } });
const acmeCasOf = async (cookie = acmeOrg.cookie, orgId = acmeOrg.orgId) => (await h.api(`/api/organizations/${orgId}/acme-cas`, { cookie })).body.items as any[];
const auditOf = async (cookie = acmeOrg.cookie, orgId = acmeOrg.orgId) =>
  (await h.api(`/api/organizations/${orgId}/audit-events`, { cookie })).body.items as { action: string; target: any; detail: any }[];

/** The base64 body of a PEM, which is what would show if a key leaked in any encoding that keeps it intact. */
const pemBody = (pem: string) => pem.replace(/-----[^-]+-----|\s/g, "");

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

async function join(email: string, role: string, orgId = acmeOrg.orgId) {
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: acmeOrg.cookie, body: { email, role, organizationId: orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}

/** The CA's side of an account's key being rolled over: `account` now answers only to the returned key. */
async function rollOverAtCa(account: { accountUrl: string; accountKey: string }) {
  const newKey = (await acme.crypto.createPrivateEcdsaKey("P-256")).toString();
  const client = new acme.Client({ directoryUrl: PEBBLE_DIRECTORY, accountKey: account.accountKey, accountUrl: account.accountUrl });
  await client.updateAccountKey(newKey);
  return newKey;
}

describe("creating an ACME account", () => {
  test("an Organization Administrator registers the Organization's account, with Let's Encrypt Staging unless another ACME CA is chosen", async () => {
    const created = await admin().create();
    expect(created.status).toBe(201);
    expect(created.body).toEqual({
      id: expect.any(String),
      acmeCaId: "letsencrypt-staging",
      accountUrl: expect.stringContaining("/my-account/"),
      contactEmail: null,
    });

    const production = await admin().create({ acmeCaId: "letsencrypt-production", contactEmail: "pki@acme.test", termsOfServiceAgreed: true });
    expect(production.status).toBe(201);
    expect(production.body).toMatchObject({ acmeCaId: "letsencrypt-production", contactEmail: "pki@acme.test" });

    const listed = await admin().list();
    expect(listed.status).toBe(200);
    expect(listed.body.items.map((a: any) => a.acmeCaId)).toEqual(["letsencrypt-staging", "letsencrypt-production"]);
  });

  test("the account exists at the CA, and the platform can act as it", async () => {
    const { body } = await admin().create();
    const tested = await admin().test(body.id);
    expect(tested.status).toBe(200);
    expect(tested.body).toEqual({ ok: true });
  });

  test("an Organization has one account per ACME CA", async () => {
    expect((await admin().create()).status).toBe(201);
    expect((await admin().create()).status).toBe(409);
    expect((await admin().create({ acmeCaId: "letsencrypt-production", termsOfServiceAgreed: true })).status).toBe(201);
    expect((await admin().list()).body.items).toHaveLength(2);
  });

  test("an ACME CA the Organization cannot use is a 404, and nothing is registered", async () => {
    expect((await admin().create({ acmeCaId: "letsencrypt-elsewhere", termsOfServiceAgreed: true })).status).toBe(404);
    expect((await admin().list()).body.items).toEqual([]);
    expect(h.createdAccountKeys).toEqual([]);
  });

  test("the terms of service must be agreed to", async () => {
    expect((await admin().create({})).status).toBe(400);
    expect((await admin().create({ termsOfServiceAgreed: false })).status).toBe(400);
    expect((await admin().list()).body.items).toEqual([]);
  });

  test("an unreachable CA is a 502 and leaves nothing behind", async () => {
    h.caDirectories["letsencrypt-staging"] = "https://localhost:1/dir";
    const res = await admin().create();
    expect(res.status).toBe(502);
    expect(res.body.error).toContain("could not reach");
    expect((await admin().list()).body.items).toEqual([]);
    expect((await auditOf()).map((e) => e.action)).not.toContain("acme_account.created");
  });

  test("each account has its own key", async () => {
    await admin().create();
    await admin().create({ acmeCaId: "letsencrypt-production", termsOfServiceAgreed: true });
    expect(new Set(h.createdAccountKeys).size).toBe(2);
  });
});

describe("the ACME CAs", () => {
  const acmeCas = (cookie: string, orgId = acmeOrg.orgId) => h.api(`/api/organizations/${orgId}/acme-cas`, { cookie });

  test("Let's Encrypt Staging then Production are built in, with their tags and the directories the platform talks to", async () => {
    const listed = await acmeCas(acmeOrg.cookie);
    expect(listed.status).toBe(200);
    expect(listed.body.items).toEqual([
      { id: "letsencrypt-staging", name: "Let's Encrypt Staging", directoryUrl: PEBBLE_DIRECTORY, tag: "staging", builtIn: true, hasAccount: false, externalAccountBinding: null },
      { id: "letsencrypt-production", name: "Let's Encrypt Production", directoryUrl: PEBBLE_DIRECTORY, tag: "production", builtIn: true, hasAccount: false, externalAccountBinding: null },
    ]);
    // The same for every Organization.
    expect((await acmeCas(globex.cookie, globex.orgId)).body).toEqual(listed.body);
  });

  test("each says whether the Organization has an account with it, to everyone in it", async () => {
    expect((await admin().create({ acmeCaId: "letsencrypt-production", termsOfServiceAgreed: true })).status).toBe(201);
    const { body } = await customCa();
    const member = await join("member@acme.test", "member");
    for (const cookie of [acmeOrg.cookie, member]) {
      expect((await acmeCas(cookie)).body.items.map((ca: any) => [ca.id, ca.hasAccount])).toEqual([
        ["letsencrypt-staging", false],
        ["letsencrypt-production", true],
        [body.acmeCa.id, true],
      ]);
    }
    // Another Organization's accounts are its own.
    expect((await acmeCas(globex.cookie, globex.orgId)).body.items.map((ca: any) => ca.hasAccount)).toEqual([false, false]);
  });

  test("anyone in the Organization sees which there are, to choose one; only those who may read the ACME accounts see their configuration", async () => {
    for (const role of ["approver", "member"]) {
      const listed = await acmeCas(await join(`${role}@acme.test`, role));
      expect(listed.status).toBe(200);
      expect(listed.body.items.map((ca: any) => [ca.id, ca.tag, ca.directoryUrl])).toEqual([
        ["letsencrypt-staging", "staging", null],
        ["letsencrypt-production", "production", null],
      ]);
    }
    expect((await acmeCas(globex.cookie)).status).toBe(404);
    expect((await acmeCas("")).status).toBe(401);
  });
});

describe("adding a custom ACME CA", () => {
  test("an Organization Administrator adds one, and the Organization's account with it is registered in the same step", async () => {
    const created = await customCa({ contactEmail: "pki@acme.test" });
    expect(created.status).toBe(201);
    expect(created.body).toEqual({
      acmeCa: { id: expect.any(String), name: "Internal CA", directoryUrl: PEBBLE_DIRECTORY, tag: "staging", builtIn: false, hasAccount: true, externalAccountBinding: null },
      account: { id: expect.any(String), acmeCaId: created.body.acmeCa.id, accountUrl: expect.stringContaining("/my-account/"), contactEmail: "pki@acme.test" },
    });
    expect(h.createdAccountKeys).toHaveLength(1);

    // Listed after the built-in ones, with its account; and the account works at the CA.
    expect((await acmeCasOf()).map((ca) => [ca.name, ca.tag, ca.builtIn])).toEqual([
      ["Let's Encrypt Staging", "staging", true],
      ["Let's Encrypt Production", "production", true],
      ["Internal CA", "staging", false],
    ]);
    expect((await admin().list()).body.items).toEqual([created.body.account]);
    expect((await admin().test(created.body.account.id)).body).toEqual({ ok: true });
    // It has its account already.
    expect((await admin().create({ acmeCaId: created.body.acmeCa.id, termsOfServiceAgreed: true })).status).toBe(409);
  });

  test("the tag is staging, production or none", async () => {
    expect((await customCa({ name: "Untagged", tag: undefined })).body.acmeCa.tag).toBeNull();
    expect((await customCa({ name: "Null", tag: null })).body.acmeCa.tag).toBeNull();
    expect((await customCa({ name: "Production", tag: "production" })).body.acmeCa.tag).toBe("production");
    expect((await customCa({ name: "Testing", tag: "testing" })).status).toBe(400);
    expect((await acmeCasOf()).filter((ca) => !ca.builtIn).map((ca) => [ca.name, ca.tag])).toEqual([
      ["Untagged", null],
      ["Null", null],
      ["Production", "production"],
    ]);
  });

  test("an Organization may have several, under names unique within it; a name taken leaves nothing at the CA", async () => {
    expect((await customCa({ name: "First" })).status).toBe(201);
    expect((await customCa({ name: "Second" })).status).toBe(201);
    expect(h.createdAccountKeys).toHaveLength(2);

    for (const name of ["First", "  First ", "Let's Encrypt Staging"]) {
      const taken = await customCa({ name });
      expect(taken.status).toBe(409);
      expect(taken.body.error).toContain("already an ACME CA named");
    }
    expect(h.createdAccountKeys).toHaveLength(2);
    expect((await acmeCasOf()).filter((ca) => !ca.builtIn).map((ca) => ca.name)).toEqual(["First", "Second"]);

    // Another Organization may use the same name.
    expect((await customCa({ name: "First" }, globex.cookie, globex.orgId)).status).toBe(201);
  });

  test("when the CA refuses the registration, its reason is shown and nothing is saved", async () => {
    h.registrationRefusal.reason = "urn:ietf:params:acme:error:externalAccountRequired: an external account binding is required";
    const refused = await customCa();
    expect(refused.status).toBe(422);
    expect(refused.body.error).toContain("an external account binding is required");
    expect((await acmeCasOf()).filter((ca) => !ca.builtIn)).toEqual([]);
    expect((await admin().list()).body.items).toEqual([]);
    expect((await auditOf()).map((e) => e.action).filter((a) => a.startsWith("acme_"))).toEqual([]);

    // Nothing is left to stop it being added once the CA accepts.
    h.registrationRefusal.reason = null;
    expect((await customCa()).status).toBe(201);
  });

  test("a directory that does not answer as an ACME directory is a 502, and nothing is saved", async () => {
    const res = await customCa({ directoryUrl: new URL("/no-such-directory", PEBBLE_DIRECTORY).href });
    expect(res.status).toBe(502);
    expect(res.body.error).toContain("could not reach Internal CA");
    expect((await acmeCasOf()).filter((ca) => !ca.builtIn)).toEqual([]);
    expect(h.createdAccountKeys).toEqual([]);
  });

  test("a directory URL that is not https is refused", async () => {
    for (const directoryUrl of [PEBBLE_DIRECTORY.replace(/^https:/, "http:"), "ftp://ca.example.test/dir", "not a url"]) {
      const res = await customCa({ directoryUrl });
      expect(res.status).toBe(400);
    }
    expect(JSON.stringify((await customCa({ directoryUrl: "http://ca.example.test/dir" })).body)).toContain("the directory URL must be https");
    expect((await acmeCasOf()).filter((ca) => !ca.builtIn)).toEqual([]);
  });

  test("a directory URL at a loopback or link-local address, the metadata address included, is refused with a clear message", async () => {
    const pebblePort = new URL(PEBBLE_DIRECTORY).port;
    for (const directoryUrl of [
      // Pebble itself, by another origin than the one the tests allow: the rule stops it, not the network.
      `https://127.0.0.1:${pebblePort}/dir`,
      `https://[::1]:${pebblePort}/dir`,
      `https://127.0.0.2:${pebblePort}/dir`,
      `https://0.0.0.0:${pebblePort}/dir`,
      // Its management port: localhost, but not an origin the tests allow (14001 is the Pebble requiring EAB, which they do).
      `https://localhost:${new URL(PEBBLE_MANAGEMENT).port}/dir`,
      "https://169.254.169.254/latest/meta-data/",
      "https://[fe80::1]/dir",
      "https://[::ffff:127.0.0.1]/dir",
      "https://2130706433/dir",
    ]) {
      const res = await customCa({ directoryUrl });
      expect(res.status).toBe(422);
      expect(res.body.error).toBe("the directory URL must not point at a loopback or link-local address");
    }
    expect((await acmeCasOf()).filter((ca) => !ca.builtIn)).toEqual([]);
    expect(h.createdAccountKeys).toEqual([]);
  });

  test("the rule is checked again each time the platform connects to the CA", async () => {
    const { body } = await customCa();
    expect((await admin().test(body.account.id)).body).toEqual({ ok: true });
    // As if its directory had been moved to where it may not be, past the check when it was saved.
    await h.pool.query(`update acme_ca set directory_url = $1 where id = $2`, [`https://127.0.0.1:${new URL(PEBBLE_DIRECTORY).port}/dir`, body.acmeCa.id]);
    expect((await admin().test(body.account.id)).body).toEqual({ ok: false, error: "the directory URL must not point at a loopback or link-local address" });
  });

  test("the terms of service must be agreed to, and a name given", async () => {
    expect((await customCa({ termsOfServiceAgreed: false })).status).toBe(400);
    expect((await customCa({ termsOfServiceAgreed: undefined })).status).toBe(400);
    expect((await customCa({ name: "  " })).status).toBe(400);
    expect(h.createdAccountKeys).toEqual([]);
  });

  test("anyone in the Organization sees it listed, to choose it; only an Organization Administrator sees its configuration or adds one", async () => {
    const { body } = await customCa();
    for (const role of ["approver", "member"]) {
      const cookie = await join(`${role}@acme.test`, role);
      expect((await acmeCasOf(cookie)).find((ca) => ca.id === body.acmeCa.id)).toEqual({ ...body.acmeCa, directoryUrl: null });
      expect((await customCa({ name: `By ${role}` }, cookie)).status).toBe(403);
    }
    expect((await customCa({ name: "By no one" }, "")).status).toBe(401);
    expect((await customCa({ name: "By an operator" }, operator)).status).toBe(404);
    expect(h.createdAccountKeys).toHaveLength(1);
  });

  test("another Organization neither sees it nor can use it", async () => {
    const { body } = await customCa();
    expect((await customCa({ name: "Elsewhere" }, globex.cookie)).status).toBe(404);
    expect((await acmeCasOf(globex.cookie, globex.orgId)).map((ca) => ca.id)).toEqual(["letsencrypt-staging", "letsencrypt-production"]);
    // Naming it from another Organization finds no such ACME CA.
    expect((await accounts(globex.cookie, globex.orgId).create({ acmeCaId: body.acmeCa.id, termsOfServiceAgreed: true })).status).toBe(404);
  });

  test("adding it and registering its account each write an Audit Event, in the same change, without the key", async () => {
    const { body } = await customCa({ name: "Internal CA", tag: "production", contactEmail: "pki@acme.test" });
    const events = (await auditOf()).filter((e) => e.action.startsWith("acme_"));
    expect(events).toEqual([
      expect.objectContaining({
        action: "acme_ca.created",
        target: { type: "acme_ca", id: body.acmeCa.id },
        actor: { id: expect.any(String), email: "admin@acme.test" },
        detail: { name: "Internal CA", directoryUrl: PEBBLE_DIRECTORY, tag: "production", externalAccountBinding: null },
      }),
      expect.objectContaining({
        action: "acme_account.created",
        target: { type: "acme_account", id: body.account.id },
        actor: { id: expect.any(String), email: "admin@acme.test" },
        detail: { acmeCaId: body.acmeCa.id, accountUrl: body.account.accountUrl, contactEmail: "pki@acme.test" },
      }),
    ]);
    expect(JSON.stringify(await auditOf())).not.toContain(pemBody(h.createdAccountKeys[0]!));
  });
});

describe("External Account Binding", () => {
  // A CA that requires it (the second Pebble) registers only an account bound with a key id and HMAC key it issued.
  const eabCa = (externalAccountBinding?: unknown, body: Record<string, unknown> = {}) =>
    customCa({ name: "Commercial CA", directoryUrl: PEBBLE_EAB_DIRECTORY, tag: "production", externalAccountBinding, ...body });
  const wrongHmacKey = "pM_tQXbIwoXQ_LIC6jrMnM-Ty_2y8Fi9kpGX2Ikbi28";

  test("a CA that requires it registers the account when given the key id and HMAC key, and administrators see the key id", async () => {
    const created = await eabCa(PEBBLE_EAB_KEY);
    expect(created.status).toBe(201);
    expect(created.body.acmeCa).toEqual({
      id: expect.any(String),
      name: "Commercial CA",
      directoryUrl: PEBBLE_EAB_DIRECTORY,
      tag: "production",
      builtIn: false,
      hasAccount: true,
      externalAccountBinding: { keyId: PEBBLE_EAB_KEY.keyId },
    });
    expect((await acmeCasOf()).find((ca) => ca.id === created.body.acmeCa.id)).toEqual(created.body.acmeCa);
    expect((await admin().test(created.body.account.id)).body).toEqual({ ok: true });

    // Like the directory URL, it is configuration: not shown to anyone else.
    const member = await join("member@acme.test", "member");
    expect((await acmeCasOf(member)).find((ca) => ca.id === created.body.acmeCa.id)).toEqual({ ...created.body.acmeCa, directoryUrl: null, externalAccountBinding: null });
  });

  test("a CA that requires it refuses the registration when it is absent or wrong, with the CA's reason, and nothing is saved", async () => {
    for (const binding of [undefined, { keyId: PEBBLE_EAB_KEY.keyId, hmacKey: wrongHmacKey }, { keyId: "no-such-kid", hmacKey: PEBBLE_EAB_KEY.hmacKey }]) {
      const refused = await eabCa(binding);
      expect(refused.status).toBe(422);
      expect(refused.body.error).toBeTruthy();
    }
    expect((await eabCa(undefined)).body.error).toMatch(/external ?account/i);
    expect((await acmeCasOf()).filter((ca) => !ca.builtIn)).toEqual([]);
    expect((await admin().list()).body.items).toEqual([]);
    expect(h.createdAccountKeys).toEqual([]);
    expect((await auditOf()).map((e) => e.action).filter((a) => a.startsWith("acme_"))).toEqual([]);

    // Given the right one, it is added.
    expect((await eabCa(PEBBLE_EAB_KEY)).status).toBe(201);
  });

  test("the key id and HMAC key are given together, and the HMAC key is base64 or base64url", async () => {
    for (const binding of [{ keyId: PEBBLE_EAB_KEY.keyId }, { hmacKey: PEBBLE_EAB_KEY.hmacKey }, { keyId: "", hmacKey: PEBBLE_EAB_KEY.hmacKey }, { keyId: PEBBLE_EAB_KEY.keyId, hmacKey: "not base64url!" }]) {
      const res = await eabCa(binding);
      expect(res.status).toBe(400);
      expect(JSON.stringify(res.body)).not.toContain(PEBBLE_EAB_KEY.hmacKey);
    }
    expect(h.createdAccountKeys).toEqual([]);
  });

  test("adding the CA is audited with the key id, and never the HMAC key", async () => {
    const { body } = await eabCa(PEBBLE_EAB_KEY);
    const [created] = (await auditOf()).filter((e) => e.action === "acme_ca.created");
    expect(created!.detail).toEqual({ name: "Commercial CA", directoryUrl: PEBBLE_EAB_DIRECTORY, tag: "production", externalAccountBinding: { keyId: PEBBLE_EAB_KEY.keyId } });
    expect(created!.target).toEqual({ type: "acme_ca", id: body.acmeCa.id });
  });

  test("the HMAC key is a secret: no response, to anyone, Audit Event, error or log contains it", async () => {
    const logged: unknown[] = [];
    const spies = (["log", "info", "warn", "error", "debug"] as const).map((level) => spyOn(console, level).mockImplementation((...args: unknown[]) => void logged.push(...args)));
    try {
      const created = await eabCa(PEBBLE_EAB_KEY);
      const wrong = await eabCa({ keyId: PEBBLE_EAB_KEY.keyId, hmacKey: wrongHmacKey }, { name: "Another" });
      const tested = await admin().test(created.body.account.id);
      const approver = await join("approver@acme.test", "approver");
      const seen = [
        JSON.stringify(created.body),
        JSON.stringify(wrong.body),
        JSON.stringify(tested.body),
        JSON.stringify(await auditOf()),
        await everythingReadable(acmeOrg.cookie, acmeOrg.orgId),
        await everythingReadable(approver, acmeOrg.orgId),
        logged.map((v) => (v instanceof Error ? `${v.message}\n${v.stack}` : typeof v === "string" ? v : JSON.stringify(v))).join("\n"),
      ].join("\n");
      expect(seen).toContain(PEBBLE_EAB_KEY.keyId);
      // Nor is it stored in the clear: only as a Secret, encrypted.
      const stored = JSON.stringify((await h.pool.query("select * from acme_ca")).rows) + JSON.stringify((await h.pool.query("select encode(ciphertext, 'escape') from secret")).rows);
      expect(stored).toContain(PEBBLE_EAB_KEY.keyId);
      expect(stored).not.toContain(PEBBLE_EAB_KEY.hmacKey);
      for (const hmacKey of [PEBBLE_EAB_KEY.hmacKey, wrongHmacKey]) {
        expect(seen).not.toContain(hmacKey);
        expect(seen).not.toContain(hmacKey.slice(0, 16));
        expect(seen).not.toContain(Buffer.from(hmacKey, "base64url").toString("base64").slice(0, 16));
      }
    } finally {
      for (const spy of spies) spy.mockRestore();
    }
  });
});

describe("who may manage ACME accounts", () => {
  test("only an Organization Administrator", async () => {
    const { body } = await admin().create();
    for (const role of ["approver", "member"]) {
      const cookie = await join(`${role}@acme.test`, role);
      const as = accounts(cookie, acmeOrg.orgId);
      expect((await as.list()).status).toBe(403);
      expect((await as.create()).status).toBe(403);
      expect((await as.replaceKey(body.id, "x")).status).toBe(403);
      expect((await as.test(body.id)).status).toBe(403);
    }
    const anon = accounts("", acmeOrg.orgId);
    expect((await anon.list()).status).toBe(401);
    expect((await anon.create()).status).toBe(401);
  });

  test("another Organization sees nothing: not the list, and not the account by its id", async () => {
    const { body } = await admin().create();
    const other = accounts(globex.cookie, acmeOrg.orgId);
    expect((await other.list()).status).toBe(404);
    expect((await other.create()).status).toBe(404);
    expect((await other.test(body.id)).status).toBe(404);

    // Naming one's own Organization with another's account id finds nothing either.
    const own = accounts(globex.cookie, globex.orgId);
    expect((await own.test(body.id)).status).toBe(404);
    expect((await own.replaceKey(body.id, (await acme.crypto.createPrivateEcdsaKey("P-256")).toString())).status).toBe(404);
    expect((await own.list()).body.items).toEqual([]);
  });

  test("a Platform Operator who was not invited into the Organization sees nothing", async () => {
    const { body } = await admin().create();
    const op = accounts(operator, acmeOrg.orgId);
    expect((await op.list()).status).toBe(404);
    expect((await op.create()).status).toBe(404);
    expect((await op.test(body.id)).status).toBe(404);
  });

  test("Organizations have separate accounts even with the same ACME CA", async () => {
    const mine = await admin().create();
    const theirs = await accounts(globex.cookie, globex.orgId).create();
    expect(mine.body.accountUrl).not.toBe(theirs.body.accountUrl);
    expect((await admin().list()).body.items).toHaveLength(1);
  });
});

describe("the account key is write-only", () => {
  test("no response, to anyone, contains the key; neither does the audit log", async () => {
    const created = await admin().create();
    const [key] = h.createdAccountKeys;
    const newKey = await rollOverAtCa({ accountUrl: created.body.accountUrl, accountKey: key! });
    const replaced = await admin().replaceKey(created.body.id, newKey);
    const tested = await admin().test(created.body.id);

    const approver = await join("approver@acme.test", "approver");
    const seen = [
      JSON.stringify(created.body),
      JSON.stringify(replaced.body),
      JSON.stringify(tested.body),
      await everythingReadable(acmeOrg.cookie, acmeOrg.orgId),
      await everythingReadable(approver, acmeOrg.orgId),
    ].join("\n");
    for (const secretKey of [key!, newKey]) {
      expect(seen).not.toContain(pemBody(secretKey));
      expect(seen).not.toContain(pemBody(secretKey).slice(0, 40));
    }
  });

  test("an impersonating Platform Operator reads no more than the administrator does", async () => {
    await admin().create();
    const me = await h.api("/api/me", { cookie: acmeOrg.cookie });
    const impersonated = await h.api("/api/auth/admin/impersonate-user", { cookie: operator, body: { userId: me.body.user.id } });
    expect(impersonated.status).toBe(200);
    // The operator now holds the impersonated administrator's session.
    const cookie = impersonated.cookie;
    expect(cookie).toBeTruthy();
    const seen = await everythingReadable(cookie, acmeOrg.orgId);
    expect(seen).toContain("my-account");
    expect(seen).not.toContain(pemBody(h.createdAccountKeys[0]!));
  });
});

describe("replacing and testing the account key", () => {
  test("a test reports whether the stored key still works at the CA, and changes nothing", async () => {
    const { body } = await admin().create();
    expect((await admin().test(body.id)).body).toEqual({ ok: true });
    await rollOverAtCa({ accountUrl: body.accountUrl, accountKey: h.createdAccountKeys[0]! });

    const stale = await admin().test(body.id);
    expect(stale.status).toBe(200);
    expect(stale.body).toEqual({ ok: false, error: expect.any(String) });
    expect((await auditOf()).map((e) => e.action).filter((a) => a.startsWith("acme_account."))).toEqual(["acme_account.created"]);
  });

  test("the key can be replaced with the key the CA now accepts for the account", async () => {
    const { body } = await admin().create();
    const newKey = await rollOverAtCa({ accountUrl: body.accountUrl, accountKey: h.createdAccountKeys[0]! });
    expect((await admin().test(body.id)).body.ok).toBe(false);

    const replaced = await admin().replaceKey(body.id, newKey);
    expect(replaced.status).toBe(200);
    expect(replaced.body).toEqual(body);
    expect((await admin().test(body.id)).body).toEqual({ ok: true });
  });

  test("a key the CA does not accept for the account is refused, and the stored key stays", async () => {
    const { body } = await admin().create();
    const stranger = (await acme.crypto.createPrivateEcdsaKey("P-256")).toString();
    const res = await admin().replaceKey(body.id, stranger);
    expect(res.status).toBe(422);
    expect(res.body.error).toEqual(expect.any(String));
    expect(res.body.error).not.toContain(pemBody(stranger));
    expect((await admin().test(body.id)).body).toEqual({ ok: true });
    expect((await auditOf()).map((e) => e.action)).not.toContain("acme_account.key_replaced");
  });

  test("something that is not a private key is refused", async () => {
    const { body } = await admin().create();
    const publicKey = acme.crypto.getPublicKey(h.createdAccountKeys[0]!).toString();
    expect((await admin().replaceKey(body.id, "not a key")).status).toBe(400);
    expect((await admin().replaceKey(body.id, publicKey)).status).toBe(400);
    expect((await admin().test(body.id)).body).toEqual({ ok: true });
  });

  test("an unknown account is a 404", async () => {
    const id = "00000000-0000-4000-8000-000000000000";
    expect((await admin().test(id)).status).toBe(404);
    expect((await admin().replaceKey(id, "x")).status).toBe(404);
  });
});

describe("audit", () => {
  test("creating an account and replacing its key are audited, without the key", async () => {
    const { body } = await admin().create({ acmeCaId: "letsencrypt-production", contactEmail: "pki@acme.test", termsOfServiceAgreed: true });
    const newKey = await rollOverAtCa({ accountUrl: body.accountUrl, accountKey: h.createdAccountKeys[0]! });
    expect((await admin().replaceKey(body.id, newKey)).status).toBe(200);

    const events = (await auditOf()).filter((e) => e.action.startsWith("acme_account."));
    expect(events).toEqual([
      expect.objectContaining({
        action: "acme_account.created",
        target: { type: "acme_account", id: body.id },
        actor: { id: expect.any(String), email: "admin@acme.test" },
        detail: { acmeCaId: "letsencrypt-production", accountUrl: body.accountUrl, contactEmail: "pki@acme.test" },
      }),
      expect.objectContaining({
        action: "acme_account.key_replaced",
        target: { type: "acme_account", id: body.id },
        detail: { acmeCaId: "letsencrypt-production" },
      }),
    ]);
    const log = JSON.stringify(await auditOf());
    expect(log).not.toContain(pemBody(h.createdAccountKeys[0]!));
    expect(log).not.toContain(pemBody(newKey));
  });
});
