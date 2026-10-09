// An Organization's ACME account with Let's Encrypt, and the write-only secret behind it. The CA is Pebble and the
// ACME client is the real one; the account's key is a secret that no API returns (ADR 0002).
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import acme from "acme-client";
import { PASSWORD, PEBBLE_DIRECTORY, createHarness, type Harness } from "./harness";

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
const auditOf = async (cookie = acmeOrg.cookie, orgId = acmeOrg.orgId) =>
  (await h.api(`/api/organizations/${orgId}/audit-events`, { cookie })).body.items as { action: string; target: any; detail: any }[];

/** The base64 body of a PEM, which is what would show if a key leaked in any encoding that keeps it intact. */
const pemBody = (pem: string) => pem.replace(/-----[^-]+-----|\s/g, "");

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
  test("an Organization Administrator registers the Organization's account, in staging unless production is chosen", async () => {
    const created = await admin().create();
    expect(created.status).toBe(201);
    expect(created.body).toEqual({
      id: expect.any(String),
      environment: "staging",
      accountUrl: expect.stringContaining("/my-account/"),
      contactEmail: null,
    });

    const production = await admin().create({ environment: "production", contactEmail: "pki@acme.test", termsOfServiceAgreed: true });
    expect(production.status).toBe(201);
    expect(production.body).toMatchObject({ environment: "production", contactEmail: "pki@acme.test" });

    const listed = await admin().list();
    expect(listed.status).toBe(200);
    expect(listed.body.items.map((a: any) => a.environment)).toEqual(["staging", "production"]);
  });

  test("the account exists at the CA, and the platform can act as it", async () => {
    const { body } = await admin().create();
    const tested = await admin().test(body.id);
    expect(tested.status).toBe(200);
    expect(tested.body).toEqual({ ok: true });
  });

  test("an Organization has one account per environment", async () => {
    expect((await admin().create()).status).toBe(201);
    expect((await admin().create()).status).toBe(409);
    expect((await admin().create({ environment: "production", termsOfServiceAgreed: true })).status).toBe(201);
    expect((await admin().list()).body.items).toHaveLength(2);
  });

  test("the terms of service must be agreed to", async () => {
    expect((await admin().create({})).status).toBe(400);
    expect((await admin().create({ termsOfServiceAgreed: false })).status).toBe(400);
    expect((await admin().list()).body.items).toEqual([]);
  });

  test("an unreachable CA is a 502 and leaves nothing behind", async () => {
    h.caDirectories.staging = "https://localhost:1/dir";
    const res = await admin().create();
    expect(res.status).toBe(502);
    expect(res.body.error).toContain("could not reach");
    expect((await admin().list()).body.items).toEqual([]);
    expect((await auditOf()).map((e) => e.action)).not.toContain("acme_account.created");
  });

  test("each account has its own key", async () => {
    await admin().create();
    await admin().create({ environment: "production", termsOfServiceAgreed: true });
    expect(new Set(h.createdAccountKeys).size).toBe(2);
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

  test("Organizations have separate accounts even in the same environment", async () => {
    const mine = await admin().create();
    const theirs = await accounts(globex.cookie, globex.orgId).create();
    expect(mine.body.accountUrl).not.toBe(theirs.body.accountUrl);
    expect((await admin().list()).body.items).toHaveLength(1);
  });
});

describe("the account key is write-only", () => {
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
    const { body } = await admin().create({ environment: "production", contactEmail: "pki@acme.test", termsOfServiceAgreed: true });
    const newKey = await rollOverAtCa({ accountUrl: body.accountUrl, accountKey: h.createdAccountKeys[0]! });
    expect((await admin().replaceKey(body.id, newKey)).status).toBe(200);

    const events = (await auditOf()).filter((e) => e.action.startsWith("acme_account."));
    expect(events).toEqual([
      expect.objectContaining({
        action: "acme_account.created",
        target: { type: "acme_account", id: body.id },
        actor: { id: expect.any(String), email: "admin@acme.test" },
        detail: { environment: "production", accountUrl: body.accountUrl, contactEmail: "pki@acme.test" },
      }),
      expect.objectContaining({
        action: "acme_account.key_replaced",
        target: { type: "acme_account", id: body.id },
        detail: { environment: "production" },
      }),
    ]);
    const log = JSON.stringify(await auditOf());
    expect(log).not.toContain(pemBody(h.createdAccountKeys[0]!));
    expect(log).not.toContain(pemBody(newKey));
  });
});
