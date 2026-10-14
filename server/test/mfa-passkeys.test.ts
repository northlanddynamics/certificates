// MFA and passkeys, through the platform's HTTP API: a user sets up TOTP as a second factor and registers passkeys
// (Better Auth's two-factor and passkey plugins), each change an Audit Event in the user's Organizations, and an
// Organization Administrator can require MFA, after which a password user without it must set it up before going on.
// The authenticator app and the passkey are doubles in the test (totp.ts, passkey-double.ts); time for TOTP codes is real.
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { PASSWORD, createHarness, type Harness } from "./harness";
import { createPasskeyDouble, type PasskeyDouble } from "./passkey-double";
import { totpCode } from "./totp";

setDefaultTimeout(30_000);

let h: Harness;
let operator: string;
let org: { orgId: string; cookie: string };

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  operator = await h.createOperator("op@platform.test", PASSWORD);
  org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
});
afterAll(async () => {
  await h.close();
});

const BA = "/api/auth/organization";
const auditOf = async (orgId = org.orgId, cookie = org.cookie) =>
  (await h.api(`/api/organizations/${orgId}/audit-events`, { cookie })).body.items as { action: string; actor: any; target: any; detail: any }[];

async function join(email: string, role = "member") {
  const invited = await h.api(`${BA}/invite-member`, { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api(`${BA}/accept-invitation`, { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}

/** Sets up TOTP for the signed-in user: asks for a secret, then proves the authenticator app has it. Returns the secret's URI and the session cookie that replaces `cookie`. */
async function setUpTotp(cookie: string) {
  const enabled = await h.api("/api/auth/two-factor/enable", { cookie, body: { password: PASSWORD } });
  expect(enabled.status).toBe(200);
  const verified = await h.api("/api/auth/two-factor/verify-totp", { cookie, body: { code: totpCode(enabled.body.totpURI) } });
  expect(verified.status).toBe(200);
  return { totpURI: enabled.body.totpURI as string, backupCodes: enabled.body.backupCodes as string[], cookie: verified.cookie || cookie };
}

/** Password sign-in, answering the second factor with `code` if one is asked for. Returns the session cookie, or none. */
async function signInWithTotp(email: string, code: () => string) {
  const first = await h.api("/api/auth/sign-in/email", { body: { email, password: PASSWORD } });
  expect(first.status).toBe(200);
  expect(first.body.twoFactorRedirect).toBe(true);
  return h.api("/api/auth/two-factor/verify-totp", { cookie: first.cookie, body: { code: code() } });
}

const ORIGIN = "http://localhost";
/** Both cookie headers' cookies, the later one's winning: a session cookie and the challenge cookie a ceremony sets. */
const withCookies = (...cookies: string[]) => cookies.filter(Boolean).join("; ");

/** Registers `device` as a passkey of the signed-in user, as the browser would. Returns the stored passkey. */
async function registerPasskey(cookie: string, device: PasskeyDouble, name?: string) {
  const options = await h.api("/api/auth/passkey/generate-register-options", { cookie });
  expect(options.status).toBe(200);
  const response = await device.register(options.body, ORIGIN);
  return h.api("/api/auth/passkey/verify-registration", { cookie: withCookies(cookie, options.cookie), body: { response, name } });
}

/** Signs in with `device` alone, as the browser would. */
async function signInWithPasskey(device: PasskeyDouble) {
  const options = await h.api("/api/auth/passkey/generate-authenticate-options");
  expect(options.status).toBe(200);
  const response = await device.authenticate(options.body, ORIGIN);
  return h.api("/api/auth/passkey/verify-authentication", { cookie: options.cookie, body: { response } });
}

describe("passkeys", () => {
  test("a user registers a passkey and signs in with it, without a password or a second factor", async () => {
    const { cookie } = await setUpTotp(org.cookie);
    const device = await createPasskeyDouble();
    const registered = await registerPasskey(cookie, device, "Laptop");
    expect(registered.status).toBe(200);
    expect(registered.body).toMatchObject({ name: "Laptop", credentialID: device.credentialId });

    const signedIn = await signInWithPasskey(device);
    expect(signedIn.status).toBe(200);
    expect((await h.api("/api/me", { cookie: signedIn.cookie })).body.user.email).toBe("admin@acme.test");
    // An unknown passkey signs no one in.
    expect((await signInWithPasskey(await createPasskeyDouble())).status).toBe(401);
  });

  test("registering, renaming and deleting a passkey are Audit Events, and a deleted passkey signs no one in", async () => {
    const device = await createPasskeyDouble();
    const { body: key } = await registerPasskey(org.cookie, device, "Laptop");
    expect((await h.api("/api/auth/passkey/update-passkey", { cookie: org.cookie, body: { id: key.id, name: "Work laptop" } })).status).toBe(200);
    expect((await h.api("/api/auth/passkey/delete-passkey", { cookie: org.cookie, body: { id: key.id } })).status).toBe(200);

    expect((await auditOf()).filter((e) => e.action.startsWith("passkey."))).toMatchObject([
      { action: "passkey.registered", actor: { email: "admin@acme.test" }, target: { type: "passkey", id: key.id }, detail: { email: "admin@acme.test", name: "Laptop" } },
      { action: "passkey.renamed", target: { type: "passkey", id: key.id }, detail: { from: "Laptop", to: "Work laptop" } },
      { action: "passkey.deleted", target: { type: "passkey", id: key.id }, detail: { name: "Work laptop" } },
    ]);
    expect((await signInWithPasskey(device)).status).toBe(401);
  });

  test("a passkey's answer to someone else's challenge registers nothing", async () => {
    const bob = await join("bob@acme.test");
    const options = await h.api("/api/auth/passkey/generate-register-options", { cookie: bob });
    const response = await (await createPasskeyDouble()).register(options.body, ORIGIN);
    const stolen = await h.api("/api/auth/passkey/verify-registration", { cookie: withCookies(org.cookie, options.cookie), body: { response } });
    expect(stolen.status).toBeGreaterThanOrEqual(400);
    expect((await auditOf()).filter((e) => e.action.startsWith("passkey."))).toEqual([]);
  });
});

describe("TOTP as a second factor", () => {
  test("a user sets up TOTP, after which password sign-in asks for a code", async () => {
    const { totpURI } = await setUpTotp(org.cookie);
    expect(totpURI).toStartWith("otpauth://totp/Certificate%20Platform:admin%40acme.test?");

    const wrong = await signInWithTotp("admin@acme.test", () => "000000");
    expect(wrong.status).toBe(401);
    const signedIn = await signInWithTotp("admin@acme.test", () => totpCode(totpURI));
    expect(signedIn.status).toBe(200);
    expect((await h.api("/api/me", { cookie: signedIn.cookie })).body.user.email).toBe("admin@acme.test");
  });

  test("enabling and disabling TOTP are Audit Events in each of the user's Organizations", async () => {
    const { cookie } = await setUpTotp(org.cookie);
    const disabled = await h.api("/api/auth/two-factor/disable", { cookie, body: { password: PASSWORD } });
    expect(disabled.status).toBe(200);

    const events = (await auditOf(org.orgId, disabled.cookie)).filter((e) => e.action.startsWith("two_factor."));
    expect(events).toMatchObject([
      { action: "two_factor.enabled", actor: { email: "admin@acme.test" }, target: { type: "user" }, detail: { email: "admin@acme.test" } },
      { action: "two_factor.disabled", actor: { email: "admin@acme.test" }, target: { type: "user" }, detail: { email: "admin@acme.test" } },
    ]);
  });

  test("asking for a secret is not yet setting it up, and a wrong first code turns nothing on", async () => {
    const enabled = await h.api("/api/auth/two-factor/enable", { cookie: org.cookie, body: { password: PASSWORD } });
    expect(enabled.status).toBe(200);
    const wrong = await h.api("/api/auth/two-factor/verify-totp", { cookie: org.cookie, body: { code: "000000" } });
    expect(wrong.status).toBe(401);

    expect((await auditOf()).filter((e) => e.action.startsWith("two_factor."))).toEqual([]);
    // Password sign-in still needs no code.
    const signedIn = await h.api("/api/auth/sign-in/email", { body: { email: "admin@acme.test", password: PASSWORD } });
    expect(signedIn.body.twoFactorRedirect).toBeUndefined();
  });

  test("regenerating backup codes is an Audit Event, and a backup code answers the second factor once", async () => {
    const { cookie } = await setUpTotp(org.cookie);
    const regenerated = await h.api("/api/auth/two-factor/generate-backup-codes", { cookie, body: { password: PASSWORD } });
    expect(regenerated.status).toBe(200);
    const [code] = regenerated.body.backupCodes as string[];
    expect((await auditOf(org.orgId, cookie)).map((e) => e.action)).toContain("two_factor.backup_codes_regenerated");

    const use = async () => {
      const first = await h.api("/api/auth/sign-in/email", { body: { email: "admin@acme.test", password: PASSWORD } });
      return h.api("/api/auth/two-factor/verify-backup-code", { cookie: first.cookie, body: { code } });
    };
    expect((await use()).status).toBe(200);
    expect((await use()).status).toBe(401);
  });

  test("setting up TOTP is audited in every Organization of the user's, and in no other", async () => {
    const globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    const invited = await h.api(`${BA}/invite-member`, { cookie: globex.cookie, body: { email: "admin@acme.test", role: "member", organizationId: globex.orgId } });
    await h.api(`${BA}/accept-invitation`, { cookie: org.cookie, body: { invitationId: invited.body.id } });
    const bob = await join("bob@acme.test");
    await setUpTotp(bob);

    const enabled = (orgId: string, cookie: string) => auditOf(orgId, cookie).then((events) => events.filter((e) => e.action === "two_factor.enabled"));
    expect(await enabled(org.orgId, org.cookie)).toMatchObject([{ actor: { email: "bob@acme.test" } }]);
    expect(await enabled(globex.orgId, globex.cookie)).toEqual([]);
  });
});

describe("requiring MFA", () => {
  const policy = (cookie = org.cookie) => h.api(`/api/organizations/${org.orgId}/login-policy`, { cookie });
  const setPolicy = (requireMfa: boolean, cookie = org.cookie) => h.api(`/api/organizations/${org.orgId}/login-policy`, { method: "PUT", cookie, body: { requireMfa } });
  const certificates = (cookie: string) => h.api(`/api/organizations/${org.orgId}/managed-certificates`, { cookie });

  test("an Organization Administrator requires MFA, which is an Audit Event; no one else may", async () => {
    org = { ...org, cookie: (await setUpTotp(org.cookie)).cookie };
    expect((await policy()).body).toEqual({ requireMfa: false });
    const bob = await join("bob@acme.test", "approver");
    expect((await setPolicy(true, bob)).status).toBe(403);

    expect((await setPolicy(true)).status).toBe(200);
    expect((await setPolicy(true)).status).toBe(200); // no change, so no Audit Event
    expect((await policy()).body).toEqual({ requireMfa: true });
    expect((await auditOf()).filter((e) => e.action.startsWith("login_policy."))).toMatchObject([
      { action: "login_policy.changed", actor: { email: "admin@acme.test" }, target: { type: "organization", id: org.orgId }, detail: { requireMfa: { from: false, to: true } } },
    ]);
  });

  test("a password user without MFA must set it up before going on, and may once they have", async () => {
    const bob = await join("bob@acme.test");
    await setPolicy(true);

    const me = await h.api("/api/me", { cookie: bob });
    expect(me.status).toBe(200);
    expect(me.body.user.mfa).toEqual({ enabled: false, setupRequired: true });
    const refused = await certificates(bob);
    expect(refused.status).toBe(403);
    expect(refused.body.error).toMatch(/MFA/);
    // Better Auth's organization endpoints too.
    expect((await h.api(`${BA}/list-members?organizationId=${org.orgId}`, { cookie: bob })).status).toBe(403);

    const { cookie } = await setUpTotp(bob);
    expect((await h.api("/api/me", { cookie })).body.user.mfa).toEqual({ enabled: true, setupRequired: false });
    expect((await certificates(cookie)).status).toBe(200);
  });

  test("an Organization Administrator who requires MFA without having it must set it up too", async () => {
    await setPolicy(true);
    expect((await certificates(org.cookie)).status).toBe(403);
    // Setting it up is open to them, and so is the requirement's own page, so it can be undone.
    expect((await policy()).status).toBe(200);
    expect((await setPolicy(false)).status).toBe(200);
    expect((await certificates(org.cookie)).status).toBe(200);
  });

  test("a requirement holds only while it is on, and a user signed in by passkey still needs TOTP for their password", async () => {
    const bob = await join("bob@acme.test");
    const device = await createPasskeyDouble();
    expect((await registerPasskey(bob, device)).status).toBe(200);
    await setPolicy(true);
    const byPasskey = (await signInWithPasskey(device)).cookie;
    expect((await certificates(byPasskey)).status).toBe(403);
    await setPolicy(false);
    expect((await certificates(byPasskey)).status).toBe(200);
    expect((await h.api("/api/me", { cookie: byPasskey })).body.user.mfa).toEqual({ enabled: false, setupRequired: false });
  });

  test("a held user's API keys are held with them, and an Organization's are not", async () => {
    const bob = await join("bob@acme.test");
    const keys = `/api/organizations/${org.orgId}/api-keys`;
    const bobsKey = (await h.api(keys, { cookie: bob, body: { name: "ci" } })).body.key as string;
    const orgKey = (await h.api(keys, { cookie: org.cookie, body: { name: "ci", type: "organization" } })).body.key as string;
    // A Managed Certificate that is not there: a key that gets past the login policy is refused for that instead.
    const fetchWith = async (key: string) => {
      const res = await h.app.request(`http://localhost/api/organizations/${org.orgId}/managed-certificates/00000000-0000-0000-0000-000000000000/certificate`, { headers: { "x-api-key": key } });
      return { status: res.status, error: ((await res.json()) as { error: string }).error };
    };
    const heldUp = { status: 403, error: expect.stringMatching(/MFA/) };
    expect(await fetchWith(bobsKey)).not.toMatchObject(heldUp);

    await setPolicy(true);
    expect(await fetchWith(bobsKey)).toMatchObject(heldUp);
    expect(await fetchWith(orgKey)).toMatchObject({ status: 404 });

    await setUpTotp(bob);
    expect(await fetchWith(bobsKey)).not.toMatchObject(heldUp);
  });
});
