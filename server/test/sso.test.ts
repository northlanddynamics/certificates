// SSO, through the platform's HTTP API: an Organization Administrator sets up SAML and OIDC connections that belong to
// their Organization, users sign in through them (Better Auth's SSO plugin) and are made Members on their first sign-in,
// and an Organization can require SSO, after which its members sign in no other way. Every configuration and policy
// change is an Audit Event. The identity providers are doubles served on local ports (oidc-idp-double.ts, saml-idp-double.ts).
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { PASSWORD, cookieFrom, createHarness, type Harness } from "./support/harness";
import { createPasskeyDouble } from "./support/passkey-double";
import { createOidcIdpDouble, type OidcIdentity, type OidcIdpDouble } from "./support/oidc-idp-double";
import { createSamlIdpDouble, type SamlIdpDouble } from "./support/saml-idp-double";

setDefaultTimeout(30_000);

let h: Harness;
let idp: OidcIdpDouble;
let samlIdp: SamlIdpDouble;
let operator: string;
let org: { orgId: string; cookie: string };

beforeAll(async () => {
  idp = await createOidcIdpDouble();
  samlIdp = await createSamlIdpDouble();
  // The IdP is on a local address, which the platform fetches from only when it is a trusted origin.
  h = await createHarness({ trustedOrigins: [idp.issuer] });
});
beforeEach(async () => {
  await h.reset();
  operator = await h.createOperator("op@platform.test", PASSWORD);
  org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
});
afterAll(async () => {
  await h.close();
  idp.stop();
});

const BA = "/api/auth/organization";
const connections = (orgId = org.orgId) => `/api/organizations/${orgId}/sso-connections`;
type AuditEvent = { action: string; actor: any; target: any; detail: any };
const auditOf = async (orgId = org.orgId, cookie = org.cookie) => (await h.api(`/api/organizations/${orgId}/audit-events`, { cookie })).body.items as AuditEvent[];
/** The Organization's Audit Events of `action`, in the order the audit log lists them (oldest first). */
const eventsOf = async (action: string) => (await auditOf()).filter((e) => e.action === action);

async function join(email: string, role = "member") {
  const invited = await h.api(`${BA}/invite-member`, { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api(`${BA}/accept-invitation`, { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}

/** TXT records the tests publish, as the DNS would answer: by name. */
let txt: Map<string, string[]>;
beforeEach(() => {
  txt = new Map();
  h.dcvResolver.current = { lookupTxt: async (name) => txt.get(name) ?? [], lookupCname: async () => [] };
});

/** Publishes the TXT record a connection asks for, and has the platform check it. */
async function verifyDomain(connection: { id: string; domainVerification: { name: string; value: string } }, orgId = org.orgId, cookie = org.cookie) {
  txt.set(connection.domainVerification.name, [...(txt.get(connection.domainVerification.name) ?? []), connection.domainVerification.value]);
  const verified = await h.api(`${connections(orgId)}/${connection.id}/verify-domain`, { method: "POST", cookie });
  expect(verified.status).toBe(200);
  return verified.body;
}

const oidcConnection = (overrides: Record<string, unknown> = {}) => ({
  name: "Acme IdP",
  domain: "acme.test",
  oidc: { issuer: idp.issuer, clientId: idp.clientId, clientSecret: idp.clientSecret },
  ...overrides,
});

/** Adds an OIDC connection and verifies its domain. */
async function createOidc(overrides: Record<string, unknown> = {}) {
  const created = await h.api(connections(), { cookie: org.cookie, body: oidcConnection(overrides) });
  expect(created.status).toBe(201);
  return (await verifyDomain(created.body)) as { id: string };
}

/** Signs in through SSO as the browser would, for the connection of `enteredEmail`'s domain, the IdP answering as `identity`. Returns where the platform sent the browser, and its cookies. */
async function signInWithOidc(identity: OidcIdentity, enteredEmail = identity.email) {
  const started = await h.api("/api/auth/sign-in/sso", { body: { email: enteredEmail, callbackURL: "/" } });
  expect(started.status).toBe(200);
  const back = await h.app.request(idp.authorize(started.body.url, identity), { headers: { cookie: started.cookie } });
  expect(back.status).toBe(302);
  return { location: back.headers.get("location") ?? "", cookie: cookieFrom(back) };
}

const samlConnection = (overrides: Record<string, unknown> = {}) => ({
  name: "Ping",
  domain: "acme.test",
  saml: { entityId: samlIdp.entityId, ssoUrl: samlIdp.ssoUrl, certificate: samlIdp.certificate },
  ...overrides,
});

/** Adds a SAML connection and verifies its domain. */
async function createSaml(overrides: Record<string, unknown> = {}) {
  const created = await h.api(connections(), { cookie: org.cookie, body: samlConnection(overrides) });
  expect(created.status).toBe(201);
  return (await verifyDomain(created.body)) as { id: string; serviceProvider: { entityId: string; acsUrl: string } };
}

/** Goes through a SAML connection as the browser would: to the IdP, which answers as `email`, and back to the ACS with its form. Returns the ACS's answer. */
async function throughSaml(connection: { serviceProvider: { entityId: string; acsUrl: string } }, email: string, opts?: { signedBy?: SamlIdpDouble }) {
  const started = await h.api("/api/auth/sign-in/sso", { body: { email, callbackURL: "/" } });
  expect(started.status).toBe(200);
  const form = await samlIdp.respond(started.body.url, connection.serviceProvider, email, opts);
  expect(form.action).toBe(connection.serviceProvider.acsUrl);
  return h.app.request(form.action, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", origin: new URL(samlIdp.ssoUrl).origin },
    body: new URLSearchParams({ SAMLResponse: form.SAMLResponse, RelayState: form.RelayState }).toString(),
  });
}

/** Signs in through a SAML connection; returns where the platform sent the browser, and its cookies. */
async function signInWithSaml(connection: { serviceProvider: { entityId: string; acsUrl: string } }, email: string) {
  const back = await throughSaml(connection, email);
  expect(back.status).toBe(302);
  return { location: back.headers.get("location") ?? "", cookie: cookieFrom(back) };
}

describe("SSO connections", () => {
  test("an Organization Administrator creates an OIDC connection; it is audited and its secret is never returned", async () => {
    const created = await h.api(connections(), { cookie: org.cookie, body: oidcConnection() });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({
      name: "Acme IdP",
      type: "oidc",
      domain: "acme.test",
      oidc: { issuer: idp.issuer, clientId: idp.clientId },
      serviceProvider: { redirectUri: `http://localhost/api/auth/sso/callback/${created.body.id}` },
      domainVerified: false,
      domainVerification: { name: "_certificate-platform-sso.acme.test", value: expect.any(String) },
    });
    expect(JSON.stringify(created.body)).not.toContain(idp.clientSecret);

    const listed = await h.api(connections(), { cookie: org.cookie });
    expect(listed.status).toBe(200);
    expect(listed.body.items).toEqual([created.body]);

    const [event] = await eventsOf("sso_connection.created");
    expect(event).toMatchObject({
      actor: { email: "admin@acme.test" },
      target: { type: "sso_connection", id: created.body.id },
      detail: { name: "Acme IdP", type: "oidc", domain: "acme.test", issuer: idp.issuer },
    });
    expect(JSON.stringify(event)).not.toContain(idp.clientSecret);
  });

  test("a Member may neither see nor create connections", async () => {
    const member = await join("m@acme.test");
    expect((await h.api(connections(), { cookie: member })).status).toBe(403);
    expect((await h.api(connections(), { cookie: member, body: oidcConnection() })).status).toBe(403);
  });
});

describe("proving the domain", () => {
  test("a connection signs nobody in until a TXT record in its domain proves the Organization holds it", async () => {
    const created = (await h.api(connections(), { cookie: org.cookie, body: oidcConnection() })).body;
    expect((await h.api("/api/auth/sign-in/sso", { body: { email: "new@acme.test", callbackURL: "/" } })).status).toBe(401);

    const unproven = await h.api(`${connections()}/${created.id}/verify-domain`, { method: "POST", cookie: org.cookie });
    expect(unproven.status).toBe(409);
    txt.set(created.domainVerification.name, ["something else"]);
    expect((await h.api(`${connections()}/${created.id}/verify-domain`, { method: "POST", cookie: org.cookie })).status).toBe(409);

    const verified = await verifyDomain(created);
    expect(verified).toMatchObject({ id: created.id, domainVerified: true });
    expect((await eventsOf("sso_connection.domain_verified"))[0]).toMatchObject({ target: { id: created.id }, detail: { domain: "acme.test" } });
    const signedIn = await signInWithOidc({ sub: "u-1", email: "new@acme.test" });
    expect((await h.api("/api/me", { cookie: signedIn.cookie })).status).toBe(200);
  });

  test("another Organization's record does not prove a domain, and a new domain must be proven again", async () => {
    const created = (await h.api(connections(), { cookie: org.cookie, body: oidcConnection() })).body;
    const other = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    const theirs = (await h.api(connections(other.orgId), { cookie: other.cookie, body: samlConnection({ domain: "globex.test" }) })).body;
    await verifyDomain(theirs, other.orgId, other.cookie);
    // Their record is published under their domain's name, with their value.
    txt.set(created.domainVerification.name, [theirs.domainVerification.value]);
    expect((await h.api(`${connections()}/${created.id}/verify-domain`, { method: "POST", cookie: org.cookie })).status).toBe(409);

    await verifyDomain(created);
    const moved = await h.api(`${connections()}/${created.id}`, { method: "PATCH", cookie: org.cookie, body: { domain: "acme.example" } });
    expect(moved.body).toMatchObject({ domainVerified: false, domainVerification: { name: "_certificate-platform-sso.acme.example" } });
    expect(moved.body.domainVerification.value).not.toBe(created.domainVerification.value);
  });
});

describe("changing a connection", () => {
  const connection = (id: string) => `${connections()}/${id}`;

  test("renaming it and replacing its secret are audited, and the secret is never recorded", async () => {
    const { id } = await createOidc();
    const changed = await h.api(connection(id), { method: "PATCH", cookie: org.cookie, body: { name: "Okta", oidc: { clientSecret: "a-new-secret" } } });
    expect(changed.status).toBe(200);
    expect(changed.body).toMatchObject({ id, name: "Okta", oidc: { issuer: idp.issuer, clientId: idp.clientId } });
    const [event] = await eventsOf("sso_connection.changed");
    expect(event).toMatchObject({ target: { type: "sso_connection", id }, detail: { name: { from: "Acme IdP", to: "Okta" }, clientSecret: "replaced" } });
    expect(JSON.stringify(event)).not.toContain("a-new-secret");
    // The new secret is what the platform now presents to the IdP, which knows only the old one.
    const refused = await signInWithOidc({ sub: "u-5", email: "new@acme.test" });
    expect(refused.location).toContain("error=");
  });

  test("which identity provider it trusts cannot change once users have signed in through it", async () => {
    const saml = await createSaml();
    const moved = { saml: { entityId: "https://other-idp.test/saml" } };
    // Before anyone has signed in, it can.
    expect((await h.api(connection(saml.id), { method: "PATCH", cookie: org.cookie, body: moved })).status).toBe(200);
    await h.api(connection(saml.id), { method: "PATCH", cookie: org.cookie, body: { saml: { entityId: samlIdp.entityId } } });
    await signInWithSaml(saml, "pat@acme.test");
    const refused = await h.api(connection(saml.id), { method: "PATCH", cookie: org.cookie, body: moved });
    expect(refused.status).toBe(409);
    // A new signing certificate is not a new identity provider.
    expect((await h.api(connection(saml.id), { method: "PATCH", cookie: org.cookie, body: { saml: { certificate: samlIdp.certificate } } })).status).toBe(200);
  });

  test("a domain belongs to one connection, in whichever Organization", async () => {
    await createOidc();
    const other = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    const taken = await h.api(connections(other.orgId), { cookie: other.cookie, body: samlConnection() });
    expect(taken.status).toBe(409);
    expect((await h.api(connections(other.orgId), { cookie: other.cookie, body: samlConnection({ domain: "globex.test" }) })).status).toBe(201);
  });

  test("a connection of another Organization is not found", async () => {
    const { id } = await createOidc();
    const other = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    expect((await h.api(`${connections(other.orgId)}/${id}`, { method: "PATCH", cookie: other.cookie, body: { name: "Mine" } })).status).toBe(404);
    expect((await h.api(`${connections(other.orgId)}/${id}`, { method: "DELETE", cookie: other.cookie })).status).toBe(404);
  });

  test("deleting it is audited, and those who signed in through it can no longer", async () => {
    const saml = await createSaml();
    await signInWithSaml(saml, "pat@acme.test");
    const deleted = await h.api(connection(saml.id), { method: "DELETE", cookie: org.cookie });
    expect(deleted.status).toBe(204);
    expect((await h.api(connections(), { cookie: org.cookie })).body.items).toEqual([]);
    expect((await eventsOf("sso_connection.deleted"))[0]).toMatchObject({ target: { id: saml.id }, detail: { name: "Ping", type: "saml" } });
    const { rows } = await h.pool.query(`select 1 from account where provider_id = $1`, [saml.id]);
    expect(rows).toHaveLength(0);
    expect((await h.api("/api/auth/sign-in/sso", { body: { email: "pat@acme.test", callbackURL: "/" } })).status).toBe(404);
  });

  test("testing it checks it against the identity provider, and is audited", async () => {
    const oidc = await createOidc();
    const tested = await h.api(`${connection(oidc.id)}/test`, { method: "POST", cookie: org.cookie });
    expect(tested.status).toBe(200);
    expect(tested.body).toEqual({ ok: true });

    const saml = await createSaml({ domain: "saml.acme.test" });
    h.setNow(new Date(Date.now() + 2 * 365 * 24 * 3600_000));
    const expired = await h.api(`${connection(saml.id)}/test`, { method: "POST", cookie: org.cookie });
    expect(expired.body).toEqual({ ok: false, error: expect.stringContaining("certificate") });
    expect((await eventsOf("sso_connection.tested")).map((e) => e.detail)).toEqual([{ ok: true }, { ok: false, error: expired.body.error }]);
  });
});

describe("signing in through a connection", () => {
  test("a user's first sign-in through an OIDC connection makes them a Member of its Organization", async () => {
    const connection = await createOidc();
    const signedIn = await signInWithOidc({ sub: "u-1", email: "new@acme.test", name: "New Person" });
    expect(signedIn.location).toBe("/");

    const me = await h.api("/api/me", { cookie: signedIn.cookie });
    expect(me.status).toBe(200);
    expect(me.body.user).toMatchObject({ email: "new@acme.test", name: "New Person" });
    expect(me.body.organizations).toEqual([expect.objectContaining({ id: org.orgId, role: "member" })]);

    const [event] = await eventsOf("member.provisioned");
    expect(event).toMatchObject({
      actor: { id: me.body.user.id, email: "new@acme.test" },
      target: { type: "member" },
      detail: { userId: me.body.user.id, email: "new@acme.test", role: "member", connectionId: connection.id },
    });

    // Signing in again is not a first sign-in.
    const again = await signInWithOidc({ sub: "u-1", email: "new@acme.test" });
    expect((await h.api("/api/me", { cookie: again.cookie })).body.user.id).toBe(me.body.user.id);
    expect(await eventsOf("member.provisioned")).toHaveLength(1);
  });
});

describe("signing in through a SAML connection", () => {
  test("an Organization Administrator creates a SAML connection and is told what to give the identity provider", async () => {
    const created = await h.api(connections(), { cookie: org.cookie, body: samlConnection() });
    expect(created.status).toBe(201);
    const id = created.body.id;
    expect(created.body).toMatchObject({
      type: "saml",
      saml: { entityId: samlIdp.entityId, ssoUrl: samlIdp.ssoUrl, certificate: { subject: "CN=Test IdP" } },
      serviceProvider: {
        entityId: `http://localhost/api/auth/sso/saml2/sp/metadata?providerId=${id}`,
        acsUrl: `http://localhost/api/auth/sso/saml2/sp/acs/${id}`,
        metadataUrl: `http://localhost/api/auth/sso/saml2/sp/metadata?providerId=${id}`,
      },
    });
    const metadata = await h.app.request(created.body.serviceProvider.metadataUrl);
    expect(metadata.status).toBe(200);
    expect(await metadata.text()).toContain(created.body.serviceProvider.acsUrl);
    expect((await eventsOf("sso_connection.created"))[0]).toMatchObject({ detail: { type: "saml", issuer: samlIdp.entityId, ssoUrl: samlIdp.ssoUrl } });
  });

  test("a certificate that is not one is refused", async () => {
    const refused = await h.api(connections(), { cookie: org.cookie, body: samlConnection({ saml: { entityId: samlIdp.entityId, ssoUrl: samlIdp.ssoUrl, certificate: "not a certificate" } }) });
    expect(refused.status).toBe(400);
  });

  test("a user's first sign-in through a SAML connection makes them a Member of its Organization", async () => {
    const connection = await createSaml();
    const signedIn = await signInWithSaml(connection, "pat@acme.test");
    expect(signedIn.location).toBe("/");
    const me = await h.api("/api/me", { cookie: signedIn.cookie });
    expect(me.body.user.email).toBe("pat@acme.test");
    expect(me.body.organizations).toEqual([expect.objectContaining({ id: org.orgId, role: "member" })]);
    expect((await eventsOf("member.provisioned"))[0]).toMatchObject({ detail: { email: "pat@acme.test", connectionId: connection.id } });
  });

  test("an assertion not signed by the connection's certificate signs nobody in", async () => {
    const connection = await createSaml();
    const impostor = await createSamlIdpDouble(samlIdp.entityId);
    const back = await throughSaml(connection, "pat@acme.test", { signedBy: impostor });
    expect(back.status).toBe(302);
    expect(back.headers.get("location")).toContain("error_description=Invalid+SAML+response");
    expect(cookieFrom(back)).not.toContain("session_token");
    const { rows } = await h.pool.query(`select 1 from "user" where email = 'pat@acme.test'`);
    expect(rows).toHaveLength(0);
  });
});

describe("who a connection signs in", () => {
  test("an identity provider that asserts an address outside the connection's domain is refused, and no user is made", async () => {
    await createOidc();
    const signedIn = await signInWithOidc({ sub: "u-2", email: "ceo@elsewhere.test" }, "someone@acme.test");
    expect(signedIn.location).toContain("error=");
    expect((await h.api("/api/me", { cookie: signedIn.cookie })).status).toBe(401);
    const { rows } = await h.pool.query(`select 1 from "user" where email = 'ceo@elsewhere.test'`);
    expect(rows).toHaveLength(0);
  });

  test("an existing member who signs in through the connection keeps their account and their role", async () => {
    await join("approver@acme.test", "approver");
    await createOidc();
    const signedIn = await signInWithOidc({ sub: "u-3", email: "approver@acme.test" });
    const me = await h.api("/api/me", { cookie: signedIn.cookie });
    expect(me.body.organizations).toEqual([expect.objectContaining({ id: org.orgId, role: "approver" })]);
    expect(await eventsOf("member.provisioned")).toHaveLength(0);
    // Their password still signs in too, while SSO is not required.
    await h.signIn("approver@acme.test", PASSWORD);
  });

  test("a Platform Operator's account is never linked to a connection, even as a member", async () => {
    const invited = await h.api(`${BA}/invite-member`, { cookie: org.cookie, body: { email: "op@platform.test", role: "member", organizationId: org.orgId } });
    await h.api(`${BA}/accept-invitation`, { cookie: operator, body: { invitationId: invited.body.id } });
    await createOidc({ domain: "platform.test" });
    const signedIn = await signInWithOidc({ sub: "op", email: "op@platform.test" });
    expect(signedIn.location).toContain("error=");
    expect((await h.api("/api/me", { cookie: signedIn.cookie })).status).toBe(401);
  });

  test("someone who signed in while invited becomes a Member at a later sign-in if the invitation lapses, but a removed member does not come back", async () => {
    const invited = await h.api(`${BA}/invite-member`, { cookie: org.cookie, body: { email: "late@acme.test", role: "approver", organizationId: org.orgId } });
    await createOidc();
    const first = await signInWithOidc({ sub: "late", email: "late@acme.test" });
    expect((await h.api("/api/me", { cookie: first.cookie })).body.organizations).toEqual([]);
    await h.api(`${BA}/cancel-invitation`, { cookie: org.cookie, body: { invitationId: invited.body.id } });
    const second = await signInWithOidc({ sub: "late", email: "late@acme.test" });
    const me = await h.api("/api/me", { cookie: second.cookie });
    expect(me.body.organizations).toEqual([expect.objectContaining({ id: org.orgId, role: "member" })]);

    const [membership] = (await h.api(`${BA}/list-members?organizationId=${org.orgId}`, { cookie: org.cookie })).body.members.filter((m: any) => m.userId === me.body.user.id);
    expect((await h.api(`${BA}/remove-member`, { cookie: org.cookie, body: { memberIdOrEmail: membership.id, organizationId: org.orgId } })).status).toBe(200);
    const third = await signInWithOidc({ sub: "late", email: "late@acme.test" });
    expect((await h.api("/api/me", { cookie: third.cookie })).body.organizations).toEqual([]);
    expect(await eventsOf("member.provisioned")).toHaveLength(1);
  });

  test("an account with the address that is not a member of the connection's Organization is not linked to it", async () => {
    await createOidc();
    const outsider = await h.signUp("outsider@acme.test", PASSWORD);
    const signedIn = await signInWithOidc({ sub: "u-4", email: "outsider@acme.test" });
    expect(signedIn.location).toContain("error=");
    expect((await h.api("/api/me", { cookie: signedIn.cookie })).status).toBe(401);
    const { rows } = await h.pool.query(`select provider_id from account a join "user" u on u.id = a.user_id where u.email = 'outsider@acme.test'`);
    expect(rows).toEqual([{ provider_id: "credential" }]);
    expect((await h.api("/api/me", { cookie: outsider })).body.organizations).toEqual([]);
  });
});

describe("requiring SSO", () => {
  const policy = () => `/api/organizations/${org.orgId}/login-policy`;
  const requireSso = (cookie = org.cookie, on = true) => h.api(policy(), { method: "PUT", cookie, body: { requireSso: on } });

  /** The Organization has an OIDC connection and its administrator has signed in through it; returns their SSO session. */
  async function adminThroughSso() {
    await createOidc();
    return (await signInWithOidc({ sub: "admin", email: "admin@acme.test" })).cookie;
  }

  test("an Organization cannot require SSO before it has a connection its administrator has signed in through", async () => {
    expect((await requireSso()).status).toBe(409);
    await createOidc();
    // Not having signed in through it, they could not be sure it lets them back in.
    expect((await requireSso()).status).toBe(409);
    const sso = (await signInWithOidc({ sub: "admin", email: "admin@acme.test" })).cookie;
    expect((await requireSso(sso)).status).toBe(200);
  });

  test("requiring SSO is audited, and its members can then sign in only through SSO", async () => {
    await join("m@acme.test");
    const sso = await adminThroughSso();
    const changed = await requireSso(sso);
    expect(changed.status).toBe(200);
    expect(changed.body).toEqual({ requireMfa: false, requireSso: true });
    expect((await h.api(policy(), { cookie: sso })).body).toEqual({ requireMfa: false, requireSso: true });
    expect((await eventsOf("login_policy.changed"))[0]).toMatchObject({ actor: { email: "admin@acme.test" }, detail: { requireSso: { from: false, to: true } } });

    for (const email of ["m@acme.test", "admin@acme.test"]) {
      const refused = await h.api("/api/auth/sign-in/email", { body: { email, password: PASSWORD } });
      expect(refused.status).toBe(403);
      expect(refused.body.code).toBe("SSO_REQUIRED");
      expect(refused.cookie).not.toContain("session_token");
    }
    const member = await signInWithOidc({ sub: "m", email: "m@acme.test" });
    expect((await h.api("/api/me", { cookie: member.cookie })).body.user.email).toBe("m@acme.test");

    // Turning it off lets passwords in again.
    expect((await requireSso(sso, false)).status).toBe(200);
    await h.signIn("m@acme.test", PASSWORD);
    expect((await eventsOf("login_policy.changed")).map((e) => e.detail)).toEqual([{ requireSso: { from: false, to: true } }, { requireSso: { from: true, to: false } }]);
  });

  test("a passkey does not sign a member in either", async () => {
    const member = await join("m@acme.test");
    const device = await createPasskeyDouble();
    const options = await h.api("/api/auth/passkey/generate-register-options", { cookie: member });
    const registered = await h.api("/api/auth/passkey/verify-registration", {
      cookie: `${member}; ${options.cookie}`,
      body: { response: await device.register(options.body, "http://localhost") },
    });
    expect(registered.status).toBe(200);
    expect((await requireSso(await adminThroughSso())).status).toBe(200);
    const challenge = await h.api("/api/auth/passkey/generate-authenticate-options");
    const refused = await h.api("/api/auth/passkey/verify-authentication", { cookie: challenge.cookie, body: { response: await device.authenticate(challenge.body, "http://localhost") } });
    expect(refused.status).toBe(403);
    expect(refused.cookie).not.toContain("session_token");
  });

  test("users who are not its members, and Platform Operators who are, still sign in with a password", async () => {
    await h.signUp("outsider@acme.test", PASSWORD);
    const invited = await h.api(`${BA}/invite-member`, { cookie: org.cookie, body: { email: "op@platform.test", role: "member", organizationId: org.orgId } });
    await h.api(`${BA}/accept-invitation`, { cookie: operator, body: { invitationId: invited.body.id } });
    expect((await requireSso(await adminThroughSso())).status).toBe(200);
    await h.signIn("outsider@acme.test", PASSWORD);
    await h.signIn("op@platform.test", PASSWORD);
  });

  test("a Platform Operator may still impersonate one of its members", async () => {
    await join("m@acme.test");
    expect((await requireSso(await adminThroughSso())).status).toBe(200);
    const { rows } = await h.pool.query(`select id from "user" where email = 'm@acme.test'`);
    const impersonated = await h.api("/api/auth/admin/impersonate-user", { cookie: operator, body: { userId: rows[0].id } });
    expect(impersonated.status).toBe(200);
    expect((await h.api("/api/me", { cookie: impersonated.cookie })).body.user.email).toBe("m@acme.test");
  });

  test("a Member may not change it, and its last connection cannot be deleted while it is required", async () => {
    const member = await join("m@acme.test");
    expect((await requireSso(member)).status).toBe(403);
    const sso = await adminThroughSso();
    expect((await requireSso(sso)).status).toBe(200);
    const [only] = (await h.api(connections(), { cookie: sso })).body.items;
    expect((await h.api(`${connections()}/${only.id}`, { method: "DELETE", cookie: sso })).status).toBe(409);
  });
});
