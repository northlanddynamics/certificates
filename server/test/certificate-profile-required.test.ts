// Requiring a Certificate Profile: an Organization setting, off by default, under which those who may not create a
// Managed Certificate outright propose one only through a profile, with their API keys too. Organization
// Administrators, and Name Changes, are unaffected. Each check is of what the API answers and the Audit Events it leaves.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import acme from "acme-client";
import { PASSWORD, createHarness, type Harness } from "./support/harness";

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
const base = () => `/api/organizations/${org.orgId}`;
const settingsPath = () => `${base()}/certificate-profile-settings`;
const createMc = (body: unknown, cookie = org.cookie) => h.api(`${base()}/managed-certificates`, { cookie, body });
const createWithKey = (body: unknown, apiKey: string) =>
  h.app.request(`http://localhost${base()}/managed-certificates`, { method: "POST", headers: { "x-api-key": apiKey, "content-type": "application/json" }, body: JSON.stringify(body) });
const setRequireProfile = (requireProfile: boolean, cookie = org.cookie) => h.api(settingsPath(), { cookie, method: "PUT", body: { requireProfile } });
const auditOf = async (action: string) =>
  ((await h.api(`${base()}/audit-events`, { cookie: org.cookie })).body.items as { action: string; actor: any; target: any; detail: any }[]).filter((e) => e.action === action);
/** Whether `/api/me` tells the caller they may request a Managed Certificate without a profile in the Organization. */
const openWithoutProfile = async (cookie: string) => (await h.api("/api/me", { cookie })).body.organizations.find((o: any) => o.id === org.orgId).requestsWithoutProfile as boolean;

async function join(email: string, role: string) {
  const invited = await h.api(`${BA}/invite-member`, { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api(`${BA}/accept-invitation`, { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}

const makeKey = async (cookie: string, type: "user" | "organization" = "user") => {
  const made = await h.api(`${base()}/api-keys`, { cookie, body: { name: "ci", type } });
  expect(made.status).toBe(201);
  return made.body.key as string;
};

/** A Private CA permitting names under internal.acme, and a profile issuing from its first Issuing CA. */
async function createProfile() {
  const ca = await h.api(`${base()}/private-cas`, {
    cookie: org.cookie,
    body: { name: "Internal", subject: "CN=Internal, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["internal.acme"] } },
  });
  expect(ca.status).toBe(201);
  const issuer = { kind: "private_ca", issuingCaId: ca.body.issuingCas[0].id as string };
  const profile = await h.api(`${base()}/certificate-profiles`, { cookie: org.cookie, body: { name: "Internal web", issuer, allowedKeyAlgorithms: ["ecdsa-p256"] } });
  expect(profile.status).toBe(201);
  return { id: profile.body.id as string, issuer };
}

/** What a requester submits: names, and a CSR for them under a fresh key. */
async function request(names: string[]) {
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, await acme.crypto.createPrivateEcdsaKey("P-256"));
  return { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() };
}

describe("the setting", () => {
  test("is off by default, is changed by an Organization Administrator with an Audit Event, and is read by every member", async () => {
    const member = await join("member@acme.test", "member");
    expect((await h.api(settingsPath(), { cookie: member })).body).toEqual({ requireProfile: false });

    const changed = await setRequireProfile(true);
    expect(changed.status).toBe(200);
    expect(changed.body).toEqual({ requireProfile: true });
    expect((await h.api(settingsPath(), { cookie: member })).body).toEqual({ requireProfile: true });
    // Setting it to what it is already changes nothing, and is not audited.
    expect((await setRequireProfile(true)).status).toBe(200);
    expect(await auditOf("certificate_profile_settings.changed")).toEqual([
      expect.objectContaining({ target: { type: "organization", id: org.orgId }, detail: { requireProfile: { from: false, to: true } } }),
    ]);
  });

  test("is changed only by those with certificateProfile.update", async () => {
    for (const role of ["member", "approver"]) {
      const cookie = await join(`${role}@acme.test`, role);
      expect((await setRequireProfile(true, cookie)).status).toBe(403);
    }
    expect((await h.api(settingsPath(), { cookie: org.cookie })).body).toEqual({ requireProfile: false });
  });
});

describe("while a Certificate Profile is required", () => {
  test("a Member's request without a profile is refused with 403, and through one is a Proposal", async () => {
    const profile = await createProfile();
    const member = await join("member@acme.test", "member");
    expect(await openWithoutProfile(member)).toBe(true);
    expect((await setRequireProfile(true)).status).toBe(200);
    expect(await openWithoutProfile(member)).toBe(false);

    const refused = await createMc({ ...(await request(["www.internal.acme"])), issuer: profile.issuer }, member);
    expect(refused.status).toBe(403);
    expect(refused.body.error).toMatch(/Certificate Profile/);
    expect(await auditOf("managed_certificate.proposed")).toEqual([]);

    const through = await createMc({ ...(await request(["www.internal.acme"])), profileId: profile.id }, member);
    expect(through.status).toBe(201);
    expect(through.body.approval.status).toBe("pending");
  });

  test("an Approver's request without a profile is refused too", async () => {
    const profile = await createProfile();
    const approver = await join("approver@acme.test", "approver");
    await setRequireProfile(true);
    expect(await openWithoutProfile(approver)).toBe(false);
    expect((await createMc({ ...(await request(["www.internal.acme"])), issuer: profile.issuer }, approver)).status).toBe(403);
  });

  test("an Organization Administrator still creates one without a profile", async () => {
    const profile = await createProfile();
    await setRequireProfile(true);
    expect(await openWithoutProfile(org.cookie)).toBe(true);
    const res = await createMc({ ...(await request(["www.internal.acme"])), issuer: profile.issuer });
    expect(res.status).toBe(201);
    expect(res.body.approval.status).toBe("not_required");
  });

  test("a Member's API key is refused without a profile, and proposes through one", async () => {
    const profile = await createProfile();
    const member = await join("member@acme.test", "member");
    const key = await makeKey(member);
    await setRequireProfile(true);

    const refused = await createWithKey({ ...(await request(["www.internal.acme"])), issuer: profile.issuer }, key);
    expect(refused.status).toBe(403);
    const through = await createWithKey({ ...(await request(["www.internal.acme"])), profileId: profile.id }, key);
    expect(through.status).toBe(201);
    const proposed = await through.json();
    expect(proposed).toMatchObject({ approval: { status: "pending", proposedBy: { email: "member@acme.test" } }, profile: { id: profile.id } });
    // The key leaves a trace of what it was used for.
    expect(await auditOf("api_key.used")).toEqual([
      expect.objectContaining({ actor: expect.objectContaining({ email: "member@acme.test" }), target: { type: "managed_certificate", id: proposed.id }, detail: expect.objectContaining({ apiKeyName: "ci", managedCertificate: "proposed" }) }),
    ]);
  });

  test("an Organization Administrator's own API key still creates one without a profile", async () => {
    const profile = await createProfile();
    const key = await makeKey(org.cookie);
    await setRequireProfile(true);
    const res = await createWithKey({ ...(await request(["www.internal.acme"])), issuer: profile.issuer }, key);
    expect(res.status).toBe(201);
    expect((await res.json()).approval.status).toBe("not_required");
  });

  test("an Organization's API key, which carries no create, is refused", async () => {
    const profile = await createProfile();
    const key = await makeKey(org.cookie, "organization");
    await setRequireProfile(true);
    expect((await createWithKey({ ...(await request(["www.internal.acme"])), issuer: profile.issuer }, key)).status).toBe(403);
    expect((await createWithKey({ ...(await request(["www.internal.acme"])), profileId: profile.id }, key)).status).toBe(403);
  });

  test("an Owner still proposes a Name Change on a Managed Certificate made without a profile", async () => {
    const profile = await createProfile();
    const member = await join("member@acme.test", "member");
    const proposed = await createMc({ ...(await request(["www.internal.acme"])), issuer: profile.issuer }, member);
    expect(proposed.status).toBe(201);
    const approver = await join("approver@acme.test", "approver");
    expect((await h.api(`${base()}/managed-certificates/${proposed.body.id}/approve`, { cookie: approver, body: {} })).status).toBe(200);
    await h.settleIssuances();
    // A Member who proposed one is not its Owner unless named; so make them one.
    const memberId = (await h.api("/api/me", { cookie: member })).body.user.id as string;
    expect((await h.api(`${base()}/managed-certificates/${proposed.body.id}/owners`, { cookie: org.cookie, body: { type: "user", id: memberId } })).status).toBe(200);
    await setRequireProfile(true);

    const changed = await h.api(`${base()}/managed-certificates/${proposed.body.id}/name-change`, { cookie: member, body: await request(["www.internal.acme", "app.internal.acme"]) });
    expect(changed.status).toBe(201);
  });

  test("an Owner still proposes a Name Change on a Managed Certificate made through a profile", async () => {
    const profile = await createProfile();
    const member = await join("member@acme.test", "member");
    const proposed = await createMc({ ...(await request(["www.internal.acme"])), profileId: profile.id }, member);
    expect(proposed.status).toBe(201);
    const approver = await join("approver@acme.test", "approver");
    expect((await h.api(`${base()}/managed-certificates/${proposed.body.id}/approve`, { cookie: approver, body: {} })).status).toBe(200);
    await h.settleIssuances();
    await setRequireProfile(true);

    const changed = await h.api(`${base()}/managed-certificates/${proposed.body.id}/name-change`, { cookie: member, body: await request(["www.internal.acme", "app.internal.acme"]) });
    expect(changed.status).toBe(201);
  });
});

test("when it is off, a Member's request without a profile is a Proposal as before", async () => {
  const profile = await createProfile();
  const member = await join("member@acme.test", "member");
  await setRequireProfile(true);
  await setRequireProfile(false);
  const res = await createMc({ ...(await request(["www.internal.acme"])), issuer: profile.issuer }, member);
  expect(res.status).toBe(201);
  expect(res.body.approval.status).toBe("pending");
  expect((await auditOf("certificate_profile_settings.changed")).map((e) => e.detail.requireProfile)).toEqual([
    { from: false, to: true },
    { from: true, to: false },
  ]);
});
