// Detaching a Managed Certificate from its Certificate Profile: an Organization Administrator makes it an ordinary
// Managed Certificate. It keeps its settings and Owners, renews again while the profile stays disabled, and its Name
// Changes are no longer checked against the profile's name rules. The CA is a Private CA of the platform's own, so no
// Pebble; time is the harness's clock.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import acme from "acme-client";
import { PASSWORD, createHarness, type Harness } from "./support/harness";

let h: Harness;
let operator: string;
let org: { orgId: string; cookie: string };
let member: string | undefined;

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  operator = await h.createOperator("op@platform.test", PASSWORD);
  org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
  member = undefined;
});
afterAll(async () => {
  await h.close();
});

const JAN_1 = Date.parse("2026-01-01T00:00:00Z");
const DAY = 86_400_000;
const days = (n: number) => new Date(JAN_1 + n * DAY);

const BA = "/api/auth/organization";
const base = () => `/api/organizations/${org.orgId}`;
const api = (path: string, opts: { cookie?: string; body?: unknown; method?: string } = {}) => h.api(`${base()}${path}`, { cookie: opts.cookie ?? org.cookie, body: opts.body, method: opts.method });
const detach = (id: string, cookie = org.cookie) => api(`/managed-certificates/${id}/profile`, { cookie, method: "DELETE" });
const disable = (id: string) => api(`/certificate-profiles/${id}/disable`, { body: {} });
const read = async (id: string) => (await api(`/managed-certificates/${id}`)).body;
const auditOf = async (action: string) => ((await api("/audit-events")).body.items as { action: string; actor: any; target: any; detail: any }[]).filter((e) => e.action === action);

async function join(email: string, role: string) {
  const invited = await h.api(`${BA}/invite-member`, { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api(`${BA}/accept-invitation`, { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}

const RULES = { exact: ["www.internal.acme"], zones: [], maxNames: 1, wildcards: false };

/** A profile on a Private CA's Issuing CA permitting names under internal.acme, whose Certificates live 90 days and are due 30 days before they end, allowing only www.internal.acme. */
async function createProfile() {
  const ca = await api("/private-cas", {
    body: { name: "Internal", subject: "CN=Internal, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["internal.acme"] } },
  });
  expect(ca.status).toBe(201);
  const res = await api("/certificate-profiles", {
    body: { name: "Internal web", issuer: { kind: "private_ca", issuingCaId: ca.body.issuingCas[0].id }, allowedKeyAlgorithms: ["ecdsa-p256"], validityDays: 90, nameRules: RULES },
  });
  expect(res.status).toBe(201);
  return res.body.id as string;
}

async function request(names: string[]) {
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, await acme.crypto.createPrivateEcdsaKey("P-256"));
  return { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() };
}

/** A Managed Certificate a Member proposed through the profile and the admin approved, issued on 1 January, with the Member its Owner. */
async function issuedFrom(profileId: string) {
  h.setNow(days(0));
  member ??= await join("member@acme.test", "member");
  const created = await api("/managed-certificates", { cookie: member, body: { ...(await request(["www.internal.acme"])), profileId } });
  expect(created.status).toBe(201);
  expect((await api(`/managed-certificates/${created.body.id}/approve`, { body: {} })).status).toBe(200);
  await h.settleIssuances();
  const mc = await read(created.body.id);
  expect(mc.issuance.status).toBe("succeeded");
  return { id: mc.id as string, member: member! };
}

describe("detaching a Managed Certificate from its Certificate Profile", () => {
  test("clears its link to the profile and changes nothing else, audited naming the profile", async () => {
    const profile = await createProfile();
    const { id } = await issuedFrom(profile);
    const before = await read(id);
    expect(before.profile).toEqual({ id: profile, name: "Internal web", enabled: true });

    const res = await detach(id);
    expect(res.status).toBe(200);
    expect(res.body.profile).toBeNull();
    const { profile: _was, ...unchanged } = before;
    expect(await read(id)).toMatchObject(unchanged);

    expect(await auditOf("managed_certificate.profile_detached")).toMatchObject([
      { actor: { email: "admin@acme.test" }, target: { type: "managed_certificate", id }, detail: { names: ["www.internal.acme"], certificateProfile: { id: profile, name: "Internal web" } } },
    ]);
    // The profile no longer counts it.
    expect((await api(`/certificate-profiles/${profile}`)).body.linked).toBe(0);
  });

  test("is refused with 409 for one with no profile, a Proposal, or one archived", async () => {
    const profile = await createProfile();
    const { id, member } = await issuedFrom(profile);
    expect((await detach(id)).status).toBe(200);
    const again = await detach(id);
    expect(again.status).toBe(409);
    expect(again.body.error).toMatch(/not linked to a Certificate Profile/);
    expect(await auditOf("managed_certificate.profile_detached")).toHaveLength(1);

    const free = await api("/managed-certificates", { body: { ...(await request(["free.internal.acme"])), issuer: { kind: "private_ca", issuingCaId: (await read(id)).issuer.issuingCa.id } } });
    expect(free.status).toBe(201);
    expect((await detach(free.body.id)).status).toBe(409);

    const proposed = await api("/managed-certificates", { cookie: member, body: { ...(await request(["www.internal.acme"])), profileId: profile } });
    expect(proposed.status).toBe(201);
    const pending = await detach(proposed.body.id);
    expect(pending.status).toBe(409);
    expect(pending.body.error).toMatch(/Proposal/);
    expect((await read(proposed.body.id)).profile.id).toBe(profile);

    const { id: archived } = await issuedFrom(profile);
    expect((await api(`/managed-certificates/${archived}/archive`, { body: {} })).status).toBe(200);
    expect((await detach(archived)).status).toBe(409);
  });

  test("needs managedCertificate.detachProfile, which only Organization Administrators hold and /api/me reports", async () => {
    const profile = await createProfile();
    const { id, member } = await issuedFrom(profile);
    const approver = await join("approver@acme.test", "approver");
    for (const cookie of [member, approver]) {
      expect((await detach(id, cookie)).status).toBe(403);
      expect((await h.api("/api/me", { cookie })).body.organizations[0].permissions.managedCertificate).not.toContain("detachProfile");
    }
    expect((await read(id)).profile).not.toBeNull();
    expect((await h.api("/api/me", { cookie: org.cookie })).body.organizations[0].permissions.managedCertificate).toContain("detachProfile");
  });
});

describe("once detached, a Managed Certificate made from a disabled profile", () => {
  test("is no longer renewal-blocked, and a due one renews on the scheduler's next pass", async () => {
    const profile = await createProfile();
    const { id } = await issuedFrom(profile);
    await disable(profile);
    h.setNow(days(60));
    expect(await h.runRenewalScheduler()).toBe(0);
    expect((await read(id)).renewal.blocked).not.toBeNull();

    const res = await detach(id);
    expect(res.status).toBe(200);
    expect(res.body.renewal.blocked).toBeNull();
    h.setNow(days(61));
    expect(await h.runRenewalScheduler()).toBe(1);
    await h.settleIssuances();
    const renewed = await read(id);
    expect(renewed.issuance).toMatchObject({ kind: "renewal", status: "succeeded" });
    expect(renewed.currentCertificate.notAfter).toBe(days(151).toISOString());
    // The settings copied from the profile still hold: the Issuing CA and the 90-day validity.
    expect(renewed.validityDays).toBe(90);
  });

  test("may be renewed now and have its names changed, and an Owner's Name Change is no longer held to the profile's name rules", async () => {
    const profile = await createProfile();
    const { id, member } = await issuedFrom(profile);
    await disable(profile);
    // Before detaching, the disabled profile refuses both.
    expect((await api(`/managed-certificates/${id}/renewals`, { cookie: member, body: {} })).status).toBe(422);
    expect((await api(`/managed-certificates/${id}/name-change`, { cookie: member, body: await request(["www.internal.acme"]) })).status).toBe(422);

    expect((await detach(id)).status).toBe(200);
    expect((await api(`/managed-certificates/${id}/renewals`, { cookie: member, body: {} })).status).toBe(202);
    await h.settleIssuances();
    // Outside the profile's rules (one exact name only), within the Issuing CA's permitted names.
    const changed = await api(`/managed-certificates/${id}/name-change`, { cookie: member, body: await request(["www.internal.acme", "db.internal.acme"]) });
    expect(changed.status).toBe(201);
    expect((await api(`/managed-certificates/${id}/name-change/approve`, { body: {} })).status).toBe(200);
    await h.settleIssuances();
    expect((await read(id)).names).toEqual(["www.internal.acme", "db.internal.acme"]);
    // The Issuing CA's own limits still hold.
    const outside = await api(`/managed-certificates/${id}/name-change`, { cookie: member, body: await request(["www.example.com"]) });
    expect(outside.status).toBe(422);
  });
});
