// Disabling and enabling a Certificate Profile: while it is disabled nothing more is proposed or approved under it,
// for everyone. Pending Proposals and Name Changes from it stay pending, rejectable but not approvable, until it is
// enabled again. Each check is of what the API answers and the Audit Events it leaves.
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
const createMc = (body: unknown, cookie = org.cookie) => h.api(`${base()}/managed-certificates`, { cookie, body });
const changeNames = (id: string, body: unknown, cookie: string) => h.api(`${base()}/managed-certificates/${id}/name-change`, { cookie, body });
const disable = (id: string, cookie = org.cookie) => h.api(`${base()}/certificate-profiles/${id}/disable`, { cookie, body: {} });
const enable = (id: string, cookie = org.cookie) => h.api(`${base()}/certificate-profiles/${id}/enable`, { cookie, body: {} });
const readProfile = (id: string, cookie = org.cookie) => h.api(`${base()}/certificate-profiles/${id}`, { cookie });
const auditOf = async (action: string) =>
  ((await h.api(`${base()}/audit-events`, { cookie: org.cookie })).body.items as { action: string; actor: any; target: any; detail: any }[]).filter((e) => e.action === action);

async function join(email: string, role: string) {
  const invited = await h.api(`${BA}/invite-member`, { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api(`${BA}/accept-invitation`, { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}

/** A profile on an Issuing CA of a Private CA with a platform-made root, permitting names under internal.acme. */
async function createProfile() {
  const ca = await h.api(`${base()}/private-cas`, {
    cookie: org.cookie,
    body: { name: "Internal", subject: "CN=Internal, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["internal.acme"] } },
  });
  expect(ca.status).toBe(201);
  const res = await h.api(`${base()}/certificate-profiles`, {
    cookie: org.cookie,
    body: { name: "Internal web", issuer: { kind: "private_ca", issuingCaId: ca.body.issuingCas[0].id }, allowedKeyAlgorithms: ["ecdsa-p256"] },
  });
  expect(res.status).toBe(201);
  return res.body.id as string;
}

/** Names, and a CSR for them under a fresh key. */
async function request(names: string[]) {
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, await acme.crypto.createPrivateEcdsaKey("P-256"));
  return { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() };
}

describe("disabling and enabling a Certificate Profile", () => {
  test("needs certificateProfile.disable, is audited, and refuses what is already so with 409", async () => {
    const id = await createProfile();
    const member = await join("member@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");
    expect((await disable(id, member)).status).toBe(403);
    expect((await disable(id, approver)).status).toBe(403);

    const disabled = await disable(id);
    expect(disabled.status).toBe(200);
    expect(disabled.body.enabled).toBe(false);
    expect((await disable(id)).status).toBe(409);
    expect((await enable(id, approver)).status).toBe(403);

    const enabled = await enable(id);
    expect(enabled.status).toBe(200);
    expect(enabled.body.enabled).toBe(true);
    expect((await enable(id)).status).toBe(409);

    expect((await auditOf("certificate_profile.disabled")).map((e) => [e.target, e.detail, e.actor.email])).toEqual([
      [{ type: "certificate_profile", id }, { name: "Internal web" }, "admin@acme.test"],
    ]);
    expect((await auditOf("certificate_profile.enabled")).map((e) => [e.target, e.detail])).toEqual([[{ type: "certificate_profile", id }, { name: "Internal web" }]]);
  });

  test("hides it from Members and Approvers while it is disabled; Organization Administrators still see it", async () => {
    const id = await createProfile();
    const member = await join("member@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");
    await disable(id);
    for (const cookie of [member, approver]) {
      expect((await h.api(`${base()}/certificate-profiles`, { cookie })).body.items).toEqual([]);
      expect((await readProfile(id, cookie)).status).toBe(404);
    }
    expect((await h.api(`${base()}/certificate-profiles`, { cookie: org.cookie })).body.items.map((p: any) => [p.id, p.enabled])).toEqual([[id, false]]);
  });
});

describe("while a Certificate Profile is disabled", () => {
  test("a request through it is refused with 422 for everyone, Organization Administrators included", async () => {
    const id = await createProfile();
    const member = await join("member@acme.test", "member");
    await disable(id);
    for (const cookie of [member, org.cookie]) {
      const res = await createMc({ ...(await request(["www.internal.acme"])), profileId: id }, cookie);
      expect(res.status).toBe(422);
      expect(res.body.error).toMatch(/Internal web is disabled/);
    }
  });

  test("its pending Proposals can be rejected but not approved, until it is enabled again", async () => {
    const id = await createProfile();
    const member = await join("member@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");
    const first = await createMc({ ...(await request(["a.internal.acme"])), profileId: id }, member);
    const second = await createMc({ ...(await request(["b.internal.acme"])), profileId: id }, member);
    expect([first.status, second.status]).toEqual([201, 201]);
    await disable(id);

    // The Approval queue still names the profile, as disabled.
    const queue = await h.api(`${base()}/approvals`, { cookie: approver });
    expect(queue.body.items.map((mc: any) => mc.profile)).toEqual([
      { id, name: "Internal web", enabled: false },
      { id, name: "Internal web", enabled: false },
    ]);

    const refused = await h.api(`${base()}/managed-certificates/${first.body.id}/approve`, { cookie: approver, body: {} });
    expect(refused.status).toBe(422);
    expect(refused.body.error).toMatch(/Certificate Profile Internal web is disabled/);
    expect((await h.api(`${base()}/managed-certificates/${first.body.id}`, { cookie: approver })).body.approval.status).toBe("pending");
    expect(await auditOf("managed_certificate.approved")).toEqual([]);

    const rejected = await h.api(`${base()}/managed-certificates/${second.body.id}/reject`, { cookie: approver, body: { reason: "not needed" } });
    expect(rejected.status).toBe(200);

    await enable(id);
    const approved = await h.api(`${base()}/managed-certificates/${first.body.id}/approve`, { cookie: approver, body: {} });
    expect(approved.status).toBe(200);
    await h.settleIssuances();
    expect((await h.api(`${base()}/managed-certificates/${first.body.id}`, { cookie: approver })).body.currentCertificate).not.toBeNull();
  });

  test("a Name Change on a Managed Certificate made from it is refused for everyone, and a pending one cannot be approved until it is enabled", async () => {
    const id = await createProfile();
    const member = await join("member@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");
    const proposed = await createMc({ ...(await request(["www.internal.acme"])), profileId: id }, member);
    expect((await h.api(`${base()}/managed-certificates/${proposed.body.id}/approve`, { cookie: approver, body: {} })).status).toBe(200);
    await h.settleIssuances();
    const mc = proposed.body.id as string;
    expect((await changeNames(mc, await request(["www.internal.acme", "api.internal.acme"]), member)).status).toBe(201);

    await disable(id);
    for (const cookie of [member, org.cookie]) {
      const res = await changeNames(mc, await request(["db.internal.acme"]), cookie);
      expect(res.status).toBe(422);
      expect(res.body.error).toMatch(/Certificate Profile Internal web is disabled/);
    }
    expect((await h.api(`${base()}/approvals`, { cookie: approver })).body.nameChanges.map((n: any) => n.profile)).toEqual([{ id, name: "Internal web", enabled: false }]);
    const refused = await h.api(`${base()}/managed-certificates/${mc}/name-change/approve`, { cookie: approver, body: {} });
    expect(refused.status).toBe(422);
    expect(refused.body.error).toMatch(/Certificate Profile Internal web is disabled/);
    expect(await auditOf("name_change.approved")).toEqual([]);
    // Nor is it issued another way while the profile is disabled.
    for (const path of ["renewals", "issuances"]) {
      const res = await h.api(`${base()}/managed-certificates/${mc}/${path}`, { cookie: org.cookie, body: {} });
      expect(res.status).toBe(422);
      expect(res.body.error).toMatch(/Certificate Profile Internal web is disabled/);
    }

    await enable(id);
    expect((await h.api(`${base()}/managed-certificates/${mc}/name-change/approve`, { cookie: approver, body: {} })).status).toBe(200);
    expect(await auditOf("name_change.approved")).toHaveLength(1);
  });

  test("a pending Name Change can still be rejected", async () => {
    const id = await createProfile();
    const member = await join("member@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");
    const proposed = await createMc({ ...(await request(["www.internal.acme"])), profileId: id }, member);
    await h.api(`${base()}/managed-certificates/${proposed.body.id}/approve`, { cookie: approver, body: {} });
    await h.settleIssuances();
    expect((await changeNames(proposed.body.id, await request(["api.internal.acme"]), member)).status).toBe(201);
    await disable(id);
    expect((await h.api(`${base()}/managed-certificates/${proposed.body.id}/name-change/reject`, { cookie: approver, body: { reason: "no" } })).status).toBe(200);
  });
});

test("reading a profile reports how many Proposals and Name Changes from it are pending", async () => {
  const id = await createProfile();
  const member = await join("member@acme.test", "member");
  const approver = await join("approver@acme.test", "approver");
  expect((await readProfile(id)).body.pending).toEqual({ proposals: 0, nameChanges: 0 });

  const issued = await createMc({ ...(await request(["www.internal.acme"])), profileId: id }, member);
  await h.api(`${base()}/managed-certificates/${issued.body.id}/approve`, { cookie: approver, body: {} });
  await h.settleIssuances();
  await changeNames(issued.body.id, await request(["api.internal.acme"]), member);
  await createMc({ ...(await request(["a.internal.acme"])), profileId: id }, member);
  await createMc({ ...(await request(["b.internal.acme"])), profileId: id }, member);
  const archived = await createMc({ ...(await request(["c.internal.acme"])), profileId: id }, member);
  expect((await h.api(`${base()}/managed-certificates/${archived.body.id}/archive`, { cookie: org.cookie, body: {} })).status).toBe(200);

  expect((await readProfile(id)).body.pending).toEqual({ proposals: 2, nameChanges: 1 });
});
