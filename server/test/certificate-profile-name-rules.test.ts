// A Certificate Profile's name rules: the exact names and zones its requests may name, how many, and whether wildcards.
// A non-administrator's Proposal through the profile, and their Name Change on a Managed Certificate made from it, keep
// to the rules as they are now; an Organization Administrator is held only to the issuer's limits. Each check is of
// what the API answers and the Audit Events it leaves.
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
const updateProfile = (id: string, body: unknown) => h.api(`${base()}/certificate-profiles/${id}`, { cookie: org.cookie, method: "PATCH", body });
const auditOf = async (action: string) =>
  ((await h.api(`${base()}/audit-events`, { cookie: org.cookie })).body.items as { action: string; actor: any; target: any; detail: any }[]).filter((e) => e.action === action);

async function join(email: string, role: string) {
  const invited = await h.api(`${BA}/invite-member`, { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api(`${BA}/accept-invitation`, { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}

/** An Issuing CA of a Private CA with a platform-made root, permitting names under internal.acme. */
async function createIssuingCa(name = "Internal") {
  const res = await h.api(`${base()}/private-cas`, {
    cookie: org.cookie,
    body: { name, subject: `CN=${name}, O=Acme`, keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["internal.acme"] } },
  });
  expect(res.status).toBe(201);
  return res.body.issuingCas[0].id as string;
}

/** A profile on the Issuing CA, as an Organization Administrator creates it. */
async function createProfile(body: Record<string, unknown> = {}) {
  const issuingCaId = await createIssuingCa();
  const res = await h.api(`${base()}/certificate-profiles`, {
    cookie: org.cookie,
    body: { name: "Internal web", issuer: { kind: "private_ca", issuingCaId }, allowedKeyAlgorithms: ["ecdsa-p256"], ...body },
  });
  expect(res.status).toBe(201);
  return res.body as { id: string; nameRules: unknown };
}

/** Names, and a CSR for them under a fresh key. */
async function request(names: string[]) {
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, await acme.crypto.createPrivateEcdsaKey("P-256"));
  return { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() };
}

const RULES = { exact: ["www.internal.acme"], zones: ["apps.internal.acme"], maxNames: 2, wildcards: false };

describe("a Certificate Profile's name rules", () => {
  test("are none unless given, and are created, shown, edited and audited", async () => {
    const plain = await createProfile();
    expect(plain.nameRules).toEqual({ exact: [], zones: [], maxNames: null, wildcards: true });

    const created = await h.api(`${base()}/certificate-profiles`, {
      cookie: org.cookie,
      body: { name: "Apps", issuer: { kind: "private_ca", issuingCaId: await createIssuingCa("Apps") }, allowedKeyAlgorithms: ["ecdsa-p256"], nameRules: { ...RULES, exact: ["WWW.Internal.Acme."] } },
    });
    expect(created.status).toBe(201);
    // Normalised as names are.
    expect(created.body.nameRules).toEqual(RULES);
    expect((await auditOf("certificate_profile.created")).find((e) => e.detail.name === "Apps")!.detail.nameRules).toEqual(RULES);

    const edited = await updateProfile(created.body.id, { nameRules: { exact: [], zones: ["internal.acme"], maxNames: null, wildcards: true } });
    expect(edited.status).toBe(200);
    expect(edited.body.nameRules).toEqual({ exact: [], zones: ["internal.acme"], maxNames: null, wildcards: true });
    expect((await auditOf("certificate_profile.updated"))[0]!.detail.changes).toEqual({
      nameRules: { from: RULES, to: { exact: [], zones: ["internal.acme"], maxNames: null, wildcards: true } },
    });
  });

  test("that are not names, or name a wildcard while wildcards are not allowed, are refused with 400", async () => {
    const profile = await createProfile();
    for (const nameRules of [
      { exact: ["not a name"], zones: [], maxNames: null, wildcards: true },
      { exact: [], zones: ["*.internal.acme"], maxNames: null, wildcards: true },
      { exact: ["*.internal.acme"], zones: [], maxNames: null, wildcards: false },
      { exact: [], zones: [], maxNames: 0, wildcards: true },
    ]) {
      expect((await updateProfile(profile.id, { nameRules })).status).toBe(400);
    }
  });
});

describe("a non-administrator's Proposal through a profile with name rules", () => {
  test("is refused with 422 naming the names outside the rules, wildcards when they are not allowed, or too many names", async () => {
    const profile = await createProfile({ nameRules: RULES });
    const member = await join("member@acme.test", "member");
    const propose = async (names: string[]) => createMc({ ...(await request(names)), profileId: profile.id }, member);

    const outside = await propose(["www.internal.acme", "db.internal.acme"]);
    expect(outside.status).toBe(422);
    expect(outside.body.error).toMatch(/db\.internal\.acme is outside the name rules of the Certificate Profile Internal web/);

    const wildcard = await propose(["*.apps.internal.acme"]);
    expect(wildcard.status).toBe(422);
    expect(wildcard.body.error).toMatch(/\*\.apps\.internal\.acme: the Certificate Profile Internal web allows no wildcards/);

    const tooMany = await propose(["www.internal.acme", "a.apps.internal.acme", "b.apps.internal.acme"]);
    expect(tooMany.status).toBe(422);
    expect(tooMany.body.error).toMatch(/Internal web allows at most 2 names, not 3/);

    const within = await propose(["www.internal.acme", "a.apps.internal.acme"]);
    expect(within.status).toBe(201);
    expect(within.body.approval.status).toBe("pending");
  });

  test("is still held to the issuer's limits, which the rules cannot widen", async () => {
    const profile = await createProfile({ nameRules: { exact: ["www.example.com"], zones: [], maxNames: null, wildcards: true } });
    const member = await join("member@acme.test", "member");
    const res = await createMc({ ...(await request(["www.example.com"])), profileId: profile.id }, member);
    expect(res.status).toBe(422);
    expect(res.body.error).toMatch(/www\.example\.com is outside the permitted names/);
  });

  test("editing the rules leaves a pending Proposal as it is, still approvable", async () => {
    const profile = await createProfile({ nameRules: RULES });
    const member = await join("member@acme.test", "member");
    const proposed = await createMc({ ...(await request(["www.internal.acme"])), profileId: profile.id }, member);
    expect(proposed.status).toBe(201);
    expect((await updateProfile(profile.id, { nameRules: { ...RULES, exact: [] } })).status).toBe(200);
    const approver = await join("approver@acme.test", "approver");
    const approved = await h.api(`${base()}/managed-certificates/${proposed.body.id}/approve`, { cookie: approver, body: {} });
    expect(approved.status).toBe(200);
  });
});

test("an Organization Administrator's request through a profile is held only to the issuer's limits", async () => {
  const profile = await createProfile({ nameRules: RULES });
  const res = await createMc({ ...(await request(["*.db.internal.acme", "db.internal.acme", "x.internal.acme"])), profileId: profile.id });
  expect(res.status).toBe(201);
  expect(res.body.approval.status).toBe("not_required");
});

describe("a Name Change on a Managed Certificate made from a profile", () => {
  /** A Managed Certificate a Member proposed through the profile and an Approver approved, issued, with the Member its Owner. */
  async function approvedThrough(profileId: string) {
    const member = await join("member@acme.test", "member");
    const proposed = await createMc({ ...(await request(["www.internal.acme"])), profileId }, member);
    expect(proposed.status).toBe(201);
    const approver = await join("approver@acme.test", "approver");
    expect((await h.api(`${base()}/managed-certificates/${proposed.body.id}/approve`, { cookie: approver, body: {} })).status).toBe(200);
    await h.settleIssuances();
    return { id: proposed.body.id as string, member };
  }

  test("by an Owner is checked against the profile's rules as they are now", async () => {
    const profile = await createProfile({ nameRules: RULES });
    const mc = await approvedThrough(profile.id);

    const outside = await changeNames(mc.id, await request(["www.internal.acme", "db.internal.acme"]), mc.member);
    expect(outside.status).toBe(422);
    expect(outside.body.error).toMatch(/db\.internal\.acme is outside the name rules of the Certificate Profile Internal web/);

    // Once the rules take the name in, the same change is proposed.
    expect((await updateProfile(profile.id, { nameRules: { ...RULES, zones: ["internal.acme"] } })).status).toBe(200);
    const within = await changeNames(mc.id, await request(["www.internal.acme", "db.internal.acme"]), mc.member);
    expect(within.status).toBe(201);
    expect(await auditOf("name_change.proposed")).toHaveLength(1);
  });

  test("by an Organization Administrator is held only to the issuer's limits", async () => {
    const profile = await createProfile({ nameRules: RULES });
    const mc = await approvedThrough(profile.id);
    const res = await changeNames(mc.id, await request(["*.db.internal.acme", "db.internal.acme", "x.internal.acme"]), org.cookie);
    expect(res.status).toBe(201);
    expect(await auditOf("managed_certificate.names_changed")).toHaveLength(1);

    const outsideIssuer = await changeNames(mc.id, await request(["www.example.com"]), org.cookie);
    expect(outsideIssuer.status).toBe(422);
    expect(outsideIssuer.body.error).toMatch(/www\.example\.com is outside the permitted names/);
  });
});
