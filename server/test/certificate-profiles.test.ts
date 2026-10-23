// Certificate Profiles: an Organization Administrator creates and edits them, and every member lists the enabled ones.
// Each check is of what the API answers and the Audit Events it leaves.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { PASSWORD, createHarness, type Harness } from "./support/harness";
import { eq } from "drizzle-orm";
import { acmeAccount, certificateProfile, secret } from "../src/platform/db/schema";

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
const profiles = (orgId = org.orgId) => `/api/organizations/${orgId}/certificate-profiles`;
const create = (body: unknown, cookie = org.cookie) => h.api(profiles(), { cookie, body });
const update = (id: string, body: unknown, cookie = org.cookie) => h.api(`${profiles()}/${id}`, { cookie, method: "PATCH", body });
const list = async (cookie = org.cookie) => (await h.api(profiles(), { cookie })).body.items as any[];
const auditOf = async (action: string) =>
  ((await h.api(`/api/organizations/${org.orgId}/audit-events`, { cookie: org.cookie })).body.items as { action: string; actor: any; target: any; detail: any }[]).filter((e) => e.action === action);

/** A Private CA with a platform-made root whose keys are `keyAlgorithm`, and its first Issuing CA. */
async function createCa(keyAlgorithm = "ecdsa-p256", name = `Internal ${keyAlgorithm}`) {
  const res = await h.api(`/api/organizations/${org.orgId}/private-cas`, {
    cookie: org.cookie,
    body: { name, subject: `CN=${name}, O=Acme`, keyAlgorithm, lifetimeYears: 5, permittedNames: { exact: [], zones: ["internal.acme"] } },
  });
  expect(res.status).toBe(201);
  return { id: res.body.id as string, issuing: res.body.issuingCas[0] as { id: string; validity: { maximumDays: number } } };
}

/** An ACME Account of the Organization's with the ACME CA, as registering one would leave it (registration itself is the ACME Accounts tests' to check). */
async function haveAcmeAccount(acmeCaId = "letsencrypt-staging") {
  const [held] = await h.db.insert(secret).values({ organizationId: org.orgId, ciphertext: Buffer.from("not-a-key") }).returning();
  await h.db.insert(acmeAccount).values({ organizationId: org.orgId, acmeCaId, accountUrl: `https://acme.test/acct/${acmeCaId}`, secretId: held!.id });
}

async function join(email: string, role: string) {
  const invited = await h.api(`${BA}/invite-member`, { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api(`${BA}/accept-invitation`, { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}

/** Disabling is ticket 04's; until then a test disables a profile directly. */
const eqId = (id: string) => eq(certificateProfile.id, id);

const createTeam = async (name: string) => (await h.api(`${BA}/create-team`, { cookie: org.cookie, body: { name, organizationId: org.orgId } })).body.id as string;

describe("creating a Certificate Profile", () => {
  test("an Organization Administrator creates one on an Issuing CA, which is listed and audited", async () => {
    const ca = await createCa();
    const team = await createTeam("Web");
    const res = await create({
      name: "Internal web",
      description: "TLS for internal web servers",
      issuer: { kind: "private_ca", issuingCaId: ca.issuing.id },
      allowedKeyAlgorithms: ["ecdsa-p256", "rsa-2048"],
      validityDays: 90,
      renewalPolicy: { mode: "automatic", daysBeforeExpiry: 20 },
      defaultTeamId: team,
    });
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({
      name: "Internal web",
      description: "TLS for internal web servers",
      issuer: { kind: "private_ca", issuingCaId: ca.issuing.id },
      allowedKeyAlgorithms: ["ecdsa-p256", "rsa-2048"],
      validityDays: 90,
      renewalPolicy: { mode: "automatic", daysBeforeExpiry: 20 },
      defaultTeam: { id: team, name: "Web" },
      enabled: true,
    });
    expect(await list()).toEqual([res.body]);
    expect(await auditOf("certificate_profile.created")).toEqual([
      expect.objectContaining({
        actor: expect.objectContaining({ email: "admin@acme.test" }),
        target: { type: "certificate_profile", id: res.body.id },
        detail: {
          name: "Internal web",
          description: "TLS for internal web servers",
          issuer: { kind: "private_ca", issuingCaId: ca.issuing.id },
          allowedKeyAlgorithms: ["ecdsa-p256", "rsa-2048"],
          validityDays: 90,
          renewalPolicy: { mode: "automatic", daysBeforeExpiry: 20 },
          defaultTeam: { id: team, name: "Web" },
        },
      }),
    ]);
  });
});

/** A profile on the Issuing CA, as an Organization Administrator creates it, with `extra` given too. */
async function createOn(issuingCaId: string, extra: Record<string, unknown> = {}) {
  const res = await create({ name: "Internal web", issuer: { kind: "private_ca", issuingCaId }, allowedKeyAlgorithms: ["ecdsa-p256"], ...extra });
  expect(res.status).toBe(201);
  return res.body as { id: string; name: string };
}

describe("a Certificate Profile's issuer", () => {
  test("an ACME CA is taken once the Organization has an ACME Account with it, with the default Renewal Policy and no validity", async () => {
    const body = { name: "Public web", issuer: { kind: "acme", acmeCaId: "letsencrypt-production" }, allowedKeyAlgorithms: ["ecdsa-p256"] };
    const refused = await create(body);
    expect(refused.status).toBe(422);
    expect(refused.body.error).toMatch(/no ACME Account with Let's Encrypt Production/);
    await haveAcmeAccount("letsencrypt-production");
    const res = await create(body);
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ issuer: { kind: "acme", acmeCaId: "letsencrypt-production" }, validityDays: null, renewalPolicy: { mode: "automatic", daysBeforeExpiry: 30 }, defaultTeam: null });
  });

  test("an ACME CA the Organization cannot use is refused", async () => {
    const res = await create({ name: "Public web", issuer: { kind: "acme", acmeCaId: "no-such-ca" }, allowedKeyAlgorithms: ["ecdsa-p256"] });
    expect(res.status).toBe(422);
    expect(res.body.error).toMatch(/no such ACME CA/);
    // Nor is one chosen for it.
    expect((await create({ name: "Public web", issuer: { kind: "acme" }, allowedKeyAlgorithms: ["ecdsa-p256"] })).status).toBe(400);
  });

  test("an Issuing CA that is not the Organization's, or does not issue, is refused with the reason", async () => {
    const theirs = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    const own = await createCa();
    const res = await h.api(`/api/organizations/${theirs.orgId}/certificate-profiles`, {
      cookie: theirs.cookie,
      body: { name: "Theirs", issuer: { kind: "private_ca", issuingCaId: own.issuing.id }, allowedKeyAlgorithms: ["ecdsa-p256"] },
    });
    expect(res.status).toBe(422);
    expect(res.body.error).toMatch(/no such Issuing CA/);

    expect((await h.api(`/api/organizations/${org.orgId}/private-cas/${own.id}/issuing-cas/${own.issuing.id}/retire`, { cookie: org.cookie, body: {} })).status).toBe(200);
    const retired = await create({ name: "Internal web", issuer: { kind: "private_ca", issuingCaId: own.issuing.id }, allowedKeyAlgorithms: ["ecdsa-p256"] });
    expect(retired.status).toBe(422);
    expect(retired.body.error).toMatch(/retired, so it issues nothing/);
  });

  test("its key algorithms are some of those the issuer takes, and at least one", async () => {
    const classical = await createCa();
    const mlDsa = await createCa("ml-dsa-65");
    await haveAcmeAccount();
    const attempt = (issuer: unknown, allowedKeyAlgorithms: string[]) => create({ name: "Keys", issuer, allowedKeyAlgorithms });
    const onAcme = await attempt({ kind: "acme", acmeCaId: "letsencrypt-staging" }, ["ecdsa-p256", "ml-dsa-65"]);
    expect([onAcme.status, onAcme.body.error]).toEqual([422, expect.stringMatching(/takes keys of .*not ml-dsa-65/)]);
    const classicalOnMlDsa = await attempt({ kind: "private_ca", issuingCaId: mlDsa.issuing.id }, ["ml-dsa-65", "rsa-2048"]);
    expect([classicalOnMlDsa.status, classicalOnMlDsa.body.error]).toEqual([422, expect.stringMatching(/not rsa-2048/)]);
    const mlDsaOnClassical = await attempt({ kind: "private_ca", issuingCaId: classical.issuing.id }, ["ml-dsa-44"]);
    expect(mlDsaOnClassical.status).toBe(422);
    expect((await attempt({ kind: "private_ca", issuingCaId: classical.issuing.id }, [])).status).toBe(400);
    expect((await attempt({ kind: "private_ca", issuingCaId: classical.issuing.id }, ["rsa-2048", "rsa-2048"])).status).toBe(400);
    const onMlDsa = await attempt({ kind: "private_ca", issuingCaId: mlDsa.issuing.id }, ["ml-dsa-65", "ml-dsa-87"]);
    expect([onMlDsa.status, onMlDsa.body.allowedKeyAlgorithms]).toEqual([201, ["ml-dsa-65", "ml-dsa-87"]]);
  });

  test("a validity is for a Private CA only, at most its Issuing CA's maximum", async () => {
    const ca = await createCa();
    await haveAcmeAccount();
    const onAcme = await create({ name: "Public web", issuer: { kind: "acme", acmeCaId: "letsencrypt-staging" }, allowedKeyAlgorithms: ["ecdsa-p256"], validityDays: 30 });
    expect(onAcme.status).toBe(400);
    const max = ca.issuing.validity.maximumDays;
    const above = await create({ name: "Internal web", issuer: { kind: "private_ca", issuingCaId: ca.issuing.id }, allowedKeyAlgorithms: ["ecdsa-p256"], validityDays: max + 1 });
    expect([above.status, above.body.error]).toEqual([422, expect.stringMatching(new RegExp(`above the maximum of ${max} days`))]);
    expect((await createOn(ca.issuing.id, { validityDays: max })) as any).toMatchObject({ validityDays: max });
  });
});

describe("the rest of a Certificate Profile", () => {
  test("its Renewal Policy follows the Renewal Policy rules, and its default Team is one of the Organization's", async () => {
    const ca = await createCa();
    const issuer = { kind: "private_ca", issuingCaId: ca.issuing.id };
    for (const renewalPolicy of [{ mode: "sometimes", daysBeforeExpiry: 30 }, { mode: "manual", daysBeforeExpiry: 0 }, { mode: "manual", daysBeforeExpiry: 366 }]) {
      expect((await create({ name: "Internal web", issuer, allowedKeyAlgorithms: ["ecdsa-p256"], renewalPolicy })).status).toBe(400);
    }
    const theirs = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    const theirTeam = (await h.api(`${BA}/create-team`, { cookie: theirs.cookie, body: { name: "Theirs", organizationId: theirs.orgId } })).body.id;
    const res = await create({ name: "Internal web", issuer, allowedKeyAlgorithms: ["ecdsa-p256"], defaultTeamId: theirTeam });
    expect([res.status, res.body.error]).toEqual([422, expect.stringMatching(/no such Team/)]);
  });

  test("a default Team that is deleted leaves the profile with none", async () => {
    const ca = await createCa();
    const team = await createTeam("Web");
    const profile = await createOn(ca.issuing.id, { defaultTeamId: team });
    expect((await h.api(`${BA}/remove-team`, { cookie: org.cookie, body: { teamId: team, organizationId: org.orgId } })).status).toBe(200);
    expect((await h.api(`${profiles()}/${profile.id}`, { cookie: org.cookie })).body.defaultTeam).toBeNull();
  });

  test("its name is unique within the Organization, but not across Organizations", async () => {
    const ca = await createCa();
    await createOn(ca.issuing.id);
    const again = await create({ name: "Internal web", issuer: { kind: "private_ca", issuingCaId: ca.issuing.id }, allowedKeyAlgorithms: ["rsa-2048"] });
    expect(again.status).toBe(409);
    const theirs = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    const theirCa = await h.api(`/api/organizations/${theirs.orgId}/private-cas`, {
      cookie: theirs.cookie,
      body: { name: "Globex", subject: "CN=Globex, O=Globex", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["globex.test"] } },
    });
    const theirProfile = await h.api(`/api/organizations/${theirs.orgId}/certificate-profiles`, {
      cookie: theirs.cookie,
      body: { name: "Internal web", issuer: { kind: "private_ca", issuingCaId: theirCa.body.issuingCas[0].id }, allowedKeyAlgorithms: ["ecdsa-p256"] },
    });
    expect(theirProfile.status).toBe(201);
    // Neither Organization sees the other's.
    expect((await list()).map((p) => p.id)).not.toContain(theirProfile.body.id);
  });
});

describe("who may see and change Certificate Profiles", () => {
  test("Members and Approvers list and read the enabled ones, but create and edit none; /api/me says so", async () => {
    const ca = await createCa();
    const enabled = await createOn(ca.issuing.id);
    const disabled = await createOn(ca.issuing.id, { name: "Retired web" });
    await h.db.update(certificateProfile).set({ enabled: false }).where(eqId(disabled.id));
    expect((await list()).map((p) => p.name)).toEqual(["Internal web", "Retired web"]);
    expect((await h.api(`${profiles()}/${disabled.id}`, { cookie: org.cookie })).status).toBe(200);

    for (const [email, role] of [["member@acme.test", "member"], ["approver@acme.test", "approver"]] as const) {
      const cookie = await join(email, role);
      const me = (await h.api("/api/me", { cookie })).body.organizations[0].permissions;
      expect(me.certificateProfile).toEqual(["read"]);
      expect((await list(cookie)).map((p) => p.id)).toEqual([enabled.id]);
      expect((await h.api(`${profiles()}/${enabled.id}`, { cookie })).status).toBe(200);
      expect((await h.api(`${profiles()}/${disabled.id}`, { cookie })).status).toBe(404);
      expect((await create({ name: "Mine", issuer: { kind: "private_ca", issuingCaId: ca.issuing.id }, allowedKeyAlgorithms: ["ecdsa-p256"] }, cookie)).status).toBe(403);
      expect((await update(enabled.id, { description: "mine now" }, cookie)).status).toBe(403);
    }
    const adminMe = (await h.api("/api/me", { cookie: org.cookie })).body.organizations[0].permissions;
    expect(adminMe.certificateProfile).toEqual(["read", "create", "update", "disable"]);
    // Outsiders learn nothing of the Organization.
    const outsider = await h.signUp("stranger@else.test", PASSWORD);
    expect((await h.api(profiles(), { cookie: outsider })).status).toBe(404);
    expect((await h.api(profiles(), {})).status).toBe(401);
  });
});

describe("editing a Certificate Profile", () => {
  test("changes any of its settings, including its issuer, and audits what changed", async () => {
    const ca = await createCa();
    const other = await createCa("ecdsa-p384", "Second");
    const team = await createTeam("Web");
    const profile = await createOn(ca.issuing.id, { validityDays: 90, defaultTeamId: team });
    const res = await update(profile.id, {
      name: "Internal services",
      description: "Every internal service",
      issuer: { kind: "private_ca", issuingCaId: other.issuing.id },
      allowedKeyAlgorithms: ["ecdsa-p384"],
      validityDays: null,
      renewalPolicy: { mode: "manual", daysBeforeExpiry: 10 },
      defaultTeamId: null,
    });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      id: profile.id,
      name: "Internal services",
      description: "Every internal service",
      issuer: { kind: "private_ca", issuingCaId: other.issuing.id },
      allowedKeyAlgorithms: ["ecdsa-p384"],
      validityDays: null,
      renewalPolicy: { mode: "manual", daysBeforeExpiry: 10 },
      defaultTeam: null,
    });
    expect((await h.api(`${profiles()}/${profile.id}`, { cookie: org.cookie })).body).toEqual(res.body);
    expect((await auditOf("certificate_profile.updated")).map((e) => e.detail)).toEqual([
      {
        name: "Internal services",
        changes: {
          name: { from: "Internal web", to: "Internal services" },
          description: { from: "", to: "Every internal service" },
          issuer: { from: { kind: "private_ca", issuingCaId: ca.issuing.id }, to: { kind: "private_ca", issuingCaId: other.issuing.id } },
          allowedKeyAlgorithms: { from: ["ecdsa-p256"], to: ["ecdsa-p384"] },
          validityDays: { from: 90, to: null },
          renewalPolicy: { from: { mode: "automatic", daysBeforeExpiry: 30 }, to: { mode: "manual", daysBeforeExpiry: 10 } },
          defaultTeam: { from: { id: team, name: "Web" }, to: null },
        },
      },
    ]);
  });

  test("re-checks the issuer with what is left as it is, and a change that changes nothing is not audited", async () => {
    const ca = await createCa();
    const mlDsa = await createCa("ml-dsa-65");
    await haveAcmeAccount();
    const profile = await createOn(ca.issuing.id, { validityDays: 90 });
    // Its ECDSA keys do not go on an ML-DSA CA, nor its validity on an ACME CA, unless changed with it.
    expect((await update(profile.id, { issuer: { kind: "private_ca", issuingCaId: mlDsa.issuing.id } })).status).toBe(422);
    expect((await update(profile.id, { issuer: { kind: "acme", acmeCaId: "letsencrypt-staging" } })).status).toBe(400);
    expect((await update(profile.id, { validityDays: ca.issuing.validity.maximumDays + 1 })).status).toBe(422);
    const moved = await update(profile.id, { issuer: { kind: "acme", acmeCaId: "letsencrypt-staging" }, validityDays: null });
    expect([moved.status, moved.body.issuer]).toEqual([200, { kind: "acme", acmeCaId: "letsencrypt-staging" }]);
    expect((await update(profile.id, { name: "Internal web", allowedKeyAlgorithms: ["ecdsa-p256"] })).status).toBe(200);
    expect(await auditOf("certificate_profile.updated")).toHaveLength(1);
  });

  test("keeps names unique, and is refused for a profile of another Organization", async () => {
    const ca = await createCa();
    const first = await createOn(ca.issuing.id);
    await createOn(ca.issuing.id, { name: "Second" });
    expect((await update(first.id, { name: "Second" })).status).toBe(409);
    const theirs = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    expect((await h.api(`/api/organizations/${theirs.orgId}/certificate-profiles/${first.id}`, { cookie: theirs.cookie, method: "PATCH", body: { name: "Mine" } })).status).toBe(404);
    expect((await update("not-an-id", { name: "Mine" })).status).toBe(404);
  });
});
