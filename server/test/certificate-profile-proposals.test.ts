// Requesting a Managed Certificate through a Certificate Profile: the profile's issuer, validity and Renewal Policy are
// copied onto it, a Member's request is a Proposal and an Organization Administrator's is created outright, and the
// requester and the profile's default Team become its Owners. Each check is of what the API answers and the Audit Events it leaves.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import acme from "acme-client";
import { eq } from "drizzle-orm";
import { PASSWORD, createHarness, type Harness } from "./support/harness";
import { acmeAccount, secret } from "../src/platform/db/schema";

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
const auditOf = async (action: string) =>
  ((await h.api(`${base()}/audit-events`, { cookie: org.cookie })).body.items as { action: string; actor: any; target: any; detail: any }[]).filter((e) => e.action === action);

async function join(email: string, role: string) {
  const invited = await h.api(`${BA}/invite-member`, { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api(`${BA}/accept-invitation`, { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}
const userId = async (cookie: string) => (await h.api("/api/me", { cookie })).body.user.id as string;

/** A Private CA with a platform-made root whose keys are ECDSA P-256, permitting names under internal.acme, and its first Issuing CA. */
async function createCa() {
  const res = await h.api(`${base()}/private-cas`, {
    cookie: org.cookie,
    body: { name: "Internal", subject: "CN=Internal, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["internal.acme"] } },
  });
  expect(res.status).toBe(201);
  return { id: res.body.id as string, issuingCaId: res.body.issuingCas[0].id as string };
}

/** A profile, as an Organization Administrator creates it. */
async function createProfile(body: Record<string, unknown>) {
  const res = await h.api(`${base()}/certificate-profiles`, { cookie: org.cookie, body: { name: "Internal web", allowedKeyAlgorithms: ["ecdsa-p256"], ...body } });
  expect(res.status).toBe(201);
  return res.body as { id: string; name: string };
}

const KEYS = {
  "ecdsa-p256": () => acme.crypto.createPrivateEcdsaKey("P-256"),
  "rsa-2048": () => acme.crypto.createPrivateRsaKey(2048),
} as const;

/** What a requester submits: names, and a CSR for them under a fresh key of the algorithm. */
async function request(names: string[], keyAlgorithm: keyof typeof KEYS = "ecdsa-p256") {
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, await KEYS[keyAlgorithm]());
  return { names, keyAlgorithm, csr: csr.toString() };
}

const createTeam = async (name: string) => (await h.api(`${BA}/create-team`, { cookie: org.cookie, body: { name, organizationId: org.orgId } })).body.id as string;

describe("a Member's request through a Certificate Profile", () => {
  test("is a Proposal with the profile's settings, owned by the requester and the default Team, and audited with the profile", async () => {
    const ca = await createCa();
    const team = await createTeam("Web");
    const profile = await createProfile({
      issuer: { kind: "private_ca", issuingCaId: ca.issuingCaId },
      validityDays: 90,
      renewalPolicy: { mode: "manual", daysBeforeExpiry: 14 },
      defaultTeamId: team,
    });
    const member = await join("member@acme.test", "member");
    const memberId = await userId(member);

    const res = await createMc({ ...(await request(["www.internal.acme"])), profileId: profile.id }, member);
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({
      names: ["www.internal.acme"],
      issuer: { kind: "private_ca", issuingCa: { id: ca.issuingCaId } },
      validityDays: 90,
      renewal: { policy: { mode: "manual", daysBeforeExpiry: 14 } },
      approval: { status: "pending", proposedBy: { email: "member@acme.test" } },
      profile: { id: profile.id, name: "Internal web" },
      owners: [
        { type: "user", id: memberId, email: "member@acme.test" },
        { type: "team", id: team, name: "Web" },
      ],
      issuance: null,
    });
    expect(await auditOf("managed_certificate.proposed")).toEqual([
      expect.objectContaining({ detail: expect.objectContaining({ certificateProfile: { id: profile.id, name: "Internal web" }, validityDays: 90 }) }),
    ]);
    expect((await auditOf("managed_certificate.owner_added")).map((e) => e.detail.owner)).toEqual([
      expect.objectContaining({ type: "user", id: memberId }),
      expect.objectContaining({ type: "team", id: team }),
    ]);

    // An Approver sees which profile it came from in the Approval queue.
    const approver = await join("approver@acme.test", "approver");
    const queue = await h.api(`${base()}/approvals`, { cookie: approver });
    expect(queue.body.items.map((i: any) => i.profile)).toEqual([{ id: profile.id, name: "Internal web", enabled: true }]);
  });
});

describe("an Organization Administrator's request through a Certificate Profile", () => {
  test("is created outright and issued with the profile's settings, which a later edit of the profile does not change", async () => {
    const ca = await createCa();
    const profile = await createProfile({ issuer: { kind: "private_ca", issuingCaId: ca.issuingCaId }, validityDays: 30 });
    const adminId = await userId(org.cookie);

    const res = await createMc({ ...(await request(["api.internal.acme"])), profileId: profile.id });
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({
      approval: { status: "not_required" },
      profile: { id: profile.id, name: "Internal web", enabled: true },
      owners: [{ type: "user", id: adminId }],
      issuance: { status: "running" },
    });
    expect(await auditOf("managed_certificate.created")).toEqual([expect.objectContaining({ detail: expect.objectContaining({ certificateProfile: { id: profile.id, name: "Internal web" } }) })]);
    await h.settleIssuances();

    const edited = await h.api(`${base()}/certificate-profiles/${profile.id}`, {
      cookie: org.cookie,
      method: "PATCH",
      body: { name: "Internal services", validityDays: 60, renewalPolicy: { mode: "manual", daysBeforeExpiry: 10 } },
    });
    expect(edited.status).toBe(200);
    const after = (await h.api(`${base()}/managed-certificates/${res.body.id}`, { cookie: org.cookie })).body;
    expect(after).toMatchObject({
      validityDays: 30,
      renewal: { policy: { mode: "automatic", daysBeforeExpiry: 30 } },
      issuance: { status: "succeeded" },
      // It is still linked to the profile, which it names as it is now.
      profile: { id: profile.id, name: "Internal services" },
    });
  });
});

describe("a request through a Certificate Profile is refused", () => {
  test("when it also chooses what the profile fixes", async () => {
    const ca = await createCa();
    const profile = await createProfile({ issuer: { kind: "private_ca", issuingCaId: ca.issuingCaId } });
    const asked = { ...(await request(["www.internal.acme"])), profileId: profile.id };
    for (const chosen of [
      { issuer: { kind: "private_ca", issuingCaId: ca.issuingCaId } },
      { acmeCaId: "letsencrypt-staging" },
      { validityDays: 10 },
      { renewalPolicy: { mode: "manual", daysBeforeExpiry: 30 } },
    ]) {
      const res = await createMc({ ...asked, ...chosen });
      expect(res.status).toBe(400);
      expect(res.body.error).toContain(`\`${Object.keys(chosen)[0]}\``);
    }
  });

  test("for a key algorithm the profile does not allow, and for names or a CSR the issuer would refuse", async () => {
    const ca = await createCa();
    const profile = await createProfile({ issuer: { kind: "private_ca", issuingCaId: ca.issuingCaId } });
    const member = await join("member@acme.test", "member");

    const rsa = await createMc({ ...(await request(["www.internal.acme"], "rsa-2048")), profileId: profile.id }, member);
    expect(rsa.status).toBe(422);
    expect(rsa.body.error).toMatch(/Internal web allows keys of ecdsa-p256, not rsa-2048/);

    const outside = await createMc({ ...(await request(["www.example.com"])), profileId: profile.id }, member);
    expect(outside.status).toBe(422);
    expect(outside.body.error).toMatch(/www\.example\.com is outside the permitted names/);

    const mismatched = await createMc({ ...(await request(["www.internal.acme"])), names: ["api.internal.acme"], profileId: profile.id }, member);
    expect(mismatched.status).toBe(422);
    expect(mismatched.body.error).toMatch(/the CSR must ask for exactly the names/);
  });

  test("for a profile the Organization does not have", async () => {
    const res = await createMc({ ...(await request(["www.internal.acme"])), profileId: "8d1e5a7c-0f43-4b6e-9a2d-3c5b7e9f1a20" });
    expect(res.status).toBe(422);
    expect(res.body.error).toMatch(/no such Certificate Profile/);
    expect((await createMc({ ...(await request(["www.internal.acme"])), profileId: "not-an-id" })).status).toBe(422);
  });

  test("while the profile's Issuing CA is not active", async () => {
    const ca = await createCa();
    const profile = await createProfile({ issuer: { kind: "private_ca", issuingCaId: ca.issuingCaId } });
    expect((await h.api(`${base()}/private-cas/${ca.id}/issuing-cas/${ca.issuingCaId}/retire`, { cookie: org.cookie, body: {} })).status).toBe(200);
    const res = await createMc({ ...(await request(["www.internal.acme"])), profileId: profile.id });
    expect(res.status).toBe(422);
    expect(res.body.error).toMatch(/Internal web cannot issue now: .* is retired/);
  });

  test("while the Organization has no ACME Account with the profile's ACME CA", async () => {
    const [held] = await h.db.insert(secret).values({ organizationId: org.orgId, ciphertext: Buffer.from("not-a-key") }).returning();
    await h.db.insert(acmeAccount).values({ organizationId: org.orgId, acmeCaId: "letsencrypt-production", accountUrl: "https://acme.test/acct/1", secretId: held!.id });
    const profile = await createProfile({ name: "Public web", issuer: { kind: "acme", acmeCaId: "letsencrypt-production" } });
    // The platform deletes no ACME Account; the test takes it away to stand for one the profile can no longer use.
    await h.db.delete(acmeAccount).where(eq(acmeAccount.organizationId, org.orgId));
    const member = await join("member@acme.test", "member");
    const res = await createMc({ ...(await request(["www.acme.test"])), profileId: profile.id }, member);
    expect(res.status).toBe(422);
    expect(res.body.error).toMatch(/Public web cannot issue now: the Organization has no ACME Account with Let's Encrypt Production/);
  });
});

test("the Owners named in a request through a profile are added after the requester and the default Team, each once", async () => {
  const ca = await createCa();
  const web = await createTeam("Web");
  const ops = await createTeam("Ops");
  const profile = await createProfile({ issuer: { kind: "private_ca", issuingCaId: ca.issuingCaId }, defaultTeamId: web });
  const member = await join("member@acme.test", "member");
  const memberId = await userId(member);
  const res = await createMc(
    {
      ...(await request(["www.internal.acme"])),
      profileId: profile.id,
      owners: [
        { type: "team", id: ops },
        { type: "team", id: web },
        { type: "user", id: memberId },
      ],
    },
    member,
  );
  expect(res.status).toBe(201);
  expect(res.body.owners.map((o: any) => o.id)).toEqual([memberId, web, ops]);
});
