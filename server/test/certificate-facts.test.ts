// One Certificate's full facts, as the Issued certificates tab's side sheet shows them: its subject and names, issuer,
// serial, signature algorithm, the chain the CA served, the CA and ACME Account it came from, and any revocation. Who
// may see them is who may see its Managed Certificate. Certificates are issued, and revoked, by Pebble for real.
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import acme from "acme-client";
import { randomBytes } from "node:crypto";
import { BIND, PASSWORD, createHarness, type Harness } from "./support/harness";

setDefaultTimeout(60_000);

let h: Harness;
let operator: string;
let org: { orgId: string; cookie: string };
let globex: { orgId: string; cookie: string };

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  operator = await h.createOperator("op@platform.test", PASSWORD);
  org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
  globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
});
afterAll(async () => {
  await h.close();
});

const base = (orgId = org.orgId) => `/api/organizations/${orgId}/managed-certificates`;
const host = () => `t${randomBytes(5).toString("hex")}.${BIND.zone}`;

async function request(names = [host()]) {
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return { names, keyAlgorithm: "ecdsa-p256" as const, csr: csr.toString() };
}

async function join(email: string, role: string) {
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}
const userId = async (cookie: string) => (await h.api("/api/me", { cookie })).body.user.id as string;

async function readyToIssue() {
  expect((await h.api(`/api/organizations/${org.orgId}/acme-accounts`, { cookie: org.cookie, body: { termsOfServiceAgreed: true } })).status).toBe(201);
  expect(
    (
      await h.api(`/api/organizations/${org.orgId}/dns-providers`, {
        cookie: org.cookie,
        body: { name: "BIND", type: "rfc2136", settings: { server: BIND.server, port: BIND.port, zone: BIND.zone, keyName: BIND.keyName }, secret: BIND.keySecret },
      })
    ).status,
  ).toBe(201);
}

/** A Managed Certificate with its first Certificate issued, and an Owner who is a Member. */
async function setup() {
  await readyToIssue();
  const owner = await join("owner@acme.test", "member");
  const body = await request([host(), host()]);
  const created = await h.api(base(), { cookie: org.cookie, body: { ...body, owners: [{ type: "user", id: await userId(owner) }] } });
  expect(created.status).toBe(201);
  await h.settleIssuances();
  return { id: created.body.id as string, names: body.names, owner };
}

const listed = async (id: string, cookie = org.cookie) => (await h.api(`${base()}/${id}/certificates`, { cookie })).body.items as any[];
const facts = (id: string, certificateId: string, cookie = org.cookie, orgId = org.orgId) => h.api(`${base(orgId)}/${id}/certificates/${certificateId}`, { cookie });

describe("a Certificate's facts", () => {
  test("an Owner sees its subject names, issuer, serial, signature algorithm, chain, and the CA and ACME Account that issued it", async () => {
    const mc = await setup();
    const [listItem] = await listed(mc.id, mc.owner);
    const account = (await h.api(`/api/organizations/${org.orgId}/acme-accounts`, { cookie: org.cookie })).body.items[0];

    const res = await facts(mc.id, listItem.id, mc.owner);

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      id: listItem.id,
      fingerprint: listItem.fingerprint,
      serial: listItem.serial,
      names: expect.arrayContaining(mc.names),
      // Pebble, like Let's Encrypt's short-lived profile, puts the names only in the subject alternative names.
      subject: "",
      issuer: expect.stringMatching(/^CN=Pebble Intermediate CA [0-9a-f]+$/),
      signatureAlgorithm: "ECDSA with SHA-256",
      ca: "lets-encrypt",
      acmeAccount: { id: account.id, acmeCaId: "letsencrypt-staging" },
      revocation: null,
    });
    expect(res.body.serial).toMatch(/^[0-9A-F]+$/);
    // The leaf, then the intermediate it was signed by.
    expect(res.body.chain).toHaveLength(2);
    expect(res.body.chain[0]).toMatchObject({ subject: res.body.subject, issuer: res.body.issuer, serial: res.body.serial, fingerprint: res.body.fingerprint });
    expect(res.body.chain[1]).toMatchObject({ subject: res.body.issuer, issuer: expect.stringMatching(/^CN=Pebble Root CA [0-9a-f]+$/) });
    expect(res.body.chain[1].fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  test("an earlier Certificate has its own facts, and a revoked one shows who revoked it, when and why", async () => {
    const mc = await setup();
    expect((await h.api(`${base()}/${mc.id}/renewals`, { cookie: org.cookie, body: {} })).status).toBe(202);
    await h.settleIssuances();
    const [newest, first] = await listed(mc.id);
    h.setNow(new Date("2026-01-02T00:00:00Z"));
    expect((await h.api(`${base()}/${mc.id}/certificates/${first.id}/revocation`, { cookie: mc.owner, body: { reason: "superseded" } })).status).toBe(200);

    const earlier = await facts(mc.id, first.id, mc.owner);
    const current = await facts(mc.id, newest.id, mc.owner);

    expect(earlier.status).toBe(200);
    expect(earlier.body).toMatchObject({ id: first.id, serial: first.serial, revocation: { reason: "superseded", revokedAt: "2026-01-02T00:00:00.000Z", revokedBy: { email: "owner@acme.test" } } });
    expect(earlier.body.chain[0].serial).toBe(first.serial);
    expect(current.body).toMatchObject({ id: newest.id, serial: newest.serial, revocation: null });
    expect(current.body.serial).not.toBe(earlier.body.serial);
  });
});

describe("who may see a Certificate's facts", () => {
  test("whoever may see the Managed Certificate: its Owner, an Approver and an Organization Administrator", async () => {
    const mc = await setup();
    const approver = await join("approver@acme.test", "approver");
    const [{ id: certificateId }] = await listed(mc.id);

    for (const cookie of [mc.owner, approver, org.cookie]) expect((await facts(mc.id, certificateId, cookie)).status).toBe(200);
  });

  test("a Member who may not see the Managed Certificate is refused as for the Managed Certificate itself, and another Organization does not find it", async () => {
    const mc = await setup();
    const stranger = await join("stranger@acme.test", "member");
    const [{ id: certificateId }] = await listed(mc.id);

    // As `GET …/managed-certificates/:id` answers them; the web shows both as "not found".
    expect((await facts(mc.id, certificateId, stranger)).status).toBe(403);
    expect((await h.api(`${base()}/${mc.id}`, { cookie: stranger })).status).toBe(403);
    expect((await facts(mc.id, certificateId, globex.cookie)).status).toBe(404);
    expect((await facts(mc.id, certificateId, globex.cookie, globex.orgId)).status).toBe(404);
  });

  test("a Certificate of another Managed Certificate, or no Certificate at all, is not found", async () => {
    const mc = await setup();
    const other = await h.api(base(), { cookie: org.cookie, body: await request() });
    await h.settleIssuances();
    const [{ id: othersCertificate }] = await listed(other.body.id);

    for (const certificateId of [othersCertificate, crypto.randomUUID(), "not-a-uuid"]) {
      const res = await facts(mc.id, certificateId, mc.owner);
      expect(res.status).toBe(404);
      expect(res.body.error).toBe("Certificate not found");
    }
  });
});

