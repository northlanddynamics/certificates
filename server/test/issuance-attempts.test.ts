// A Managed Certificate's Issuance attempts, as its Activity shows them: each attempt's time, kind (its first issue, a
// Renewal or a Name Change), status and failure, newest first, so a failure that a retry cleared can still be explained.
// No ACME account is set up, so every attempt ends at once as failed (no_acme_account); a Certificate it already has is
// written to the database, as an Issuance against a CA would leave it.
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import acme from "acme-client";
import { randomBytes } from "node:crypto";
import { acmeAccount, certificate, secret } from "../src/db/schema";
import { PASSWORD, createHarness, type Harness } from "./harness";

setDefaultTimeout(60_000);

let h: Harness;
let org: { orgId: string; cookie: string };
let globex: { orgId: string; cookie: string };

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  const operator = await h.createOperator("op@platform.test", PASSWORD);
  org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
  globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
});
afterAll(async () => {
  await h.close();
});

const base = (orgId = org.orgId) => `/api/organizations/${orgId}/managed-certificates`;
const attempts = (id: string, cookie = org.cookie, orgId = org.orgId) => h.api(`${base(orgId)}/${id}/issuances`, { cookie });

async function request(names: string[]) {
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() };
}

/** An Organization Administrator creates a Managed Certificate at the time given; its first Issuance fails. */
async function adminCreates(at: Date, names = ["a.example.test"]) {
  h.setNow(at);
  const res = await h.api(base(), { cookie: org.cookie, body: await request(names) });
  expect(res.status).toBe(201);
  await h.settleIssuances();
  return res.body as { id: string };
}

/** The Certificate an Issuance against a CA would have stored for the Managed Certificate. */
async function issuedFor(managedCertificateId: string, names: string[], at: Date) {
  const [secretRow] = await h.db.insert(secret).values({ organizationId: org.orgId, ciphertext: Buffer.from("not-a-secret") }).returning();
  // For production, so the Managed Certificate's staging Issuances still find no ACME account and fail.
  const [account] = await h.db
    .insert(acmeAccount)
    .values({ organizationId: org.orgId, environment: "production", accountUrl: "https://acme.test/acct/1", secretId: secretRow!.id })
    .returning();
  await h.db.insert(certificate).values({
    organizationId: org.orgId,
    managedCertificateId,
    fingerprint: randomBytes(32).toString("hex"),
    serial: "01",
    notBefore: at,
    notAfter: new Date(at.getTime() + 90 * 86_400_000),
    names,
    chainPem: "not-a-chain",
    ca: "pebble",
    environment: "staging",
    acmeAccountId: account!.id,
    issuedAt: at,
  });
}

async function join(email: string, role: string) {
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}

const NO_ACME_ACCOUNT = { code: "no_acme_account", message: expect.stringContaining("no staging ACME account") };

describe("Issuance attempts", () => {
  test("each attempt with its time, kind, status and failure, newest first: a first issue tried again, a Renewal and a Name Change", async () => {
    const mc = await adminCreates(new Date("2026-03-01T10:00:00Z"));

    h.setNow(new Date("2026-03-01T11:00:00Z"));
    expect((await h.api(`${base()}/${mc.id}/issuances`, { cookie: org.cookie, method: "POST" })).status).toBe(202);
    await h.settleIssuances();

    await issuedFor(mc.id, ["a.example.test"], new Date("2026-03-02T00:00:00Z"));
    h.setNow(new Date("2026-03-03T09:00:00Z"));
    expect((await h.api(`${base()}/${mc.id}/renewals`, { cookie: org.cookie, method: "POST" })).status).toBe(202);
    await h.settleIssuances();

    h.setNow(new Date("2026-03-04T09:00:00Z"));
    expect((await h.api(`${base()}/${mc.id}/name-change`, { cookie: org.cookie, body: await request(["a.example.test", "b.example.test"]) })).status).toBe(201);
    await h.settleIssuances();

    const res = await attempts(mc.id);
    expect(res.status).toBe(200);
    expect(res.body.items).toEqual([
      expect.objectContaining({ kind: "name_change", status: "failed", startedAt: "2026-03-04T09:00:00.000Z", failure: NO_ACME_ACCOUNT, requestedBy: expect.objectContaining({ email: "admin@acme.test" }) }),
      expect.objectContaining({ kind: "renewal", status: "failed", startedAt: "2026-03-03T09:00:00.000Z", failure: NO_ACME_ACCOUNT }),
      expect.objectContaining({ kind: "first_issue", status: "failed", startedAt: "2026-03-01T11:00:00.000Z", finishedAt: "2026-03-01T11:00:00.000Z", failure: NO_ACME_ACCOUNT }),
      expect.objectContaining({ kind: "first_issue", status: "failed", startedAt: "2026-03-01T10:00:00.000Z", failure: NO_ACME_ACCOUNT }),
    ]);
  });

  test("a Managed Certificate that never had an attempt, a Proposal, has none", async () => {
    const member = await join("member@acme.test", "member");
    const proposed = await h.api(base(), { cookie: member, body: await request(["p.example.test"]) });
    expect(proposed.status).toBe(201);

    const res = await attempts(proposed.body.id, member);
    expect(res.status).toBe(200);
    expect(res.body.items).toEqual([]);
  });

  test("refused to a caller who may not see the Managed Certificate, as the Managed Certificate itself is, and not found in another Organization", async () => {
    const mc = await adminCreates(new Date("2026-03-01T10:00:00Z"));
    const member = await join("member@acme.test", "member");

    // A Member who does not own it is refused as for the Managed Certificate and its history; the page shows either as "not found".
    expect((await h.api(`${base()}/${mc.id}`, { cookie: member })).status).toBe(403);
    expect((await attempts(mc.id, member)).status).toBe(403);
    expect((await attempts(mc.id, globex.cookie)).status).toBe(404);
    expect((await attempts(mc.id, globex.cookie, globex.orgId)).status).toBe(404);
    expect((await attempts(crypto.randomUUID())).status).toBe(404);
  });
});
