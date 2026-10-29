// The Dashboard: one answer for what needs doing across the Managed Certificates the caller sees. Its counts match the
// inventory's filters, it lists those needing someone now, and it shows when Certificates end in the weeks ahead and
// which CAs they come from. No Pebble: Certificates come from a Private CA, and an ACME one with no ACME Account fails.
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
  h.setNow(new Date(JAN_1));
  operator = await h.createOperator("op@platform.test", PASSWORD);
  org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
});
afterAll(async () => {
  await h.close();
});

const JAN_1 = Date.parse("2026-01-01T00:00:00Z");
const DAY = 86_400_000;

const api = (path: string, body?: unknown, cookie = org.cookie) => h.api(`/api/organizations/${org.orgId}${path}`, { cookie, body });
const dashboard = async (cookie = org.cookie) => {
  const res = await api("/dashboard", undefined, cookie);
  expect(res.status).toBe(200);
  return res.body;
};

async function join(email: string, role: string) {
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}

async function request(names: string[]) {
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() };
}

async function createCa() {
  const res = await api("/private-cas", { name: "Internal TLS", subject: "CN=Acme Internal TLS, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["internal.acme"] } });
  expect(res.status).toBe(201);
  return { id: res.body.id as string, issuingCaId: res.body.issuingCas[0].id as string };
}

/** A Managed Certificate on the Private CA, issued, valid for `validityDays`. */
async function issued(ca: { issuingCaId: string }, name: string, validityDays: number, renewalPolicy?: { mode: string; daysBeforeExpiry: number }) {
  const created = await api("/managed-certificates", { ...(await request([name])), issuer: { kind: "private_ca", issuingCaId: ca.issuingCaId }, validityDays, renewalPolicy });
  expect(created.status).toBe(201);
  await h.settleIssuances();
  return created.body as { id: string };
}

describe("the Dashboard", () => {
  test("counts as the inventory filters do, lists what needs attention, and shows the weeks ahead and the CAs", async () => {
    const ca = await createCa();
    // Ends in 20 days and renews itself: expiring soon, but nobody need do anything.
    await issued(ca, "auto.internal.acme", 20);
    // Ends in 25 days and only a person renews it, which they may now.
    const manual = await issued(ca, "manual.internal.acme", 25, { mode: "manual", daysBeforeExpiry: 30 });
    // Ends in 30 days too, but nobody need renew it for another 20.
    await issued(ca, "notyet.internal.acme", 30, { mode: "manual", daysBeforeExpiry: 10 });
    // Well clear of the outlook.
    const later = await issued(ca, "later.internal.acme", 200);
    // No ACME Account: its first Issuance fails.
    const failed = await api("/managed-certificates", await request(["never.example.test"]));
    expect(failed.status).toBe(201);
    await h.settleIssuances();
    const member = await join("member@acme.test", "member");
    expect((await api("/managed-certificates", { ...(await request(["proposed.internal.acme"])), issuer: { kind: "private_ca", issuingCaId: ca.issuingCaId } }, member)).status).toBe(201);

    const board = await dashboard();
    expect(board.counts).toEqual({ managed: 6, expiringSoon: 3, renewalFailing: 0, agentOffline: 0, pendingApproval: 1 });
    // The one never issued first, then the soonest to end.
    expect(board.attention.total).toBe(2);
    expect(board.attention.items.map((m: { id: string }) => m.id)).toEqual([failed.body.id, manual.id]);
    // Each count is what the inventory gives for the filter of the same name.
    expect((await api("/managed-certificates?expiringSoon=true")).body.total).toBe(board.counts.expiringSoon);

    expect(board.expiry).toHaveLength(13);
    expect(board.expiry[0].start).toBe(new Date(JAN_1).toISOString());
    expect(board.expiry[2]).toMatchObject({ automatic: 1, manual: 0 });
    expect(board.expiry[3]).toMatchObject({ automatic: 0, manual: 1 });
    expect(board.expiry[4]).toMatchObject({ automatic: 0, manual: 1 });
    expect(board.expiry.reduce((n: number, w: { automatic: number; manual: number }) => n + w.automatic + w.manual, 0)).toBe(3);

    expect(board.issuers).toEqual([
      { kind: "private_ca", id: ca.id, name: "Internal TLS", count: 5 },
      { kind: "acme", id: "letsencrypt-staging", name: null, count: 1 },
    ]);

    // Archived ones are left out of all of it.
    expect((await h.api(`/api/organizations/${org.orgId}/managed-certificates/${later.id}/archive`, { cookie: org.cookie, method: "POST", body: {} })).status).toBe(200);
    expect((await dashboard()).counts.managed).toBe(5);
  });

  test("lists a Certificate that has ended, however it renews", async () => {
    const ca = await createCa();
    const short = await issued(ca, "short.internal.acme", 5);
    expect((await dashboard()).attention.total).toBe(0);
    h.setNow(new Date(JAN_1 + 6 * DAY));
    const board = await dashboard();
    expect(board.attention.items.map((m: { id: string }) => m.id)).toEqual([short.id]);
    // Nothing ends ahead of now any more.
    expect(board.expiry.every((w: { automatic: number; manual: number }) => w.automatic + w.manual === 0)).toBe(true);
  });

  test("a Member's is of what they see: their own proposal, and nothing else", async () => {
    const ca = await createCa();
    await issued(ca, "admin.internal.acme", 20, { mode: "manual", daysBeforeExpiry: 10 });
    const member = await join("member@acme.test", "member");
    const proposed = await api("/managed-certificates", { ...(await request(["mine.internal.acme"])), issuer: { kind: "private_ca", issuingCaId: ca.issuingCaId } }, member);
    expect(proposed.status).toBe(201);

    const board = await dashboard(member);
    expect(board.counts).toEqual({ managed: 1, expiringSoon: 0, renewalFailing: 0, agentOffline: 0, pendingApproval: 1 });
    expect(board.attention).toEqual({ items: [], total: 0 });
    expect(board.issuers).toEqual([{ kind: "private_ca", id: ca.id, name: "Internal TLS", count: 1 }]);
  });

  test("is only for members of the Organization", async () => {
    const outsider = await h.signUp("outsider@else.test", PASSWORD);
    expect((await api("/dashboard", undefined, outsider)).status).toBe(404);
  });
});
