// A disabled Certificate Profile stops Renewal: while it is disabled, no Managed Certificate made from it renews. The
// scheduler marks a due one as blocked and tells its Subscribers once; "Renew now" is refused; everything that does not
// issue keeps working; enabling the profile again lets it renew on the next pass. The CA is a Private CA of the
// platform's own, so no Pebble; time is the harness's clock.
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

const JAN_1 = Date.parse("2026-01-01T00:00:00Z");
const DAY = 86_400_000;
const days = (n: number) => new Date(JAN_1 + n * DAY);

const BA = "/api/auth/organization";
const base = () => `/api/organizations/${org.orgId}`;
const api = (path: string, opts: { cookie?: string; body?: unknown; method?: string } = {}) => h.api(`${base()}${path}`, { cookie: opts.cookie ?? org.cookie, body: opts.body, method: opts.method });
const disable = (id: string) => api(`/certificate-profiles/${id}/disable`, { body: {} });
const enable = (id: string) => api(`/certificate-profiles/${id}/enable`, { body: {} });
const read = async (id: string) => (await api(`/managed-certificates/${id}`)).body;
const blockedNotices = () => h.mailer.sent.filter((m) => /Renewal blocked/.test(m.subject));

async function join(email: string, role: string) {
  const invited = await h.api(`${BA}/invite-member`, { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api(`${BA}/accept-invitation`, { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}

/** A profile on a Private CA's Issuing CA, whose Certificates live 90 days and are due 30 days before they end. */
async function createProfile() {
  const ca = await api("/private-cas", {
    body: { name: "Internal", subject: "CN=Internal, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["internal.acme"] } },
  });
  expect(ca.status).toBe(201);
  const res = await api("/certificate-profiles", {
    body: { name: "Internal web", issuer: { kind: "private_ca", issuingCaId: ca.body.issuingCas[0].id }, allowedKeyAlgorithms: ["ecdsa-p256"], validityDays: 90 },
  });
  expect(res.status).toBe(201);
  return res.body.id as string;
}

async function request(names: string[]) {
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, await acme.crypto.createPrivateEcdsaKey("P-256"));
  return { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() };
}

/** A Managed Certificate made from the profile by `cookie` (an Organization Administrator's by default, created outright), issued on 1 January, with the admin subscribed. */
async function issuedFrom(profileId: string, cookie = org.cookie) {
  h.setNow(days(0));
  const created = await api("/managed-certificates", { cookie, body: { ...(await request(["www.internal.acme"])), profileId } });
  expect(created.status).toBe(201);
  if (created.body.approval.status === "pending") expect((await api(`/managed-certificates/${created.body.id}/approve`, { body: {} })).status).toBe(200);
  await h.settleIssuances();
  const me = (await h.api("/api/me", { cookie: org.cookie })).body.user.id as string;
  expect((await api(`/managed-certificates/${created.body.id}/subscribers`, { body: { type: "user", id: me } })).status).toBe(200);
  const mc = await read(created.body.id);
  expect(mc.issuance.status).toBe("succeeded");
  h.mailer.sent.length = 0;
  return mc.id as string;
}

describe("while its Certificate Profile is disabled, a due Managed Certificate", () => {
  test("is not renewed by the scheduler, shows as blocked, and its Subscribers are told once", async () => {
    const profile = await createProfile();
    const mc = await issuedFrom(profile);
    await disable(profile);

    // Not yet due: nothing is blocked.
    h.setNow(days(59));
    expect(await h.runRenewalScheduler()).toBe(0);
    expect((await read(mc)).renewal.blocked).toBeNull();
    await h.deliverNotices();
    expect(blockedNotices()).toEqual([]);

    h.setNow(days(60));
    expect(await h.runRenewalScheduler()).toBe(0);
    await h.settleIssuances();
    const blocked = await read(mc);
    expect(blocked.renewal.blocked).toEqual({ since: days(60).toISOString(), profile: { id: profile, name: "Internal web" } });
    expect(blocked.currentCertificate.notAfter).toBe(days(90).toISOString());
    expect(blocked.issuance.kind).toBe("first_issue");
    // The inventory reports it too.
    expect((await api("/managed-certificates")).body.items.find((m: any) => m.id === mc).renewal.blocked).not.toBeNull();

    await h.deliverNotices();
    expect(blockedNotices().map((m) => m.to)).toEqual(["admin@acme.test"]);
    expect(blockedNotices()[0]!.text).toMatch(/Certificate Profile Internal web, which is disabled/);

    // Further passes while it stays blocked tell nobody again.
    for (const at of [61, 62, 70]) {
      h.setNow(days(at));
      expect(await h.runRenewalScheduler()).toBe(0);
    }
    await h.deliverNotices();
    expect(blockedNotices()).toHaveLength(1);
    expect((await read(mc)).renewal.blocked.since).toBe(days(60).toISOString());
  });

  test("renews on the next pass once the profile is enabled, and is no longer blocked", async () => {
    const profile = await createProfile();
    const mc = await issuedFrom(profile);
    await disable(profile);
    h.setNow(days(60));
    await h.runRenewalScheduler();
    expect((await read(mc)).renewal.blocked).not.toBeNull();

    expect((await enable(profile)).status).toBe(200);
    expect((await read(mc)).renewal.blocked).toBeNull();
    h.setNow(days(61));
    expect(await h.runRenewalScheduler()).toBe(1);
    await h.settleIssuances();
    const renewed = await read(mc);
    expect(renewed.issuance).toMatchObject({ kind: "renewal", status: "succeeded" });
    expect(renewed.currentCertificate.notAfter).toBe(days(151).toISOString());

    // Blocked again by a second disabling, its Subscribers are told again.
    await h.deliverNotices();
    await disable(profile);
    h.mailer.sent.length = 0;
    h.setNow(days(121));
    await h.runRenewalScheduler();
    await h.deliverNotices();
    expect(blockedNotices()).toHaveLength(1);
  });

  test("'Renew now' is refused with 422 naming the profile, for Owners and Organization Administrators alike", async () => {
    const profile = await createProfile();
    const member = await join("member@acme.test", "member");
    const mc = await issuedFrom(profile, member);
    expect((await read(mc)).owners.map((o: any) => o.email)).toContain("member@acme.test");
    await disable(profile);
    for (const cookie of [member, org.cookie]) {
      const res = await api(`/managed-certificates/${mc}/renewals`, { cookie, body: {} });
      expect(res.status).toBe(422);
      expect(res.body.error).toMatch(/Certificate Profile Internal web is disabled/);
    }
  });

  test("keeps everything that does not issue: Renewal Policy, Owners, Subscribers, download, revocation and archive", async () => {
    const profile = await createProfile();
    const mc = await issuedFrom(profile);
    await disable(profile);
    h.setNow(days(60));
    await h.runRenewalScheduler();
    const team = (await h.api(`${BA}/create-team`, { cookie: org.cookie, body: { name: "Web", organizationId: org.orgId } })).body.id as string;

    expect((await api(`/managed-certificates/${mc}/renewal-policy`, { method: "PUT", body: { mode: "automatic", daysBeforeExpiry: 20 } })).status).toBe(200);
    expect((await api(`/managed-certificates/${mc}/owners`, { body: { type: "team", id: team } })).status).toBe(200);
    expect((await api(`/managed-certificates/${mc}/subscribers`, { body: { type: "team", id: team } })).status).toBe(200);
    const certificate = (await read(mc)).currentCertificate.id as string;
    const download = await h.app.request(`http://localhost${base()}/managed-certificates/${mc}/certificates/${certificate}/download?format=pem`, { headers: { cookie: org.cookie } });
    expect(download.status).toBe(200);
    expect((await api(`/managed-certificates/${mc}/certificates/${certificate}/revocation`, { body: { reason: "superseded" } })).status).toBe(200);
    expect((await api(`/managed-certificates/${mc}/archive`, { body: {} })).status).toBe(200);
  });

  test("the notice reaches webhook channels as the renewal.blocked event, naming the profile", async () => {
    const profile = await createProfile();
    const mc = await issuedFrom(profile);
    const channel = await api("/notification-channels", { body: { name: "SIEM", kind: "webhook", url: "https://hooks.example.test/T000/B000/s3cr3t" } });
    expect(channel.status).toBe(201);
    expect((await api(`/managed-certificates/${mc}/subscribers`, { body: { type: "channel", id: channel.body.id } })).status).toBe(200);
    await disable(profile);
    h.setNow(days(60));
    await h.runRenewalScheduler();
    await h.deliverNotices();
    expect(h.webhooks.sent.map((w) => w.body)).toEqual([
      expect.objectContaining({
        event: "renewal.blocked",
        managedCertificate: expect.objectContaining({ id: mc }),
        detail: { certificateProfile: { id: profile, name: "Internal web" }, dueAt: days(60).toISOString() },
        subject: "www.internal.acme: Renewal blocked",
      }),
    ]);
  });

  test("is no longer shown as blocked once it would not renew anyway: switched to manual, or archived", async () => {
    const profile = await createProfile();
    const manual = await issuedFrom(profile);
    const archived = await issuedFrom(profile);
    await disable(profile);
    h.setNow(days(60));
    await h.runRenewalScheduler();
    expect((await read(manual)).renewal.blocked).not.toBeNull();
    await api(`/managed-certificates/${manual}/renewal-policy`, { method: "PUT", body: { mode: "manual", daysBeforeExpiry: 30 } });
    await api(`/managed-certificates/${archived}/archive`, { body: {} });
    expect((await read(manual)).renewal.blocked).toBeNull();
    expect((await read(archived)).renewal.blocked).toBeNull();
  });

  test("expiry notices continue as usual", async () => {
    const profile = await createProfile();
    await issuedFrom(profile);
    await disable(profile);
    h.setNow(days(76));
    await h.runRenewalScheduler();
    await h.deliverNotices();
    expect(h.mailer.sent.map((m) => m.subject)).toEqual(expect.arrayContaining([expect.stringMatching(/Renewal blocked/), expect.stringMatching(/ends in 14 days/)]));
  });
});

test("reading a profile reports how many live Managed Certificates are linked to it", async () => {
  const profile = await createProfile();
  expect((await api(`/certificate-profiles/${profile}`)).body.linked).toBe(0);
  await issuedFrom(profile);
  const archived = await issuedFrom(profile);
  await issuedFrom(profile);
  expect((await api(`/managed-certificates/${archived}/archive`, { body: {} })).status).toBe(200);
  expect((await api(`/certificate-profiles/${profile}`)).body.linked).toBe(2);
});
