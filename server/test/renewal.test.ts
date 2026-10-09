// Renewal: a Managed Certificate's Renewal Policy (automatic or manual, and how many days before expiry), the scheduler
// that renews automatic ones when due with the stored CSR, "renew now", new CSRs from Owners, and failed Renewals that
// are retried with backoff. Certificates are issued by Pebble for real; time is the harness's clock.
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { Pkcs10CertificateRequest } from "@peculiar/x509";
import acme from "acme-client";
import { X509Certificate, randomBytes } from "node:crypto";
import { BIND, PASSWORD, createHarness, type Harness } from "./harness";

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

const DAY = 86_400_000;
const base = (orgId = org.orgId) => `/api/organizations/${orgId}/managed-certificates`;
const auditOf = async (orgId = org.orgId, cookie = org.cookie) =>
  (await h.api(`/api/organizations/${orgId}/audit-events`, { cookie })).body.items as { action: string; actor: any; target: any; detail: any }[];

const host = () => `t${randomBytes(5).toString("hex")}.${BIND.zone}`;
async function request(names = [host()], keyAlgorithm: "ecdsa-p256" | "ecdsa-p384" | "rsa-2048" = "ecdsa-p256") {
  const key = await (keyAlgorithm === "ecdsa-p256" ? acme.crypto.createPrivateEcdsaKey("P-256") : keyAlgorithm === "ecdsa-p384" ? acme.crypto.createPrivateEcdsaKey("P-384") : acme.crypto.createPrivateRsaKey(2048));
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return { names, keyAlgorithm, csr: csr.toString() };
}

async function join(email: string, role: string, target = org) {
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: target.cookie, body: { email, role, organizationId: target.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}
const userId = async (cookie: string) => (await h.api("/api/me", { cookie })).body.user.id as string;

async function readyToIssue(target = org) {
  expect((await h.api(`/api/organizations/${target.orgId}/acme-accounts`, { cookie: target.cookie, body: { termsOfServiceAgreed: true } })).status).toBe(201);
  expect(
    (
      await h.api(`/api/organizations/${target.orgId}/dns-providers`, {
        cookie: target.cookie,
        body: { name: "BIND", type: "rfc2136", settings: { server: BIND.server, port: BIND.port, zone: BIND.zone, keyName: BIND.keyName }, secret: BIND.keySecret },
      })
    ).status,
  ).toBe(201);
}

/**
 * How many days before its Certificate ends a Managed Certificate is due, in these tests. Pebble dates Certificates by the
 * real time and for however long its profile says (days or weeks), so the tests ask for a few days to be sure they are
 * inside any Certificate's life.
 */
const DUE_DAYS = 2;

/** A Managed Certificate whose first Certificate is issued, due `DUE_DAYS` before it ends; `body` is what was submitted, so its CSR is known. */
async function issued(opts: { owners?: { type: string; id: string }[]; target?: { orgId: string; cookie: string }; days?: number | null } = {}) {
  const target = opts.target ?? org;
  const body = await request();
  const created = await h.api(base(target.orgId), { cookie: target.cookie, body: { ...body, owners: opts.owners ?? [] } });
  expect(created.status).toBe(201);
  await h.settleIssuances();
  if (opts.days !== null) {
    const policy = await h.api(`${base(target.orgId)}/${created.body.id}/renewal-policy`, { cookie: target.cookie, method: "PUT", body: { mode: "automatic", daysBeforeExpiry: opts.days ?? DUE_DAYS } });
    expect(policy.status).toBe(200);
  }
  return { id: created.body.id as string, body };
}

const get = async (id: string, cookie = org.cookie, orgId = org.orgId) => {
  const res = await h.api(`${base(orgId)}/${id}`, { cookie });
  expect(res.status).toBe(200);
  return res.body;
};
const certificates = async (id: string, cookie = org.cookie, orgId = org.orgId) => (await h.api(`${base(orgId)}/${id}/certificates`, { cookie })).body.items as { id: string; notAfter: string; notBefore: string; fingerprint: string }[];
const setPolicy = (id: string, body: unknown, cookie = org.cookie, orgId = org.orgId) => h.api(`${base(orgId)}/${id}/renewal-policy`, { cookie, method: "PUT", body });
const renewNow = (id: string, cookie = org.cookie, orgId = org.orgId) => h.api(`${base(orgId)}/${id}/renewals`, { cookie, method: "POST", body: {} });
const uploadCsr = (id: string, csr: string, cookie = org.cookie, orgId = org.orgId) => h.api(`${base(orgId)}/${id}/csr`, { cookie, method: "POST", body: { csr } });

/** The moment `days` before the current Certificate ends. */
const daysBeforeExpiry = async (id: string, days: number, target = { cookie: org.cookie, orgId: org.orgId }) => new Date(Date.parse((await get(id, target.cookie, target.orgId)).currentCertificate.notAfter) - days * DAY);
const due = (id: string) => daysBeforeExpiry(id, DUE_DAYS);
const leafKey = (pem: string) => new X509Certificate(pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/)![0]).publicKey.export({ type: "spki", format: "der" });
const csrKey = (csr: string) => Buffer.from(new Pkcs10CertificateRequest(csr).publicKey.rawData);
const downloaded = async (id: string) => (await h.app.request(`http://localhost${base()}/${id}/certificate`, { headers: { cookie: org.cookie } })).text();

/** One pass of the scheduler, and the Renewals it started run to their end. */
async function schedule() {
  const started = await h.runRenewalScheduler();
  await h.settleIssuances();
  return started;
}

describe("Renewal Policy", () => {
  test("a new Managed Certificate renews automatically 30 days before its Certificate ends", async () => {
    await readyToIssue();
    const { id } = await issued({ days: null });
    const mc = await get(id);
    expect(mc.renewal.policy).toEqual({ mode: "automatic", daysBeforeExpiry: 30 });
    // Due somewhere in the life of its Certificate (how far depends on how long the CA's Certificates live).
    expect(Date.parse(mc.renewal.dueAt)).toBeGreaterThan(Date.parse(mc.currentCertificate.notBefore));
    expect(Date.parse(mc.renewal.dueAt)).toBeLessThan(Date.parse(mc.currentCertificate.notAfter));
    expect(mc.renewal.failing).toBeNull();
  });

  test("an Organization Administrator sets it, and the change is audited", async () => {
    await readyToIssue();
    const { id } = await issued({ days: null });
    const changed = await setPolicy(id, { mode: "automatic", daysBeforeExpiry: 3 });
    expect(changed.status).toBe(200);
    expect(changed.body.renewal.policy).toEqual({ mode: "automatic", daysBeforeExpiry: 3 });
    expect(changed.body.renewal.dueAt).toBe((await daysBeforeExpiry(id, 3)).toISOString());

    const manual = await setPolicy(id, { mode: "manual", daysBeforeExpiry: 3 });
    expect(manual.body.renewal.policy.mode).toBe("manual");
    // A manual Managed Certificate has no due time: nothing renews it but a person.
    expect(manual.body.renewal.dueAt).toBeNull();

    const events = (await auditOf()).filter((e) => e.action === "managed_certificate.renewal_policy_changed");
    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({
      actor: { email: "admin@acme.test" },
      target: { type: "managed_certificate", id },
      detail: { from: { mode: "automatic", daysBeforeExpiry: 30 }, to: { mode: "automatic", daysBeforeExpiry: 3 } },
    });
    expect(events[1]!.detail).toEqual({ from: { mode: "automatic", daysBeforeExpiry: 3 }, to: { mode: "manual", daysBeforeExpiry: 3 } });
  });

  test("an Owner may set it, whatever their role; nobody else but an Organization Administrator", async () => {
    await readyToIssue();
    const owner = await join("owner@acme.test", "member");
    const bystander = await join("bystander@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");
    const { id } = await issued({ days: null, owners: [{ type: "user", id: await userId(owner) }] });

    expect((await setPolicy(id, { mode: "manual", daysBeforeExpiry: 20 }, owner)).status).toBe(200);
    // A Member who does not own it cannot even see it; an Approver sees it but may not change it.
    expect((await setPolicy(id, { mode: "automatic", daysBeforeExpiry: 5 }, bystander)).status).toBe(403);
    expect((await setPolicy(id, { mode: "automatic", daysBeforeExpiry: 5 }, approver)).status).toBe(403);
    expect((await get(id)).renewal.policy).toEqual({ mode: "manual", daysBeforeExpiry: 20 });
  });

  test("the days must be a whole number of at least one", async () => {
    await readyToIssue();
    const { id } = await issued({ days: null });
    for (const daysBeforeExpiry of [0, -3, 1.5, 366, "soon"]) {
      expect((await setPolicy(id, { mode: "automatic", daysBeforeExpiry })).status).toBe(400);
    }
    expect((await setPolicy(id, { mode: "sometimes", daysBeforeExpiry: 10 })).status).toBe(400);
    expect((await get(id)).renewal.policy).toEqual({ mode: "automatic", daysBeforeExpiry: 30 });
  });

  test("another Organization's Managed Certificate is not found", async () => {
    await readyToIssue();
    const { id } = await issued({ days: null });
    expect((await setPolicy(id, { mode: "manual", daysBeforeExpiry: 10 }, globex.cookie, org.orgId)).status).toBe(404);
    expect((await setPolicy(id, { mode: "manual", daysBeforeExpiry: 10 }, globex.cookie, globex.orgId)).status).toBe(404);
  });
});

describe("automatic Renewal", () => {
  test("is done by the scheduler once the configured days before expiry are reached, with the stored CSR", async () => {
    await readyToIssue();
    const { id, body } = await issued();
    const first = (await get(id)).currentCertificate;

    h.setNow(await daysBeforeExpiry(id, DUE_DAYS + 1));
    expect(await schedule()).toBe(0);
    expect(await certificates(id)).toHaveLength(1);

    h.setNow(await due(id));
    expect(await schedule()).toBe(1);
    const mc = await get(id);
    expect(mc.issuance).toMatchObject({ status: "succeeded", failure: null });
    expect(mc.currentCertificate.fingerprint).not.toBe(first.fingerprint);
    expect(await certificates(id)).toHaveLength(2);
    // The Owner's CSR was reused: the new Certificate is for the same key and names.
    expect(leafKey(await downloaded(id))).toEqual(csrKey(body.csr));
    expect(mc.currentCertificate.names).toEqual(body.names);

    expect(mc.renewal.failing).toBeNull();

    // The new Certificate is not due until its own time: as of now it is not, and as of then it is.
    h.setNow(new Date());
    expect(await schedule()).toBe(0);
    expect(await certificates(id)).toHaveLength(2);
    h.setNow(new Date(mc.renewal.dueAt));
    expect(await schedule()).toBe(1);
    expect(await certificates(id)).toHaveLength(3);
  });

  test("follows the days the Renewal Policy gives", async () => {
    await readyToIssue();
    const { id } = await issued();
    await setPolicy(id, { mode: "automatic", daysBeforeExpiry: 4 });
    h.setNow(await daysBeforeExpiry(id, 5));
    expect(await schedule()).toBe(0);
    h.setNow(await daysBeforeExpiry(id, 4));
    expect(await schedule()).toBe(1);
    expect(await certificates(id)).toHaveLength(2);
  });

  test("a policy longer than the Certificate lives cannot make it due at once", async () => {
    await readyToIssue();
    const { id } = await issued();
    const changed = await setPolicy(id, { mode: "automatic", daysBeforeExpiry: 365 });
    const [current] = await certificates(id);
    const lived = Date.parse(current!.notAfter) - Date.parse(current!.notBefore);
    // However many days are asked for, the first tenth of a Certificate's life is never "due".
    expect(Date.parse(changed.body.renewal.dueAt)).toBeGreaterThanOrEqual(Date.parse(current!.notBefore) + lived / 10);
    h.setNow(new Date(Date.parse(current!.notBefore) + lived / 20));
    expect(await schedule()).toBe(0);
    h.setNow(new Date(Date.parse(current!.notBefore) + lived / 10 + 1000));
    expect(await schedule()).toBe(1);
  });

  test("starts one Renewal when two passes of the scheduler run at once", async () => {
    await readyToIssue();
    const { id } = await issued();
    h.setNow(await due(id));
    const started = await Promise.all([h.runRenewalScheduler(), h.runRenewalScheduler()]);
    await h.settleIssuances();
    expect(started.reduce((a, b) => a + b, 0)).toBe(1);
    expect(await certificates(id)).toHaveLength(2);
  });

  test("renews every Organization's Managed Certificates, each through its own account", async () => {
    await readyToIssue();
    await readyToIssue(globex);
    const mine = await issued();
    const theirs = await issued({ target: globex });
    const theirDue = await daysBeforeExpiry(theirs.id, DUE_DAYS, globex);
    h.setNow(new Date(Math.max(+(await due(mine.id)), +theirDue)));
    expect(await schedule()).toBe(2);
    const globexCert = (await get(theirs.id, globex.cookie, globex.orgId)).currentCertificate;
    expect(globexCert.acmeAccountId).not.toBe((await get(mine.id)).currentCertificate.acmeAccountId);
    expect((await certificates(theirs.id, globex.cookie, globex.orgId)).length).toBe(2);
  });

  test("a Renewal is audited, attributed to no one, and says it was scheduled", async () => {
    await readyToIssue();
    const { id } = await issued();
    h.setNow(await due(id));
    await schedule();
    const events = (await auditOf()).filter((e) => e.target.id === id).slice(-2);
    expect(events.map((e) => e.action)).toEqual(["issuance.started", "issuance.succeeded"]);
    expect(events[0]).toMatchObject({ actor: { id: null, email: null }, detail: { renewal: "scheduled" } });
    expect(events[1]!.actor).toEqual({ id: null, email: null });
  });
});

describe("manual Renewal", () => {
  test("the scheduler never renews a manual Managed Certificate, however late", async () => {
    await readyToIssue();
    const { id } = await issued();
    await setPolicy(id, { mode: "manual", daysBeforeExpiry: 30 });
    h.setNow(new Date(Date.parse((await get(id)).currentCertificate.notAfter) + 5 * DAY));
    expect(await schedule()).toBe(0);
    expect(await certificates(id)).toHaveLength(1);
  });

  test("an Organization Administrator starts one with renew now", async () => {
    await readyToIssue();
    const { id, body } = await issued();
    await setPolicy(id, { mode: "manual", daysBeforeExpiry: 30 });
    const started = await renewNow(id);
    expect(started.status).toBe(202);
    expect(started.body).toMatchObject({ status: "running" });
    await h.settleIssuances();
    expect(await certificates(id)).toHaveLength(2);
    expect(leafKey(await downloaded(id))).toEqual(csrKey(body.csr));
    const events = (await auditOf()).filter((e) => e.target.id === id && e.action === "issuance.started");
    expect(events.at(-1)).toMatchObject({ actor: { email: "admin@acme.test" }, detail: { renewal: "requested" } });
  });

  test("an Owner may renew now, before it is due; a Member who does not own it, and an Approver, may not", async () => {
    await readyToIssue();
    const owner = await join("owner@acme.test", "member");
    const bystander = await join("bystander@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");
    const { id } = await issued({ owners: [{ type: "user", id: await userId(owner) }] });

    expect((await renewNow(id, bystander)).status).toBe(403);
    expect((await renewNow(id, approver)).status).toBe(403);
    await h.settleIssuances();
    expect(await certificates(id)).toHaveLength(1);

    expect((await renewNow(id, owner)).status).toBe(202);
    await h.settleIssuances();
    expect(await certificates(id)).toHaveLength(2);
    expect(((await auditOf()).filter((e) => e.action === "issuance.started").at(-1))!.actor.email).toBe("owner@acme.test");
  });

  test("an Owner through a Team may renew now", async () => {
    await readyToIssue();
    const member = await join("teammate@acme.test", "member");
    const team = await h.api("/api/auth/organization/create-team", { cookie: org.cookie, body: { name: "Web", organizationId: org.orgId } });
    expect((await h.api("/api/auth/organization/add-team-member", { cookie: org.cookie, body: { teamId: team.body.id, userId: await userId(member), organizationId: org.orgId } })).status).toBe(200);
    const { id } = await issued({ owners: [{ type: "team", id: team.body.id }] });
    expect((await renewNow(id, member)).status).toBe(202);
    await h.settleIssuances();
    expect(await certificates(id)).toHaveLength(2);
  });

  test("only one Renewal runs at a time", async () => {
    await readyToIssue();
    const { id } = await issued();
    const [a, b] = await Promise.all([renewNow(id), renewNow(id)]);
    expect([a.status, b.status].sort()).toEqual([202, 409]);
    await h.settleIssuances();
    expect(await certificates(id)).toHaveLength(2);
  });

  test("there is nothing to renew until a first Certificate exists", async () => {
    await readyToIssue();
    h.caDirectories.staging = "https://localhost:1/dir";
    const created = await h.api(base(), { cookie: org.cookie, body: await request() });
    await h.settleIssuances();
    const refused = await renewNow(created.body.id);
    expect(refused.status).toBe(409);
    expect(refused.body.error).toContain("no Certificate");
    // And a Managed Certificate without one has nothing to be due.
    expect((await get(created.body.id)).renewal).toMatchObject({ dueAt: null, failing: null });
  });
});

describe("a new CSR", () => {
  test("an Owner uploads one for the same algorithm and names, and the next Renewal uses it", async () => {
    await readyToIssue();
    const owner = await join("owner@acme.test", "member");
    const { id, body } = await issued({ owners: [{ type: "user", id: await userId(owner) }] });
    const replacement = await request(body.names);

    const uploaded = await uploadCsr(id, replacement.csr, owner);
    expect(uploaded.status).toBe(200);
    // It changes nothing until a Renewal: the current Certificate is still for the old key.
    expect(await certificates(id)).toHaveLength(1);
    expect(leafKey(await downloaded(id))).toEqual(csrKey(body.csr));

    h.setNow(await due(id));
    expect(await schedule()).toBe(1);
    expect(leafKey(await downloaded(id))).toEqual(csrKey(replacement.csr));
    // And the one after it keeps using the new CSR.
    expect((await renewNow(id)).status).toBe(202);
    await h.settleIssuances();
    expect(leafKey(await downloaded(id))).toEqual(csrKey(replacement.csr));
    expect(await certificates(id)).toHaveLength(3);
  });

  test("is refused when its key algorithm or its names differ, or it is not a CSR", async () => {
    await readyToIssue();
    const { id, body } = await issued();
    const otherAlgorithm = await request(body.names, "ecdsa-p384");
    const refusedAlgorithm = await uploadCsr(id, otherAlgorithm.csr);
    expect(refusedAlgorithm.status).toBe(422);
    expect(refusedAlgorithm.body.error).toContain("ecdsa-p384");

    const otherNames = await request([...body.names, host()]);
    const refusedNames = await uploadCsr(id, otherNames.csr);
    expect(refusedNames.status).toBe(422);
    expect(refusedNames.body.error).toContain(body.names[0]);

    expect((await uploadCsr(id, "not a csr")).status).toBe(400);

    // None of them was kept: a Renewal still uses the first CSR.
    expect((await renewNow(id)).status).toBe(202);
    await h.settleIssuances();
    expect(leafKey(await downloaded(id))).toEqual(csrKey(body.csr));
    expect((await auditOf()).filter((e) => e.action === "managed_certificate.csr_uploaded")).toEqual([]);
  });

  test("a Member who does not own it, and an Approver, may not upload one; another Organization finds nothing", async () => {
    await readyToIssue();
    const bystander = await join("bystander@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");
    const { id, body } = await issued();
    const replacement = await request(body.names);
    expect((await uploadCsr(id, replacement.csr, bystander)).status).toBe(403);
    expect((await uploadCsr(id, replacement.csr, approver)).status).toBe(403);
    expect((await uploadCsr(id, replacement.csr, globex.cookie, org.orgId)).status).toBe(404);
  });

  test("is audited with the CSR's fingerprint, never the CSR", async () => {
    await readyToIssue();
    const { id, body } = await issued();
    const replacement = await request(body.names);
    h.setNow(new Date("2026-03-01T10:00:00Z"));
    await uploadCsr(id, replacement.csr);
    const events = (await auditOf()).filter((e) => e.action === "managed_certificate.csr_uploaded");
    expect(events).toHaveLength(1);
    const { csrFingerprint, previousCsrFingerprint } = events[0]!.detail;
    expect(csrFingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(previousCsrFingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(csrFingerprint).not.toBe(previousCsrFingerprint);
    expect(events[0]).toMatchObject({ actor: { email: "admin@acme.test" }, target: { type: "managed_certificate", id } });
    expect(JSON.stringify(events)).not.toContain("CERTIFICATE REQUEST");
  });
});

describe("failed Renewals", () => {
  const renewalFailing = async (cookie = org.cookie, orgId = org.orgId) =>
    ((await h.api(`${base(orgId)}?renewalFailing=true`, { cookie })).body.items as { id: string }[]).map((m) => m.id);

  test("are retried with a growing backoff, shown in the inventory, and heal when the cause goes", async () => {
    await readyToIssue();
    const { id } = await issued();
    const dueAt = await due(id);
    h.setNow(dueAt);
    h.caDirectories.staging = "https://localhost:1/dir";

    expect(await schedule()).toBe(1);
    let mc = await get(id);
    expect(mc.issuance).toMatchObject({ status: "failed", failure: { code: "ca_unreachable" } });
    // Still the old Certificate, and now visibly failing, with when the next attempt is.
    // (Read before matching: a matcher with `expect.any` leaves the matcher where the value was.)
    const firstRetry = Date.parse(mc.renewal.failing.nextAttemptAt);
    expect(mc.renewal.failing).toMatchObject({ failures: 1, lastFailure: { code: "ca_unreachable", at: dueAt.toISOString() } });
    expect(firstRetry).toBeGreaterThan(dueAt.getTime());
    expect(await renewalFailing()).toEqual([id]);

    // Nothing happens before the backoff has passed...
    h.setNow(new Date(firstRetry - 1000));
    expect(await schedule()).toBe(0);
    expect((await get(id)).renewal.failing.failures).toBe(1);

    // ...and then it is tried again, and waits longer.
    h.setNow(new Date(firstRetry));
    expect(await schedule()).toBe(1);
    mc = await get(id);
    expect(mc.renewal.failing).toMatchObject({ failures: 2 });
    const secondRetry = Date.parse(mc.renewal.failing.nextAttemptAt);
    expect(secondRetry - firstRetry).toBeGreaterThan(firstRetry - dueAt.getTime());

    // The cause goes away: the next attempt renews, and the failure state clears.
    h.caDirectories.staging = h.caDirectories.production;
    h.setNow(new Date(secondRetry));
    expect(await schedule()).toBe(1);
    mc = await get(id);
    expect(mc.issuance.status).toBe("succeeded");
    expect(mc.renewal.failing).toBeNull();
    expect(await certificates(id)).toHaveLength(2);
    expect(await renewalFailing()).toEqual([]);
    const events = (await auditOf()).filter((e) => e.target.id === id).map((e) => e.action);
    expect(events.slice(-6)).toEqual(["issuance.started", "issuance.failed", "issuance.started", "issuance.failed", "issuance.started", "issuance.succeeded"]);
  });

  test("the backoff stops growing at a ceiling", async () => {
    await readyToIssue();
    const { id } = await issued();
    h.setNow(await due(id));
    h.caDirectories.staging = "https://localhost:1/dir";
    let waits: number[] = [];
    for (let i = 0; i < 12; i++) {
      await schedule();
      const failing = (await get(id)).renewal.failing;
      expect(failing.failures).toBe(i + 1);
      const next = Date.parse(failing.nextAttemptAt);
      waits.push(next - Date.parse(failing.lastFailure.at));
      h.setNow(new Date(next));
    }
    expect(waits[1]).toBeGreaterThan(waits[0]!);
    expect(waits.at(-1)).toBe(waits.at(-2)!);
    expect(waits.at(-1)).toBeLessThanOrEqual(DAY);
  });

  test("a manual Managed Certificate whose Renewal failed is failing too, but is never retried", async () => {
    await readyToIssue();
    const { id } = await issued();
    await setPolicy(id, { mode: "manual", daysBeforeExpiry: 30 });
    h.caDirectories.staging = "https://localhost:1/dir";
    expect((await renewNow(id)).status).toBe(202);
    await h.settleIssuances();
    const mc = await get(id);
    expect(mc.renewal.failing).toMatchObject({ failures: 1, lastFailure: { code: "ca_unreachable" }, nextAttemptAt: null });
    expect(await renewalFailing()).toEqual([id]);
    h.setNow(new Date(Date.parse(mc.currentCertificate.notAfter) + DAY));
    expect(await schedule()).toBe(0);
  });

  test("a failed first Issuance is not a failing Renewal", async () => {
    await readyToIssue();
    h.caDirectories.staging = "https://localhost:1/dir";
    const created = await h.api(base(), { cookie: org.cookie, body: await request() });
    await h.settleIssuances();
    expect((await get(created.body.id)).issuance.status).toBe("failed");
    expect(await renewalFailing()).toEqual([]);
    // The scheduler has nothing to renew for it, and does not try.
    h.setNow(new Date("2031-01-01T00:00:00Z"));
    expect(await schedule()).toBe(0);
  });

  test("a failing Renewal of one Organization is not listed for another", async () => {
    await readyToIssue();
    await readyToIssue(globex);
    const { id } = await issued();
    // Only the first is due: Pebble may date both Certificates within the same second.
    const other = await issued({ target: globex });
    await setPolicy(other.id, { mode: "manual", daysBeforeExpiry: 30 }, globex.cookie, globex.orgId);
    h.setNow(await due(id));
    h.caDirectories.staging = "https://localhost:1/dir";
    await schedule();
    expect(await renewalFailing()).toEqual([id]);
    expect(await renewalFailing(globex.cookie, globex.orgId)).toEqual([]);
  });
});
