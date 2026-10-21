// Revocation and Archive: Owners and Organization Administrators revoke a Certificate with an RFC 5280 reason and the
// CA is told; only Organization Administrators archive a Managed Certificate, which stops its Renewal but keeps it, its
// Certificates and its history. Nothing revokes on its own. Certificates are issued, and revoked, by Pebble for real.
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

const DAY = 86_400_000;
const base = (orgId = org.orgId) => `/api/organizations/${orgId}/managed-certificates`;
const auditOf = async () => (await h.api(`/api/organizations/${org.orgId}/audit-events`, { cookie: org.cookie })).body.items as { action: string; actor: any; target: any; detail: any }[];

const host = () => `t${randomBytes(5).toString("hex")}.${BIND.zone}`;
async function request(names = [host()]) {
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return { names, keyAlgorithm: "ecdsa-p256" as const, csr: csr.toString() };
}
/** What an Owner submits with a name change: the names and a CSR for them. */
async function change(names: string[]) {
  const { csr } = await request(names);
  return { names, csr };
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

const get = async (id: string, cookie = org.cookie) => {
  const res = await h.api(`${base()}/${id}`, { cookie });
  expect(res.status).toBe(200);
  return res.body;
};
const certificates = async (id: string, cookie = org.cookie) => (await h.api(`${base()}/${id}/certificates`, { cookie })).body.items as { id: string; fingerprint: string; serial: string; notAfter: string; revocation: any }[];
/** The Managed Certificate's only Certificate. */
const only = async (id: string) => (await certificates(id))[0]!;
const inventory = async (query = "", cookie = org.cookie) => ((await h.api(`${base()}${query}`, { cookie })).body.items as { id: string }[]).map((m) => m.id);
const archive = (id: string, cookie = org.cookie) => h.api(`${base()}/${id}/archive`, { cookie, method: "POST", body: {} });
const revoke = (id: string, certificateId: string, body: unknown = { reason: "keyCompromise" }, cookie = org.cookie) =>
  h.api(`${base()}/${id}/certificates/${certificateId}/revocation`, { cookie, method: "POST", body });
/** The leaf of the current Certificate as downloaded. */
const leafOf = async (id: string) => (await (await h.app.request(`http://localhost${base()}/${id}/certificate?chain=leaf`, { headers: { cookie: org.cookie } })).text()).trim();
const setPolicy = (id: string, body: unknown) => h.api(`${base()}/${id}/renewal-policy`, { cookie: org.cookie, method: "PUT", body });

/** A Managed Certificate with its first Certificate issued, an Owner who is a Member, and an Approver. */
async function setup() {
  await readyToIssue();
  const owner = await join("owner@acme.test", "member");
  const approver = await join("approver@acme.test", "approver");
  const body = await request();
  const created = await h.api(base(), { cookie: org.cookie, body: { ...body, owners: [{ type: "user", id: await userId(owner) }] } });
  expect(created.status).toBe(201);
  await h.settleIssuances();
  return { id: created.body.id as string, names: body.names, owner, approver };
}

describe("Archive", () => {
  test("only an Organization Administrator archives; the Managed Certificate shows when and is audited", async () => {
    const mc = await setup();

    expect((await archive(mc.id, mc.owner)).status).toBe(403);
    expect((await archive(mc.id, mc.approver)).status).toBe(403);
    expect((await archive(mc.id, globex.cookie)).status).toBe(404);
    expect((await get(mc.id)).archivedAt).toBeNull();

    const res = await archive(mc.id);

    expect(res.status).toBe(200);
    expect(Date.parse(res.body.archivedAt)).not.toBeNaN();
    expect((await get(mc.id)).archivedAt).toBe(res.body.archivedAt);
    const event = (await auditOf()).find((e) => e.action === "managed_certificate.archived")!;
    expect(event).toMatchObject({ actor: { email: "admin@acme.test" }, target: { type: "managed_certificate", id: mc.id }, detail: { names: mc.names } });
    expect((await auditOf()).filter((e) => e.action === "managed_certificate.archived")).toHaveLength(1);
  });

  test("it can be archived only once", async () => {
    const mc = await setup();
    expect((await archive(mc.id)).status).toBe(200);
    const again = await archive(mc.id);
    expect(again.status).toBe(409);
    expect(again.body.error).toContain("archived");
  });

  test("archived, it leaves the inventory unless asked for, and it, its Certificates and its history remain", async () => {
    const mc = await setup();
    const other = await h.api(base(), { cookie: org.cookie, body: await request() });
    await h.settleIssuances();
    const before = await certificates(mc.id);
    expect(await inventory()).toEqual([mc.id, other.body.id]);

    h.setNow(new Date("2026-01-02T00:00:00Z"));
    await archive(mc.id);

    expect(await inventory()).toEqual([other.body.id]);
    expect(await inventory("?archived=true")).toEqual([mc.id]);
    // The Owner still sees what they own, under the filter.
    expect(await inventory("?archived=true", mc.owner)).toEqual([mc.id]);
    expect(await certificates(mc.id)).toEqual(before);
    expect((await get(mc.id)).currentCertificate.fingerprint).toBe(before[0]!.fingerprint);
    const history = (await h.api(`${base()}/${mc.id}/history`, { cookie: org.cookie })).body.items as { kind: string; actor: any }[];
    expect(history.map((e) => e.kind)).toEqual(["created", "certificate_issued", "archived"]);
    expect(history.at(-1)!.actor).toMatchObject({ email: "admin@acme.test" });
  });

  test("archived, it is not renewed by the scheduler, by 'renew now' or by trying again", async () => {
    const mc = await setup();
    const { notAfter } = (await certificates(mc.id))[0]!;
    expect((await setPolicy(mc.id, { mode: "automatic", daysBeforeExpiry: 2 })).status).toBe(200);
    // Past its due time, an automatic Managed Certificate would be renewed: the same one, before it is archived, is.
    h.setNow(new Date(Date.parse(notAfter) - DAY));
    expect(await h.runRenewalScheduler()).toBe(1);
    await h.settleIssuances();
    expect(await certificates(mc.id)).toHaveLength(2);
    h.setNow(new Date(Date.parse(notAfter) - DAY / 2));
    await archive(mc.id);

    expect(await h.runRenewalScheduler()).toBe(0);
    await h.settleIssuances();
    const renew = await h.api(`${base()}/${mc.id}/renewals`, { cookie: org.cookie, body: {} });
    expect(renew.status).toBe(409);
    expect(renew.body.error).toContain("archived");
    expect((await h.api(`${base()}/${mc.id}/issuances`, { cookie: org.cookie, body: {} })).status).toBe(409);
    expect(await certificates(mc.id)).toHaveLength(2);
  });

  test("an archived proposal is not in the Approval queue and cannot be approved; it stays awaiting Approval", async () => {
    await readyToIssue();
    const approver = await join("approver@acme.test", "approver");
    const proposer = await join("proposer@acme.test", "member");
    const proposed = await h.api(base(), { cookie: proposer, body: await request() });
    expect(proposed.status).toBe(201);
    expect((await h.api(`/api/organizations/${org.orgId}/approvals`, { cookie: approver })).body.items).toHaveLength(1);

    await archive(proposed.body.id);

    expect((await h.api(`/api/organizations/${org.orgId}/approvals`, { cookie: approver })).body.items).toEqual([]);
    const approved = await h.api(`${base()}/${proposed.body.id}/approve`, { cookie: approver, body: {} });
    expect(approved.status).toBe(409);
    expect(approved.body.error).toContain("archived");
    const after = await get(proposed.body.id);
    expect(after.approval.status).toBe("pending");
    expect(after.issuance).toBeNull();
    expect(await inventory("?archived=true")).toEqual([proposed.body.id]);
  });

  test("archiving discards the pending name change, with the reason in its history", async () => {
    const mc = await setup();
    const proposed = await h.api(`${base()}/${mc.id}/name-change`, { cookie: mc.owner, body: await change([host()]) });
    expect(proposed.status).toBe(201);
    expect(proposed.body.pendingNameChange).not.toBeNull();

    await archive(mc.id);

    expect((await get(mc.id)).pendingNameChange).toBeNull();
    const discarded = (await auditOf()).filter((e) => e.action === "name_change.discarded");
    expect(discarded).toHaveLength(1);
    expect(discarded[0]).toMatchObject({ target: { id: mc.id }, detail: { reason: "the Managed Certificate was archived" } });
    const kinds = (await h.api(`${base()}/${mc.id}/history`, { cookie: org.cookie })).body.items.map((e: any) => e.kind);
    expect(kinds).toEqual(expect.arrayContaining(["names_change_discarded", "archived"]));
    // A new one is refused for an archived Managed Certificate.
    expect((await h.api(`${base()}/${mc.id}/name-change`, { cookie: mc.owner, body: await change([host()]) })).status).toBe(409);
  });
});

describe("Revocation", () => {
  test("an Owner revokes a Certificate with an RFC 5280 reason: the CA is told, the Certificate shows it, and it is audited", async () => {
    const mc = await setup();
    const { id: certificateId, fingerprint, serial } = await only(mc.id);
    expect((await get(mc.id)).currentCertificate.revocation).toBeNull();
    h.setNow(new Date("2026-01-02T00:00:00Z"));

    const res = await revoke(mc.id, certificateId, { reason: "keyCompromise" }, mc.owner);

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ id: certificateId, revocation: { reason: "keyCompromise", revokedAt: "2026-01-02T00:00:00.000Z", revokedBy: { email: "owner@acme.test" } } });
    expect(h.revocations).toEqual([{ certificate: expect.any(String), reason: "keyCompromise" }]);
    // The CA is given the Certificate's chain, leaf first.
    expect(h.revocations[0]!.certificate.trim().startsWith(await leafOf(mc.id))).toBe(true);
    expect(await certificates(mc.id)).toEqual([expect.objectContaining({ id: certificateId, revocation: res.body.revocation })]);
    expect((await get(mc.id)).currentCertificate.revocation).toEqual(res.body.revocation);
    const events = (await auditOf()).filter((e) => e.action === "certificate.revoked");
    expect(events).toEqual([
      expect.objectContaining({ actor: expect.objectContaining({ email: "owner@acme.test" }), target: { type: "managed_certificate", id: mc.id }, detail: { certificateId, fingerprint, serial, reason: "keyCompromise" } }),
    ]);
    const history = (await h.api(`${base()}/${mc.id}/history`, { cookie: org.cookie })).body.items as any[];
    expect(history.map((e) => e.kind)).toEqual(["created", "certificate_issued", "certificate_revoked"]);
    expect(history.at(-1)).toMatchObject({ reason: "keyCompromise", actor: { email: "owner@acme.test" } });
    expect(history[1].certificate.revocation).toMatchObject({ reason: "keyCompromise" });
  });

  test("an Organization Administrator revokes any, and every reason the CA honours is accepted", async () => {
    await readyToIssue();
    for (const reason of ["unspecified", "keyCompromise", "superseded", "cessationOfOperation"]) {
      const created = await h.api(base(), { cookie: org.cookie, body: await request() });
      await h.settleIssuances();
      const { id: certificateId } = await only(created.body.id);

      const res = await revoke(created.body.id, certificateId, { reason });

      expect(res.status).toBe(200);
      expect(res.body.revocation).toMatchObject({ reason, revokedBy: { email: "admin@acme.test" } });
    }
    expect(h.revocations.map((r) => r.reason)).toEqual(["unspecified", "keyCompromise", "superseded", "cessationOfOperation"]);
  });

  test("anyone else may not, nor may another Organization's administrator; and the reason must be one an ACME CA takes", async () => {
    const mc = await setup();
    const { id: certificateId } = await only(mc.id);
    const stranger = await join("stranger@acme.test", "member");
    // Another Managed Certificate owned by someone else, whose Owner has no say over this one.
    const otherOwner = await join("other@acme.test", "member");
    await h.api(base(), { cookie: org.cookie, body: { ...(await request()), owners: [{ type: "user", id: await userId(otherOwner) }] } });
    await h.settleIssuances();

    expect((await revoke(mc.id, certificateId, undefined, mc.approver)).status).toBe(403);
    expect((await revoke(mc.id, certificateId, undefined, stranger)).status).toBe(403);
    expect((await revoke(mc.id, certificateId, undefined, otherOwner)).status).toBe(403);
    expect((await revoke(mc.id, certificateId, undefined, globex.cookie)).status).toBe(404);
    expect((await revoke(mc.id, certificateId, { reason: "certificateHold" })).status).toBe(400);
    // A Private CA's reasons, which an ACME CA does not take from a subscriber.
    expect((await revoke(mc.id, certificateId, { reason: "affiliationChanged" })).status).toBe(422);
    expect((await revoke(mc.id, certificateId, { reason: "privilegeWithdrawn" })).status).toBe(422);
    expect((await revoke(mc.id, certificateId, { reason: "because" })).status).toBe(400);
    expect((await revoke(mc.id, certificateId, {})).status).toBe(400);
    expect((await revoke(mc.id, crypto.randomUUID())).status).toBe(404);
    expect((await revoke(mc.id, "not-a-uuid")).status).toBe(404);
    expect(h.revocations).toEqual([]);
    expect((await get(mc.id)).currentCertificate.revocation).toBeNull();
    expect((await auditOf()).filter((e) => e.action === "certificate.revoked")).toEqual([]);
  });

  test("a revoked Certificate is not revoked again, and the CA is not told twice", async () => {
    const mc = await setup();
    const { id: certificateId } = await only(mc.id);
    expect((await revoke(mc.id, certificateId)).status).toBe(200);

    const again = await revoke(mc.id, certificateId, { reason: "superseded" });

    expect(again.status).toBe(409);
    expect(again.body.error).toContain("revoked");
    expect(h.revocations).toHaveLength(1);
    expect((await get(mc.id)).currentCertificate.revocation.reason).toBe("keyCompromise");
  });

  test("when the CA cannot be reached, the Certificate is not shown as revoked and nothing is audited", async () => {
    const mc = await setup();
    const { id: certificateId } = await only(mc.id);
    h.caDirectories["letsencrypt-staging"] = "https://localhost:1/dir";

    const res = await revoke(mc.id, certificateId);

    expect(res.status).toBe(502);
    expect((await get(mc.id)).currentCertificate.revocation).toBeNull();
    expect((await auditOf()).filter((e) => e.action === "certificate.revoked")).toEqual([]);
    // Once the CA is back it can be revoked.
    h.caDirectories["letsencrypt-staging"] = h.caDirectories["letsencrypt-production"];
    expect((await revoke(mc.id, certificateId)).status).toBe(200);
  });

  test("an archived Managed Certificate's Certificates can still be revoked, and an earlier Certificate is revoked on its own", async () => {
    const mc = await setup();
    const renewed = await h.api(`${base()}/${mc.id}/renewals`, { cookie: org.cookie, body: {} });
    expect(renewed.status).toBe(202);
    await h.settleIssuances();
    const [newest, first] = await certificates(mc.id);
    await archive(mc.id);

    expect((await revoke(mc.id, first!.id)).status).toBe(200);

    const listed = (await h.api(`${base()}/${mc.id}/certificates`, { cookie: org.cookie })).body.items as any[];
    expect(listed.find((c) => c.id === first!.id).revocation).not.toBeNull();
    expect(listed.find((c) => c.id === newest!.id).revocation).toBeNull();
    expect((await get(mc.id)).currentCertificate.revocation).toBeNull();
  });
});

describe("Who may revoke", () => {
  test("a member of an owning Team may, even once the Managed Certificate is archived", async () => {
    await readyToIssue();
    const member = await join("teammate@acme.test", "member");
    const team = (await h.api("/api/auth/organization/create-team", { cookie: org.cookie, body: { name: "Web", organizationId: org.orgId } })).body.id as string;
    await h.api("/api/auth/organization/add-team-member", { cookie: org.cookie, body: { teamId: team, userId: await userId(member), organizationId: org.orgId } });
    const created = await h.api(base(), { cookie: org.cookie, body: { ...(await request()), owners: [{ type: "team", id: team }] } });
    await h.settleIssuances();
    const { id: certificateId } = await only(created.body.id);
    await archive(created.body.id);

    const res = await revoke(created.body.id, certificateId, { reason: "superseded" }, member);

    expect(res.status).toBe(200);
    expect(res.body.revocation).toMatchObject({ reason: "superseded", revokedBy: { email: "teammate@acme.test" } });
  });

  test("two revocations of one Certificate at once: one wins and the CA is told once", async () => {
    const mc = await setup();
    const { id: certificateId } = await only(mc.id);

    const results = await Promise.all([revoke(mc.id, certificateId, { reason: "keyCompromise" }), revoke(mc.id, certificateId, { reason: "superseded" }, mc.owner)]);

    expect(results.map((r) => r.status).sort()).toEqual([200, 409]);
    expect(h.revocations).toHaveLength(1);
    expect((await auditOf()).filter((e) => e.action === "certificate.revoked")).toHaveLength(1);
  });
});

describe("Nothing revokes automatically", () => {
  test("archiving, changing names and removing a user revoke nothing and tell the CA nothing", async () => {
    const mc = await setup();
    const second = await h.api(base(), { cookie: org.cookie, body: { ...(await request()), owners: [{ type: "user", id: await userId(mc.approver) }] } });
    await h.settleIssuances();
    const members = (await h.api(`/api/auth/organization/list-members?organizationId=${org.orgId}`, { cookie: org.cookie })).body.members as { id: string; userId: string }[];
    const approverId = await userId(mc.approver);

    // A name change by an Organization Administrator replaces the names and issues for the new ones.
    expect((await h.api(`${base()}/${mc.id}/name-change`, { cookie: org.cookie, body: await change([host()]) })).status).toBe(201);
    await h.settleIssuances();
    // A member who owns one leaves the Organization.
    const removed = await h.api("/api/auth/organization/remove-member", { cookie: org.cookie, body: { memberIdOrEmail: members.find((m) => m.userId === approverId)!.id, organizationId: org.orgId } });
    expect(removed.status).toBe(200);
    expect((await archive(mc.id)).status).toBe(200);
    expect((await archive(second.body.id)).status).toBe(200);

    expect(h.revocations).toEqual([]);
    expect((await auditOf()).filter((e) => e.action === "certificate.revoked")).toEqual([]);
    for (const id of [mc.id, second.body.id]) {
      const all = (await h.api(`${base()}/${id}/certificates`, { cookie: org.cookie })).body.items as any[];
      expect(all.length).toBeGreaterThan(0);
      expect(all.every((c) => c.revocation === null)).toBe(true);
    }
    expect((await get(mc.id)).currentCertificate.names).toHaveLength(1);
  });
});
