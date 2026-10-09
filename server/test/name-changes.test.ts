// Name changes: an Owner proposes other names for a Managed Certificate together with a CSR for them, and the change
// waits for Approval while Renewal continues with the last approved names and CSR; an Organization Administrator's
// change applies at once. Certificates are issued by Pebble for real, so what a Renewal used is read off what it issued.
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { Pkcs10CertificateRequest } from "@peculiar/x509";
import acme from "acme-client";
import { X509Certificate, randomBytes } from "node:crypto";
import { discardPendingNameChange } from "../src/name-change";
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

const base = (orgId = org.orgId) => `/api/organizations/${orgId}/managed-certificates`;
const auditOf = async () => (await h.api(`/api/organizations/${org.orgId}/audit-events`, { cookie: org.cookie })).body.items as { action: string; actor: any; target: any; detail: any }[];

const host = () => `t${randomBytes(5).toString("hex")}.${BIND.zone}`;
async function request(names = [host()], keyAlgorithm: "ecdsa-p256" | "rsa-2048" = "ecdsa-p256") {
  const key = await (keyAlgorithm === "ecdsa-p256" ? acme.crypto.createPrivateEcdsaKey("P-256") : acme.crypto.createPrivateRsaKey(2048));
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return { names, keyAlgorithm, csr: csr.toString() };
}
/** What an Owner submits with a name change: the names and a CSR for them. */
async function change(names: string[], keyAlgorithm: "ecdsa-p256" | "rsa-2048" = "ecdsa-p256") {
  const { csr } = await request(names, keyAlgorithm);
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
const certificates = async (id: string) => (await h.api(`${base()}/${id}/certificates`, { cookie: org.cookie })).body.items as { names: string[]; fingerprint: string }[];
const propose = (id: string, body: unknown, cookie: string) => h.api(`${base()}/${id}/name-change`, { cookie, body });
const decide = (id: string, verdict: "approve" | "reject", cookie: string, body: unknown = {}) => h.api(`${base()}/${id}/name-change/${verdict}`, { cookie, body });
const queue = (cookie: string) => h.api(`/api/organizations/${org.orgId}/approvals`, { cookie });
const leafKey = (pem: string) => new X509Certificate(pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/)![0]).publicKey.export({ type: "spki", format: "der" });
const csrKey = (csr: string) => Buffer.from(new Pkcs10CertificateRequest(csr).publicKey.rawData);
const downloaded = async (id: string) => (await h.app.request(`http://localhost${base()}/${id}/certificate`, { headers: { cookie: org.cookie } })).text();

/** A Managed Certificate with its first Certificate issued, an Owner who is a Member, and an Approver. */
async function setup() {
  await readyToIssue();
  const owner = await join("owner@acme.test", "member");
  const approver = await join("approver@acme.test", "approver");
  const first = await request();
  const created = await h.api(base(), { cookie: org.cookie, body: { ...first, owners: [{ type: "user", id: await userId(owner) }] } });
  expect(created.status).toBe(201);
  await h.settleIssuances();
  return { id: created.body.id as string, names: first.names, csr: first.csr, owner, approver };
}

describe("proposing a name change", () => {
  test("an Owner proposes other names with a CSR for them; it waits, changes nothing and is audited", async () => {
    const mc = await setup();
    const proposed = await change([host(), host()]);

    const res = await propose(mc.id, proposed, mc.owner);

    expect(res.status).toBe(201);
    expect(res.body.names).toEqual(mc.names);
    expect(res.body.pendingNameChange).toMatchObject({ names: proposed.names, proposedBy: { email: "owner@acme.test" }, proposedAt: expect.any(String) });
    expect(res.body.issuance.status).toBe("succeeded");
    expect(await certificates(mc.id)).toHaveLength(1);
    expect((await get(mc.id, mc.owner)).pendingNameChange.names).toEqual(proposed.names);
    const event = (await auditOf()).find((e) => e.action === "name_change.proposed")!;
    expect(event).toMatchObject({ actor: { email: "owner@acme.test" }, target: { id: mc.id }, detail: { from: mc.names, to: proposed.names } });
    expect(JSON.stringify(event.detail)).not.toContain("BEGIN CERTIFICATE REQUEST");
  });

  test("the CSR must be for the key algorithm and ask for exactly the new names, which must be names", async () => {
    const mc = await setup();
    const names = [host()];
    const other = await change([host()]);

    expect((await propose(mc.id, { names, csr: other.csr }, mc.owner)).status).toBe(422);
    expect((await propose(mc.id, await change(names, "rsa-2048"), mc.owner)).status).toBe(422);
    expect((await propose(mc.id, { names: ["not a name"], csr: other.csr }, mc.owner)).status).toBe(400);
    expect((await propose(mc.id, { names, csr: "nonsense" }, mc.owner)).status).toBe(400);
    expect((await propose(mc.id, { names: [], csr: other.csr }, mc.owner)).status).toBe(400);
    expect((await get(mc.id)).pendingNameChange).toBeNull();
  });

  test("the same names are not a change", async () => {
    const mc = await setup();
    const res = await propose(mc.id, await change([...mc.names].reverse()), mc.owner);
    expect(res.status).toBe(422);
    expect(res.body.error).toContain("same names");
  });

  test("at most one is pending at a time, until it is decided", async () => {
    const mc = await setup();
    expect((await propose(mc.id, await change([host()]), mc.owner)).status).toBe(201);

    const second = await propose(mc.id, await change([host()]), mc.owner);
    expect(second.status).toBe(409);
    expect(second.body.error).toContain("pending");

    expect((await decide(mc.id, "reject", mc.approver, { reason: "no" })).status).toBe(200);
    expect((await propose(mc.id, await change([host()]), mc.owner)).status).toBe(201);
  });

  test("two proposals at once leave one pending", async () => {
    const mc = await setup();
    const results = await Promise.all([propose(mc.id, await change([host()]), mc.owner), propose(mc.id, await change([host()]), mc.owner)]);
    expect(results.map((r) => r.status).sort()).toEqual([201, 409]);
    expect((await auditOf()).filter((e) => e.action === "name_change.proposed")).toHaveLength(1);
  });

  test("only the Managed Certificate's Owners and Organization Administrators may; an Approver who owns nothing may not", async () => {
    const mc = await setup();
    const stranger = await join("stranger@acme.test", "member");
    const body = await change([host()]);

    expect((await propose(mc.id, body, stranger)).status).toBe(403);
    expect((await propose(mc.id, body, mc.approver)).status).toBe(403);
    expect((await propose(mc.id, body, globex.cookie)).status).toBe(404);
    expect((await get(mc.id)).pendingNameChange).toBeNull();
    expect((await auditOf()).filter((e) => e.action.startsWith("name_change"))).toEqual([]);
  });

  test("not while the Managed Certificate is awaiting Approval, rejected or archived", async () => {
    const mc = await setup();
    const body = await change([host()]);
    for (const [set, mentions] of [
      ["approval_status = 'pending'", "Approval"],
      ["approval_status = 'rejected'", "rejected"],
      ["archived_at = now()", "archived"],
    ] as const) {
      await h.pool.query(`update managed_certificate set ${set} where id = $1`, [mc.id]);
      const res = await propose(mc.id, body, mc.owner);
      expect(res.status).toBe(409);
      expect(res.body.error).toContain(mentions);
      await h.pool.query(`update managed_certificate set approval_status = 'not_required', archived_at = null where id = $1`, [mc.id]);
    }
  });
});

describe("while a name change is pending", () => {
  test("renewing now, and the scheduler, keep using the last approved names and CSR", async () => {
    const mc = await setup();
    await h.api(`${base()}/${mc.id}/renewal-policy`, { cookie: org.cookie, method: "PUT", body: { mode: "automatic", daysBeforeExpiry: 2 } });
    expect((await propose(mc.id, await change([host()]), mc.owner)).status).toBe(201);

    expect((await h.api(`${base()}/${mc.id}/renewals`, { cookie: mc.owner, body: {} })).status).toBe(202);
    await h.settleIssuances();
    const afterRenewNow = await certificates(mc.id);
    expect(afterRenewNow).toHaveLength(2);

    h.setNow(new Date(Date.parse((await get(mc.id)).currentCertificate.notAfter) - 86_400_000));
    expect(await h.runRenewalScheduler()).toBe(1);
    await h.settleIssuances();

    expect((await get(mc.id)).issuance.failure).toBeNull();
    const renewed = await certificates(mc.id);
    expect(renewed).toHaveLength(3);
    for (const c of renewed) expect(c.names).toEqual(mc.names);
    expect(leafKey(await downloaded(mc.id)).equals(csrKey(mc.csr))).toBe(true);
    expect((await get(mc.id)).names).toEqual(mc.names);
    expect((await get(mc.id)).pendingNameChange).not.toBeNull();
  });
});

describe("deciding a name change", () => {
  test("approving applies the names and CSR, and the next issuance uses them", async () => {
    const mc = await setup();
    const proposed = await change([host(), host()]);
    await propose(mc.id, proposed, mc.owner);

    const replacesBefore = h.ari.replaces.length;
    const approved = await decide(mc.id, "approve", mc.approver, { reason: "known services" });

    expect(approved.status).toBe(200);
    expect(approved.body.names).toEqual(proposed.names);
    expect(approved.body.pendingNameChange).toBeNull();
    expect(approved.body.issuance.status).toBe("running");
    await h.settleIssuances();
    const issued = await certificates(mc.id);
    expect(issued).toHaveLength(2);
    expect(issued[0]!.names.sort()).toEqual([...proposed.names].sort());
    expect(leafKey(await downloaded(mc.id)).equals(csrKey(proposed.csr))).toBe(true);
    // The Certificate for other names is not what this one renews, so the order does not say it replaces it.
    expect(h.ari.replaces.slice(replacesBefore)).toEqual([undefined]);
    // From now on a Renewal asks for the new names too, and replaces the Certificate for them.
    expect((await h.api(`${base()}/${mc.id}/renewals`, { cookie: mc.owner, body: {} })).status).toBe(202);
    await h.settleIssuances();
    expect(h.ari.replaces[replacesBefore + 1]).toContain("BEGIN CERTIFICATE");
    expect((await certificates(mc.id))[0]!.names.sort()).toEqual([...proposed.names].sort());

    const events = (await auditOf()).filter((e) => e.target.id === mc.id).map((e) => e.action);
    expect(events).toContain("name_change.approved");
    expect(events.indexOf("name_change.approved")).toBeLessThan(events.lastIndexOf("issuance.started"));
    expect((await auditOf()).find((e) => e.action === "name_change.approved")).toMatchObject({
      actor: { email: "approver@acme.test" },
      detail: { reason: "known services", proposedBy: "owner@acme.test", from: mc.names, to: proposed.names },
    });
  });

  test("an Organization Administrator may approve too; a reason is optional", async () => {
    const mc = await setup();
    await propose(mc.id, await change([host()]), mc.owner);
    expect((await decide(mc.id, "approve", org.cookie)).status).toBe(200);
  });

  test("approving is refused while an Issuance runs, and may be done once it has ended", async () => {
    const mc = await setup();
    const proposed = await change([host()]);
    await propose(mc.id, proposed, mc.owner);
    expect((await h.api(`${base()}/${mc.id}/renewals`, { cookie: mc.owner, body: {} })).status).toBe(202);

    const early = await decide(mc.id, "approve", mc.approver);

    expect(early.status).toBe(409);
    expect(early.body.error).toContain("running");
    // Nothing was decided: the Managed Certificate still has its names and the change still waits.
    const waiting = await get(mc.id);
    expect(waiting.names).toEqual(mc.names);
    expect(waiting.pendingNameChange).not.toBeNull();
    expect((await auditOf()).filter((e) => e.action === "name_change.approved")).toEqual([]);

    await h.settleIssuances();
    expect((await decide(mc.id, "approve", mc.approver)).status).toBe(200);
    await h.settleIssuances();
    expect((await certificates(mc.id))[0]!.names).toEqual(proposed.names);
  });

  test("rejecting needs a reason, discards the change and leaves the Managed Certificate as it was", async () => {
    const mc = await setup();
    await propose(mc.id, await change([host()]), mc.owner);

    expect((await decide(mc.id, "reject", mc.approver)).status).toBe(400);
    const rejected = await decide(mc.id, "reject", mc.approver, { reason: "not ours" });

    expect(rejected.status).toBe(200);
    expect(rejected.body.pendingNameChange).toBeNull();
    expect(rejected.body.names).toEqual(mc.names);
    expect(rejected.body.issuance.status).toBe("succeeded");
    await h.settleIssuances();
    expect(await certificates(mc.id)).toHaveLength(1);
    expect((await auditOf()).find((e) => e.action === "name_change.rejected")).toMatchObject({ actor: { email: "approver@acme.test" }, detail: { reason: "not ours", proposedBy: "owner@acme.test" } });
    // Renewal carries on with the CSR it had.
    expect((await h.api(`${base()}/${mc.id}/renewals`, { cookie: mc.owner, body: {} })).status).toBe(202);
    await h.settleIssuances();
    expect(leafKey(await downloaded(mc.id)).equals(csrKey(mc.csr))).toBe(true);
  });

  test("nobody decides their own proposal, Members cannot decide, and there must be a change to decide", async () => {
    const mc = await setup();
    expect((await decide(mc.id, "approve", mc.approver)).status).toBe(409);

    await propose(mc.id, await change([host()]), mc.owner);
    expect((await decide(mc.id, "approve", mc.owner)).status).toBe(403);
    expect((await decide(mc.id, "reject", mc.owner, { reason: "x" })).status).toBe(403);
    expect((await decide(mc.id, "approve", globex.cookie)).status).toBe(404);
    expect((await get(mc.id)).pendingNameChange).not.toBeNull();

    // An Approver who owns the Managed Certificate may propose, but another decides it.
    await decide(mc.id, "reject", mc.approver, { reason: "no" });
    await h.api(`${base()}/${mc.id}/owners`, { cookie: org.cookie, body: { type: "user", id: await userId(mc.approver) } });
    expect((await propose(mc.id, await change([host()]), mc.approver)).status).toBe(201);
    expect((await decide(mc.id, "approve", mc.approver)).status).toBe(403);
    expect((await decide(mc.id, "approve", org.cookie)).status).toBe(200);
  });

  test("a decision is final: of two made at once one wins", async () => {
    const mc = await setup();
    await propose(mc.id, await change([host()]), mc.owner);

    const results = await Promise.all([decide(mc.id, "approve", mc.approver), decide(mc.id, "reject", org.cookie, { reason: "no" })]);

    expect(results.map((r) => r.status).sort()).toEqual([200, 409]);
    await h.settleIssuances();
    const decisions = (await auditOf()).filter((e) => e.action === "name_change.approved" || e.action === "name_change.rejected");
    expect(decisions).toHaveLength(1);
  });
});

describe("a name change that ends without a decision", () => {
  const withdraw = (id: string, cookie: string) => h.api(`${base()}/${id}/name-change/withdraw`, { cookie, body: {} });

  test("its proposer withdraws it, and it is gone from the queue, audited and in the history", async () => {
    const mc = await setup();
    await propose(mc.id, await change([host()]), mc.owner);

    const withdrawn = await withdraw(mc.id, mc.owner);

    expect(withdrawn.status).toBe(200);
    expect(withdrawn.body.pendingNameChange).toBeNull();
    expect(withdrawn.body.names).toEqual(mc.names);
    expect((await queue(mc.approver)).body.nameChanges).toEqual([]);
    expect((await auditOf()).find((e) => e.action === "name_change.withdrawn")).toMatchObject({ actor: { email: "owner@acme.test" }, target: { id: mc.id }, detail: { from: mc.names, proposedBy: "owner@acme.test" } });
    const history = (await h.api(`${base()}/${mc.id}/history`, { cookie: mc.owner })).body.items as { kind: string }[];
    expect(history.map((e) => e.kind)).toContain("names_change_withdrawn");
    // Nothing is left to decide, and another may be proposed.
    expect((await decide(mc.id, "approve", mc.approver)).status).toBe(409);
    expect((await withdraw(mc.id, mc.owner)).status).toBe(409);
    expect((await propose(mc.id, await change([host()]), mc.owner)).status).toBe(201);
  });

  test("nobody else withdraws it: others decide it", async () => {
    const mc = await setup();
    await propose(mc.id, await change([host()]), mc.owner);
    const coOwner = await join("co-owner@acme.test", "member");
    await h.api(`${base()}/${mc.id}/owners`, { cookie: org.cookie, body: { type: "user", id: await userId(coOwner) } });

    expect((await withdraw(mc.id, coOwner)).status).toBe(403);
    expect((await withdraw(mc.id, mc.approver)).status).toBe(403);
    expect((await withdraw(mc.id, org.cookie)).status).toBe(403);
    expect((await withdraw(mc.id, globex.cookie)).status).toBe(404);
    expect((await get(mc.id)).pendingNameChange).not.toBeNull();
  });

  test("of a withdrawal and an approval at once, one wins", async () => {
    const mc = await setup();
    await propose(mc.id, await change([host()]), mc.owner);

    const results = await Promise.all([withdraw(mc.id, mc.owner), decide(mc.id, "approve", mc.approver)]);

    expect(results.map((r) => r.status).sort()).toEqual([200, 409]);
    await h.settleIssuances();
    const events = (await auditOf()).map((e) => e.action);
    expect(events.filter((a) => a === "name_change.withdrawn" || a === "name_change.approved")).toHaveLength(1);
    expect((await get(mc.id)).names.length).toBe(1);
  });

  test("it is discarded when its proposer leaves the Organization, and the Managed Certificate is unaffected", async () => {
    const mc = await setup();
    await propose(mc.id, await change([host()]), mc.owner);
    const members = (await h.api(`/api/auth/organization/list-members?organizationId=${org.orgId}`, { cookie: org.cookie })).body.members as { id: string; userId: string }[];
    const ownerId = await userId(mc.owner);

    const removed = await h.api("/api/auth/organization/remove-member", {
      cookie: org.cookie,
      body: { memberIdOrEmail: members.find((m) => m.userId === ownerId)!.id, organizationId: org.orgId },
    });

    expect(removed.status).toBe(200);
    expect((await queue(mc.approver)).body.nameChanges).toEqual([]);
    expect((await get(mc.id, org.cookie)).pendingNameChange).toBeNull();
    expect((await get(mc.id, org.cookie)).names).toEqual(mc.names);
    expect((await auditOf()).find((e) => e.action === "name_change.discarded")).toMatchObject({
      actor: { email: "admin@acme.test" },
      target: { id: mc.id },
      detail: { from: mc.names, proposedBy: "owner@acme.test", reason: expect.stringContaining("left the Organization") },
    });
    expect((await decide(mc.id, "approve", mc.approver)).status).toBe(409);
  });

  test("it is discarded when its Managed Certificate is archived (the Archive's one call), and a change proposed by another is left alone", async () => {
    const mc = await setup();
    await propose(mc.id, await change([host()]), mc.owner);
    // Another Managed Certificate, with a change of its own pending.
    const second = await h.api(base(), { cookie: org.cookie, body: { ...(await request()), owners: [{ type: "user", id: await userId(mc.approver) }] } });
    await h.settleIssuances();
    const other = { id: second.body.id as string };
    expect((await propose(other.id, await change([host()]), mc.approver)).status).toBe(201);

    await h.unitOfWork.run({ id: await userId(org.cookie), email: "admin@acme.test" }, async (tx, c) => {
      await discardPendingNameChange(tx, c, { id: mc.id, organizationId: org.orgId }, "the Managed Certificate was archived");
      // Nothing pending is no error.
      await discardPendingNameChange(tx, c, { id: mc.id, organizationId: org.orgId }, "the Managed Certificate was archived");
    });

    expect((await get(mc.id)).pendingNameChange).toBeNull();
    expect((await get(other.id)).pendingNameChange).not.toBeNull();
    const discarded = (await auditOf()).filter((e) => e.action === "name_change.discarded");
    expect(discarded).toHaveLength(1);
    expect(discarded[0]).toMatchObject({ target: { id: mc.id }, detail: { reason: "the Managed Certificate was archived" } });
    expect((await h.api(`${base()}/${mc.id}/history`, { cookie: org.cookie })).body.items.map((e: any) => e.kind)).toContain("names_change_discarded");
  });
});

describe("an Organization Administrator's name change", () => {
  test("applies at once, starts an Issuance with the new names and CSR, and needs no Approval", async () => {
    const mc = await setup();
    const proposed = await change([host()]);

    const res = await propose(mc.id, proposed, org.cookie);

    expect(res.status).toBe(201);
    expect(res.body.names).toEqual(proposed.names);
    expect(res.body.pendingNameChange).toBeNull();
    expect(res.body.issuance.status).toBe("running");
    await h.settleIssuances();
    expect((await certificates(mc.id))[0]!.names).toEqual(proposed.names);
    expect(leafKey(await downloaded(mc.id)).equals(csrKey(proposed.csr))).toBe(true);
    expect((await queue(mc.approver)).body.nameChanges).toEqual([]);
    expect((await auditOf()).find((e) => e.action === "managed_certificate.names_changed")).toMatchObject({
      actor: { email: "admin@acme.test" },
      target: { id: mc.id },
      detail: { from: mc.names, to: proposed.names },
    });
  });

  test("is refused while an Issuance runs", async () => {
    const mc = await setup();
    expect((await h.api(`${base()}/${mc.id}/renewals`, { cookie: org.cookie, body: {} })).status).toBe(202);

    const res = await propose(mc.id, await change([host()]), org.cookie);

    expect(res.status).toBe(409);
    expect((await get(mc.id)).names).toEqual(mc.names);
    expect((await auditOf()).filter((e) => e.action === "managed_certificate.names_changed")).toEqual([]);
  });

  test("waits for a pending name change to be decided", async () => {
    const mc = await setup();
    await propose(mc.id, await change([host()]), mc.owner);

    const res = await propose(mc.id, await change([host()]), org.cookie);

    expect(res.status).toBe(409);
    expect((await get(mc.id)).names).toEqual(mc.names);
  });
});

describe("the Approval queue and the history", () => {
  test("an Approver sees pending name changes with the names they replace, and not their own", async () => {
    const mc = await setup();
    const proposed = await change([host()]);
    await propose(mc.id, proposed, mc.owner);

    const queued = (await queue(mc.approver)).body;
    expect(queued.items).toEqual([]);
    expect(queued.nameChanges).toEqual([
      { managedCertificateId: mc.id, currentNames: mc.names, names: proposed.names, proposedBy: { id: expect.any(String), email: "owner@acme.test" }, proposedAt: expect.any(String) },
    ]);
    expect((await queue(org.cookie)).body.nameChanges).toHaveLength(1);
    expect((await queue(mc.owner)).status).toBe(403);

    await h.api(`${base()}/${mc.id}/owners`, { cookie: org.cookie, body: { type: "user", id: await userId(mc.approver) } });
    await decide(mc.id, "reject", mc.approver, { reason: "no" });
    await propose(mc.id, await change([host()]), mc.approver);
    expect((await queue(mc.approver)).body.nameChanges).toEqual([]);
    expect((await queue(org.cookie)).body.nameChanges).toHaveLength(1);

    // Archived, a change cannot be approved, so it is not asked for.
    await h.pool.query(`update managed_certificate set archived_at = now() where id = $1`, [mc.id]);
    expect((await queue(org.cookie)).body.nameChanges).toEqual([]);
  });

  test("proposals and decisions appear in the history, with the names", async () => {
    const mc = await setup();
    const first = await change([host()]);
    const second = await change([host()]);
    await propose(mc.id, first, mc.owner);
    await decide(mc.id, "reject", mc.approver, { reason: "no" });
    await propose(mc.id, second, mc.owner);
    await decide(mc.id, "approve", mc.approver, { reason: "yes" });
    await h.settleIssuances();
    const third = await change([host()]);
    await propose(mc.id, third, org.cookie);
    await h.settleIssuances();

    const history = (await h.api(`${base()}/${mc.id}/history`, { cookie: mc.owner })).body.items as { kind: string; reason: string | null; actor: any; names: any }[];
    const kinds = history.map((e) => e.kind).filter((k) => k !== "certificate_issued");
    expect(kinds).toEqual(["created", "names_change_proposed", "names_change_rejected", "names_change_proposed", "names_change_approved", "names_changed"]);
    expect(history.filter((e) => e.kind === "names_change_proposed").map((e) => e.names)).toEqual([
      { from: mc.names, to: first.names },
      { from: mc.names, to: second.names },
    ]);
    expect(history.find((e) => e.kind === "names_change_rejected")).toMatchObject({ reason: "no", actor: { email: "approver@acme.test" } });
    expect(history.find((e) => e.kind === "names_changed")).toMatchObject({ names: { from: second.names, to: third.names }, actor: { email: "admin@acme.test" } });
  });

  test("what each role may do is reported by /api/me", async () => {
    const mc = await setup();
    const permissions = async (cookie: string) => (await h.api("/api/me", { cookie })).body.organizations[0].permissions.managedCertificate as string[];
    expect(await permissions(org.cookie)).toEqual(expect.arrayContaining(["changeNames", "proposeNameChange"]));
    expect(await permissions(mc.owner)).not.toContain("changeNames");
  });
});
