// Owners and visibility: a Managed Certificate has Owners (users or Teams) or none; a Member sees only the Managed
// Certificates they own, directly or through a Team, while Approvers and Organization Administrators see the whole
// Organization; the inventory can be filtered; and each Managed Certificate has a history. Proposals (pending
// Approval) are enough for most of it; the few scenarios that need an issued Certificate issue one against Pebble.
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import acme from "acme-client";
import { randomBytes } from "node:crypto";
import { BIND, PASSWORD, PEBBLE_DIRECTORY, createHarness, type Harness } from "./support/harness";

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
const certs = (cookie: string, orgId = org.orgId) => ({
  list: (query = "") => h.api(`${base(orgId)}${query}`, { cookie }),
  create: (body: unknown) => h.api(base(orgId), { cookie, body }),
  get: (id: string) => h.api(`${base(orgId)}/${id}`, { cookie }),
  certificates: (id: string) => h.api(`${base(orgId)}/${id}/certificates`, { cookie }),
  download: (id: string) => h.app.request(`http://localhost${base(orgId)}/${id}/certificate`, { headers: { cookie } }),
  history: (id: string) => h.api(`${base(orgId)}/${id}/history`, { cookie }),
  addOwner: (id: string, owner: { type: string; id: string }) => h.api(`${base(orgId)}/${id}/owners`, { cookie, body: owner }),
  removeOwner: (id: string, type: string, ownerId: string) => h.api(`${base(orgId)}/${id}/owners/${type}/${ownerId}`, { cookie, method: "DELETE" }),
  decide: (id: string, verdict: "approve" | "reject", body: unknown = {}) => h.api(`${base(orgId)}/${id}/${verdict}`, { cookie, body }),
});
const admin = () => certs(org.cookie);
const auditOf = async (orgId = org.orgId, cookie = org.cookie) =>
  (await h.api(`/api/organizations/${orgId}/audit-events`, { cookie })).body.items as { action: string; actor: any; target: any; detail: any }[];
const actions = async () => (await auditOf()).map((e) => e.action);
const ids = (res: { body: { items: { id: string }[] } }) => res.body.items.map((i) => i.id);

const host = () => `t${randomBytes(5).toString("hex")}.${BIND.zone}`;
async function request(names = [host()]) {
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() };
}

async function join(email: string, role: string, target = org) {
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: target.cookie, body: { email, role, organizationId: target.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}
const userId = async (cookie: string) => (await h.api("/api/me", { cookie })).body.user.id as string;
const BA = "/api/auth/organization";
const createTeam = async (name: string, target = org) =>
  (await h.api(`${BA}/create-team`, { cookie: target.cookie, body: { name, organizationId: target.orgId } })).body.id as string;
const addToTeam = (teamId: string, user: string) =>
  h.api(`${BA}/add-team-member`, { cookie: org.cookie, body: { teamId, userId: user, organizationId: org.orgId } });
const removeFromTeam = (teamId: string, user: string) =>
  h.api(`${BA}/remove-team-member`, { cookie: org.cookie, body: { teamId, userId: user, organizationId: org.orgId } });

/** An Organization Administrator creates a Managed Certificate (no ACME account is set up, so it only starts Issuance and fails). */
async function adminCreates(owners: { type: string; id: string }[] = []) {
  const res = await admin().create({ ...(await request()), owners });
  expect(res.status).toBe(201);
  await h.settleIssuances();
  return res.body as { id: string };
}

describe("Owners", () => {
  test("a Managed Certificate has no Owners unless some are given, and Owners are users or Teams", async () => {
    const mc = await adminCreates();
    expect((await admin().get(mc.id)).body.owners).toEqual([]);

    const alice = await join("alice@acme.test", "member");
    const aliceId = await userId(alice);
    const platform = await createTeam("Platform");
    expect((await admin().addOwner(mc.id, { type: "user", id: aliceId })).status).toBe(200);
    const added = await admin().addOwner(mc.id, { type: "team", id: platform });
    expect(added.status).toBe(200);
    expect(added.body.owners).toEqual([
      { type: "user", id: aliceId, email: "alice@acme.test" },
      { type: "team", id: platform, name: "Platform" },
    ]);
    expect((await admin().list()).body.items[0].owners).toEqual(added.body.owners);

    const removed = await admin().removeOwner(mc.id, "user", aliceId);
    expect(removed.status).toBe(200);
    expect(removed.body.owners).toEqual([{ type: "team", id: platform, name: "Platform" }]);
    // Zero Owners is allowed.
    expect((await admin().removeOwner(mc.id, "team", platform)).body.owners).toEqual([]);
    expect((await admin().get(mc.id)).body.owners).toEqual([]);
  });

  test("Owners can be named when creating or proposing, and nothing is created if one cannot be an Owner", async () => {
    const member = await join("member@acme.test", "member");
    const bob = await join("bob@acme.test", "member");
    const bobId = await userId(bob);
    const platform = await createTeam("Platform");

    const proposed = await certs(member).create({ ...(await request()), owners: [{ type: "user", id: bobId }, { type: "team", id: platform }, { type: "user", id: bobId }] });
    expect(proposed.status).toBe(201);
    expect(proposed.body.owners).toEqual([
      { type: "user", id: bobId, email: "bob@acme.test" },
      { type: "team", id: platform, name: "Platform" },
    ]);
    const created = await admin().create({ ...(await request()), owners: [{ type: "user", id: bobId }] });
    expect(created.body.owners).toEqual([{ type: "user", id: bobId, email: "bob@acme.test" }]);
    await h.settleIssuances();

    const before = (await admin().list()).body.items.length;
    const stranger = await userId(globex.cookie);
    const foreignTeam = await createTeam("Their team", globex);
    for (const owner of [
      { type: "user", id: stranger }, // not a member of this Organization
      { type: "user", id: "no-such-user" },
      { type: "team", id: foreignTeam }, // another Organization's Team
      { type: "team", id: "no-such-team" },
    ]) {
      expect((await certs(member).create({ ...(await request()), owners: [owner] })).status).toBe(422);
      expect((await admin().create({ ...(await request()), owners: [owner] })).status).toBe(422);
    }
    expect((await admin().list()).body.items).toHaveLength(before);
    expect((await auditOf()).filter((e) => e.action === "managed_certificate.owner_added")).toHaveLength(3);
  });

  test("a user or Team of another Organization cannot be added later either, and adding an Owner twice changes nothing", async () => {
    const mc = await adminCreates();
    const stranger = await userId(globex.cookie);
    const foreignTeam = await createTeam("Their team", globex);
    expect((await admin().addOwner(mc.id, { type: "user", id: stranger })).status).toBe(422);
    expect((await admin().addOwner(mc.id, { type: "team", id: foreignTeam })).status).toBe(422);
    expect((await admin().addOwner(mc.id, { type: "team", id: "no-such-team" })).status).toBe(422);

    const alice = await userId(await join("alice@acme.test", "member"));
    expect((await admin().addOwner(mc.id, { type: "user", id: alice })).status).toBe(200);
    const again = await admin().addOwner(mc.id, { type: "user", id: alice });
    expect(again.status).toBe(200);
    expect(again.body.owners).toHaveLength(1);
    expect((await auditOf()).filter((e) => e.action === "managed_certificate.owner_added")).toHaveLength(1);

    // Removing someone who is not an Owner is not found, and is not audited.
    expect((await admin().removeOwner(mc.id, "user", stranger)).status).toBe(404);
    expect((await admin().removeOwner(mc.id, "team", "no-such-team")).status).toBe(404);
    expect((await admin().removeOwner(mc.id, "person", alice)).status).toBe(400);
    expect((await auditOf()).filter((e) => e.action === "managed_certificate.owner_removed")).toEqual([]);
    expect((await admin().addOwner("not-a-uuid", { type: "user", id: alice })).status).toBe(404);
  });

  test("an Organization Administrator or an Owner changes Owners; nobody else does", async () => {
    const mc = await adminCreates();
    const alice = await join("alice@acme.test", "member");
    const bob = await join("bob@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");
    const [aliceId, bobId] = [await userId(alice), await userId(bob)];
    await admin().addOwner(mc.id, { type: "user", id: aliceId });

    // Someone who can see it but is not its Owner, and someone who cannot see it.
    expect((await certs(approver).addOwner(mc.id, { type: "user", id: bobId })).status).toBe(403);
    expect((await certs(bob).addOwner(mc.id, { type: "user", id: bobId })).status).toBe(403);
    expect((await certs(bob).removeOwner(mc.id, "user", aliceId)).status).toBe(403);
    expect((await certs(approver).removeOwner(mc.id, "user", aliceId)).status).toBe(403);
    expect((await admin().get(mc.id)).body.owners).toHaveLength(1);

    // An Owner shares the responsibility, and may take it off themselves.
    expect((await certs(alice).addOwner(mc.id, { type: "user", id: bobId })).status).toBe(200);
    expect((await certs(bob).get(mc.id)).status).toBe(200);
    expect((await certs(bob).removeOwner(mc.id, "user", aliceId)).status).toBe(200);
    expect((await certs(alice).get(mc.id)).status).toBe(403);
    expect((await admin().get(mc.id)).body.owners.map((o: any) => o.id)).toEqual([bobId]);
  });

  test("an Owner through a Team changes Owners too, and another Organization's Administrator cannot", async () => {
    const mc = await adminCreates();
    const carol = await join("carol@acme.test", "member");
    const platform = await createTeam("Platform");
    await addToTeam(platform, await userId(carol));
    await admin().addOwner(mc.id, { type: "team", id: platform });
    expect((await certs(carol).addOwner(mc.id, { type: "user", id: await userId(carol) })).status).toBe(200);
    expect((await certs(globex.cookie, org.orgId).addOwner(mc.id, { type: "user", id: await userId(carol) })).status).toBe(404);
    expect((await certs(globex.cookie, globex.orgId).addOwner(mc.id, { type: "user", id: await userId(carol) })).status).toBe(404);
  });

  test("changes to Owners are audited, with who was added or removed", async () => {
    const mc = await adminCreates();
    const alice = await userId(await join("alice@acme.test", "member"));
    const platform = await createTeam("Platform");
    await admin().addOwner(mc.id, { type: "user", id: alice });
    await admin().addOwner(mc.id, { type: "team", id: platform });
    await admin().removeOwner(mc.id, "user", alice);

    const events = (await auditOf()).filter((e) => e.action.startsWith("managed_certificate.owner_"));
    expect(events.map((e) => e.action)).toEqual(["managed_certificate.owner_added", "managed_certificate.owner_added", "managed_certificate.owner_removed"]);
    expect(events[0]).toMatchObject({
      actor: { email: "admin@acme.test" },
      target: { type: "managed_certificate", id: mc.id },
      detail: { owner: { type: "user", id: alice, email: "alice@acme.test" } },
    });
    expect(events[1]!.detail).toMatchObject({ owner: { type: "team", id: platform, name: "Platform" } });
    expect(events[2]!.detail).toMatchObject({ owner: { type: "user", id: alice, email: "alice@acme.test" } });
  });

  test("Owners named when proposing are audited as added, after the proposal", async () => {
    const member = await join("member@acme.test", "member");
    const alice = await userId(await join("alice@acme.test", "member"));
    const proposed = await certs(member).create({ ...(await request()), owners: [{ type: "user", id: alice }] });
    const events = (await auditOf()).filter((e) => e.target.id === proposed.body.id);
    expect(events.map((e) => e.action)).toEqual(["managed_certificate.proposed", "managed_certificate.owner_added"]);
    expect(events[1]).toMatchObject({ actor: { email: "member@acme.test" }, detail: { owner: { id: alice } } });
  });

  test("removing a user from the Organization takes them off every Managed Certificate's Owners, audited", async () => {
    const [first, second] = [await adminCreates(), await adminCreates()];
    const alice = await join("alice@acme.test", "member");
    const aliceId = await userId(alice);
    const bobId = await userId(await join("bob@acme.test", "member"));
    for (const mc of [first, second]) await admin().addOwner(mc.id, { type: "user", id: aliceId });
    await admin().addOwner(first.id, { type: "user", id: bobId });

    const members = (await h.api(`${BA}/list-members?organizationId=${org.orgId}`, { cookie: org.cookie })).body.members as { id: string; userId: string }[];
    const removal = await h.api(`${BA}/remove-member`, { cookie: org.cookie, body: { memberIdOrEmail: members.find((m) => m.userId === aliceId)!.id, organizationId: org.orgId } });
    expect(removal.status).toBe(200);

    expect((await admin().get(first.id)).body.owners.map((o: any) => o.id)).toEqual([bobId]);
    expect((await admin().get(second.id)).body.owners).toEqual([]);
    const removed = (await auditOf()).filter((e) => e.action === "managed_certificate.owner_removed");
    expect(removed.map((e) => e.target.id).sort()).toEqual([first.id, second.id].sort());
    expect(removed[0]).toMatchObject({ actor: { email: "admin@acme.test" }, detail: { owner: { type: "user", id: aliceId, email: "alice@acme.test" }, because: "member_removed" } });
    expect((await certs(alice).list()).status).toBe(404);
  });

  test("deleting a Team takes it off the Owners, audited, and the removal of the Team is not blocked", async () => {
    const mc = await adminCreates();
    const platform = await createTeam("Platform");
    await admin().addOwner(mc.id, { type: "team", id: platform });
    const deleted = await h.api(`${BA}/remove-team`, { cookie: org.cookie, body: { teamId: platform, organizationId: org.orgId } });
    expect(deleted.status).toBe(200);

    expect((await admin().get(mc.id)).body.owners).toEqual([]);
    const events = (await auditOf()).filter((e) => e.action === "managed_certificate.owner_removed");
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ target: { id: mc.id }, detail: { owner: { type: "team", id: platform, name: "Platform" }, because: "team_deleted" } });
    expect(await actions()).toContain("team.deleted");
  });
});

describe("visibility", () => {
  test("a Member sees only the Managed Certificates they own, directly or through a Team, in the list and in every read", async () => {
    const [mine, viaTeam, notMine, nobody] = [await adminCreates(), await adminCreates(), await adminCreates(), await adminCreates()];
    const alice = await join("alice@acme.test", "member");
    const aliceId = await userId(alice);
    const platform = await createTeam("Platform");
    const elsewhere = await createTeam("Elsewhere");
    await addToTeam(platform, aliceId);
    await admin().addOwner(mine.id, { type: "user", id: aliceId });
    await admin().addOwner(viaTeam.id, { type: "team", id: platform });
    await admin().addOwner(notMine.id, { type: "team", id: elsewhere });
    await admin().addOwner(notMine.id, { type: "user", id: await userId(await join("bob@acme.test", "member")) });

    const who = certs(alice);
    expect(ids(await who.list())).toEqual([mine.id, viaTeam.id]);
    for (const id of [mine.id, viaTeam.id]) {
      expect((await who.get(id)).status).toBe(200);
      expect((await who.certificates(id)).status).toBe(200);
      expect((await who.history(id)).status).toBe(200);
      expect((await who.download(id)).status).toBe(404); // visible, but nothing issued yet
    }
    for (const id of [notMine.id, nobody.id]) {
      expect((await who.get(id)).status).toBe(403);
      expect((await who.certificates(id)).status).toBe(403);
      expect((await who.history(id)).status).toBe(403);
      expect((await who.download(id)).status).toBe(403);
    }
    // They see who owns the ones they see.
    expect((await who.get(viaTeam.id)).body.owners).toEqual([{ type: "team", id: platform, name: "Platform" }]);
  });

  test("joining or leaving a Team changes what a Member sees at once", async () => {
    const mc = await adminCreates();
    const alice = await join("alice@acme.test", "member");
    const aliceId = await userId(alice);
    const platform = await createTeam("Platform");
    await admin().addOwner(mc.id, { type: "team", id: platform });

    expect(ids(await certs(alice).list())).toEqual([]);
    await addToTeam(platform, aliceId);
    expect(ids(await certs(alice).list())).toEqual([mc.id]);
    await removeFromTeam(platform, aliceId);
    expect(ids(await certs(alice).list())).toEqual([]);
    expect((await certs(alice).get(mc.id)).status).toBe(403);
  });

  test("a Member also keeps seeing what they proposed, owned or not", async () => {
    const member = await join("member@acme.test", "member");
    const proposed = await certs(member).create(await request());
    expect(ids(await certs(member).list())).toEqual([proposed.body.id]);
    expect((await certs(member).get(proposed.body.id)).body.owners).toEqual([]);
  });

  test("Approvers and Organization Administrators see every Managed Certificate in the Organization, and not another's", async () => {
    const [a, b] = [await adminCreates(), await adminCreates()];
    const member = await join("member@acme.test", "member");
    const proposed = await certs(member).create(await request());
    const approver = await join("approver@acme.test", "approver");

    for (const cookie of [approver, org.cookie]) {
      const who = certs(cookie);
      expect(ids(await who.list())).toEqual([a.id, b.id, proposed.body.id]);
      expect((await who.get(b.id)).status).toBe(200);
      expect((await who.certificates(b.id)).status).toBe(200);
      expect((await who.history(b.id)).status).toBe(200);
      expect((await who.get(proposed.body.id)).body.approval.status).toBe("pending");
    }
    expect((await certs(approver).get(crypto.randomUUID())).status).toBe(404);
    expect(ids(await certs(globex.cookie, globex.orgId).list())).toEqual([]);
    expect((await certs(globex.cookie, org.orgId).list()).status).toBe(404);
    expect((await certs(globex.cookie, globex.orgId).get(a.id)).status).toBe(404);
  });

  test("what each role may do is reported by /api/me", async () => {
    const me = async (cookie: string) => (await h.api("/api/me", { cookie })).body.organizations[0].permissions;
    expect((await me(await join("member@acme.test", "member"))).managedCertificate).toEqual(["propose", "download"]);
    expect((await me(await join("approver@acme.test", "approver"))).managedCertificate).toEqual(["read", "propose", "download"]);
    expect((await me(org.cookie)).managedCertificate).toEqual(expect.arrayContaining(["read", "create", "propose", "issue", "changeOwners", "download"]));
  });
});

describe("filters", () => {
  const filtered = async (query: string, cookie = org.cookie) => {
    const res = await certs(cookie).list(query);
    expect(res.status).toBe(200);
    return ids(res);
  };
  const archive = (id: string) => h.pool.query(`update managed_certificate set archived_at = now() where id = $1`, [id]);

  test("pending Approval, no Owners and Key Custody narrow the inventory, and filters combine", async () => {
    const member = await join("member@acme.test", "member");
    const alice = await userId(await join("alice@acme.test", "member"));
    const owned = await adminCreates([{ type: "user", id: alice }]);
    const unowned = await adminCreates();
    const pending = (await certs(member).create(await request())).body.id as string;

    expect(await filtered("")).toEqual([owned.id, unowned.id, pending]);
    expect(await filtered("?pendingApproval=true")).toEqual([pending]);
    expect(await filtered("?noOwners=true")).toEqual([unowned.id, pending]);
    expect(await filtered("?noOwners=true&pendingApproval=true")).toEqual([pending]);
    expect(await filtered("?keyCustody=owner")).toEqual([owned.id, unowned.id, pending]);
    expect(await filtered("?keyCustody=owner&noOwners=true")).toEqual([unowned.id, pending]);
  });

  test("archived Managed Certificates are shown only when asked for", async () => {
    const [kept, retired] = [await adminCreates(), await adminCreates()];
    await archive(retired.id);
    expect(await filtered("")).toEqual([kept.id]);
    expect(await filtered("?archived=true")).toEqual([retired.id]);
    expect(await filtered("?archived=true&noOwners=true")).toEqual([retired.id]);
    expect(await filtered("?archived=true&pendingApproval=true")).toEqual([]);
    // They are still readable on their own.
    expect((await admin().get(retired.id)).status).toBe(200);
  });

  test("expiring soon shows those whose current Certificate ends within 30 days, or has ended", async () => {
    const account = await h.api(`/api/organizations/${org.orgId}/acme-accounts`, { cookie: org.cookie, body: { termsOfServiceAgreed: true } });
    expect(account.status).toBe(201);
    const bind = await h.api(`/api/organizations/${org.orgId}/dns-providers`, {
      cookie: org.cookie,
      body: { name: "BIND", type: "rfc2136", settings: { server: BIND.server, port: BIND.port, zone: BIND.zone, keyName: BIND.keyName }, secret: BIND.keySecret },
    });
    expect(bind.status).toBe(201);
    const issued = (await admin().create(await request())).body.id as string;
    await h.settleIssuances();
    const notAfter = new Date((await admin().get(issued)).body.currentCertificate.notAfter);
    const neverIssued = (await certs(await join("member@acme.test", "member")).create(await request())).body; // no Certificate: not expiring, just absent

    const DAY = 86_400_000;
    h.setNow(new Date(notAfter.getTime() - 60 * DAY));
    expect(await filtered("?expiringSoon=true")).toEqual([]);
    h.setNow(new Date(notAfter.getTime() - 29 * DAY));
    expect(await filtered("?expiringSoon=true")).toEqual([issued]);
    h.setNow(new Date(notAfter.getTime() + DAY));
    expect(await filtered("?expiringSoon=true")).toEqual([issued]);
    expect(await filtered("")).toContain(neverIssued.id);
  });

  test("a Member's filters apply within what they own", async () => {
    const alice = await join("alice@acme.test", "member");
    const aliceId = await userId(alice);
    const co = await userId(await join("bob@acme.test", "member"));
    const [one, two] = [await adminCreates([{ type: "user", id: aliceId }]), await adminCreates([{ type: "user", id: aliceId }, { type: "user", id: co }])];
    await adminCreates();

    expect(await filtered("", alice)).toEqual([one.id, two.id]);
    expect(await filtered("?noOwners=true", alice)).toEqual([]); // others have no Owners, but are not theirs
    expect(await filtered("?pendingApproval=true", alice)).toEqual([]);
    await archive(one.id);
    expect(await filtered("", alice)).toEqual([two.id]);
    expect(await filtered("?archived=true", alice)).toEqual([one.id]);
  });

  test("the ACME CA's tag and key algorithm each take one or more values, any of which matches", async () => {
    const staging = await adminCreates();
    const production = (await admin().create({ ...(await request()), acmeCaId: "letsencrypt-production" })).body.id as string;
    await h.settleIssuances();

    expect(await filtered("?tag=staging")).toEqual([staging.id]);
    expect(await filtered("?tag=production")).toEqual([production]);
    expect(await filtered("?tag=staging,production")).toEqual([staging.id, production]);
    expect(await filtered("?keyAlgorithm=ecdsa-p256")).toEqual([staging.id, production]);
    expect(await filtered("?keyAlgorithm=rsa-2048,rsa-4096")).toEqual([]);
    expect(await filtered("?keyAlgorithm=rsa-2048,ecdsa-p256&tag=production")).toEqual([production]);
  });

  test("a custom ACME CA's tag matches as a built-in one's does", async () => {
    const addCa = async (name: string, tag: string | null) =>
      (await h.api(`/api/organizations/${org.orgId}/acme-cas`, { cookie: org.cookie, body: { name, directoryUrl: PEBBLE_DIRECTORY, tag, termsOfServiceAgreed: true } })).body.acmeCa.id as string;
    const [internalProduction, untagged] = [await addCa("Internal production", "production"), await addCa("Untagged", null)];
    const onCa = async (acmeCaId: string) => (await admin().create({ ...(await request()), acmeCaId })).body.id as string;
    const staging = (await adminCreates()).id;
    const [custom, none] = [await onCa(internalProduction), await onCa(untagged)];
    await h.settleIssuances();

    expect(await filtered("?tag=production")).toEqual([custom]);
    expect(await filtered("?tag=staging,production")).toEqual([staging, custom]);
    expect(await filtered("")).toContain(none);
  });

  test("the inventory is listed a page at a time, with how many match in all", async () => {
    const made = [await adminCreates(), await adminCreates(), await adminCreates()].map((m) => m.id);
    const page = async (query: string) => (await certs(org.cookie).list(query)).body as { items: { id: string }[]; total: number; page: number; pageSize: number };

    expect(await page("")).toMatchObject({ total: 3, page: 1, pageSize: 25 });
    expect((await page("?pageSize=2")).items.map((i) => i.id)).toEqual(made.slice(0, 2));
    expect(await page("?pageSize=2&page=2")).toMatchObject({ total: 3, page: 2, pageSize: 2, items: [{ id: made[2] }] });
    expect((await page("?pageSize=2&page=3")).items).toEqual([]);
    // The total is of what the filters leave, not of the page.
    expect(await page("?pageSize=1&noOwners=true&page=3")).toMatchObject({ total: 3, items: [{ id: made[2] }] });
    expect(await page("?pageSize=1&pendingApproval=true")).toMatchObject({ total: 0, items: [] });
  });

  test("a filter value that means nothing is refused", async () => {
    for (const query of ["?keyCustody=nobody", "?noOwners=maybe", "?expiringSoon=1", "?archived=yes", "?pendingApproval=", "?tag=dev", "?tag=staging,", "?keyAlgorithm=des", "?page=0", "?pageSize=0", "?pageSize=101", "?page=x"]) {
      expect((await certs(org.cookie).list(query)).status).toBe(400);
    }
  });
});

describe("history", () => {
  test("shows a proposal, its Approval and the Certificates issued, oldest first", async () => {
    const account = await h.api(`/api/organizations/${org.orgId}/acme-accounts`, { cookie: org.cookie, body: { termsOfServiceAgreed: true } });
    expect(account.status).toBe(201);
    await h.api(`/api/organizations/${org.orgId}/dns-providers`, {
      cookie: org.cookie,
      body: { name: "BIND", type: "rfc2136", settings: { server: BIND.server, port: BIND.port, zone: BIND.zone, keyName: BIND.keyName }, secret: BIND.keySecret },
    });
    const member = await join("member@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");
    h.setNow(new Date("2026-03-01T09:00:00Z"));
    const proposed = (await certs(member).create(await request())).body.id as string;
    expect((await certs(member).history(proposed)).body.items).toMatchObject([{ kind: "proposed", at: "2026-03-01T09:00:00.000Z", actor: { email: "member@acme.test" }, reason: null }]);

    h.setNow(new Date("2026-03-02T09:00:00Z"));
    await certs(approver).decide(proposed, "approve", { reason: "known service" });
    await h.settleIssuances();
    h.setNow(new Date("2026-03-03T09:00:00Z"));
    expect((await admin().get(proposed)).body.issuance.status).toBe("succeeded");
    expect((await h.api(`${base()}/${proposed}/issuances`, { cookie: org.cookie, method: "POST", body: {} })).status).toBe(202);
    await h.settleIssuances();

    const history = (await certs(member).history(proposed)).body.items;
    expect(history.map((e: any) => e.kind)).toEqual(["proposed", "approved", "certificate_issued", "certificate_issued"]);
    expect(history[1]).toMatchObject({ at: "2026-03-02T09:00:00.000Z", actor: { email: "approver@acme.test" }, reason: "known service" });
    const [first, second] = (await admin().certificates(proposed)).body.items.reverse();
    expect(history[2].certificate).toEqual(first);
    expect(history[3].certificate).toEqual(second);
    expect(history[3].at).toBe("2026-03-03T09:00:00.000Z");
  });

  test("shows a rejection with its reason, and an Organization Administrator's creation", async () => {
    const member = await join("member@acme.test", "member");
    const proposed = (await certs(member).create(await request())).body.id as string;
    await admin().decide(proposed, "reject", { reason: "wrong team" });
    expect((await certs(member).history(proposed)).body.items.map((e: any) => [e.kind, e.reason])).toEqual([
      ["proposed", null],
      ["rejected", "wrong team"],
    ]);

    const created = await adminCreates();
    const history = (await admin().history(created.id)).body.items;
    expect(history).toMatchObject([{ kind: "created", actor: { email: "admin@acme.test" }, reason: null }]);
  });

  test("is shown to those who may see the Managed Certificate, and only for it", async () => {
    const [mine, other] = [await adminCreates(), await adminCreates()];
    const alice = await join("alice@acme.test", "member");
    await admin().addOwner(mine.id, { type: "user", id: await userId(alice) });
    expect((await certs(alice).history(mine.id)).status).toBe(200);
    expect((await certs(alice).history(other.id)).status).toBe(403);
    expect((await certs(globex.cookie, globex.orgId).history(mine.id)).status).toBe(404);
    expect((await certs(globex.cookie, org.orgId).history(mine.id)).status).toBe(404);
    expect((await admin().history("not-a-uuid")).status).toBe(404);
    // Each one's history is its own.
    expect((await admin().history(other.id)).body.items).toHaveLength(1);
  });
});
