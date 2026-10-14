// Notifications, through the platform's HTTP API: Organization Administrators configure email and webhook notification
// channels; Owners and Organization Administrators add Subscribers (users, Teams or channels) to a Managed Certificate,
// none by default; and each notified event (upcoming expiry, Renewal succeeded or failed, Deployment Run failed, Agent
// offline, Approval decided) reaches its Subscribers by email or webhook. Mail and webhooks are captured, not sent;
// Certificates are issued by Pebble for real, and time is the harness's clock.
import acme from "acme-client";
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { TestAgent } from "./agent-double";
import { BIND, PASSWORD, createHarness, type Harness } from "./harness";

setDefaultTimeout(60_000);

let h: Harness;
let operator: string;
let org: { orgId: string; cookie: string };
let globex: { orgId: string; cookie: string };
type Org = typeof org;

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  operator = await h.createOperator("op@platform.test", PASSWORD);
  org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
  globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
  // The invitations that made the Organizations are mail too; the tests look only at notices.
  h.mailer.sent.length = 0;
});
afterAll(async () => {
  await h.close();
});

const DAY = 86_400_000;
const BA = "/api/auth/organization";
const api = (path: string, opts: { cookie?: string; body?: unknown; method?: string; target?: Org } = {}) =>
  h.api(`/api/organizations/${(opts.target ?? org).orgId}${path}`, { cookie: opts.cookie ?? (opts.target ?? org).cookie, body: opts.body, method: opts.method });
const auditOf = async (target: Org = org) => (await api("/audit-events", { target })).body.items as { action: string; actor: any; target: any; detail: any }[];

async function join(email: string, role: string, target: Org = org) {
  const invited = await h.api(`${BA}/invite-member`, { cookie: target.cookie, body: { email, role, organizationId: target.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api(`${BA}/accept-invitation`, { cookie, body: { invitationId: invited.body.id } });
  h.mailer.sent.length = 0;
  return h.signIn(email, PASSWORD);
}
const userId = async (cookie: string) => (await h.api("/api/me", { cookie })).body.user.id as string;
const createTeam = async (name: string, target: Org = org) =>
  (await h.api(`${BA}/create-team`, { cookie: target.cookie, body: { name, organizationId: target.orgId } })).body.id as string;
const addToTeam = (teamId: string, user: string) => h.api(`${BA}/add-team-member`, { cookie: org.cookie, body: { teamId, userId: user, organizationId: org.orgId } });
async function removeMember(user: string) {
  const members = (await h.api(`${BA}/list-members?organizationId=${org.orgId}`, { cookie: org.cookie })).body.members as { id: string; userId: string }[];
  const removal = await h.api(`${BA}/remove-member`, { cookie: org.cookie, body: { memberIdOrEmail: members.find((m) => m.userId === user)!.id, organizationId: org.orgId } });
  expect(removal.status).toBe(200);
}

const channels = (opts: { cookie?: string; target?: Org } = {}) => api("/notification-channels", opts);
const addChannel = (body: unknown, opts: { cookie?: string; target?: Org } = {}) => api("/notification-channels", { ...opts, body });
async function emailChannel(name = "Ops list", email = "ops@acme.test", target: Org = org) {
  const created = await addChannel({ name, kind: "email", email }, { target });
  expect(created.status).toBe(201);
  return created.body as { id: string };
}
async function webhookChannel(name = "SIEM", url = "https://hooks.example.test/T000/B000/s3cr3t", target: Org = org) {
  const created = await addChannel({ name, kind: "webhook", url }, { target });
  expect(created.status).toBe(201);
  return created.body as { id: string };
}

describe("notification channels", () => {
  test("an Organization Administrator adds email and webhook channels; a webhook's URL is never shown, only its host", async () => {
    const email = await addChannel({ name: "Ops list", kind: "email", email: "ops@acme.test" });
    expect(email.status).toBe(201);
    expect(email.body).toEqual({ id: expect.any(String), name: "Ops list", kind: "email", email: "ops@acme.test", webhookHost: null, createdAt: expect.any(String) });
    const webhook = await addChannel({ name: "SIEM", kind: "webhook", url: "https://hooks.example.test/T000/B000/s3cr3t" });
    expect(webhook.status).toBe(201);
    expect(webhook.body).toMatchObject({ name: "SIEM", kind: "webhook", email: null, webhookHost: "hooks.example.test" });

    const listed = await channels();
    expect(listed.status).toBe(200);
    expect(listed.body.items.map((c: any) => c.name)).toEqual(["Ops list", "SIEM"]);
    expect(JSON.stringify(listed.body)).not.toContain("s3cr3t");

    const created = (await auditOf()).filter((e) => e.action === "notification_channel.created");
    expect(created).toHaveLength(2);
    expect(created[1]).toMatchObject({ actor: { email: "admin@acme.test" }, target: { type: "notification_channel", id: webhook.body.id }, detail: { name: "SIEM", kind: "webhook", webhookHost: "hooks.example.test" } });
    expect(JSON.stringify(await auditOf())).not.toContain("s3cr3t");
  });

  test("Members and Approvers may list them to choose one, but only an Organization Administrator adds or removes one", async () => {
    const { id } = await emailChannel();
    for (const cookie of [await join("member@acme.test", "member"), await join("approver@acme.test", "approver")]) {
      expect((await channels({ cookie })).body.items).toHaveLength(1);
      expect((await addChannel({ name: "Mine", kind: "email", email: "me@acme.test" }, { cookie })).status).toBe(403);
      expect((await api(`/notification-channels/${id}`, { cookie, method: "DELETE" })).status).toBe(403);
    }
    expect((await channels()).body.items).toHaveLength(1);
  });

  test("an email channel needs an address, a webhook an https URL to a host that is not internal, and names are not shared", async () => {
    expect((await addChannel({ name: "x", kind: "email", email: "not an address" })).status).toBe(400);
    expect((await addChannel({ name: "x", kind: "email" })).status).toBe(400);
    for (const url of [
      "ftp://hooks.example.test/x",
      "not a url",
      "http://hooks.example.test/x",
      "https://localhost/x",
      "https://127.0.0.1:5432/x",
      "https://10.1.2.3/x",
      "https://169.254.169.254/latest/meta-data",
      "https://[::1]/x",
    ]) {
      expect((await addChannel({ name: "x", kind: "webhook", url })).status).toBe(400);
    }
    expect((await addChannel({ name: "", kind: "email", email: "ops@acme.test" })).status).toBe(400);
    await emailChannel("Ops list");
    expect((await addChannel({ name: "ops LIST", kind: "email", email: "other@acme.test" })).status).toBe(409);
    expect((await channels()).body.items).toHaveLength(1);
  });

  test("another Organization's channels are neither listed nor removable", async () => {
    const theirs = await emailChannel("Theirs", "ops@globex.test", globex);
    expect((await channels()).body.items).toEqual([]);
    expect((await api(`/notification-channels/${theirs.id}`, { method: "DELETE" })).status).toBe(404);
    expect((await channels({ target: globex })).body.items).toHaveLength(1);
  });

  test("removing one is audited", async () => {
    const { id } = await emailChannel();
    expect((await api(`/notification-channels/${id}`, { method: "DELETE" })).body).toEqual({ deleted: true });
    expect((await channels()).body.items).toEqual([]);
    expect((await auditOf()).find((e) => e.action === "notification_channel.deleted")).toMatchObject({ target: { type: "notification_channel", id }, detail: { name: "Ops list" } });
    expect((await api(`/notification-channels/${id}`, { method: "DELETE" })).status).toBe(404);
  });
});

const host = () => `t${randomBytes(5).toString("hex")}.${BIND.zone}`;
async function request(names = [host()]) {
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() };
}
/** A Managed Certificate an Organization Administrator created; with no ACME account it only fails to issue, which is no Renewal. */
async function created(opts: { owners?: { type: string; id: string }[]; target?: Org } = {}) {
  const res = await api("/managed-certificates", { target: opts.target, body: { ...(await request()), owners: opts.owners ?? [] } });
  expect(res.status).toBe(201);
  await h.settleIssuances();
  return res.body as { id: string; names: string[] };
}
const subscribers = (id: string, opts: { cookie?: string; target?: Org } = {}) => api(`/managed-certificates/${id}/subscribers`, opts);
const subscribe = (id: string, ref: { type: string; id: string }, opts: { cookie?: string; target?: Org } = {}) => api(`/managed-certificates/${id}/subscribers`, { ...opts, body: ref });
const unsubscribe = (id: string, ref: { type: string; id: string }, opts: { cookie?: string } = {}) =>
  api(`/managed-certificates/${id}/subscribers/${ref.type}/${ref.id}`, { ...opts, method: "DELETE" });

describe("Subscribers", () => {
  test("nobody is subscribed by default, not even the Owners or whoever created it", async () => {
    const ownerId = await userId(await join("owner@acme.test", "member"));
    const mc = await created({ owners: [{ type: "user", id: ownerId }] });
    expect((await subscribers(mc.id)).body).toEqual({ items: [] });
  });

  test("an Organization Administrator adds users, Teams and channels, each audited, and naming one twice changes nothing", async () => {
    const mc = await created();
    const aliceId = await userId(await join("alice@acme.test", "member"));
    const teamId = await createTeam("Web");
    const channel = await webhookChannel();

    for (const ref of [{ type: "user", id: aliceId }, { type: "team", id: teamId }, { type: "channel", id: channel.id }, { type: "user", id: aliceId }]) {
      expect((await subscribe(mc.id, ref)).status).toBe(200);
    }
    expect((await subscribers(mc.id)).body.items).toEqual([
      { type: "user", id: aliceId, email: "alice@acme.test" },
      { type: "team", id: teamId, name: "Web" },
      { type: "channel", id: channel.id, name: "SIEM", kind: "webhook" },
    ]);
    const added = (await auditOf()).filter((e) => e.action === "managed_certificate.subscriber_added");
    expect(added).toHaveLength(3);
    expect(added[0]).toMatchObject({ actor: { email: "admin@acme.test" }, target: { type: "managed_certificate", id: mc.id }, detail: { subscriber: { type: "user", id: aliceId, email: "alice@acme.test" } } });

    expect((await unsubscribe(mc.id, { type: "team", id: teamId })).body.items.map((s: any) => s.type)).toEqual(["user", "channel"]);
    expect((await auditOf()).find((e) => e.action === "managed_certificate.subscriber_removed")).toMatchObject({ target: { id: mc.id }, detail: { subscriber: { type: "team", id: teamId, name: "Web" } } });
    expect((await unsubscribe(mc.id, { type: "team", id: teamId })).status).toBe(404);
  });

  test("an Owner may change them, whatever their role; a Member who does not own it and an Approver may not", async () => {
    const owner = await join("owner@acme.test", "member");
    const ownerId = await userId(owner);
    const member = await join("member@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");
    const mc = await created({ owners: [{ type: "user", id: ownerId }] });
    const channel = await emailChannel();

    expect((await subscribe(mc.id, { type: "channel", id: channel.id }, { cookie: owner })).status).toBe(200);
    expect((await subscribers(mc.id, { cookie: owner })).body.items).toHaveLength(1);
    expect((await subscribe(mc.id, { type: "user", id: ownerId }, { cookie: member })).status).toBe(403);
    expect((await subscribe(mc.id, { type: "user", id: ownerId }, { cookie: approver })).status).toBe(403);
    expect((await unsubscribe(mc.id, { type: "channel", id: channel.id }, { cookie: approver })).status).toBe(403);
    // An Approver sees every Managed Certificate, so may see who is subscribed; a Member who does not own it sees neither.
    expect((await subscribers(mc.id, { cookie: approver })).body.items).toHaveLength(1);
    expect((await subscribers(mc.id, { cookie: member })).status).toBe(403);
    expect((await unsubscribe(mc.id, { type: "channel", id: channel.id }, { cookie: owner })).status).toBe(200);
  });

  test("only the Organization's own users, Teams and channels may be Subscribers", async () => {
    const mc = await created();
    const outsiderId = await userId(await join("outsider@globex.test", "member", globex));
    const theirTeam = await createTeam("Theirs", globex);
    const theirChannel = await emailChannel("Theirs", "ops@globex.test", globex);
    for (const ref of [{ type: "user", id: outsiderId }, { type: "team", id: theirTeam }, { type: "channel", id: theirChannel.id }, { type: "channel", id: "not-a-uuid" }]) {
      expect((await subscribe(mc.id, ref)).status).toBe(422);
    }
    expect((await subscribe(mc.id, { type: "group", id: outsiderId })).status).toBe(400);
    expect((await subscribers(mc.id)).body.items).toEqual([]);
    // Nor may another Organization reach this one's Managed Certificate.
    expect((await subscribe(mc.id, { type: "channel", id: theirChannel.id }, { target: globex })).status).toBe(404);
  });

  test("removing a user from the Organization, deleting a Team or removing a channel takes it off, audited with why", async () => {
    const [first, second] = [await created(), await created()];
    const aliceId = await userId(await join("alice@acme.test", "member"));
    const teamId = await createTeam("Web");
    const channel = await emailChannel();
    for (const mc of [first, second]) {
      for (const ref of [{ type: "user", id: aliceId }, { type: "team", id: teamId }, { type: "channel", id: channel.id }]) await subscribe(mc.id, ref);
    }

    await removeMember(aliceId);
    expect((await h.api(`${BA}/remove-team`, { cookie: org.cookie, body: { teamId, organizationId: org.orgId } })).status).toBe(200);
    expect((await api(`/notification-channels/${channel.id}`, { method: "DELETE" })).status).toBe(200);

    for (const mc of [first, second]) expect((await subscribers(mc.id)).body.items).toEqual([]);
    const removed = (await auditOf()).filter((e) => e.action === "managed_certificate.subscriber_removed");
    expect(removed.map((e) => e.detail.because).sort()).toEqual(["channel_deleted", "channel_deleted", "member_removed", "member_removed", "team_deleted", "team_deleted"]);
    expect(removed.find((e) => e.detail.because === "member_removed")).toMatchObject({ detail: { subscriber: { type: "user", id: aliceId, email: "alice@acme.test" } } });
  });
});

/** What issuing needs in the Organization: an ACME account in staging, and a DNS Provider for the zone BIND serves. */
async function readyToIssue(target: Org = org) {
  expect((await api("/acme-accounts", { target, body: { termsOfServiceAgreed: true } })).status).toBe(201);
  const provider = await api("/dns-providers", {
    target,
    body: { name: "BIND", type: "rfc2136", settings: { server: BIND.server, port: BIND.port, zone: BIND.zone, keyName: BIND.keyName }, secret: BIND.keySecret },
  });
  expect(provider.status).toBe(201);
}
/** A Managed Certificate whose first Certificate is issued. */
async function issued(opts: { owners?: { type: string; id: string }[] } = {}) {
  const mc = await created(opts);
  expect((await api(`/managed-certificates/${mc.id}`)).body.issuance.status).toBe("succeeded");
  return mc;
}
const renewNow = async (id: string, cookie = org.cookie) => {
  const res = await api(`/managed-certificates/${id}/renewals`, { cookie, body: {} });
  expect(res.status).toBe(202);
  await h.settleIssuances();
};
/** The notices sent by one pass: each email as who it went to and its subject, each webhook post as its body. */
async function delivered() {
  await h.deliverNotices();
  const mail = h.mailer.sent.map((m) => ({ to: m.to, subject: m.subject, text: m.text }));
  const posts = h.webhooks.sent.map((w) => ({ url: w.url, body: w.body }));
  h.mailer.sent.length = 0;
  h.webhooks.sent.length = 0;
  return { mail, posts, to: mail.map((m) => m.to).sort() };
}

const INSTALL = "#!/usr/bin/env bash\ncp \"$CERT_FULLCHAIN_FILE\" /etc/ssl/site.pem\n";
/** A Deployment whose Agent made the key, whose Certificate was issued and whose script ran once. */
async function deployed() {
  const hostName = `host-${randomBytes(3).toString("hex")}`;
  const agent = await TestAgent.registered(h, org.cookie, org.orgId, { hostName });
  const scripts = (await api("/deployment-scripts")).body.items as { id: string; name: string }[];
  const script = scripts.find((s) => s.name === "install") ?? (await api("/deployment-scripts", { body: { name: "install", interpreter: "bash", content: INSTALL } })).body;
  const set = await api("/deployments", { body: { agentId: agent.id, scriptId: script.id, names: [host()], keyAlgorithm: "ecdsa-p256" } });
  expect(set.status).toBe(201);
  await agent.work();
  await h.settleIssuances();
  await agent.work();
  return { agent, hostName, deploymentId: set.body.id as string, managedCertificateId: set.body.managedCertificateId as string };
}
/** Has the Agent run the Deployment again for its current Certificate, and report how it went. */
async function rerun(agent: TestAgent) {
  const [d] = (await api("/deployments")).body.items.filter((d: any) => d.agent.id === agent.id);
  expect((await api(`/deployments/${d.id}/runs`, { body: {} })).status).toBe(202);
  await agent.work();
}

describe("notices", () => {
  test("a Renewal that succeeds is told to each Subscriber once: users, Teams' members, email channels and webhooks", async () => {
    await readyToIssue();
    const alice = await userId(await join("alice@acme.test", "member"));
    const bob = await userId(await join("bob@acme.test", "member"));
    const carol = await userId(await join("carol@acme.test", "member"));
    const teamId = await createTeam("Web");
    await addToTeam(teamId, bob);
    await addToTeam(teamId, alice);
    const mc = await issued({ owners: [{ type: "user", id: carol }] });
    // The first Certificate is no Renewal, and nobody was subscribed then anyway.
    expect((await delivered()).mail).toEqual([]);

    const mailbox = await emailChannel("Ops list", "ops@acme.test");
    const hook = await webhookChannel("SIEM", "https://hooks.example.test/T000/B000/s3cr3t");
    for (const ref of [{ type: "user", id: alice }, { type: "team", id: teamId }, { type: "channel", id: mailbox.id }, { type: "channel", id: hook.id }]) {
      expect((await subscribe(mc.id, ref)).status).toBe(200);
    }
    await renewNow(mc.id);
    const current = (await api(`/managed-certificates/${mc.id}`)).body.currentCertificate;

    const { mail, posts, to } = await delivered();
    // Alice is subscribed herself and through the Team, but is told once; Carol owns it but did not subscribe.
    expect(to).toEqual(["alice@acme.test", "bob@acme.test", "ops@acme.test"]);
    expect(mail[0]!.subject).toBe(`${mc.names[0]}: renewed`);
    expect(mail[0]!.text).toContain(current.fingerprint);
    expect(posts).toEqual([
      {
        url: "https://hooks.example.test/T000/B000/s3cr3t",
        body: {
          schema: "certificate-platform.notice/1",
          event: "renewal.succeeded",
          occurredAt: expect.any(String),
          organization: { id: org.orgId },
          managedCertificate: { id: mc.id, names: mc.names, url: expect.stringContaining(`/organizations/${org.orgId}/certificates/${mc.id}`) },
          detail: { issuanceId: expect.any(String), certificateId: current.id, fingerprint: current.fingerprint, notAfter: current.notAfter },
          subject: `${mc.names[0]}: renewed`,
        },
      },
    ]);
    // Sent once: the next pass has nothing more.
    expect(await h.deliverNotices()).toBe(0);
  });

  test("a Renewal that fails is told with its cause", async () => {
    await readyToIssue();
    const mc = await issued();
    await subscribe(mc.id, { type: "channel", id: (await emailChannel()).id });
    h.caDirectories.staging = "https://localhost:1/dir";
    await renewNow(mc.id);

    const { mail } = await delivered();
    expect(mail).toEqual([{ to: "ops@acme.test", subject: `${mc.names[0]}: Renewal failed`, text: expect.stringContaining("ca_unreachable") }]);
  });

  test("the first Issuance of a Managed Certificate is no Renewal, so tells nobody, even when it fails", async () => {
    const mc = await created();
    await subscribe(mc.id, { type: "channel", id: (await emailChannel()).id });
    expect((await api(`/managed-certificates/${mc.id}/issuances`, { body: {} })).status).toBe(202);
    await h.settleIssuances();
    expect((await delivered()).mail).toEqual([]);
  });

  test("an Approver's decision on a proposal, approved or rejected, is told with the reason", async () => {
    const proposer = await join("proposer@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");
    const mailbox = await emailChannel();
    const proposed = async () => {
      const res = await api("/managed-certificates", { cookie: proposer, body: { ...(await request()), owners: [] } });
      expect(res.status).toBe(201);
      expect(res.body.approval.status).toBe("pending");
      // The proposer cannot change its Subscribers (they do not own it); an Organization Administrator can.
      expect((await subscribe(res.body.id, { type: "channel", id: mailbox.id })).status).toBe(200);
      return res.body as { id: string; names: string[] };
    };
    const [approved, rejected] = [await proposed(), await proposed()];

    expect((await api(`/managed-certificates/${approved.id}/approve`, { cookie: approver, body: {} })).status).toBe(200);
    expect((await api(`/managed-certificates/${rejected.id}/reject`, { cookie: approver, body: { reason: "use the wildcard instead" } })).status).toBe(200);
    await h.settleIssuances();

    const { mail } = await delivered();
    const about = (mc: { names: string[] }) => mail.find((m) => m.subject.startsWith(`${mc.names[0]}:`))!;
    expect(mail).toHaveLength(2);
    expect(about(approved).subject).toBe(`${approved.names[0]}: the proposal was approved`);
    expect(about(approved).text).toContain("approver@acme.test approved the proposal");
    expect(about(rejected).subject).toBe(`${rejected.names[0]}: the proposal was rejected`);
    expect(about(rejected).text).toContain("Reason: use the wildcard instead");
  });

  test("an Approver's decision on a name change is told, with the names it asked for", async () => {
    const owner = await join("owner@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");
    const mc = await created({ owners: [{ type: "user", id: await userId(owner) }] });
    await subscribe(mc.id, { type: "user", id: await userId(owner) }, { cookie: owner });
    const wanted = await request([host(), host()]);
    expect((await api(`/managed-certificates/${mc.id}/name-change`, { cookie: owner, body: { names: wanted.names, csr: wanted.csr } })).status).toBe(201);
    expect((await api(`/managed-certificates/${mc.id}/name-change/reject`, { cookie: approver, body: { reason: "no" } })).status).toBe(200);

    const { mail } = await delivered();
    expect(mail).toEqual([{ to: "owner@acme.test", subject: `${mc.names[0]}: the name change was rejected`, text: expect.stringContaining(wanted.names.join(", ")) }]);
  });

  test("a Deployment Run that fails is told with the host, the exit code and the output; one that succeeds is not", async () => {
    await readyToIssue();
    const { agent, hostName, managedCertificateId } = await deployed();
    await subscribe(managedCertificateId, { type: "channel", id: (await emailChannel()).id });
    agent.scriptOutcome = { exitCode: 0, output: "installed" };
    await rerun(agent);
    expect((await delivered()).mail).toEqual([]);

    agent.scriptOutcome = { exitCode: 3, output: "cp: cannot create /etc/ssl/site.pem" };
    await rerun(agent);
    const { mail } = await delivered();
    expect(mail).toEqual([{ to: "ops@acme.test", subject: expect.stringContaining(`: Deployment failed on ${hostName}`), text: expect.stringContaining("exited with 3") }]);
    // Not the script's output, which only those who may see the Deployment should read.
    expect(mail[0]!.text).not.toContain("cp: cannot create");
  });

  test("an Agent that goes silent is told once to the Subscribers of what it deploys, and again if it comes back and goes silent again", async () => {
    await readyToIssue();
    const { agent, hostName, managedCertificateId } = await deployed();
    const other = await deployed();
    await subscribe(managedCertificateId, { type: "channel", id: (await emailChannel()).id });
    const started = new Date("2026-01-01T00:00:00Z");

    // Not silent long enough yet: nothing.
    h.setNow(new Date(started.getTime() + 60_000));
    expect((await delivered()).mail).toEqual([]);

    h.setNow(new Date(started.getTime() + 10 * 60_000));
    const { mail } = await delivered();
    expect(mail).toEqual([{ to: "ops@acme.test", subject: expect.stringContaining(`: Agent ${hostName} is offline`), text: expect.stringContaining(hostName) }]);
    // The other Agent is as silent, but nobody subscribed to what it deploys.
    expect(mail[0]!.subject).not.toContain(other.hostName);

    // Still the same silence: told once.
    h.setNow(new Date(started.getTime() + 20 * 60_000));
    expect((await delivered()).mail).toEqual([]);

    // It comes back, then goes silent again.
    expect((await agent.poll()).status).toBe(200);
    h.setNow(new Date(started.getTime() + 40 * 60_000));
    expect((await delivered()).to).toEqual(["ops@acme.test"]);
  });

  test("a Certificate nearing its end is told 14, 7 and 1 days before, once each", async () => {
    await readyToIssue();
    const mc = await issued();
    await subscribe(mc.id, { type: "channel", id: (await emailChannel()).id });
    const notAfter = Date.parse((await api(`/managed-certificates/${mc.id}`)).body.currentCertificate.notAfter);
    const subjects = async () => (await delivered()).mail.map((m) => m.subject);

    h.setNow(new Date(notAfter - 15 * DAY));
    expect(await subjects()).toEqual([]);
    h.setNow(new Date(notAfter - 14 * DAY));
    expect(await subjects()).toEqual([`${mc.names[0]}: its Certificate ends in 14 days`]);
    h.setNow(new Date(notAfter - 10 * DAY));
    expect(await subjects()).toEqual([]);
    h.setNow(new Date(notAfter - 7 * DAY + 3_600_000));
    expect(await subjects()).toEqual([`${mc.names[0]}: its Certificate ends in 7 days`]);
    h.setNow(new Date(notAfter - DAY));
    expect(await subjects()).toEqual([`${mc.names[0]}: its Certificate ends in 1 day`]);
    h.setNow(new Date(notAfter - 3_600_000));
    expect(await subjects()).toEqual([]);
  });

  test("a Certificate first looked at with five days left is told once, not for the fourteenth day too", async () => {
    await readyToIssue();
    const mc = await issued();
    await subscribe(mc.id, { type: "channel", id: (await emailChannel()).id });
    const notAfter = Date.parse((await api(`/managed-certificates/${mc.id}`)).body.currentCertificate.notAfter);
    h.setNow(new Date(notAfter - 5 * DAY));
    expect((await delivered()).mail.map((m) => m.subject)).toEqual([`${mc.names[0]}: its Certificate ends in 5 days`]);
    h.setNow(new Date(notAfter - 4 * DAY));
    expect((await delivered()).mail).toEqual([]);
  });

  test("an archived Managed Certificate is not told of its Certificate's end", async () => {
    await readyToIssue();
    const mc = await issued();
    await subscribe(mc.id, { type: "channel", id: (await emailChannel()).id });
    expect((await api(`/managed-certificates/${mc.id}/archive`, { body: {} })).status).toBe(200);
    const notAfter = Date.parse((await api(`/managed-certificates/${mc.id}`)).body.currentCertificate.notAfter);
    h.setNow(new Date(notAfter - DAY));
    expect((await delivered()).mail).toEqual([]);
  });

  test("a webhook that fails is tried again later with backoff, then given up; email is not held back by it", async () => {
    await readyToIssue();
    const mc = await issued();
    await subscribe(mc.id, { type: "channel", id: (await webhookChannel()).id });
    await subscribe(mc.id, { type: "channel", id: (await emailChannel()).id });
    h.webhooks.failing = true;
    const start = new Date("2026-01-01T00:00:00Z");
    await renewNow(mc.id);

    expect(await h.deliverNotices()).toBe(1);
    expect(h.mailer.sent.map((m) => m.to)).toEqual(["ops@acme.test"]);
    // Not again before its first wait has passed, then again, and again after a longer wait.
    expect(await h.deliverNotices()).toBe(0);
    h.setNow(new Date(start.getTime() + 60_000));
    expect(await h.deliverNotices()).toBe(0);
    h.webhooks.failing = false;
    h.setNow(new Date(start.getTime() + 2 * 60_000));
    expect(await h.deliverNotices()).toBe(0);
    h.setNow(new Date(start.getTime() + 6 * 60_000));
    expect(await h.deliverNotices()).toBe(1);
    expect(h.webhooks.sent.map((w) => w.body.event)).toEqual(["renewal.succeeded"]);

    // One that never gets through is given up after a few tries.
    h.webhooks.failing = true;
    h.webhooks.sent.length = 0;
    await renewNow(mc.id);
    for (let hour = 1; hour <= 48; hour++) {
      h.setNow(new Date(start.getTime() + hour * 3_600_000));
      await h.deliverNotices();
    }
    h.webhooks.failing = false;
    h.setNow(new Date(start.getTime() + 100 * 3_600_000));
    expect(await h.deliverNotices()).toBe(0);
    expect(h.webhooks.sent).toEqual([]);
  });

  test("notices waiting to be sent to a channel that is removed are dropped, for an email channel as for a webhook", async () => {
    await readyToIssue();
    const alice = await userId(await join("alice@acme.test", "member"));
    const mc = await issued();
    const mailbox = await emailChannel("Ops list", "ops@acme.test");
    // Alice's own address is hers, though a channel sends to it too.
    const hers = await emailChannel("Alice's", "alice@acme.test");
    const hook = await webhookChannel();
    for (const ref of [{ type: "user", id: alice }, { type: "channel", id: mailbox.id }, { type: "channel", id: hers.id }, { type: "channel", id: hook.id }]) await subscribe(mc.id, ref);
    await renewNow(mc.id);
    for (const channel of [mailbox, hers, hook]) expect((await api(`/notification-channels/${channel.id}`, { method: "DELETE" })).status).toBe(200);

    const { to, posts } = await delivered();
    expect(to).toEqual(["alice@acme.test"]);
    expect(posts).toEqual([]);
  });

  test("a Subscriber who is not an Owner is told, but still cannot see the Managed Certificate", async () => {
    await readyToIssue();
    const watcher = await join("watcher@acme.test", "member");
    const mc = await issued();
    await subscribe(mc.id, { type: "user", id: await userId(watcher) });
    await renewNow(mc.id);
    expect((await delivered()).to).toEqual(["watcher@acme.test"]);
    expect((await api(`/managed-certificates/${mc.id}`, { cookie: watcher })).status).toBe(403);
    expect((await api(`/managed-certificates/${mc.id}/subscribers`, { cookie: watcher })).status).toBe(403);
    expect((await api("/managed-certificates", { cookie: watcher })).body.items).toEqual([]);
  });

  test("a user removed from the Organization is told nothing more", async () => {
    await readyToIssue();
    const alice = await join("alice@acme.test", "member");
    const mc = await issued();
    await subscribe(mc.id, { type: "user", id: await userId(alice) });
    await removeMember(await userId(alice));
    await renewNow(mc.id);
    expect((await delivered()).mail).toEqual([]);
  });
});
