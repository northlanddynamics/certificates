// Audit search and SIEM forwarding, through the platform's HTTP API: Organization Administrators search and filter their
// Organization's Audit Events, and forward them to a SIEM by webhook or syslog in the stable JSON schema
// `certificate-platform.audit/1` (docs/audit-events.md). What forwarders send is captured, not sent, and time is the
// harness's clock.
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { readFileSync } from "node:fs";
import { AUDIT_ACTIONS } from "../src/audit/audit";
import { PASSWORD, createHarness, type Harness } from "./support/harness";

setDefaultTimeout(30_000);

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
});
afterAll(async () => {
  await h.close();
});

const BA = "/api/auth/organization";
const api = (path: string, opts: { cookie?: string; body?: unknown; method?: string; target?: Org } = {}) =>
  h.api(`/api/organizations/${(opts.target ?? org).orgId}${path}`, { cookie: opts.cookie ?? (opts.target ?? org).cookie, body: opts.body, method: opts.method });
const search = (query: Record<string, string> = {}, opts: { cookie?: string; target?: Org } = {}) => api(`/audit-events?${new URLSearchParams(query)}`, opts);
const actions = async (query: Record<string, string> = {}) => ((await search(query)).body.items as { action: string }[]).map((e) => e.action);

async function join(email: string, role: string, target: Org = org) {
  const invited = await h.api(`${BA}/invite-member`, { cookie: target.cookie, body: { email, role, organizationId: target.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api(`${BA}/accept-invitation`, { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}
const createTeam = async (name: string, cookie = org.cookie) => (await h.api(`${BA}/create-team`, { cookie, body: { name, organizationId: org.orgId } })).body.id as string;

describe("searching the audit log", () => {
  test("filters by action, by an action's prefix, by target and by actor", async () => {
    const other = await join("other@acme.test", "organization-administrator");
    const web = await createTeam("Web");
    await createTeam("Ops", other);
    expect(await actions({ action: "team.created" })).toEqual(["team.created", "team.created"]);
    expect(await actions({ action: "invitation.*" })).toEqual(["invitation.accepted", "invitation.created", "invitation.accepted"]);
    expect((await search({ targetType: "team", targetId: web })).body.items).toMatchObject([{ action: "team.created", target: { type: "team", id: web }, actor: { email: "admin@acme.test" } }]);
    expect(await actions({ actor: "other@acme.test" })).toEqual(["invitation.accepted", "team.created"]);
  });

  test("filters by time range, newest first if asked, a page at a time", async () => {
    for (const [at, name] of [["2026-02-01T00:00:00Z", "A"], ["2026-02-02T00:00:00Z", "B"], ["2026-02-03T00:00:00Z", "C"], ["2026-02-04T00:00:00Z", "D"]] as const) {
      h.setNow(new Date(at));
      await createTeam(name);
    }
    const names = (res: { body: { items: { detail: any }[] } }) => res.body.items.map((e) => e.detail.name);
    const range = { action: "team.created", from: "2026-02-02T00:00:00Z", to: "2026-02-04T00:00:00Z" };
    expect(names(await search(range))).toEqual(["B", "C"]);
    expect(names(await search({ ...range, order: "desc" }))).toEqual(["C", "B"]);

    const first = await search({ action: "team.created", order: "desc", limit: "3" });
    expect(names(first)).toEqual(["D", "C", "B"]);
    const second = await search({ action: "team.created", order: "desc", limit: "3", cursor: first.body.nextCursor });
    expect(names(second)).toEqual(["A"]);
    expect(second.body.nextCursor).toBeNull();
  });

  test("a bad filter is refused, and only an Organization Administrator of the Organization may search", async () => {
    for (const query of [{ from: "yesterday" }, { action: "team created" }, { limit: "0" }, { limit: "501" }, { cursor: "x" }, { order: "sideways" }] as Record<string, string>[]) {
      expect((await search(query)).status).toBe(400);
    }
    for (const cookie of [await join("member@acme.test", "member"), await join("approver@acme.test", "approver")]) {
      expect((await search({}, { cookie })).status).toBe(403);
    }
    expect((await search({}, { cookie: globex.cookie })).status).toBe(404);
  });

  test("nothing in the API changes or deletes an Audit Event", async () => {
    const doc = (await h.api("/api/openapi.json")).body;
    const auditPaths = Object.entries(doc.paths as Record<string, Record<string, unknown>>).filter(([path]) => path.includes("audit-events"));
    expect(auditPaths.flatMap(([, ops]) => Object.keys(ops))).toEqual(["get"]);
    const [event] = (await search({ limit: "1" })).body.items;
    for (const method of ["DELETE", "PUT", "PATCH"]) {
      for (const path of [`/audit-events/${event.id}`, "/audit-events"]) {
        const res = await h.app.request(`http://localhost/api/organizations/${org.orgId}${path}`, { method, headers: { cookie: org.cookie, origin: "http://localhost" } });
        expect(res.status).toBe(404);
      }
    }
    expect((await search()).body.items[0]).toEqual(event);
  });
});

const forwarders = (opts: { cookie?: string; target?: Org } = {}) => api("/audit-forwarders", opts);
const addForwarder = (body: unknown, opts: { cookie?: string; target?: Org } = {}) => api("/audit-forwarders", { ...opts, body });
const SIEM_URL = "https://siem.example.test/services/collector/s3cr3t";
async function webhookForwarder(target: Org = org) {
  const created = await addForwarder({ name: "NG-SIEM", kind: "webhook", url: SIEM_URL, authorization: "Bearer t0k3n" }, { target });
  expect(created.status).toBe(201);
  return created.body as { id: string };
}

describe("forwarding to a SIEM", () => {
  test("a webhook forwarder is sent each Audit Event after it was added, in the documented schema, with its Authorization header", async () => {
    h.setNow(new Date("2026-02-01T09:00:00Z"));
    const forwarder = await webhookForwarder();
    const web = await createTeam("Web");
    expect(await h.forwardAudit()).toBe(2);

    expect(h.auditTransport.sent.map((s) => s.destination)).toEqual([
      { kind: "webhook", url: SIEM_URL, authorization: "Bearer t0k3n" },
      { kind: "webhook", url: SIEM_URL, authorization: "Bearer t0k3n" },
    ]);
    const [created, team] = h.auditTransport.sent.map((s) => s.event);
    expect(created).toMatchObject({ schema: "certificate-platform.audit/1", action: "audit_forwarder.created", target: { type: "audit_forwarder", id: forwarder.id } });
    expect(team).toEqual({
      schema: "certificate-platform.audit/1",
      id: expect.stringMatching(/^\d+$/),
      occurredAt: "2026-02-01T09:00:00.000Z",
      organization: { id: org.orgId },
      actor: { id: expect.any(String), email: "admin@acme.test" },
      action: "team.created",
      target: { type: "team", id: web },
      detail: expect.objectContaining({ name: "Web" }),
    });
    // What the API shows is the same event, less the envelope.
    const { schema: _schema, organization: _org, ...shown } = team;
    expect((await search({ targetId: web })).body.items).toEqual([shown]);

    expect(await h.forwardAudit()).toBe(0);
  });

  test("an unreachable SIEM is tried again, later and later, until every event reaches it, in the order recorded", async () => {
    h.setNow(new Date("2026-02-01T09:00:00Z"));
    await webhookForwarder();
    h.auditTransport.failing = true;
    expect(await h.forwardAudit()).toBe(0);
    await createTeam("Web");
    await createTeam("Ops");

    const [failing] = (await forwarders()).body.items;
    expect(failing).toMatchObject({ backlog: 3, lastError: "the receiver answered 503", nextAttemptAt: "2026-02-01T09:01:00.000Z", lastDeliveredAt: null });
    // Not tried again before its time, then waiting longer each time it fails.
    expect(await h.forwardAudit()).toBe(0);
    h.setNow(new Date("2026-02-01T09:01:00Z"));
    expect(await h.forwardAudit()).toBe(0);
    expect((await forwarders()).body.items[0].nextAttemptAt).toBe("2026-02-01T09:06:00.000Z");
    for (const at of ["2026-02-01T09:06:00Z", "2026-02-01T09:36:00Z", "2026-02-01T10:36:00Z", "2026-02-01T11:36:00Z", "2026-02-01T12:36:00Z"]) {
      h.setNow(new Date(at));
      expect(await h.forwardAudit()).toBe(0);
    }
    // It is never given up.
    expect((await forwarders()).body.items[0]).toMatchObject({ backlog: 3, nextAttemptAt: "2026-02-01T13:36:00.000Z" });

    h.auditTransport.failing = false;
    h.setNow(new Date("2026-02-01T13:36:00Z"));
    expect(await h.forwardAudit()).toBe(3);
    expect(h.auditTransport.sent.map((s) => [s.event.action, s.event.detail.name])).toEqual([
      ["audit_forwarder.created", "NG-SIEM"],
      ["team.created", "Web"],
      ["team.created", "Ops"],
    ]);
    expect((await forwarders()).body.items[0]).toMatchObject({ backlog: 0, lastError: null, nextAttemptAt: null, lastDeliveredAt: "2026-02-01T13:36:00.000Z" });
  });

  test("a receiver that takes part of the queue before failing is sent the rest after the shortest wait", async () => {
    h.setNow(new Date("2026-02-01T09:00:00Z"));
    await webhookForwarder();
    h.auditTransport.failing = true;
    for (const at of ["2026-02-01T09:00:00Z", "2026-02-01T09:01:00Z", "2026-02-01T09:06:00Z"]) {
      h.setNow(new Date(at));
      await h.forwardAudit();
    }
    await createTeam("Web");
    await createTeam("Ops");
    h.auditTransport.failing = false;
    h.auditTransport.failingAfter = 2;
    h.setNow(new Date("2026-02-01T09:36:00Z"));
    expect(await h.forwardAudit()).toBe(2);
    expect((await forwarders()).body.items[0]).toMatchObject({ backlog: 1, nextAttemptAt: "2026-02-01T09:37:00.000Z", lastDeliveredAt: "2026-02-01T09:36:00.000Z" });
    h.setNow(new Date("2026-02-01T09:37:00Z"));
    expect(await h.forwardAudit()).toBe(1);
    expect(h.auditTransport.sent.map((s) => s.event.action)).toEqual(["audit_forwarder.created", "team.created", "team.created"]);
  });

  test("a syslog forwarder is sent to its receiver; what was recorded before a forwarder was added, or in another Organization, is not sent", async () => {
    await createTeam("Before");
    const created = await addForwarder({ name: "Collector", kind: "syslog", host: "Collector.Example.test" });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ name: "Collector", kind: "syslog", host: "collector.example.test", port: 6514, backlog: 1 });
    await createTeam("After");
    await h.api(`${BA}/create-team`, { cookie: globex.cookie, body: { name: "Theirs", organizationId: globex.orgId } });
    await h.forwardAudit();
    expect(h.auditTransport.sent.map((s) => s.destination)).toEqual([
      { kind: "syslog", host: "collector.example.test", port: 6514 },
      { kind: "syslog", host: "collector.example.test", port: 6514 },
    ]);
    expect(h.auditTransport.sent.map((s) => s.event.action)).toEqual(["audit_forwarder.created", "team.created"]);
    expect(h.auditTransport.sent[1]!.event).toMatchObject({ organization: { id: org.orgId }, detail: { name: "After" } });
  });

  test("a webhook's URL and Authorization header are never shown or audited, only its host", async () => {
    const { id } = await webhookForwarder();
    const listed = await forwarders();
    expect(listed.body.items).toEqual([
      { id, name: "NG-SIEM", kind: "webhook", host: "siem.example.test", port: null, createdAt: expect.any(String), backlog: 1, lastDeliveredAt: null, lastError: null, nextAttemptAt: null },
    ]);
    expect((await search({ action: "audit_forwarder.created" })).body.items).toMatchObject([
      { actor: { email: "admin@acme.test" }, target: { type: "audit_forwarder", id }, detail: { name: "NG-SIEM", kind: "webhook", host: "siem.example.test" } },
    ]);
    for (const shown of [listed.body, (await search()).body]) {
      expect(JSON.stringify(shown)).not.toContain("s3cr3t");
      expect(JSON.stringify(shown)).not.toContain("t0k3n");
    }
  });

  test("removing a forwarder is audited, and it is sent nothing more", async () => {
    const { id } = await webhookForwarder();
    await createTeam("Web");
    expect((await api(`/audit-forwarders/${id}`, { method: "DELETE" })).body).toEqual({ deleted: true });
    expect((await forwarders()).body.items).toEqual([]);
    expect((await search({ action: "audit_forwarder.deleted" })).body.items).toMatchObject([
      { actor: { email: "admin@acme.test" }, target: { type: "audit_forwarder", id }, detail: { name: "NG-SIEM", kind: "webhook", host: "siem.example.test" } },
    ]);
    expect(await h.forwardAudit()).toBe(0);
    expect(h.auditTransport.sent).toEqual([]);
    expect((await api(`/audit-forwarders/${id}`, { method: "DELETE" })).status).toBe(404);
  });

  test("a forwarder needs an https URL or a syslog host that is not internal, and names are not shared", async () => {
    for (const body of [
      { name: "x", kind: "webhook", url: "http://siem.example.test/x" },
      { name: "x", kind: "webhook", url: "https://10.0.0.1/x" },
      { name: "x", kind: "webhook", url: "https://localhost/x" },
      { name: "x", kind: "webhook", url: SIEM_URL, authorization: "Bearer a\r\nX-Injected: 1" },
      { name: "x", kind: "syslog", host: "127.0.0.1" },
      { name: "x", kind: "syslog", host: "192.168.1.10", port: 514 },
      { name: "x", kind: "syslog", host: "not a host" },
      { name: "x", kind: "syslog", host: "collector.example.test", port: 0 },
      { name: "x", kind: "kafka", host: "collector.example.test" },
      { name: "", kind: "syslog", host: "collector.example.test" },
    ]) {
      expect((await addForwarder(body)).status).toBe(400);
    }
    await webhookForwarder();
    expect((await addForwarder({ name: "ng-siem", kind: "syslog", host: "collector.example.test" })).status).toBe(409);
    expect((await forwarders()).body.items).toHaveLength(1);
  });

  test("only an Organization Administrator of the Organization sees or configures forwarders", async () => {
    const { id } = await webhookForwarder();
    for (const cookie of [await join("member@acme.test", "member"), await join("approver@acme.test", "approver")]) {
      expect((await forwarders({ cookie })).status).toBe(403);
      expect((await addForwarder({ name: "Mine", kind: "syslog", host: "collector.example.test" }, { cookie })).status).toBe(403);
      expect((await api(`/audit-forwarders/${id}`, { cookie, method: "DELETE" })).status).toBe(403);
    }
    expect((await forwarders({ target: globex })).body.items).toEqual([]);
    expect((await api(`/audit-forwarders/${id}`, { target: globex, method: "DELETE" })).status).toBe(404);
    expect((await forwarders()).body.items).toHaveLength(1);
  });

  test("the schema's documentation names every action there is", () => {
    const doc = readFileSync(new URL("../../docs/audit-events.md", import.meta.url), "utf8").split("## Actions")[1]!;
    const documented = new Set([...doc.matchAll(/^\| `([a-z_]+)` \| (.+) \|$/gm)].flatMap(([, resource, verbs]) => [...verbs!.matchAll(/`([a-z_]+)`/g)].map(([, verb]) => `${resource}.${verb}`)));
    expect([...AUDIT_ACTIONS].filter((a) => !documented.has(a))).toEqual([]);
    expect([...documented].filter((a) => !(AUDIT_ACTIONS as readonly string[]).includes(a))).toEqual([]);
  });
});
