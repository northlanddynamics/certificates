import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { managedCertificate } from "../src/db/schema";
import { PASSWORD, createHarness, type Harness } from "./harness";

let h: Harness;
beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
});
afterAll(async () => {
  await h.close();
});

const createOrgWithAdmin = (operatorCookie: string, slug: string, adminEmail: string) =>
  h.createOrgWithAdmin(operatorCookie, slug, adminEmail);

describe("walking skeleton", () => {
  test("operator creates an Organization and invites its first administrator by email", async () => {
    const operator = await h.createOperator("op@platform.test", PASSWORD);
    const res = await h.api("/api/platform/organizations", {
      cookie: operator,
      body: { name: "Acme", slug: "acme", adminEmail: "admin@acme.test" },
    });
    expect(res.status).toBe(201);
    expect(h.mailer.sent).toHaveLength(1);
    expect(h.mailer.sent[0]!.to).toBe("admin@acme.test");
    expect(h.mailer.sent[0]!.text).toContain(res.body.invitationId);
  });

  test("only a Platform Operator can create Organizations", async () => {
    const user = await h.signUp("someone@acme.test", PASSWORD);
    const res = await h.api("/api/platform/organizations", {
      cookie: user,
      body: { name: "Rogue", slug: "rogue", adminEmail: "x@rogue.test" },
    });
    expect(res.status).toBe(403);
    const anon = await h.api("/api/platform/organizations", {
      body: { name: "Rogue", slug: "rogue", adminEmail: "x@rogue.test" },
    });
    expect(anon.status).toBe(401);
  });

  test("invited administrator accepts, signs in and sees an empty inventory", async () => {
    const operator = await h.createOperator("op@platform.test", PASSWORD);
    const { orgId, cookie } = await createOrgWithAdmin(operator, "acme", "admin@acme.test");

    const me = await h.api("/api/me", { cookie });
    expect(me.body.organizations).toEqual([
      {
        id: orgId,
        name: "Org acme",
        slug: "acme",
        role: "organization-administrator",
        permissions: expect.objectContaining({ invitation: ["create", "cancel"] }),
      },
    ]);
    const inventory = await h.api(`/api/organizations/${orgId}/managed-certificates`, { cookie });
    expect(inventory.status).toBe(200);
    expect(inventory.body).toEqual({ items: [] });
  });

  test("an invitation can only be accepted by the invited email, and only once", async () => {
    const operator = await h.createOperator("op@platform.test", PASSWORD);
    const created = await h.api("/api/platform/organizations", {
      cookie: operator,
      body: { name: "Acme", slug: "acme", adminEmail: "admin@acme.test" },
    });
    const url = "/api/auth/organization/accept-invitation";
    const body = { invitationId: created.body.invitationId };
    const wrong = await h.signUp("intruder@evil.test", PASSWORD);
    expect((await h.api(url, { cookie: wrong, body })).status).toBe(403);

    const right = await h.signUp("admin@acme.test", PASSWORD);
    expect((await h.api(url, { cookie: right, body })).status).toBe(200);
    expect((await h.api(url, { cookie: right, body })).status).toBe(400); // spent: Better Auth calls it not found

    // Only the one successful acceptance (plus the Organization's creation) was audited.
    const admin = await h.signIn("admin@acme.test", PASSWORD);
    const audit = await h.api(`/api/organizations/${created.body.id}/audit-events`, { cookie: admin });
    expect(audit.body.items.map((e: any) => e.action)).toEqual(["organization.created", "invitation.accepted"]);
  });

  test("users of one Organization cannot see or reach another Organization", async () => {
    const operator = await h.createOperator("op@platform.test", PASSWORD);
    const a = await createOrgWithAdmin(operator, "a", "admin@a.test");
    const b = await createOrgWithAdmin(operator, "b", "admin@b.test");

    expect((await h.api(`/api/organizations/${b.orgId}/managed-certificates`, { cookie: a.cookie })).status).toBe(404);
    expect((await h.api(`/api/organizations/${b.orgId}/audit-events`, { cookie: a.cookie })).status).toBe(404);
    const meA = await h.api("/api/me", { cookie: a.cookie });
    expect(meA.body.organizations.map((o: any) => o.id)).toEqual([a.orgId]);
    // Rows that exist in B never leak into A's inventory.
    await h.db.insert(managedCertificate).values({ organizationId: b.orgId });
    const inv = await h.api(`/api/organizations/${a.orgId}/managed-certificates`, { cookie: a.cookie });
    expect(inv.body.items).toEqual([]);
  });

  test("a Platform Operator cannot see inside an Organization they were not invited into", async () => {
    const operator = await h.createOperator("op@platform.test", PASSWORD);
    const a = await createOrgWithAdmin(operator, "a", "admin@a.test");
    expect((await h.api(`/api/organizations/${a.orgId}/managed-certificates`, { cookie: operator })).status).toBe(404);
    expect((await h.api(`/api/organizations/${a.orgId}/audit-events`, { cookie: operator })).status).toBe(404);
    const list = await h.api("/api/platform/organizations", { cookie: operator });
    expect(list.body.items).toEqual([{ id: a.orgId, name: "Org a", slug: "a" }]);
  });

  test("creating an Organization and accepting an invitation each write an Audit Event", async () => {
    h.setNow(new Date("2026-03-01T10:00:00Z"));
    const operator = await h.createOperator("op@platform.test", PASSWORD);
    const { orgId, cookie } = await createOrgWithAdmin(operator, "acme", "admin@acme.test");
    const res = await h.api(`/api/organizations/${orgId}/audit-events`, { cookie });
    expect(res.status).toBe(200);
    const events = res.body.items.map((e: any) => ({
      action: e.action,
      actor: e.actor.email,
      targetType: e.target.type,
      at: e.occurredAt,
    }));
    expect(events).toEqual([
      { action: "organization.created", actor: "op@platform.test", targetType: "organization", at: "2026-03-01T10:00:00.000Z" },
      { action: "invitation.accepted", actor: "admin@acme.test", targetType: "invitation", at: "2026-03-01T10:00:00.000Z" },
    ]);
  });

  test("a failed state change leaves no Audit Event, and Audit Events cannot be altered", async () => {
    const operator = await h.createOperator("op@platform.test", PASSWORD);
    const first = await h.api("/api/platform/organizations", {
      cookie: operator,
      body: { name: "Acme", slug: "acme", adminEmail: "admin@acme.test" },
    });
    expect(first.status).toBe(201);
    const dupe = await h.api("/api/platform/organizations", {
      cookie: operator,
      body: { name: "Acme 2", slug: "acme", adminEmail: "other@acme.test" },
    });
    expect(dupe.status).toBe(409);
    const count = await h.pool.query(`select count(*)::int as n from audit_event`);
    expect(count.rows[0].n).toBe(1);
    expect(h.mailer.sent).toHaveLength(1);

    await expect(h.pool.query(`update audit_event set action = 'x'`)).rejects.toThrow();
    await expect(h.pool.query(`delete from audit_event`)).rejects.toThrow();
  });

  test("the HTTP API is described by OpenAPI generated from the route schemas", async () => {
    const res = await h.api("/api/openapi.json");
    expect(res.status).toBe(200);
    expect(res.body.openapi).toStartWith("3.");
    expect(Object.keys(res.body.paths)).toEqual(
      expect.arrayContaining([
        "/api/platform/organizations",
        "/api/me",
        "/api/organizations/{orgId}/managed-certificates",
        "/api/organizations/{orgId}/audit-events",
      ]),
    );
  });

  test("one API reference page shows the platform routes and Better Auth's own routes", async () => {
    const auth = await h.api("/api/auth/open-api/generate-schema");
    expect(auth.status).toBe(200);
    expect(Object.keys(auth.body.paths)).toEqual(expect.arrayContaining(["/sign-in/email", "/sign-up/email"]));

    const res = await h.app.request("http://localhost/api/docs");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    const html = await res.text();
    expect(html).toContain("/api/openapi.json");
    expect(html).toContain("/api/auth/open-api/generate-schema");
  });
});
