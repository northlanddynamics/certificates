import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import type { Permissions } from "../src/auth";
import { roleCan } from "../src/authorization";
import { memberRemovalHooks } from "../src/member-removal";
import { PASSWORD, createHarness, type Harness } from "./harness";

let h: Harness;
let operator: string;
let acme: { orgId: string; cookie: string };

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  operator = await h.createOperator("op@platform.test", PASSWORD);
  acme = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
});
afterAll(async () => {
  await h.close();
});

const org = (path: string, orgId = acme.orgId) => `/api/organizations/${orgId}${path}`;

/** The admin invites `email` with `role`; the invitee signs up, accepts and signs in. */
async function join(email: string, role: string, orgId = acme.orgId, adminCookie = acme.cookie) {
  const invited = await h.api(org("/invitations", orgId), { cookie: adminCookie, body: { email, role } });
  expect(invited.status).toBe(201);
  const cookie = await h.signUp(email, PASSWORD);
  const accepted = await h.api(`/api/invitations/${invited.body.id}/accept`, { cookie, method: "POST" });
  expect(accepted.status).toBe(200);
  return h.signIn(email, PASSWORD);
}

async function members(cookie = acme.cookie, orgId = acme.orgId) {
  const res = await h.api(org("/members", orgId), { cookie });
  expect(res.status).toBe(200);
  return res.body.items as { id: string; userId: string; email: string; role: string }[];
}
const memberOf = async (email: string) => (await members()).find((m) => m.email === email)!;
const auditActions = async () =>
  (await h.api(org("/audit-events"), { cookie: acme.cookie })).body.items.map((e: any) => e.action) as string[];

describe("invitations", () => {
  test("an administrator invites users as Member, Approver or Organization Administrator", async () => {
    for (const role of ["member", "approver", "organization-administrator"]) {
      const email = `${role}@acme.test`;
      const res = await h.api(org("/invitations"), { cookie: acme.cookie, body: { email, role } });
      expect(res.status).toBe(201);
      expect(h.mailer.sent.at(-1)!.to).toBe(email);
      expect(h.mailer.sent.at(-1)!.text).toContain(res.body.id);

      const cookie = await h.signUp(email, PASSWORD);
      await h.api(`/api/invitations/${res.body.id}/accept`, { cookie, method: "POST" });
      const me = await h.api("/api/me", { cookie });
      expect(me.body.organizations[0].role).toBe(role);
    }
  });

  test("only the three roles can be assigned, and 'owner' is not one of them", async () => {
    for (const role of ["owner", "admin", ""]) {
      const res = await h.api(org("/invitations"), { cookie: acme.cookie, body: { email: "x@acme.test", role } });
      expect(res.status).toBe(400);
    }
  });

  test("only an Organization Administrator can invite, list or cancel invitations", async () => {
    const memberCookie = await join("m@acme.test", "member");
    const approverCookie = await join("a@acme.test", "approver");
    const pending = await h.api(org("/invitations"), { cookie: acme.cookie, body: { email: "new@acme.test", role: "member" } });
    for (const cookie of [memberCookie, approverCookie]) {
      expect((await h.api(org("/invitations"), { cookie, body: { email: "n@acme.test", role: "member" } })).status).toBe(403);
      expect((await h.api(org("/invitations"), { cookie })).status).toBe(403);
      expect((await h.api(org(`/invitations/${pending.body.id}`), { cookie, method: "DELETE" })).status).toBe(403);
    }
  });

  test("inviting an existing member, or someone already invited, is a conflict", async () => {
    await join("m@acme.test", "member");
    const again = await h.api(org("/invitations"), { cookie: acme.cookie, body: { email: "M@acme.test", role: "approver" } });
    expect(again.status).toBe(409);
    const first = await h.api(org("/invitations"), { cookie: acme.cookie, body: { email: "p@acme.test", role: "member" } });
    expect(first.status).toBe(201);
    const second = await h.api(org("/invitations"), { cookie: acme.cookie, body: { email: "p@acme.test", role: "member" } });
    expect(second.status).toBe(409);
  });

  test("pending invitations are listed; a cancelled one can no longer be accepted", async () => {
    const inv = await h.api(org("/invitations"), { cookie: acme.cookie, body: { email: "p@acme.test", role: "approver" } });
    const list = await h.api(org("/invitations"), { cookie: acme.cookie });
    expect(list.body.items).toEqual([{ id: inv.body.id, email: "p@acme.test", role: "approver", expiresAt: expect.any(String) }]);

    expect((await h.api(org(`/invitations/${inv.body.id}`), { cookie: acme.cookie, method: "DELETE" })).status).toBe(204);
    expect((await h.api(org("/invitations"), { cookie: acme.cookie })).body.items).toEqual([]);
    const cookie = await h.signUp("p@acme.test", PASSWORD);
    expect((await h.api(`/api/invitations/${inv.body.id}/accept`, { cookie, method: "POST" })).status).toBe(404);
    expect(await auditActions()).toContain("invitation.canceled");
  });

  test("an invitation cannot be created or cancelled across Organizations", async () => {
    const other = await h.createOrgWithAdmin(operator, "other", "admin@other.test");
    const res = await h.api(org("/invitations", other.orgId), { cookie: acme.cookie, body: { email: "x@a.test", role: "member" } });
    expect(res.status).toBe(404);
    const inv = await h.api(org("/invitations", other.orgId), { cookie: other.cookie, body: { email: "x@a.test", role: "member" } });
    const cancel = await h.api(org(`/invitations/${inv.body.id}`), { cookie: acme.cookie, method: "DELETE" });
    expect(cancel.status).toBe(404);
  });
});

describe("roles", () => {
  test("an Organization Administrator changes a member's role, and the change takes effect at once", async () => {
    const cookie = await join("m@acme.test", "member");
    expect((await h.api(org("/invitations"), { cookie, body: { email: "n@acme.test", role: "member" } })).status).toBe(403);

    const target = await memberOf("m@acme.test");
    const res = await h.api(org(`/members/${target.id}`), { cookie: acme.cookie, method: "PATCH", body: { role: "organization-administrator" } });
    expect(res.status).toBe(200);
    expect(res.body.role).toBe("organization-administrator");
    expect((await h.api(org("/invitations"), { cookie, body: { email: "n@acme.test", role: "member" } })).status).toBe(201);
  });

  test("only an Organization Administrator can change roles", async () => {
    const memberCookie = await join("m@acme.test", "member");
    const approverCookie = await join("a@acme.test", "approver");
    const admin = await memberOf("admin@acme.test");
    const target = await memberOf("m@acme.test");
    for (const cookie of [memberCookie, approverCookie]) {
      for (const id of [admin.id, target.id]) {
        const res = await h.api(org(`/members/${id}`), { cookie, method: "PATCH", body: { role: "organization-administrator" } });
        expect(res.status).toBe(403);
      }
    }
    expect((await memberOf("m@acme.test")).role).toBe("member");
  });

  test("an invalid role is rejected", async () => {
    const target = await memberOf("admin@acme.test");
    const res = await h.api(org(`/members/${target.id}`), { cookie: acme.cookie, method: "PATCH", body: { role: "owner" } });
    expect(res.status).toBe(400);
  });

  test("the last Organization Administrator cannot be demoted or removed", async () => {
    const self = await memberOf("admin@acme.test");
    const demote = await h.api(org(`/members/${self.id}`), { cookie: acme.cookie, method: "PATCH", body: { role: "member" } });
    expect(demote.status).toBe(409);
    const remove = await h.api(org(`/members/${self.id}`), { cookie: acme.cookie, method: "DELETE" });
    expect(remove.status).toBe(409);

    await join("second@acme.test", "organization-administrator");
    const ok = await h.api(org(`/members/${self.id}`), { cookie: acme.cookie, method: "PATCH", body: { role: "member" } });
    expect(ok.status).toBe(200);
  });

  test("a member of another Organization cannot be reached", async () => {
    const other = await h.createOrgWithAdmin(operator, "other", "admin@other.test");
    const theirs = (await members(other.cookie, other.orgId))[0]!;
    const res = await h.api(org(`/members/${theirs.id}`), { cookie: acme.cookie, method: "PATCH", body: { role: "member" } });
    expect(res.status).toBe(404);
    expect((await h.api(org(`/members/${theirs.id}`), { cookie: acme.cookie, method: "DELETE" })).status).toBe(404);
    expect((await members(other.cookie, other.orgId))[0]!.role).toBe("organization-administrator");
  });

  test("any member can read the member list", async () => {
    const cookie = await join("m@acme.test", "member");
    expect((await members(cookie)).map((m) => m.email).sort()).toEqual(["admin@acme.test", "m@acme.test"]);
  });

  test("role changes are audited with the old and new role", async () => {
    await join("m@acme.test", "member");
    const target = await memberOf("m@acme.test");
    await h.api(org(`/members/${target.id}`), { cookie: acme.cookie, method: "PATCH", body: { role: "approver" } });
    const events = (await h.api(org("/audit-events"), { cookie: acme.cookie })).body.items;
    const event = events.find((e: any) => e.action === "member.role_changed");
    expect(event).toMatchObject({
      actor: { email: "admin@acme.test" },
      target: { type: "member", id: target.id },
      detail: { email: "m@acme.test", from: "member", to: "approver" },
    });
    // Setting the role it already has changes nothing and is not audited.
    await h.api(org(`/members/${target.id}`), { cookie: acme.cookie, method: "PATCH", body: { role: "approver" } });
    expect((await auditActions()).filter((a) => a === "member.role_changed")).toHaveLength(1);
  });
});

describe("Teams", () => {
  const createTeam = async (name: string, cookie = acme.cookie, orgId = acme.orgId) =>
    h.api(org("/teams", orgId), { cookie, body: { name } });

  test("an administrator creates, renames and deletes Teams", async () => {
    const created = await createTeam("Platform");
    expect(created.status).toBe(201);
    const id = created.body.id;
    expect((await h.api(org(`/teams/${id}`), { cookie: acme.cookie, method: "PATCH", body: { name: "Infra" } })).status).toBe(200);
    const list = await h.api(org("/teams"), { cookie: acme.cookie });
    expect(list.body.items).toEqual([{ id, name: "Infra", members: [] }]);
    expect((await h.api(org(`/teams/${id}`), { cookie: acme.cookie, method: "DELETE" })).status).toBe(204);
    expect((await h.api(org("/teams"), { cookie: acme.cookie })).body.items).toEqual([]);
    expect(await auditActions()).toEqual(
      expect.arrayContaining(["team.created", "team.renamed", "team.deleted"]),
    );
  });

  test("only administrators change Teams; every member can read them", async () => {
    const created = await createTeam("Platform");
    const id = created.body.id;
    const memberCookie = await join("m@acme.test", "member");
    const approverCookie = await join("a@acme.test", "approver");
    const user = await memberOf("m@acme.test");
    for (const cookie of [memberCookie, approverCookie]) {
      expect((await createTeam("Nope", cookie)).status).toBe(403);
      expect((await h.api(org(`/teams/${id}`), { cookie, method: "PATCH", body: { name: "Nope" } })).status).toBe(403);
      expect((await h.api(org(`/teams/${id}`), { cookie, method: "DELETE" })).status).toBe(403);
      expect((await h.api(org(`/teams/${id}/members`), { cookie, body: { userId: user.userId } })).status).toBe(403);
      expect((await h.api(org(`/teams/${id}/members/${user.userId}`), { cookie, method: "DELETE" })).status).toBe(403);
      expect((await h.api(org("/teams"), { cookie })).body.items).toHaveLength(1);
    }
  });

  test("Team names are unique within an Organization, not across them", async () => {
    await createTeam("Platform");
    expect((await createTeam("platform")).status).toBe(409);
    const second = await createTeam("Security");
    const rename = await h.api(org(`/teams/${second.body.id}`), { cookie: acme.cookie, method: "PATCH", body: { name: "PLATFORM" } });
    expect(rename.status).toBe(409);
    const other = await h.createOrgWithAdmin(operator, "other", "admin@other.test");
    expect((await createTeam("Platform", other.cookie, other.orgId)).status).toBe(201);
  });

  test("users are added to and removed from a Team; only Organization members can be added", async () => {
    const team = (await createTeam("Platform")).body.id;
    await join("m@acme.test", "member");
    const user = await memberOf("m@acme.test");
    const add = await h.api(org(`/teams/${team}/members`), { cookie: acme.cookie, body: { userId: user.userId } });
    expect(add.status).toBe(204);
    // Adding someone who is already in the Team changes nothing, and is not audited again.
    expect((await h.api(org(`/teams/${team}/members`), { cookie: acme.cookie, body: { userId: user.userId } })).status).toBe(204);
    expect((await auditActions()).filter((a) => a === "team.member_added")).toHaveLength(1);
    const listed = (await h.api(org("/teams"), { cookie: acme.cookie })).body.items[0];
    expect(listed.members).toEqual([{ userId: user.userId, email: "m@acme.test" }]);

    const outsider = await h.createOrgWithAdmin(operator, "other", "admin@other.test");
    const outsiderId = (await members(outsider.cookie, outsider.orgId))[0]!.userId;
    expect((await h.api(org(`/teams/${team}/members`), { cookie: acme.cookie, body: { userId: outsiderId } })).status).toBe(404);

    expect((await h.api(org(`/teams/${team}/members/${user.userId}`), { cookie: acme.cookie, method: "DELETE" })).status).toBe(204);
    expect((await h.api(org(`/teams/${team}/members/${user.userId}`), { cookie: acme.cookie, method: "DELETE" })).status).toBe(404);
    expect((await h.api(org("/teams"), { cookie: acme.cookie })).body.items[0].members).toEqual([]);
    expect(await auditActions()).toEqual(expect.arrayContaining(["team.member_added", "team.member_removed"]));
  });

  test("a Team of another Organization cannot be reached", async () => {
    const other = await h.createOrgWithAdmin(operator, "other", "admin@other.test");
    const theirs = (await createTeam("Theirs", other.cookie, other.orgId)).body.id;
    expect((await h.api(org(`/teams/${theirs}`), { cookie: acme.cookie, method: "PATCH", body: { name: "Mine" } })).status).toBe(404);
    expect((await h.api(org(`/teams/${theirs}`), { cookie: acme.cookie, method: "DELETE" })).status).toBe(404);
    expect((await h.api(org("/teams", other.orgId), { cookie: acme.cookie })).status).toBe(404);
  });
});

describe("removing a user from the Organization", () => {
  test("revokes their access, drops them from every Team, and is audited", async () => {
    const cookie = await join("m@acme.test", "member");
    const user = await memberOf("m@acme.test");
    const t1 = (await h.api(org("/teams"), { cookie: acme.cookie, body: { name: "One" } })).body.id;
    const t2 = (await h.api(org("/teams"), { cookie: acme.cookie, body: { name: "Two" } })).body.id;
    for (const t of [t1, t2]) await h.api(org(`/teams/${t}/members`), { cookie: acme.cookie, body: { userId: user.userId } });

    expect((await h.api(org("/managed-certificates"), { cookie })).status).toBe(200);
    const res = await h.api(org(`/members/${user.id}`), { cookie: acme.cookie, method: "DELETE" });
    expect(res.status).toBe(204);

    expect((await h.api(org("/managed-certificates"), { cookie })).status).toBe(404);
    expect((await h.api("/api/me", { cookie })).body.organizations).toEqual([]);
    const teams = (await h.api(org("/teams"), { cookie: acme.cookie })).body.items;
    expect(teams.flatMap((t: any) => t.members)).toEqual([]);
    expect((await members()).map((m) => m.email)).toEqual(["admin@acme.test"]);
    const event = (await h.api(org("/audit-events"), { cookie: acme.cookie })).body.items.find((e: any) => e.action === "member.removed");
    expect(event).toMatchObject({ target: { type: "member", id: user.id }, detail: { email: "m@acme.test", role: "member", teamIds: expect.arrayContaining([t1, t2]) } });
  });

  test("removal affects only the one Organization", async () => {
    const other = await h.createOrgWithAdmin(operator, "other", "admin@other.test");
    const cookie = await join("m@acme.test", "member");
    const invited = await h.api(org("/invitations", other.orgId), { cookie: other.cookie, body: { email: "m@acme.test", role: "approver" } });
    await h.api(`/api/invitations/${invited.body.id}/accept`, { cookie, method: "POST" });
    const user = await memberOf("m@acme.test");
    await h.api(org(`/members/${user.id}`), { cookie: acme.cookie, method: "DELETE" });
    expect((await h.api(org("/managed-certificates"), { cookie })).status).toBe(404);
    expect((await h.api("/api/me", { cookie })).status).toBe(200);
  });

  test("only an Organization Administrator can remove users", async () => {
    const memberCookie = await join("m@acme.test", "member");
    const approverCookie = await join("a@acme.test", "approver");
    const admin = await memberOf("admin@acme.test");
    for (const cookie of [memberCookie, approverCookie]) {
      expect((await h.api(org(`/members/${admin.id}`), { cookie, method: "DELETE" })).status).toBe(403);
    }
  });

  test("the removal hook runs in the same transaction: if it fails, nothing is removed or audited", async () => {
    await join("m@acme.test", "member");
    const user = await memberOf("m@acme.test");
    const seen: unknown[] = [];
    const hook = async (_tx: unknown, p: unknown) => {
      seen.push(p);
      throw new Error("hook failed");
    };
    memberRemovalHooks.push(hook);
    try {
      const res = await h.api(org(`/members/${user.id}`), { cookie: acme.cookie, method: "DELETE" });
      expect(res.status).toBe(500);
    } finally {
      memberRemovalHooks.splice(memberRemovalHooks.indexOf(hook), 1);
    }
    expect(seen).toEqual([{ organizationId: acme.orgId, userId: user.userId }]);
    expect((await members()).map((m) => m.email)).toContain("m@acme.test");
    expect(await auditActions()).not.toContain("member.removed");
  });
});

describe("races and leftovers", () => {
  test("an administrator demoted while their change is in flight cannot complete it", async () => {
    const second = await join("second@acme.test", "organization-administrator");
    const secondMember = await memberOf("second@acme.test");

    // Hold an uncommitted demotion of the second administrator, as a concurrent request would.
    const other = await h.pool.connect();
    try {
      await other.query("begin");
      await other.query(`update member set role = 'member' where id = $1`, [secondMember.id]);
      const inFlight = h.api(org("/invitations"), { cookie: second, body: { email: "late@acme.test", role: "member" } });
      await Bun.sleep(150); // the invitation request is now waiting on the demotion
      await other.query("commit");
      expect((await inFlight).status).toBe(403);
    } finally {
      other.release();
    }
    expect((await h.api(org("/invitations"), { cookie: acme.cookie })).body.items).toEqual([]);
  });

  test("a user cannot be a member of an Organization twice, whatever the application checked", async () => {
    await join("m@acme.test", "member");
    const user = await memberOf("m@acme.test");
    await expect(
      h.pool.query(
        `insert into member (id, organization_id, user_id, role, created_at) values ($1, $2, $3, 'member', now())`,
        [crypto.randomUUID(), acme.orgId, user.userId],
      ),
    ).rejects.toThrow();
  });

  test("accepting an invitation retires other pending invitations to the same address", async () => {
    const first = await h.api(org("/invitations"), { cookie: acme.cookie, body: { email: "p@acme.test", role: "member" } });
    // A second one that raced the first past the duplicate check.
    const second = crypto.randomUUID();
    await h.pool.query(
      `insert into invitation (id, organization_id, email, role, status, expires_at, created_at, inviter_id)
       select $1, organization_id, email, 'approver', 'pending', expires_at, created_at, inviter_id from invitation where id = $2`,
      [second, first.body.id],
    );
    const cookie = await h.signUp("p@acme.test", PASSWORD);
    expect((await h.api(`/api/invitations/${first.body.id}/accept`, { cookie, method: "POST" })).status).toBe(200);
    expect((await h.api(org("/invitations"), { cookie: acme.cookie })).body.items).toEqual([]);
    expect((await h.pool.query(`select status from invitation where id = $1`, [second])).rows[0].status).toBe("canceled");
  });

  test("removing a user cancels invitations still pending for their address", async () => {
    await join("m@acme.test", "member");
    const user = await memberOf("m@acme.test");
    const stale = crypto.randomUUID();
    await h.pool.query(
      `insert into invitation (id, organization_id, email, role, status, expires_at, created_at, inviter_id)
       values ($1, $2, 'm@acme.test', 'approver', 'pending', now() + interval '1 day', now(), (select id from "user" where email = 'admin@acme.test'))`,
      [stale, acme.orgId],
    );
    await h.api(org(`/members/${user.id}`), { cookie: acme.cookie, method: "DELETE" });
    expect((await h.pool.query(`select status from invitation where id = $1`, [stale])).rows[0].status).toBe("canceled");
    const event = (await h.api(org("/audit-events"), { cookie: acme.cookie })).body.items.find((e: any) => e.action === "member.removed");
    expect(event.detail.canceledInvitationIds).toEqual([stale]);
  });
});

describe("authorization", () => {
  test("Better Auth's own organization endpoints are not exposed; they would bypass audit and the removal hook", async () => {
    await join("m@acme.test", "member");
    const target = await memberOf("m@acme.test");
    const res = await h.api("/api/auth/organization/update-member-role", {
      cookie: acme.cookie,
      body: { memberId: target.id, role: "organization-administrator", organizationId: acme.orgId },
    });
    expect(res.status).toBe(404);
    expect((await memberOf("m@acme.test")).role).toBe("member");
  });

  test("only Organization Administrators hold the administrative permissions", () => {
    const admin = "organization-administrator";
    const administrative: Permissions[] = [
      { invitation: ["create"] },
      { invitation: ["cancel"] },
      { member: ["update"] },
      { member: ["delete"] },
      { team: ["create"] },
      { team: ["update"] },
      { team: ["delete"] },
      { audit: ["read"] },
    ];
    for (const p of administrative) {
      expect(roleCan(admin, p)).toBe(true);
      expect(roleCan("approver", p)).toBe(false);
      expect(roleCan("member", p)).toBe(false);
      expect(roleCan("owner", p)).toBe(false);
    }
  });
});
