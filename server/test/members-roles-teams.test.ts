// Better Auth's organization endpoints, served as they are (see organization-changes.ts). These tests lean on what
// Better Auth guarantees and on the platform's additions: audit in the same transaction, serialised changes,
// the removal hook, and the allowlist (every endpoint it serves is covered in organization-changes.test.ts).
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { declaredPermissions, roleCan, type Permissions } from "../src/tenancy/permissions";
import { PASSWORD, createHarness, type Harness } from "./support/harness";

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

const BA = "/api/auth/organization";
const as = (cookie: string, orgId = acme.orgId) => ({
  invite: (email: string, role: string) => h.api(`${BA}/invite-member`, { cookie, body: { email, role, organizationId: orgId } }),
  cancelInvitation: (invitationId: string) => h.api(`${BA}/cancel-invitation`, { cookie, body: { invitationId } }),
  accept: (invitationId: string) => h.api(`${BA}/accept-invitation`, { cookie, body: { invitationId } }),
  invitations: () => h.api(`${BA}/list-invitations?organizationId=${orgId}`, { cookie }),
  members: () => h.api(`${BA}/list-members?organizationId=${orgId}`, { cookie }),
  setRole: (memberId: string, role: string) => h.api(`${BA}/update-member-role`, { cookie, body: { memberId, role, organizationId: orgId } }),
  remove: (memberId: string) => h.api(`${BA}/remove-member`, { cookie, body: { memberIdOrEmail: memberId, organizationId: orgId } }),
  createTeam: (name: string) => h.api(`${BA}/create-team`, { cookie, body: { name, organizationId: orgId } }),
  renameTeam: (teamId: string, name: string) =>
    h.api(`${BA}/update-team`, { cookie, body: { teamId, data: { name, organizationId: orgId } } }),
  deleteTeam: (teamId: string) => h.api(`${BA}/remove-team`, { cookie, body: { teamId, organizationId: orgId } }),
  addToTeam: (teamId: string, userId: string) => h.api(`${BA}/add-team-member`, { cookie, body: { teamId, userId, organizationId: orgId } }),
  removeFromTeam: (teamId: string, userId: string) =>
    h.api(`${BA}/remove-team-member`, { cookie, body: { teamId, userId, organizationId: orgId } }),
  teams: () => h.api(`${BA}/list-teams?organizationId=${orgId}`, { cookie }),
  overview: (query = "") => h.api(`/api/organizations/${orgId}/teams${query}`, { cookie }),
  inventory: () => h.api(`/api/organizations/${orgId}/managed-certificates`, { cookie }),
  audit: async () => (await h.api(`/api/organizations/${orgId}/audit-events`, { cookie })).body?.items ?? [],
});
const admin = () => as(acme.cookie);
const denied = (res: { status: number }) => expect(res.status).toBeWithin(400, 500);

/** The administrator invites `email` with `role`; the invitee signs up, accepts and signs in. */
async function join(email: string, role: string, orgId = acme.orgId, adminCookie = acme.cookie) {
  const invited = await as(adminCookie, orgId).invite(email, role);
  expect(invited.status).toBe(200);
  const cookie = await h.signUp(email, PASSWORD);
  expect((await as(cookie).accept(invited.body.id)).status).toBe(200);
  return h.signIn(email, PASSWORD);
}

type Member = { id: string; userId: string; role: string; user: { email: string } };
async function members(cookie = acme.cookie, orgId = acme.orgId) {
  const res = await as(cookie, orgId).members();
  expect(res.status).toBe(200);
  return res.body.members as Member[];
}
const memberOf = async (email: string) => (await members()).find((m) => m.user.email === email)!;
const auditActions = async () => (await admin().audit()).map((e: any) => e.action) as string[];

describe("listing members a page at a time", () => {
  test("Better Auth pages members, narrows them by role (one or several) and counts them all", async () => {
    await join("m1@acme.test", "member");
    await join("m2@acme.test", "member");
    await join("a1@acme.test", "approver");
    const list = async (query: string) => (await h.api(`${BA}/list-members?organizationId=${acme.orgId}&${query}`, { cookie: acme.cookie })).body as { members: Member[]; total: number };

    const first = await list("limit=2&offset=0&sortBy=createdAt");
    expect(first.total).toBe(4);
    expect(first.members.map((m) => m.user.email)).toEqual(["admin@acme.test", "m1@acme.test"]);
    expect((await list("limit=2&offset=2&sortBy=createdAt")).members.map((m) => m.user.email)).toEqual(["m2@acme.test", "a1@acme.test"]);
    const approvers = await list("filterField=role&filterValue=approver");
    expect([approvers.total, approvers.members.map((m) => m.user.email)]).toEqual([1, ["a1@acme.test"]]);
    const several = await list("filterField=role&filterOperator=in&filterValue=approver&filterValue=organization-administrator");
    expect([several.total, several.members.map((m) => m.user.email).sort()]).toEqual([2, ["a1@acme.test", "admin@acme.test"]]);
  });
});

describe("the Teams overview a page at a time", () => {
  test("Teams are paged, counted in all, and narrowed by whether they have members", async () => {
    const ids: string[] = [];
    for (const name of ["Alpha", "Bravo", "Charlie"]) ids.push((await admin().createTeam(name)).body.id);
    await join("m@acme.test", "member");
    await admin().addToTeam(ids[1]!, (await memberOf("m@acme.test")).userId);
    const names = async (query: string) => {
      const res = await admin().overview(query);
      expect(res.status).toBe(200);
      return [res.body.total, res.body.page, res.body.pageSize, res.body.items.map((t: any) => t.name)];
    };

    expect(await names("")).toEqual([3, 1, 25, ["Alpha", "Bravo", "Charlie"]]);
    expect(await names("?pageSize=2")).toEqual([3, 1, 2, ["Alpha", "Bravo"]]);
    expect(await names("?pageSize=2&page=2")).toEqual([3, 2, 2, ["Charlie"]]);
    expect(await names("?membership=populated")).toEqual([1, 1, 25, ["Bravo"]]);
    expect(await names("?membership=empty&pageSize=1&page=2")).toEqual([2, 2, 1, ["Charlie"]]);
    // A Team's members come with the Team, whichever page it is on.
    expect((await admin().overview("?membership=populated")).body.items[0].members).toHaveLength(1);
    for (const query of ["?membership=some", "?page=0", "?pageSize=101"]) expect((await admin().overview(query)).status).toBe(400);
  });
});

describe("what the caller may do", () => {
  test("/api/me reports each Organization's permissions for the caller, and the roles the server accepts", async () => {
    const memberCookie = await join("m@acme.test", "member");
    const approverCookie = await join("a@acme.test", "approver");

    const adminMe = (await h.api("/api/me", { cookie: acme.cookie })).body;
    expect(adminMe.roles.sort()).toEqual(["approver", "member", "organization-administrator"]);
    expect(adminMe.organizations[0].permissions.invitation).toEqual(["create", "cancel"]);
    expect(adminMe.organizations[0].permissions.audit).toEqual(["read"]);

    // Approvers and Members hold only what is granted them on purpose (see permissions.ts).
    const permissionsOf = async (cookie: string) => (await h.api("/api/me", { cookie })).body.organizations[0].permissions;
    expect(await permissionsOf(memberCookie)).toEqual({ managedCertificate: ["propose", "download"], notificationChannel: ["read"], privateCa: ["read"], certificateProfile: ["read"] });
    expect(await permissionsOf(approverCookie)).toEqual({ managedCertificate: ["read", "propose", "download"], approval: ["read", "decide"], notificationChannel: ["read"], privateCa: ["read"], certificateProfile: ["read"] });
  });
});

describe("invitations", () => {
  test("an administrator invites users as Member, Approver or Organization Administrator", async () => {
    for (const role of ["member", "approver", "organization-administrator"]) {
      const email = `${role}@acme.test`;
      const res = await admin().invite(email, role);
      expect(res.status).toBe(200);
      expect(h.mailer.sent.at(-1)!.to).toBe(email);
      expect(h.mailer.sent.at(-1)!.text).toContain(res.body.id);

      const cookie = await h.signUp(email, PASSWORD);
      await as(cookie).accept(res.body.id);
      expect((await h.api("/api/me", { cookie })).body.organizations[0].role).toBe(role);
    }
  });

  test("only the three roles can be assigned, and 'owner' is not one of them", async () => {
    const mailBefore = h.mailer.sent.length;
    for (const role of ["owner", "admin", "nonsense", "member,owner"]) {
      denied(await admin().invite("x@acme.test", role));
    }
    expect(h.mailer.sent).toHaveLength(mailBefore);
  });

  test("only an Organization Administrator can invite or cancel invitations; a refused change leaves no trace", async () => {
    const memberCookie = await join("m@acme.test", "member");
    const approverCookie = await join("a@acme.test", "approver");
    const pending = await admin().invite("new@acme.test", "member");
    const before = h.mailer.sent.length;
    const auditBefore = (await auditActions()).length;
    for (const cookie of [memberCookie, approverCookie]) {
      expect((await as(cookie).invite("n@acme.test", "member")).status).toBe(403);
      denied(await as(cookie).cancelInvitation(pending.body.id));
    }
    expect(h.mailer.sent).toHaveLength(before);
    expect(await auditActions()).toHaveLength(auditBefore);
  });

  test("only those who may invite can list invitations, which show the invited addresses", async () => {
    await admin().invite("p@acme.test", "member");
    const memberCookie = await join("m@acme.test", "member");
    const approverCookie = await join("a@acme.test", "approver");
    for (const cookie of [memberCookie, approverCookie]) {
      expect((await as(cookie).invitations()).status).toBe(403);
    }
    expect((await admin().invitations()).status).toBe(200);
    expect((await h.api(`${BA}/list-invitations`, { cookie: acme.cookie })).status).toBe(400);
  });

  test("inviting an existing member, or someone already invited, is refused", async () => {
    await join("m@acme.test", "member");
    expect((await admin().invite("M@acme.test", "approver")).status).toBe(400);
    expect((await admin().invite("p@acme.test", "member")).status).toBe(200);
    expect((await admin().invite("p@acme.test", "member")).status).toBe(400);
  });

  test("an invitation can be cancelled while pending, and then cannot be accepted; a spent one cannot be cancelled", async () => {
    const inv = await admin().invite("p@acme.test", "approver");
    const pending = (await admin().invitations()).body.filter((i: any) => i.status === "pending");
    expect(pending.map((i: any) => [i.id, i.email, i.role])).toEqual([[inv.body.id, "p@acme.test", "approver"]]);

    expect((await admin().cancelInvitation(inv.body.id)).status).toBe(200);
    const cookie = await h.signUp("p@acme.test", PASSWORD);
    expect((await as(cookie).accept(inv.body.id)).status).toBe(400);
    expect(await auditActions()).toContain("invitation.canceled");

    const spent = await admin().invite("q@acme.test", "member");
    const qCookie = await h.signUp("q@acme.test", PASSWORD);
    await as(qCookie).accept(spent.body.id);
    denied(await admin().cancelInvitation(spent.body.id));
    expect((await h.pool.query(`select status from invitation where id = $1`, [spent.body.id])).rows[0].status).toBe("accepted");
  });

  test("an invitation cannot be created, listed or cancelled across Organizations", async () => {
    const other = await h.createOrgWithAdmin(operator, "other", "admin@other.test");
    expect((await as(acme.cookie, other.orgId).invite("x@a.test", "member")).status).toBeGreaterThanOrEqual(400);
    expect((await as(acme.cookie, other.orgId).invitations()).status).toBe(404);
    const inv = await as(other.cookie, other.orgId).invite("x@a.test", "member");
    denied(await admin().cancelInvitation(inv.body.id));
    expect((await h.pool.query(`select status from invitation where id = $1`, [inv.body.id])).rows[0].status).toBe("pending");
  });

  test("an invitation can be rejected by its recipient, and is audited", async () => {
    const inv = await admin().invite("p@acme.test", "member");
    const cookie = await h.signUp("p@acme.test", PASSWORD);
    expect((await h.api(`${BA}/reject-invitation`, { cookie, body: { invitationId: inv.body.id } })).status).toBe(200);
    expect(await auditActions()).toContain("invitation.rejected");
  });
});

describe("roles", () => {
  test("an Organization Administrator changes a member's role, and the change takes effect at once", async () => {
    const cookie = await join("m@acme.test", "member");
    expect((await as(cookie).invite("n@acme.test", "member")).status).toBe(403);

    const target = await memberOf("m@acme.test");
    expect((await admin().setRole(target.id, "organization-administrator")).status).toBe(200);
    expect((await memberOf("m@acme.test")).role).toBe("organization-administrator");
    expect((await as(cookie).invite("n@acme.test", "member")).status).toBe(200);
  });

  test("only an Organization Administrator can change roles", async () => {
    const memberCookie = await join("m@acme.test", "member");
    const approverCookie = await join("a@acme.test", "approver");
    const adminMember = await memberOf("admin@acme.test");
    const target = await memberOf("m@acme.test");
    for (const cookie of [memberCookie, approverCookie]) {
      for (const id of [adminMember.id, target.id]) denied(await as(cookie).setRole(id, "organization-administrator"));
    }
    expect((await memberOf("m@acme.test")).role).toBe("member");
    expect((await memberOf("admin@acme.test")).role).toBe("organization-administrator");
  });

  test("an invalid role is rejected", async () => {
    const target = await memberOf("admin@acme.test");
    for (const role of ["owner", "admin"]) denied(await admin().setRole(target.id, role));
    expect((await memberOf("admin@acme.test")).role).toBe("organization-administrator");
  });

  test("the last Organization Administrator cannot be demoted or removed", async () => {
    const self = await memberOf("admin@acme.test");
    denied(await admin().setRole(self.id, "member"));
    denied(await admin().remove(self.id));
    expect((await memberOf("admin@acme.test")).role).toBe("organization-administrator");

    await join("second@acme.test", "organization-administrator");
    expect((await admin().setRole(self.id, "member")).status).toBe(200);
  });

  test("a member of another Organization cannot be changed or removed", async () => {
    const other = await h.createOrgWithAdmin(operator, "other", "admin@other.test");
    const theirs = (await members(other.cookie, other.orgId))[0]!;
    denied(await admin().setRole(theirs.id, "member"));
    denied(await admin().remove(theirs.id));
    expect((await members(other.cookie, other.orgId))[0]!.role).toBe("organization-administrator");
  });

  test("any member can read the member list, and only their own Organization's", async () => {
    const cookie = await join("m@acme.test", "member");
    expect((await members(cookie)).map((m) => m.user.email).sort()).toEqual(["admin@acme.test", "m@acme.test"]);
    const other = await h.createOrgWithAdmin(operator, "other", "admin@other.test");
    expect((await as(cookie, other.orgId).members()).status).toBe(403);
  });

  test("role changes are audited with the old and new role", async () => {
    await join("m@acme.test", "member");
    const target = await memberOf("m@acme.test");
    await admin().setRole(target.id, "approver");
    const event = (await admin().audit()).find((e: any) => e.action === "member.role_changed");
    expect(event).toMatchObject({
      actor: { email: "admin@acme.test" },
      target: { type: "member", id: target.id },
      detail: { email: "m@acme.test", from: "member", to: "approver" },
    });
    // Setting the role it already has changes nothing and is not audited.
    await admin().setRole(target.id, "approver");
    expect((await auditActions()).filter((a) => a === "member.role_changed")).toHaveLength(1);
  });
});

describe("Teams", () => {
  const createTeam = async (name: string, cookie = acme.cookie, orgId = acme.orgId) => as(cookie, orgId).createTeam(name);

  test("an administrator creates, renames and deletes Teams", async () => {
    const created = await createTeam("Platform");
    expect(created.status).toBe(200);
    const id = created.body.id;
    expect((await admin().renameTeam(id, "Infra")).status).toBe(200);
    expect((await admin().overview()).body.items).toEqual([{ id, name: "Infra", members: [] }]);
    expect((await admin().deleteTeam(id)).status).toBe(200);
    expect((await admin().overview()).body.items).toEqual([]);
    expect(await auditActions()).toEqual(expect.arrayContaining(["team.created", "team.renamed", "team.deleted"]));
    const renamed = (await admin().audit()).find((e: any) => e.action === "team.renamed");
    expect(renamed.detail).toEqual({ from: "Platform", to: "Infra" });
  });

  test("only administrators change Teams; every member can read them", async () => {
    const id = (await createTeam("Platform")).body.id;
    const memberCookie = await join("m@acme.test", "member");
    const approverCookie = await join("a@acme.test", "approver");
    const user = await memberOf("m@acme.test");
    for (const cookie of [memberCookie, approverCookie]) {
      const them = as(cookie);
      expect((await them.createTeam("Nope")).status).toBe(403);
      denied(await them.renameTeam(id, "Nope"));
      denied(await them.deleteTeam(id));
      denied(await them.addToTeam(id, user.userId));
      denied(await them.removeFromTeam(id, user.userId));
      expect((await them.teams()).body).toHaveLength(1);
      expect((await them.overview()).body.items).toHaveLength(1);
    }
  });

  test("Team names are unique within an Organization, ignoring case, but not across them", async () => {
    await createTeam("Platform");
    denied(await createTeam("platform"));
    const second = await createTeam("Security");
    denied(await admin().renameTeam(second.body.id, "PLATFORM"));
    expect((await admin().overview()).body.items.map((t: any) => t.name)).toEqual(["Platform", "Security"]);
    const other = await h.createOrgWithAdmin(operator, "other", "admin@other.test");
    expect((await createTeam("Platform", other.cookie, other.orgId)).status).toBe(200);
  });

  test("users are added to and removed from a Team; only Organization members can be added", async () => {
    const team = (await createTeam("Platform")).body.id;
    await join("m@acme.test", "member");
    const user = await memberOf("m@acme.test");
    expect((await admin().addToTeam(team, user.userId)).status).toBe(200);
    // Adding someone who is already in the Team changes nothing, and is not audited again.
    expect((await admin().addToTeam(team, user.userId)).status).toBe(200);
    expect((await auditActions()).filter((a) => a === "team.member_added")).toHaveLength(1);
    expect((await admin().overview()).body.items[0].members).toEqual([{ userId: user.userId, email: "m@acme.test" }]);

    const outsider = await h.createOrgWithAdmin(operator, "other", "admin@other.test");
    const outsiderId = (await members(outsider.cookie, outsider.orgId))[0]!.userId;
    denied(await admin().addToTeam(team, outsiderId));

    expect((await admin().removeFromTeam(team, user.userId)).status).toBe(200);
    expect((await admin().overview()).body.items[0].members).toEqual([]);
    expect(await auditActions()).toContain("team.member_removed");
  });

  test("a Team of another Organization cannot be reached", async () => {
    const other = await h.createOrgWithAdmin(operator, "other", "admin@other.test");
    const theirs = (await createTeam("Theirs", other.cookie, other.orgId)).body.id;
    denied(await admin().renameTeam(theirs, "Mine"));
    denied(await admin().deleteTeam(theirs));
    expect((await as(acme.cookie, other.orgId).overview()).status).toBe(404);
    expect((await as(other.cookie, other.orgId).overview()).body.items.map((t: any) => t.name)).toEqual(["Theirs"]);
  });

  test("an Organization's last Team can be deleted", async () => {
    const id = (await createTeam("Only")).body.id;
    expect((await admin().deleteTeam(id)).status).toBe(200);
  });
});

describe("removing a user from the Organization", () => {
  test("revokes their access, drops them from every Team, and is audited", async () => {
    const cookie = await join("m@acme.test", "member");
    const user = await memberOf("m@acme.test");
    const t1 = (await admin().createTeam("One")).body.id;
    const t2 = (await admin().createTeam("Two")).body.id;
    for (const t of [t1, t2]) await admin().addToTeam(t, user.userId);

    expect(await as(cookie).inventory().then((r) => r.status)).toBe(200);
    expect((await admin().remove(user.id)).status).toBe(200);

    expect((await as(cookie).inventory()).status).toBe(404);
    expect((await h.api("/api/me", { cookie })).body.organizations).toEqual([]);
    expect((await admin().overview()).body.items.flatMap((t: any) => t.members)).toEqual([]);
    expect((await members()).map((m) => m.user.email)).toEqual(["admin@acme.test"]);
    const event = (await admin().audit()).find((e: any) => e.action === "member.removed");
    expect(event).toMatchObject({
      target: { type: "member", id: user.id },
      detail: { email: "m@acme.test", role: "member", teamIds: expect.arrayContaining([t1, t2]) },
    });
  });

  test("removal affects only the one Organization", async () => {
    const other = await h.createOrgWithAdmin(operator, "other", "admin@other.test");
    const cookie = await join("m@acme.test", "member");
    const invited = await as(other.cookie, other.orgId).invite("m@acme.test", "approver");
    await as(cookie).accept(invited.body.id);
    const user = await memberOf("m@acme.test");
    await admin().remove(user.id);
    expect((await as(cookie).inventory()).status).toBe(404);
    expect((await as(cookie, other.orgId).inventory()).status).toBe(200);
  });

  test("only an Organization Administrator can remove users", async () => {
    const memberCookie = await join("m@acme.test", "member");
    const approverCookie = await join("a@acme.test", "approver");
    const adminMember = await memberOf("admin@acme.test");
    const target = await memberOf("m@acme.test");
    for (const cookie of [memberCookie, approverCookie]) {
      denied(await as(cookie).remove(adminMember.id));
      denied(await as(cookie).remove(target.id));
    }
    expect(await members()).toHaveLength(3);
  });

  test("the removal hook runs in the same transaction: if it fails, nothing is removed or audited", async () => {
    await join("m@acme.test", "member");
    const user = await memberOf("m@acme.test");
    const seen: unknown[] = [];
    const hook = async (_tx: unknown, p: unknown) => {
      seen.push(p);
      throw new Error("hook failed");
    };
    h.memberRemovalHooks.push(hook);
    try {
      expect((await admin().remove(user.id)).status).toBe(500);
    } finally {
      h.memberRemovalHooks.splice(h.memberRemovalHooks.indexOf(hook), 1);
    }
    expect(seen).toEqual([{ organizationId: acme.orgId, userId: user.userId }]);
    expect((await members()).map((m) => m.user.email)).toContain("m@acme.test");
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
      const inFlight = as(second).invite("late@acme.test", "member");
      await Bun.sleep(150); // the invitation request is now waiting on the demotion
      await other.query("commit");
      expect((await inFlight).status).toBe(403);
    } finally {
      other.release();
    }
    expect((await admin().invitations()).body.map((i: any) => i.email)).not.toContain("late@acme.test");
  });

  test("two administrators demoting each other at once cannot leave the Organization with none", async () => {
    const second = await join("second@acme.test", "organization-administrator");
    const first = await memberOf("admin@acme.test");
    const secondMember = await memberOf("second@acme.test");
    const results = await Promise.all([as(acme.cookie).setRole(secondMember.id, "member"), as(second).setRole(first.id, "member")]);
    // One wins; the other finds itself demoted (or, in the other order, finds it would leave none).
    expect(results.map((r) => r.status).filter((st) => st === 200)).toHaveLength(1);
    const roles = (await members()).map((m) => m.role);
    expect(roles.filter((r) => r === "organization-administrator")).toHaveLength(1);
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
    const first = await admin().invite("p@acme.test", "member");
    // A second one that raced the first past the duplicate check.
    const second = crypto.randomUUID();
    await h.pool.query(
      `insert into invitation (id, organization_id, email, role, status, expires_at, created_at, inviter_id)
       select $1, organization_id, email, 'approver', 'pending', expires_at, created_at, inviter_id from invitation where id = $2`,
      [second, first.body.id],
    );
    const cookie = await h.signUp("p@acme.test", PASSWORD);
    expect((await as(cookie).accept(first.body.id)).status).toBe(200);
    expect((await admin().invitations()).body.filter((i: any) => i.status === "pending")).toEqual([]);
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
    await admin().remove(user.id);
    expect((await h.pool.query(`select status from invitation where id = $1`, [stale])).rows[0].status).toBe("canceled");
    const event = (await admin().audit()).find((e: any) => e.action === "member.removed");
    expect(event.detail.canceledInvitationIds).toEqual([stale]);
  });
});

describe("authorization", () => {
  test("only the allowlisted Better Auth organization endpoints are served", async () => {
    await join("m@acme.test", "member");
    const target = await memberOf("m@acme.test");
    // `leave` and Organization updates and deletion bypass the platform's hooks or are not offered.
    for (const [endpoint, body] of [
      ["leave", { organizationId: acme.orgId }],
      ["update", { data: { name: "Hijacked" }, organizationId: acme.orgId }],
      ["delete", { organizationId: acme.orgId }],
      ["create", { name: "Mine", slug: "mine" }],
      ["set-active", { organizationId: acme.orgId }],
      ["create-role", { role: "x", organizationId: acme.orgId }],
    ] as const) {
      expect((await h.api(`${BA}/${endpoint}`, { cookie: acme.cookie, body })).status).toBe(404);
    }
    expect((await h.api(`${BA}/constructor`, { cookie: acme.cookie, body: {} })).status).toBe(404);
    expect((await members()).map((m) => m.id)).toContain(target.id);
    const org = await h.pool.query(`select name from organization where id = $1`, [acme.orgId]);
    expect(org.rows[0].name).toBe("Org acme");
  });

  test("no variant of a blocked path reaches the endpoint", async () => {
    await join("m@acme.test", "member");
    const memberCookie = await join("m2@acme.test", "member");
    const before = (await members()).length;
    for (const path of [
      `${BA}/leave`,
      `${BA}/leave/`,
      "/api/auth//organization/leave",
      "/api/auth/Organization/leave",
      "/api/auth/organization/%6ceave",
      "/api/auth/organization%2Fleave",
      "/api/auth/./organization/leave",
      "/api/auth/organization/./leave",
      "/api/auth/organization/../organization/leave",
    ]) {
      const res = await h.api(path, { cookie: memberCookie, body: { organizationId: acme.orgId } });
      expect(res.status, path).toBeWithin(400, 500);
    }
    expect(await members()).toHaveLength(before);
    expect(await auditActions()).not.toContain("member.removed");
  });

  test("changes Better Auth would make without running its hooks are refused: invitations with Teams or resent", async () => {
    const team = (await admin().createTeam("Platform")).body.id;
    const withTeam = await h.api(`${BA}/invite-member`, {
      cookie: acme.cookie,
      body: { email: "t@acme.test", role: "member", organizationId: acme.orgId, teamId: team },
    });
    denied(withTeam);
    const first = await admin().invite("p@acme.test", "member");
    const expiry = async () => (await h.pool.query(`select expires_at from invitation where id = $1`, [first.body.id])).rows[0].expires_at;
    const before = await expiry();
    const mailBefore = h.mailer.sent.length;
    const resent = await h.api(`${BA}/invite-member`, {
      cookie: acme.cookie,
      body: { email: "p@acme.test", role: "member", organizationId: acme.orgId, resend: true },
    });
    expect(resent.status).toBe(400);
    expect(await expiry()).toEqual(before);
    expect(h.mailer.sent).toHaveLength(mailBefore);
  });

  test("an Organization Administrator holds every declared permission; Approvers and Members only those granted them; Better Auth's own role names none", () => {
    const granted: Record<string, string[]> = { approver: ["managedCertificate.read", "managedCertificate.propose", "managedCertificate.download", "approval.read", "approval.decide", "notificationChannel.read", "privateCa.read", "certificateProfile.read"], member: ["managedCertificate.propose", "managedCertificate.download", "notificationChannel.read", "privateCa.read", "certificateProfile.read"] };
    const declared = declaredPermissions();
    // The permissions the platform's own routes and Better Auth's endpoints ask about stay declared.
    expect(declared.invitation).toContain("create");
    expect(declared.audit).toContain("read");

    for (const [resource, actions] of Object.entries(declared)) {
      for (const action of actions as string[]) {
        const p = { [resource]: [action] } as Permissions;
        expect(roleCan("organization-administrator", p)).toBe(true);
        for (const other of ["approver", "member"]) expect(roleCan(other, p)).toBe(granted[other]!.includes(`${resource}.${action}`));
        for (const other of ["owner", "admin"]) expect(roleCan(other, p)).toBe(false);
      }
    }
  });
});
