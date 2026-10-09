// Every change endpoint the platform serves from Better Auth's organization plugin: it writes exactly one Audit
// Event on success, and an actor who may not make the change is refused and leaves no trace. A new endpoint
// added to the allowlist fails here until it has a scenario, so one cannot be exposed without its hooks.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { organizationChangeEndpoints } from "../src/organization-changes";
import { PASSWORD, createHarness, type Harness } from "./harness";

let h: Harness;
beforeAll(async () => {
  h = await createHarness();
});
afterAll(async () => {
  await h.close();
});

const BA = "/api/auth/organization";

interface Fixtures {
  orgId: string;
  admin: string;
  /** A plain Member, in the Team, who may make none of these changes. */
  member: { cookie: string; memberId: string; userId: string };
  /** A plain Member who is not in the Team. */
  other: { cookie: string; memberId: string; userId: string };
  teamId: string;
  /** Pending, for an address nobody has signed up with. */
  pendingInvitationId: string;
  /** Pending, for someone signed up and signed in. */
  invitee: { cookie: string; invitationId: string };
}

async function fixtures(): Promise<Fixtures> {
  await h.reset();
  const operator = await h.createOperator("op@platform.test", PASSWORD);
  const { orgId, cookie: admin } = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
  const post = async (path: string, cookie: string, body: unknown) => {
    const res = await h.api(`${BA}/${path}`, { cookie, body });
    expect(res.status).toBe(200);
    return res.body;
  };
  const invite = async (email: string) => (await post("invite-member", admin, { email, role: "member", organizationId: orgId })).id as string;
  const join = async (email: string) => {
    const invitationId = await invite(email);
    const signedUp = await h.signUp(email, PASSWORD);
    await post("accept-invitation", signedUp, { invitationId });
    const cookie = await h.signIn(email, PASSWORD);
    const members = (await h.api(`${BA}/list-members?organizationId=${orgId}`, { cookie: admin })).body.members as {
      id: string;
      userId: string;
      user: { email: string };
    }[];
    const found = members.find((m) => m.user.email === email)!;
    return { cookie, memberId: found.id, userId: found.userId };
  };

  const member = await join("member@acme.test");
  const other = await join("other@acme.test");
  const teamId = (await post("create-team", admin, { name: "Platform", organizationId: orgId })).id as string;
  await post("add-team-member", admin, { teamId, userId: member.userId, organizationId: orgId });
  const pendingInvitationId = await invite("pending@acme.test");
  const inviteeInvitationId = await invite("invitee@acme.test");
  const inviteeCookie = await h.signUp("invitee@acme.test", PASSWORD);
  return { orgId, admin, member, other, teamId, pendingInvitationId, invitee: { cookie: inviteeCookie, invitationId: inviteeInvitationId } };
}

/** The request that makes the change, who makes it, and the one Audit Event it must write. */
const scenarios: Record<string, (f: Fixtures) => { cookie: string; body: unknown; action: string }> = {
  "invite-member": (f) => ({ cookie: f.admin, body: { email: "new@acme.test", role: "member", organizationId: f.orgId }, action: "invitation.created" }),
  "accept-invitation": (f) => ({ cookie: f.invitee.cookie, body: { invitationId: f.invitee.invitationId }, action: "invitation.accepted" }),
  "reject-invitation": (f) => ({ cookie: f.invitee.cookie, body: { invitationId: f.invitee.invitationId }, action: "invitation.rejected" }),
  "cancel-invitation": (f) => ({ cookie: f.admin, body: { invitationId: f.pendingInvitationId }, action: "invitation.canceled" }),
  "update-member-role": (f) => ({ cookie: f.admin, body: { memberId: f.other.memberId, role: "approver", organizationId: f.orgId }, action: "member.role_changed" }),
  "remove-member": (f) => ({ cookie: f.admin, body: { memberIdOrEmail: f.other.memberId, organizationId: f.orgId }, action: "member.removed" }),
  "create-team": (f) => ({ cookie: f.admin, body: { name: "Security", organizationId: f.orgId }, action: "team.created" }),
  "update-team": (f) => ({ cookie: f.admin, body: { teamId: f.teamId, data: { name: "Platform 2", organizationId: f.orgId } }, action: "team.renamed" }),
  "remove-team": (f) => ({ cookie: f.admin, body: { teamId: f.teamId, organizationId: f.orgId }, action: "team.deleted" }),
  "add-team-member": (f) => ({ cookie: f.admin, body: { teamId: f.teamId, userId: f.other.userId, organizationId: f.orgId }, action: "team.member_added" }),
  "remove-team-member": (f) => ({ cookie: f.admin, body: { teamId: f.teamId, userId: f.member.userId, organizationId: f.orgId }, action: "team.member_removed" }),
};

const auditActions = async (f: Fixtures) =>
  ((await h.api(`/api/organizations/${f.orgId}/audit-events`, { cookie: f.admin })).body.items as { action: string }[]).map((e) => e.action);

describe("organization changes", () => {
  test("every endpoint the platform serves has a scenario here", () => {
    expect(Object.keys(scenarios).sort()).toEqual([...organizationChangeEndpoints].sort());
  });

  describe.each(Object.keys(scenarios))("%s", (endpoint) => {
    let f: Fixtures;
    beforeEach(async () => {
      f = await fixtures();
    });

    test("is refused for a Member who may not make it, leaving no trace", async () => {
      const { body } = scenarios[endpoint]!(f);
      const before = await auditActions(f);
      const mailBefore = h.mailer.sent.length;

      const res = await h.api(`${BA}/${endpoint}`, { cookie: f.member.cookie, body });

      expect(res.status).toBeWithin(400, 500);
      expect(await auditActions(f)).toEqual(before);
      expect(h.mailer.sent).toHaveLength(mailBefore);
    });

    test("writes exactly one Audit Event when it succeeds", async () => {
      const { cookie, body, action } = scenarios[endpoint]!(f);
      const before = await auditActions(f);

      const res = await h.api(`${BA}/${endpoint}`, { cookie, body });

      expect(res.status).toBe(200);
      expect((await auditActions(f)).slice(before.length)).toEqual([action]);
    });
  });
});
