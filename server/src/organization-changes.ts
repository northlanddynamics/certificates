// Better Auth's organization plugin endpoints, served as they are, but each change on a transaction of the unit of
// work, with Better Auth's organization hooks writing the Audit Events on that same transaction. Its endpoints
// open no transaction themselves (and its hooks run between separate statements), so running them in the unit of
// work is what makes "the change and its Audit Event commit or roll back together" true for everything it does.
//
// This module is the only one that knows which of those endpoints exist, which locks each change takes and which
// rules wrap it. Anything not listed here is not served. In particular `leave` removes a member without running
// Better Auth's hooks (no Audit Event, no removal hook), and updating or deleting an Organization is not offered.
import { APIError } from "better-auth/api";
import { and, asc, eq, inArray, ne, sql } from "drizzle-orm";
import { createAuth, type Auth, type AuthConfig } from "./auth";
import type { AuditAction } from "./audit";
import type { Authorizer } from "./authorization";
import type { Tx } from "./db/client";
import { invitation, member, team, teamMember } from "./db/schema";
import { HttpError } from "./http";
import { invitationEmail } from "./invitation-email";
import type { MemberRemovalHook, TeamRemovalHook } from "./member-removal";
import { ORG_ADMIN_ROLE, isKnownRole, type Permissions } from "./permissions";
import type { Actor, Change, UnitOfWork } from "./unit-of-work";

const PATH = "/api/auth/organization/";

/** Reads go straight to Better Auth. Better Auth shows a member more than we want to; the permission, where one is listed, narrows who may read. */
const READS = new Map<string, Permissions | undefined>([
  ["list-members", undefined],
  // Better Auth lists every invitation, with the invited addresses, to any member; here only to those who may invite.
  ["list-invitations", { invitation: ["create"] }],
  ["list-teams", undefined],
  ["list-team-members", undefined],
]);

/** Each changing endpoint, and whether it may remove or demote an Organization Administrator. */
const CHANGES = new Map<string, { administrators: boolean }>([
  ["invite-member", { administrators: false }],
  ["accept-invitation", { administrators: false }],
  ["reject-invitation", { administrators: false }],
  ["cancel-invitation", { administrators: false }],
  ["update-member-role", { administrators: true }],
  ["remove-member", { administrators: true }],
  ["create-team", { administrators: false }],
  ["update-team", { administrators: false }],
  ["remove-team", { administrators: false }],
  ["add-team-member", { administrators: false }],
  ["remove-team-member", { administrators: false }],
]);

/** The changing endpoints served, by name. */
export const organizationChangeEndpoints: readonly string[] = [...CHANGES.keys()];

export interface OrganizationChangesDeps {
  unitOfWork: UnitOfWork;
  /** Better Auth as configured for reads and for looking up who is asking. */
  auth: Auth;
  authConfig: Omit<AuthConfig, "db" | "organization">;
  /** For the reads that need a permission. */
  authorize: Authorizer["authorize"];
  /** Refuses a user their Organizations' login policy holds up (login-policy.ts); every endpoint asks it. */
  admit: (actor: Actor) => Promise<void>;
  /** Where users open the web UI, for the link in invitation emails. */
  webURL: string;
  /**
   * Run, in the transaction that removes a user from an Organization, for whatever depends on the user's membership
   * (Teams are cleaned up by Better Auth itself; Managed Certificate Owners register here, and Subscribers will).
   * A throwing hook rolls the removal and its Audit Event back.
   */
  memberRemovalHooks?: MemberRemovalHook[];
  /** Run, in the transaction that deletes a Team and before it is deleted, for whatever refers to the Team. */
  teamRemovalHooks?: TeamRemovalHook[];
}

export interface OrganizationChanges {
  /**
   * Answers a request under /api/auth/organization/. A refused or failed change leaves no trace, and invitation
   * emails go out only after a successful commit. Throws an HttpError where the platform itself refuses a read.
   */
  serve(request: Request): Promise<Response>;
}

/** Thrown to roll back and still answer with Better Auth's own error response. */
class Refused extends Error {
  constructor(readonly response: Response) {
    super("refused");
  }
}

const refusal = (status: number, error: string) => Response.json({ error }, { status });

export function createOrganizationChanges(deps: OrganizationChangesDeps): OrganizationChanges {
  const { unitOfWork, auth, authConfig, authorize, admit, webURL, memberRemovalHooks = [], teamRemovalHooks = [] } = deps;

  /**
   * `administrators`: the change may remove or demote an Organization Administrator. Better Auth refuses to leave
   * an Organization with none, but by reading, so two concurrent changes could both pass; locking the
   * administrators makes each wait for the other. Otherwise the actor's own memberships are locked, so that a
   * concurrent demotion or removal of the actor waits for this change instead of racing it.
   */
  async function change(actor: Actor, request: Request, { administrators }: { administrators: boolean }) {
    try {
      return await unitOfWork.run(actor, async (tx, change) => {
        await (administrators ? lockAdministrators(tx, actor) : lockMemberships(tx, actor));
        const transactional: Auth = createAuth({
          ...authConfig,
          db: tx,
          organization: {
            organizationHooks: auditHooks(tx, change, { member: memberRemovalHooks, team: teamRemovalHooks }),
            sendInvitationEmail: async ({ id, email, organization }) =>
              change.mail(invitationEmail(webURL, { to: email, invitationId: id, organizationName: organization.name })),
          },
        });
        const res = await transactional.handler(request);
        if (res.status >= 400) throw new Refused(res);
        return res;
      });
    } catch (err) {
      if (err instanceof Refused) return err.response;
      throw err;
    }
  }

  return {
    async serve(request) {
      const url = new URL(request.url);
      const endpoint = url.pathname.slice(PATH.length);

      if (request.method === "GET" && READS.has(endpoint)) {
        const needs = READS.get(endpoint);
        const session = await auth.api.getSession({ headers: request.headers });
        if (session) await admit(session.user);
        if (needs) {
          const organizationId = url.searchParams.get("organizationId");
          if (!organizationId) return refusal(400, "organizationId is required");
          if (!session) throw new HttpError(401, "sign in required");
          await authorize(session.user, organizationId, needs);
        }
        return auth.handler(request);
      }

      const rule = request.method === "POST" ? CHANGES.get(endpoint) : undefined;
      if (!rule) return refusal(404, "not found");
      const session = await auth.api.getSession({ headers: request.headers });
      if (!session) return auth.handler(request); // Better Auth's own 401
      await admit(session.user);
      // Inviting someone already invited with `resend` extends the invitation and sends it again, returning before
      // any hook runs, so it would go unaudited. Invite again after cancelling instead.
      if (endpoint === "invite-member") {
        const body = await request.clone().json().catch(() => null);
        if (body?.resend) return refusal(400, "resend is not supported");
      }
      return change(session.user, request, rule);
    },
  };
}

async function lockMemberships(tx: Tx, actor: Actor) {
  await tx.select({ id: member.id }).from(member).where(eq(member.userId, actor.id)).orderBy(asc(member.id)).for("share");
}

async function lockAdministrators(tx: Tx, actor: Actor) {
  const theirs = tx.select({ id: member.organizationId }).from(member).where(eq(member.userId, actor.id));
  await tx
    .select({ id: member.id })
    .from(member)
    .where(and(eq(member.role, ORG_ADMIN_ROLE), inArray(member.organizationId, theirs)))
    .orderBy(asc(member.id))
    .for("update");
}

const refuse = (code: string, message: string) => new APIError("BAD_REQUEST", { code, message });

/**
 * Better Auth accepts its own built-in role names (including "owner", which is reserved for the domain term Owner)
 * wherever a role is assigned, whatever roles we configure. Only ours may be.
 */
function requireKnownRoles(role: string | string[] | undefined) {
  const roles = (Array.isArray(role) ? role : [role ?? ""]).flatMap((r) => r.split(",")).map((r) => r.trim());
  if (roles.length === 0 || roles.some((r) => !isKnownRole(r))) {
    throw refuse("ROLE_NOT_FOUND", "Role not found");
  }
}

/** Better Auth organization hooks: the platform's rules and an Audit Event for each change. */
function auditHooks(tx: Tx, change: Change, removalHooks: { member: MemberRemovalHook[]; team: TeamRemovalHook[] }) {
  const record = (
    organizationId: string,
    action: AuditAction,
    target: { type: string; id: string },
    detail: Record<string, unknown>,
  ) => change.audit({ organizationId, action, target, detail });

  const teamNameTaken = async (organizationId: string, name: string, exceptTeamId?: string) => {
    const [row] = await tx
      .select({ id: team.id })
      .from(team)
      .where(
        and(
          eq(team.organizationId, organizationId),
          sql`lower(${team.name}) = lower(${name})`,
          ...(exceptTeamId ? [ne(team.id, exceptTeamId)] : []),
        ),
      );
    return Boolean(row);
  };

  // Carried from a before-hook to the matching after-hook of the same call.
  let teamIdsBeforeRemoval: string[] = [];
  let teamNameBeforeRename = "";
  let alreadyInTeam = false;

  return {
    beforeCreateInvitation: async ({ invitation: inv }) => {
      requireKnownRoles(inv.role);
      // Accepting such an invitation would add the user to those Teams, which no Team hook sees, so no Audit Event.
      if (inv.teamId) throw refuse("TEAM_INVITATIONS_NOT_SUPPORTED", "Invitations do not carry Teams");
    },
    afterCreateInvitation: async ({ invitation: inv, organization }) => {
      await record(organization.id, "invitation.created", { type: "invitation", id: inv.id }, { email: inv.email, role: inv.role });
    },
    afterAcceptInvitation: async ({ invitation: inv, member: joined, organization }) => {
      await record(organization.id, "invitation.accepted", { type: "invitation", id: inv.id }, { role: joined.role });
      // Any other invitation to the same address is now moot.
      await tx
        .update(invitation)
        .set({ status: "canceled" })
        .where(
          and(
            eq(invitation.organizationId, organization.id),
            eq(invitation.email, inv.email),
            eq(invitation.status, "pending"),
          ),
        );
    },
    afterRejectInvitation: async ({ invitation: inv, organization }) => {
      await record(organization.id, "invitation.rejected", { type: "invitation", id: inv.id }, { email: inv.email, role: inv.role });
    },
    // Better Auth cancels by id whatever the invitation's state; only a pending one can be cancelled.
    beforeCancelInvitation: async ({ invitation: inv }) => {
      if (inv.status !== "pending") throw refuse("INVITATION_NOT_PENDING", "Invitation is no longer pending");
    },
    afterCancelInvitation: async ({ invitation: inv, organization }) => {
      await record(organization.id, "invitation.canceled", { type: "invitation", id: inv.id }, { email: inv.email, role: inv.role });
    },

    beforeUpdateMemberRole: async ({ newRole }) => requireKnownRoles(newRole),
    afterUpdateMemberRole: async ({ member: updated, previousRole, user, organization }) => {
      if (previousRole === updated.role) return;
      await record(
        organization.id,
        "member.role_changed",
        { type: "member", id: updated.id },
        { userId: updated.userId, email: user.email, from: previousRole, to: updated.role },
      );
    },
    beforeRemoveMember: async ({ member: leaving, organization }) => {
      const rows = await tx
        .select({ id: teamMember.teamId })
        .from(teamMember)
        .innerJoin(team, eq(team.id, teamMember.teamId))
        .where(and(eq(teamMember.userId, leaving.userId), eq(team.organizationId, organization.id)));
      teamIdsBeforeRemoval = rows.map((r) => r.id);
    },
    afterRemoveMember: async ({ member: removed, user, organization }) => {
      // Better Auth has already removed the user from the Organization's Teams. Anything else that depends on
      // the membership goes here, in the same transaction.
      for (const hook of removalHooks.member) await hook(tx, { organizationId: organization.id, userId: removed.userId }, change);
      // An invitation still pending for this address would otherwise let them back in unnoticed.
      const canceled = await tx
        .update(invitation)
        .set({ status: "canceled" })
        .where(
          and(
            eq(invitation.organizationId, organization.id),
            eq(invitation.email, user.email.toLowerCase()),
            eq(invitation.status, "pending"),
          ),
        )
        .returning({ id: invitation.id });
      await record(
        organization.id,
        "member.removed",
        { type: "member", id: removed.id },
        {
          userId: removed.userId,
          email: user.email,
          role: removed.role,
          teamIds: teamIdsBeforeRemoval,
          canceledInvitationIds: canceled.map((r) => r.id),
        },
      );
    },

    // Team names are unique within an Organization, ignoring case (a unique index backs this up).
    beforeCreateTeam: async ({ team: t }) => {
      if (await teamNameTaken(t.organizationId, t.name)) throw refuse("TEAM_ALREADY_EXISTS", "Team already exists");
    },
    afterCreateTeam: async ({ team: t, organization }) => {
      await record(organization.id, "team.created", { type: "team", id: t.id }, { name: t.name });
    },
    beforeUpdateTeam: async ({ team: t, updates }) => {
      teamNameBeforeRename = t.name;
      if (updates.name && (await teamNameTaken(t.organizationId, updates.name, t.id))) {
        throw refuse("TEAM_ALREADY_EXISTS", "Team already exists");
      }
    },
    afterUpdateTeam: async ({ team: t, organization }) => {
      if (!t || t.name === teamNameBeforeRename) return;
      await record(organization.id, "team.renamed", { type: "team", id: t.id }, { from: teamNameBeforeRename, to: t.name });
    },
    beforeDeleteTeam: async ({ team: t, organization }) => {
      for (const hook of removalHooks.team) await hook(tx, { organizationId: organization.id, teamId: t.id, teamName: t.name }, change);
    },
    afterDeleteTeam: async ({ team: t, organization }) => {
      await record(organization.id, "team.deleted", { type: "team", id: t.id }, { name: t.name });
    },
    // Better Auth treats adding someone already in the Team as a success; it must not be audited as a change.
    beforeAddTeamMember: async ({ teamMember: tm }) => {
      const [row] = await tx
        .select({ id: teamMember.id })
        .from(teamMember)
        .where(and(eq(teamMember.teamId, tm.teamId), eq(teamMember.userId, tm.userId)));
      alreadyInTeam = Boolean(row);
    },
    afterAddTeamMember: async ({ team: t, user, organization }) => {
      if (alreadyInTeam) return;
      await record(organization.id, "team.member_added", { type: "team", id: t.id }, { name: t.name, userId: user.id, email: user.email });
    },
    afterRemoveTeamMember: async ({ team: t, user, organization }) => {
      await record(organization.id, "team.member_removed", { type: "team", id: t.id }, { name: t.name, userId: user.id, email: user.email });
    },
  } satisfies NonNullable<NonNullable<Parameters<typeof createAuth>[0]["organization"]>["organizationHooks"]>;
}
