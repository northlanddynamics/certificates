// Better Auth's organization endpoints, served as they are, but each change on a database transaction of ours,
// with Better Auth's organization hooks writing the audit entries on that same transaction. Its endpoints open
// no transaction themselves (and its hooks run between separate statements), so this is what makes "the change
// and its audit entry commit or roll back together" true for everything it does.
import { APIError } from "better-auth/api";
import { and, asc, eq, inArray, ne, sql } from "drizzle-orm";
import { ORG_ADMIN_ROLE, createAuth, orgRoles, type Auth, type AuthConfig } from "./auth";
import { recordAudit } from "./audit";
import type { Db, Tx } from "./db/client";
import { invitation, member, team, teamMember } from "./db/schema";
import { memberRemovalHooks } from "./member-removal";
import type { Mailer } from "./mailer";

export type Actor = { id: string; email: string };

export interface UnitOfWorkDeps {
  db: Db;
  authConfig: Omit<AuthConfig, "db" | "organization">;
  mailer: Mailer;
  clock: () => Date;
  /** Where users open the web UI, for the link in invitation emails. */
  webURL: string;
}

export interface UnitOfWork {
  /**
   * Hands `request` to Better Auth on a transaction. A response with an error status rolls everything back, so a
   * refused or failed change leaves no trace. Invitation emails are sent only after a successful commit.
   *
   * `administrators`: the change may remove or demote an Organization Administrator. Better Auth refuses to leave
   * an Organization with none, but by reading, so two concurrent changes could both pass; locking the
   * administrators makes each wait for the other. Otherwise the actor's own memberships are locked, so that a
   * concurrent demotion or removal of the actor waits for this change instead of racing it.
   */
  handle(actor: Actor, request: Request, options?: { administrators?: boolean }): Promise<Response>;
}

/** Thrown to roll back and still answer with Better Auth's own error response. */
class Refused extends Error {
  constructor(readonly response: Response) {
    super("refused");
  }
}

export function createUnitOfWork(deps: UnitOfWorkDeps): UnitOfWork {
  const { db, authConfig, mailer, clock, webURL } = deps;
  return {
    async handle(actor, request, { administrators = false } = {}) {
      const outbox: Array<() => Promise<void>> = [];
      let response: Response;
      try {
        response = await db.transaction(async (tx) => {
          await (administrators ? lockAdministrators(tx, actor) : lockMemberships(tx, actor));
          const auth: Auth = createAuth({
            ...authConfig,
            db: tx,
            organization: {
              organizationHooks: auditHooks(tx, actor, clock()),
              sendInvitationEmail: async ({ id, email, organization }) => {
                outbox.push(() =>
                  mailer.send({
                    to: email,
                    subject: `You are invited to join ${organization.name}`,
                    text: `Accept your invitation: ${webURL}/accept-invitation/${id}`,
                  }),
                );
              },
            },
          });
          const res = await auth.handler(request);
          if (res.status >= 400) throw new Refused(res);
          return res;
        });
      } catch (err) {
        if (err instanceof Refused) return err.response;
        throw err;
      }
      // Committed: a mail failure must not hide that from the caller.
      for (const send of outbox) await send().catch((err) => console.error("invitation email failed", err));
      return response;
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
  if (roles.length === 0 || roles.some((r) => !Object.hasOwn(orgRoles, r))) {
    throw refuse("ROLE_NOT_FOUND", "Role not found");
  }
}

/** Better Auth organization hooks: the platform's rules and an audit entry for each change. */
function auditHooks(tx: Tx, actor: Actor, occurredAt: Date) {
  const record = (
    organizationId: string,
    action: string,
    target: { type: string; id: string },
    detail: Record<string, unknown>,
  ) => recordAudit(tx, { organizationId, occurredAt, actor, action, target, detail });

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
      // Accepting such an invitation would add the user to those Teams, which no Team hook sees, so no audit entry.
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
      for (const hook of memberRemovalHooks) await hook(tx, { organizationId: organization.id, userId: removed.userId });
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
