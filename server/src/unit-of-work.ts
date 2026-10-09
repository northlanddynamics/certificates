// One audited unit of work: Better Auth's organization endpoints run on a database transaction of ours, and
// its organization hooks write the audit entries on that same transaction. Better Auth's own endpoints do not
// open a transaction (and its hooks run between separate statements), so this is what makes "the change and
// its audit entry commit or roll back together" true for everything Better Auth does.
import { and, eq, inArray } from "drizzle-orm";
import { createAuth, type Auth, type AuthConfig } from "./auth";
import { recordAudit } from "./audit";
import type { Db, Tx } from "./db/client";
import { invitation, team, teamMember } from "./db/schema";
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
   * Runs `fn` in a transaction with a Better Auth instance bound to it. Audit entries for what Better Auth
   * changes are written in the same transaction; invitation emails are sent only after it commits.
   * Anything `fn` throws rolls everything back.
   */
  run<T>(actor: Actor, fn: (auth: Auth, tx: Tx) => Promise<T>): Promise<T>;
}

export function createUnitOfWork(deps: UnitOfWorkDeps): UnitOfWork {
  const { db, authConfig, mailer, clock, webURL } = deps;
  return {
    async run(actor, fn) {
      const outbox: Array<() => Promise<void>> = [];
      const result = await db.transaction(async (tx) => {
        const auth = createAuth({
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
        return fn(auth, tx);
      });
      // Committed: a mail failure must not hide that from the caller.
      for (const send of outbox) await send().catch((err) => console.error("invitation email failed", err));
      return result;
    },
  };
}

/** Better Auth organization hooks that record an audit entry for each change. */
function auditHooks(tx: Tx, actor: Actor, occurredAt: Date) {
  const record = (
    organizationId: string,
    action: string,
    target: { type: string; id: string },
    detail: Record<string, unknown>,
  ) => recordAudit(tx, { organizationId, occurredAt, actor, action, target, detail });

  // Carried from a before-hook to the matching after-hook of the same call.
  let teamIdsBeforeRemoval: string[] = [];
  let teamNameBeforeRename = "";

  return {
    afterCreateInvitation: async ({ invitation: inv, organization }) => {
      await record(organization.id, "invitation.created", { type: "invitation", id: inv.id }, { email: inv.email, role: inv.role });
    },
    afterAcceptInvitation: async ({ invitation: inv, member, organization }) => {
      await record(organization.id, "invitation.accepted", { type: "invitation", id: inv.id }, { role: member.role });
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
    afterCancelInvitation: async ({ invitation: inv, organization }) => {
      await record(organization.id, "invitation.canceled", { type: "invitation", id: inv.id }, { email: inv.email, role: inv.role });
    },

    afterUpdateMemberRole: async ({ member, previousRole, user, organization }) => {
      if (previousRole === member.role) return;
      await record(
        organization.id,
        "member.role_changed",
        { type: "member", id: member.id },
        { userId: member.userId, email: user.email, from: previousRole, to: member.role },
      );
    },
    beforeRemoveMember: async ({ member, organization }) => {
      const rows = await tx
        .select({ id: teamMember.teamId })
        .from(teamMember)
        .innerJoin(team, eq(team.id, teamMember.teamId))
        .where(and(eq(teamMember.userId, member.userId), eq(team.organizationId, organization.id)));
      teamIdsBeforeRemoval = rows.map((r) => r.id);
    },
    afterRemoveMember: async ({ member, user, organization }) => {
      // Better Auth has already removed the user from the Organization's Teams. Anything else that depends on
      // the membership goes here, in the same transaction.
      for (const hook of memberRemovalHooks) await hook(tx, { organizationId: organization.id, userId: member.userId });
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
        { type: "member", id: member.id },
        {
          userId: member.userId,
          email: user.email,
          role: member.role,
          teamIds: teamIdsBeforeRemoval,
          canceledInvitationIds: canceled.map((r) => r.id),
        },
      );
    },

    afterCreateTeam: async ({ team: t, organization }) => {
      await record(organization.id, "team.created", { type: "team", id: t.id }, { name: t.name });
    },
    beforeUpdateTeam: async ({ team: t }) => {
      teamNameBeforeRename = t.name;
    },
    afterUpdateTeam: async ({ team: t, organization }) => {
      if (!t || t.name === teamNameBeforeRename) return;
      await record(organization.id, "team.renamed", { type: "team", id: t.id }, { from: teamNameBeforeRename, to: t.name });
    },
    afterDeleteTeam: async ({ team: t, organization }) => {
      await record(organization.id, "team.deleted", { type: "team", id: t.id }, { name: t.name });
    },
    afterAddTeamMember: async ({ team: t, user, organization }) => {
      await record(organization.id, "team.member_added", { type: "team", id: t.id }, { name: t.name, userId: user.id, email: user.email });
    },
    afterRemoveTeamMember: async ({ team: t, user, organization }) => {
      await record(organization.id, "team.member_removed", { type: "team", id: t.id }, { name: t.name, userId: user.id, email: user.email });
    },
  } satisfies NonNullable<NonNullable<Parameters<typeof createAuth>[0]["organization"]>["organizationHooks"]>;
}
