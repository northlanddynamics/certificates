// A Managed Certificate's Owners: users or Teams of its Organization, or none. They decide who sees a Managed
// Certificate that is not a Member's own proposal (a Member sees only what they own), and may change its Owners.
import { z } from "@hono/zod-openapi";
import { and, eq, inArray, sql, type SQL } from "drizzle-orm";
import type { Db, Tx } from "../platform/db/client";
import { managedCertificate, managedCertificateOwner, member, team, teamMember, user } from "../platform/db/schema";
import { HttpError } from "../platform/http";
import type { MemberRemovalHook, TeamRemovalHook } from "../tenancy/member-removal";
import type { Change } from "../platform/unit-of-work";

export const OWNER_TYPES = ["user", "team"] as const;

/** Who may be named an Owner. */
export const OwnerRef = z.object({ type: z.enum(OWNER_TYPES), id: z.string().min(1) });
export type OwnerRef = z.infer<typeof OwnerRef>;

/** An Owner as the API shows it: a user by their email, a Team by its name. */
type OwnerView = { type: "user"; id: string; email: string } | { type: "team"; id: string; name: string };

const owner = managedCertificateOwner;
/** The Owner row's column that names `ref`. */
const isRef = (ref: OwnerRef) => (ref.type === "user" ? eq(owner.userId, ref.id) : eq(owner.teamId, ref.id));

/**
 * The condition under which `userId` owns a Managed Certificate (the `managedCertificate` table of the query it goes
 * into): directly, or through a Team they are in.
 */
export function ownedByUser(organizationId: string, userId: string): SQL {
  const through = sql`${owner.teamId} in (select ${teamMember.teamId} from ${teamMember} where ${teamMember.userId} = ${userId})`;
  return sql`exists (select 1 from ${owner} where ${owner.organizationId} = ${organizationId} and ${owner.managedCertificateId} = ${managedCertificate.id} and (${owner.userId} = ${userId} or ${through}))`;
}

/** The condition under which a Managed Certificate has no Owners. */
export const hasNoOwners = (): SQL =>
  sql`not exists (select 1 from ${owner} where ${owner.managedCertificateId} = ${managedCertificate.id})`;

/** Whether `userId` owns the Managed Certificate. */
export async function isOwner(db: Db | Tx, organizationId: string, managedCertificateId: string, userId: string) {
  const [row] = await db
    .select({ id: managedCertificate.id })
    .from(managedCertificate)
    .where(and(eq(managedCertificate.id, managedCertificateId), eq(managedCertificate.organizationId, organizationId), ownedByUser(organizationId, userId)));
  return Boolean(row);
}

/** The Owners of each of the Managed Certificates, in the order they were added. */
export async function ownersOf(db: Db | Tx, managedCertificateIds: string[]): Promise<Map<string, OwnerView[]>> {
  const owners = new Map<string, OwnerView[]>(managedCertificateIds.map((id) => [id, []]));
  if (managedCertificateIds.length === 0) return owners;
  const rows = await db
    .select({ managedCertificateId: owner.managedCertificateId, userId: user.id, email: user.email, teamId: team.id, teamName: team.name })
    .from(owner)
    .leftJoin(user, eq(user.id, owner.userId))
    .leftJoin(team, eq(team.id, owner.teamId))
    .where(inArray(owner.managedCertificateId, managedCertificateIds))
    .orderBy(owner.id);
  for (const row of rows) {
    owners.get(row.managedCertificateId)?.push(row.userId ? { type: "user", id: row.userId, email: row.email! } : { type: "team", id: row.teamId!, name: row.teamName! });
  }
  return owners;
}

/**
 * Who `ref` is, once known to be one the Organization has: the user is a member and the Team is theirs. The row
 * is locked in share mode, so that removing the user from the Organization or deleting the Team, which takes its
 * Owners off, waits for this change or finds it done, and an Owner cannot outlive what it names.
 */
async function lockOwnerTarget(tx: Tx, organizationId: string, ref: OwnerRef): Promise<OwnerView> {
  if (ref.type === "user") {
    const [row] = await tx
      .select({ id: user.id, email: user.email })
      .from(member)
      .innerJoin(user, eq(user.id, member.userId))
      .where(and(eq(member.organizationId, organizationId), eq(member.userId, ref.id)))
      .for("share", { of: member });
    if (!row) throw new HttpError(422, `${ref.id} is not a member of this Organization, so cannot be an Owner`);
    return { type: "user", ...row };
  }
  const [row] = await tx
    .select({ id: team.id, name: team.name })
    .from(team)
    .where(and(eq(team.organizationId, organizationId), eq(team.id, ref.id)))
    .for("share");
  if (!row) throw new HttpError(422, `${ref.id} is not a Team of this Organization, so cannot be an Owner`);
  return { type: "team", ...row };
}

/** Makes `ref` an Owner, audited; naming one that already is changes nothing. Refuses (422) one the Organization does not have. */
export async function addOwner(tx: Tx, change: Change, organizationId: string, managedCertificateId: string, ref: OwnerRef) {
  const view = await lockOwnerTarget(tx, organizationId, ref);
  const added = await tx
    .insert(owner)
    .values({ organizationId, managedCertificateId, userId: ref.type === "user" ? ref.id : null, teamId: ref.type === "team" ? ref.id : null })
    .onConflictDoNothing()
    .returning({ id: owner.id });
  if (added.length === 0) return;
  await change.audit({
    organizationId,
    action: "managed_certificate.owner_added",
    target: { type: "managed_certificate", id: managedCertificateId },
    detail: { owner: view },
  });
}

/** Takes `ref` off the Owners, audited. Refuses (404) one that is not an Owner. */
export async function removeOwner(tx: Tx, change: Change, organizationId: string, managedCertificateId: string, ref: OwnerRef) {
  const view = (await ownersOf(tx, [managedCertificateId])).get(managedCertificateId)!.find((o) => o.type === ref.type && o.id === ref.id);
  if (!view) throw new HttpError(404, "that is not an Owner of this Managed Certificate");
  await tx.delete(owner).where(and(eq(owner.organizationId, organizationId), eq(owner.managedCertificateId, managedCertificateId), isRef(ref)));
  await change.audit({
    organizationId,
    action: "managed_certificate.owner_removed",
    target: { type: "managed_certificate", id: managedCertificateId },
    detail: { owner: view },
  });
}

/** Takes every Managed Certificate off whatever `who` names, each audited with why. */
async function removeFromAll(tx: Tx, change: Change, organizationId: string, who: OwnerView, because: string) {
  const removed = await tx
    .delete(owner)
    .where(and(eq(owner.organizationId, organizationId), isRef(who)))
    .returning({ managedCertificateId: owner.managedCertificateId });
  for (const { managedCertificateId } of removed.sort((a, b) => a.managedCertificateId.localeCompare(b.managedCertificateId))) {
    await change.audit({
      organizationId,
      action: "managed_certificate.owner_removed",
      target: { type: "managed_certificate", id: managedCertificateId },
      detail: { owner: who, because },
    });
  }
}

/** Runs when a user is removed from an Organization: they stop being an Owner of anything in it. */
export const removeUserFromOwners: MemberRemovalHook = async (tx, { organizationId, userId }, change) => {
  const [row] = await tx.select({ id: user.id, email: user.email }).from(user).where(eq(user.id, userId));
  if (row) await removeFromAll(tx, change, organizationId, { type: "user", ...row }, "member_removed");
};

/**
 * Runs before a Team is deleted: it stops being an Owner of anything. The Team is locked first, so an Owner being added
 * for it commits before this looks (and is taken off, audited) instead of being dropped unseen by the deletion.
 */
export const removeTeamFromOwners: TeamRemovalHook = async (tx, { organizationId, teamId, teamName }, change) => {
  await tx.select({ id: team.id }).from(team).where(eq(team.id, teamId)).for("update");
  await removeFromAll(tx, change, organizationId, { type: "team", id: teamId, name: teamName }, "team_deleted");
};
