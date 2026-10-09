// Organization roles and what each may do: the one place permissions are declared. Better Auth's organization
// endpoints check these roles themselves, our own `authorize` (authorization.ts) asks the same roles, and
// /api/me reports what the caller holds, so nothing else needs to know which role has which permission.
import { createAccessControl } from "better-auth/plugins/access";

// Better Auth's default "owner" role is deliberately absent: "Owner" is a domain term for the party accountable
// for a Managed Certificate.
export const ORG_ADMIN_ROLE = "organization-administrator";
export const APPROVER_ROLE = "approver";
export const MEMBER_ROLE = "member";

// Every permission there is. The organization, member, invitation and team resources are the ones Better Auth's
// organization plugin checks itself; `audit` is ours.
const statements = {
  organization: ["update", "delete"],
  member: ["create", "update", "delete"],
  invitation: ["create", "cancel"],
  team: ["create", "update", "delete"],
  audit: ["read"],
} as const;

export type Permissions = { [R in keyof typeof statements]?: (typeof statements)[R][number][] };

export const ac = createAccessControl(statements);

// An Organization Administrator has full control, so holds every declared permission, including any declared
// later. Approvers and Members hold none until one is granted to them here on purpose.
export const orgRoles = {
  [ORG_ADMIN_ROLE]: ac.newRole(statements),
  [APPROVER_ROLE]: ac.newRole({}),
  [MEMBER_ROLE]: ac.newRole({}),
};

const roleOf = (name: string) => (Object.hasOwn(orgRoles, name) ? orgRoles[name as keyof typeof orgRoles] : undefined);

/** The roles the platform accepts, which Better Auth's own built-in role names ("owner", "admin") are not. */
export const ROLE_NAMES = Object.keys(orgRoles);

export const isKnownRole = (name: string) => roleOf(name) !== undefined;

/** Whether `role` holds every permission asked for. An unknown role holds none. */
export function roleCan(role: string, permissions: Permissions): boolean {
  return roleOf(role)?.authorize(permissions).success ?? false;
}

/** Every permission `role` holds: what a client may ask about instead of comparing role names. */
export function permissionsOf(role: string): Permissions {
  const held: Record<string, readonly string[]> = roleOf(role)?.statements ?? {};
  return Object.fromEntries(Object.entries(held).filter(([, actions]) => actions.length > 0)) as Permissions;
}

/** Every permission declared, whoever holds it. */
export const declaredPermissions = (): Permissions => statements as unknown as Permissions;
