// Organization roles and what each may do: the one place permissions are declared. Better Auth's organization
// endpoints check these roles themselves, our own `authorize` (authorization.ts) asks the same roles, and
// /api/me reports what the caller holds, so nothing else needs to know which role has which permission.
import { createAccessControl } from "better-auth/plugins/access";

// Better Auth's default "owner" role is deliberately absent: "Owner" is a domain term for the party accountable
// for a Managed Certificate.
export const ORG_ADMIN_ROLE = "organization-administrator";

/** The platform-wide role (Better Auth's admin plugin) of a Platform Operator, as opposed to an Organization role. */
export const PLATFORM_OPERATOR_ROLE = "platform-operator";
export const APPROVER_ROLE = "approver";
export const MEMBER_ROLE = "member";

// Every permission there is. The organization, member, invitation and team resources are the ones Better Auth's
// organization plugin checks itself; `audit`, `acmeAccount`, `dnsProvider`, `validationZone`, `dcvRule`, `managedCertificate`, `approval`, `agent`, `deploymentScript`, `deployment`, `notificationChannel`, `auditForwarder`, `loginPolicy`, `ssoConnection`, `privateCa`, `enrollmentProfile` and `apiKey` are ours (the last is the plugin's too).
const statements = {
  organization: ["update", "delete"],
  member: ["create", "update", "delete"],
  invitation: ["create", "cancel"],
  team: ["create", "update", "delete"],
  audit: ["read"],
  acmeAccount: ["read", "create", "update", "test"],
  dnsProvider: ["read", "create", "update", "test"],
  // Delegated DCV: where `_acme-challenge` names are delegated to, and how each name or zone is validated. `dcvRule.read`
  // also shows the CNAME record a name needs.
  validationZone: ["read", "create", "delete"],
  dcvRule: ["read", "create", "update", "delete"],
  // `read` sees every Managed Certificate in the Organization (anyone else sees only what they own or proposed);
  // `create` makes one outright; `propose` asks for one that waits for Approval; `changeOwners` changes whose it is
  // (its Owners may do that too, whatever their role, as they may `changeSubscribers`, `renew` it now, `setRenewalPolicy`, `replaceCsr` and
  // `proposeNameChange`); `changeNames` changes its names outright, where a proposed name change waits for Approval;
  // `download` exports a Certificate it may see, and is what an API key must carry to do the same; `revoke` tells the CA
  // to distrust a Certificate (its Owners may, whatever their role) and `archive` retires the Managed Certificate (only
  // those who hold it may, so not its Owners); `changeIssuer` repoints it to another Issuing CA, with no Approval.
  managedCertificate: ["read", "create", "propose", "issue", "changeOwners", "renew", "setRenewalPolicy", "replaceCsr", "proposeNameChange", "changeNames", "download", "revoke", "archive", "changeSubscribers", "changeIssuer"],
  approval: ["read", "decide"],
  // Agents: `register` makes the single-use token by which one registers into the Organization, `read` lists them, `revoke` ends one's credential.
  agent: ["read", "register", "revoke"],
  // Deployment Scripts: what Agents run on their hosts (ADR 0004), so only Organization Administrators hold any of this.
  // `read` sees the library and every version's content; `upload` adds a script or a new version of one.
  deploymentScript: ["read", "upload"],
  // Deployments: an Agent making the key for a Managed Certificate and running a Deployment Script to put its Certificates to
  // use, which is running code on hosts, so only Organization Administrators hold any of this. `create` sets one up, `read`
  // sees them and their runs, `run` has an Agent run one again for its current Certificate.
  deployment: ["read", "create", "run"],
  // Notification channels: email addresses and webhooks a Managed Certificate's notices can go to. `read` lists them (names
  // and kinds, never a webhook's URL), so anyone who may subscribe one may choose it; `create` and `delete` configure them.
  notificationChannel: ["read", "create", "delete"],
  // Audit forwarders: where the Organization's Audit Events are sent, a SIEM. Like the audit log itself, only Organization
  // Administrators hold any of this.
  auditForwarder: ["read", "create", "delete"],
  // The Organization's login policy: whether its password users must have MFA. Only Organization Administrators hold any of this.
  loginPolicy: ["read", "update"],
  // The Organization's SSO connections: the identity providers its users sign in through, so only Organization Administrators
  // hold any of this. `test` checks one against its provider without signing anyone in.
  ssoConnection: ["read", "create", "update", "delete", "test"],
  // The Organization's own API keys (a user's keys need none): the organization plugin asks for these names.
  apiKey: ["create", "read", "update", "delete"],
  // Private CAs: the Organization's own CAs. Everyone may `read` them, to see which exist and download their chains, so
  // as to propose against the right one; only Organization Administrators `create`, `update`, `retire` or `revoke` one.
  privateCa: ["read", "create", "update", "retire", "revoke"],
  // Enrollment Profiles: what devices enroll under, from the Private CAs, with no Approval and no Owners, so only
  // Organization Administrators hold any of this. `read` sees them, their SCEP URLs and CA certificates; `create`,
  // `update` and `disable` configure them.
  enrollmentProfile: ["read", "create", "update", "disable"],
} as const;

export type Permissions = { [R in keyof typeof statements]?: (typeof statements)[R][number][] };

export const ac = createAccessControl(statements);

// An Organization Administrator has full control, so holds every declared permission, including any declared
// later. Approvers and Members hold only what is granted to them here on purpose: both may propose a Managed
// Certificate, only an Approver sees the Approval queue and decides, and an Approver sees every Managed Certificate
// to decide knowingly while a Member sees only their own.
export const orgRoles = {
  [ORG_ADMIN_ROLE]: ac.newRole(statements),
  [APPROVER_ROLE]: ac.newRole({ managedCertificate: ["read", "propose", "download"], approval: ["read", "decide"], notificationChannel: ["read"], privateCa: ["read"] }),
  [MEMBER_ROLE]: ac.newRole({ managedCertificate: ["propose", "download"], notificationChannel: ["read"], privateCa: ["read"] }),
};

const roleOf = (name: string) => (Object.hasOwn(orgRoles, name) ? orgRoles[name as keyof typeof orgRoles] : undefined);

/** The roles the platform accepts, which Better Auth's own built-in role names ("owner", "admin") are not. */
export const ROLE_NAMES = Object.keys(orgRoles);

export const isKnownRole = (name: string) => roleOf(name) !== undefined;

/** Whether `role` holds every permission asked for. An unknown role holds none. */
export function roleCan(role: string, permissions: Permissions): boolean {
  return roleOf(role)?.authorize(permissions).success ?? false;
}

/** Whether `carried`, what an API key was given, holds every permission asked for. */
export function carries(carried: Record<string, string[]>, needed: Permissions): boolean {
  return Object.entries(needed).every(([resource, actions]) => actions.every((action) => Object.hasOwn(carried, resource) && carried[resource]!.includes(action)));
}

/** Every permission `role` holds: what a client may ask about instead of comparing role names. */
export function permissionsOf(role: string): Permissions {
  const held: Record<string, readonly string[]> = roleOf(role)?.statements ?? {};
  return Object.fromEntries(Object.entries(held).filter(([, actions]) => actions.length > 0)) as Permissions;
}

/** Every permission declared, whoever holds it. */
export const declaredPermissions = (): Permissions => statements as unknown as Permissions;
