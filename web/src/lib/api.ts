// The web UI talks only to the platform's HTTP API (described by /api/openapi.json).
// Sign-in and sign-up go through Better Auth's endpoints, which are mounted on that same API under /api/auth.
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function call<T>(path: string, init?: { method?: string; body?: unknown }): Promise<T> {
  const res = await fetch(path, {
    method: init?.method ?? (init?.body ? "POST" : "GET"),
    credentials: "same-origin",
    headers: init?.body ? { "content-type": "application/json" } : undefined,
    body: init?.body ? JSON.stringify(init.body) : undefined,
  });
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, data?.error ?? data?.message ?? res.statusText);
  return data as T;
}

export interface Me {
  user: { id: string; email: string; name: string; isPlatformOperator: boolean };
  organizations: { id: string; name: string; slug: string; role: string }[];
}

export type OrgRole = "member" | "approver" | "organization-administrator";
export const ROLE_LABELS: Record<OrgRole, string> = {
  member: "Member",
  approver: "Approver",
  "organization-administrator": "Organization Administrator",
};
export interface OrgMember {
  id: string;
  userId: string;
  email: string;
  name: string;
  role: string;
}
export interface PendingInvitation {
  id: string;
  email: string;
  role: string;
  expiresAt: string;
}
export interface Team {
  id: string;
  name: string;
  members: { userId: string; email: string }[];
}

// The organization endpoints are Better Auth's own, served under /api/auth/organization (see the allowlist in
// server/src/app.ts). The one exception is the Teams overview, which Better Auth cannot provide.
const BA = "/api/auth/organization";
export const api = {
  me: () => call<Me>("/api/me"),
  signIn: (email: string, password: string) => call("/api/auth/sign-in/email", { body: { email, password } }),
  signUp: (email: string, password: string, name: string) =>
    call("/api/auth/sign-up/email", { body: { email, password, name } }),
  signOut: () => call("/api/auth/sign-out", { method: "POST", body: {} }),
  acceptInvitation: (invitationId: string) => call(`${BA}/accept-invitation`, { body: { invitationId } }),
  managedCertificates: (orgId: string) =>
    call<{ items: { id: string }[] }>(`/api/organizations/${orgId}/managed-certificates`),
  platformOrganizations: () => call<{ items: { id: string; name: string; slug: string }[] }>("/api/platform/organizations"),
  createOrganization: (body: { name: string; slug: string; adminEmail: string }) =>
    call<{ id: string; invitationId: string }>("/api/platform/organizations", { body }),
  members: async (orgId: string) => {
    const res = await call<{ members: { id: string; userId: string; role: string; user: { email: string; name: string } }[] }>(
      `${BA}/list-members?organizationId=${orgId}`,
    );
    return { items: res.members.map((m): OrgMember => ({ id: m.id, userId: m.userId, email: m.user.email, name: m.user.name, role: m.role })) };
  },
  changeRole: (orgId: string, memberId: string, role: OrgRole) =>
    call(`${BA}/update-member-role`, { body: { memberId, role, organizationId: orgId } }),
  removeMember: (orgId: string, memberId: string) =>
    call(`${BA}/remove-member`, { body: { memberIdOrEmail: memberId, organizationId: orgId } }),
  invitations: async (orgId: string) => {
    const all = await call<{ id: string; email: string; role: string; status: string; expiresAt: string }[]>(
      `${BA}/list-invitations?organizationId=${orgId}`,
    );
    const now = Date.now();
    const items = all.filter((i) => i.status === "pending" && Date.parse(i.expiresAt) > now);
    return { items: items.map((i): PendingInvitation => ({ id: i.id, email: i.email, role: i.role, expiresAt: i.expiresAt })) };
  },
  invite: (orgId: string, email: string, role: OrgRole) => call(`${BA}/invite-member`, { body: { email, role, organizationId: orgId } }),
  cancelInvitation: (_orgId: string, invitationId: string) => call(`${BA}/cancel-invitation`, { body: { invitationId } }),
  teams: (orgId: string) => call<{ items: Team[] }>(`/api/organizations/${orgId}/teams`),
  createTeam: (orgId: string, name: string) => call(`${BA}/create-team`, { body: { name, organizationId: orgId } }),
  renameTeam: (orgId: string, teamId: string, name: string) =>
    call(`${BA}/update-team`, { body: { teamId, data: { name, organizationId: orgId } } }),
  deleteTeam: (orgId: string, teamId: string) => call(`${BA}/remove-team`, { body: { teamId, organizationId: orgId } }),
  addTeamMember: (orgId: string, teamId: string, userId: string) =>
    call(`${BA}/add-team-member`, { body: { teamId, userId, organizationId: orgId } }),
  removeTeamMember: (orgId: string, teamId: string, userId: string) =>
    call(`${BA}/remove-team-member`, { body: { teamId, userId, organizationId: orgId } }),
};
