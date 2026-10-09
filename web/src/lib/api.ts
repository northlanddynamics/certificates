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

const orgPath = (orgId: string, rest: string) => `/api/organizations/${orgId}${rest}`;

export const api = {
  me: () => call<Me>("/api/me"),
  signIn: (email: string, password: string) => call("/api/auth/sign-in/email", { body: { email, password } }),
  signUp: (email: string, password: string, name: string) =>
    call("/api/auth/sign-up/email", { body: { email, password, name } }),
  signOut: () => call("/api/auth/sign-out", { method: "POST", body: {} }),
  acceptInvitation: (id: string) =>
    call<{ organizationId: string; role: string }>(`/api/invitations/${id}/accept`, { method: "POST", body: {} }),
  managedCertificates: (orgId: string) =>
    call<{ items: { id: string }[] }>(`/api/organizations/${orgId}/managed-certificates`),
  platformOrganizations: () => call<{ items: { id: string; name: string; slug: string }[] }>("/api/platform/organizations"),
  createOrganization: (body: { name: string; slug: string; adminEmail: string }) =>
    call<{ id: string; invitationId: string }>("/api/platform/organizations", { body }),
  members: (orgId: string) => call<{ items: OrgMember[] }>(orgPath(orgId, "/members")),
  changeRole: (orgId: string, memberId: string, role: OrgRole) =>
    call(orgPath(orgId, `/members/${memberId}`), { method: "PATCH", body: { role } }),
  removeMember: (orgId: string, memberId: string) => call(orgPath(orgId, `/members/${memberId}`), { method: "DELETE" }),
  invitations: (orgId: string) => call<{ items: PendingInvitation[] }>(orgPath(orgId, "/invitations")),
  invite: (orgId: string, email: string, role: OrgRole) => call(orgPath(orgId, "/invitations"), { body: { email, role } }),
  cancelInvitation: (orgId: string, id: string) => call(orgPath(orgId, `/invitations/${id}`), { method: "DELETE" }),
  teams: (orgId: string) => call<{ items: Team[] }>(orgPath(orgId, "/teams")),
  createTeam: (orgId: string, name: string) => call(orgPath(orgId, "/teams"), { body: { name } }),
  renameTeam: (orgId: string, teamId: string, name: string) =>
    call(orgPath(orgId, `/teams/${teamId}`), { method: "PATCH", body: { name } }),
  deleteTeam: (orgId: string, teamId: string) => call(orgPath(orgId, `/teams/${teamId}`), { method: "DELETE" }),
  addTeamMember: (orgId: string, teamId: string, userId: string) =>
    call(orgPath(orgId, `/teams/${teamId}/members`), { body: { userId } }),
  removeTeamMember: (orgId: string, teamId: string, userId: string) =>
    call(orgPath(orgId, `/teams/${teamId}/members/${userId}`), { method: "DELETE" }),
};
