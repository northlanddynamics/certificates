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
  organizations: { id: string; name: string; slug: string; role: string; permissions: Record<string, string[]> }[];
  /** The roles the server accepts when assigning one. */
  roles: string[];
}

/** Whether the caller may do `action` on `resource` in `org`, as the server reports it. */
export const can = (org: Me["organizations"][number], resource: string, action: string) =>
  org.permissions[resource]?.includes(action) ?? false;

// How roles are worded; which roles exist is the server's to say (Me.roles).
const ROLE_LABELS: Record<string, string> = {
  member: "Member",
  approver: "Approver",
  "organization-administrator": "Organization Administrator",
};
export const roleLabel = (role: string) => ROLE_LABELS[role] ?? role;
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
export interface Issuance {
  id: string;
  status: "running" | "succeeded" | "failed";
  failure: { code: string; message: string } | null;
}
export interface Approval {
  status: "not_required" | "pending" | "approved" | "rejected";
  proposedBy: { id: string; email: string } | null;
  decidedBy: { id: string; email: string } | null;
  decidedAt: string | null;
  reason: string | null;
}
export type Owner = { type: "user"; id: string; email: string } | { type: "team"; id: string; name: string };
export type OwnerRef = { type: Owner["type"]; id: string };
/** An owner as one string, for a form control's value, and back. */
export const ownerKey = (o: OwnerRef) => `${o.type}:${o.id}`;
export const ownerFromKey = (key: string): OwnerRef => ({ type: key.startsWith("team:") ? "team" : "user", id: key.slice(key.indexOf(":") + 1) });
export const ownerLabel = (o: Owner) => (o.type === "user" ? o.email : `${o.name} (Team)`);
/** The inventory's filters; each narrows what is listed, and they combine. */
export interface InventoryFilters {
  expiringSoon?: boolean;
  renewalFailing?: boolean;
  pendingApproval?: boolean;
  noOwners?: boolean;
  archived?: boolean;
  keyCustody?: "owner";
}
export type HistoryEntry =
  | { kind: "created" | "proposed" | "approved" | "rejected"; at: string; actor: { id: string; email: string } | null; reason: string | null }
  | { kind: "certificate_issued"; at: string; certificate: { fingerprint: string; notBefore: string; notAfter: string; names: string[] } };
export interface RenewalPolicy {
  mode: "automatic" | "manual";
  daysBeforeExpiry: number;
}
export interface Renewal {
  policy: RenewalPolicy;
  /** When the scheduler will renew it; none for a manual one or one with no Certificate yet. */
  dueAt: string | null;
  /** Set while the latest Renewal has failed. */
  failing: { failures: number; lastFailure: { code: string; message: string; at: string }; nextAttemptAt: string | null } | null;
}
export interface ManagedCertificate {
  id: string;
  names: string[];
  keyAlgorithm: string;
  environment: "staging" | "production";
  owners: Owner[];
  approval: Approval;
  renewal: Renewal;
  issuance: Issuance | null;
  currentCertificate: { fingerprint: string; notAfter: string } | null;
}
export const EXPORT_FORMATS: [string, string][] = [
  ["pem", "PEM"],
  ["der", "DER"],
  ["p7b", "PKCS#7 (P7B)"],
];
export const EXPORT_CHAINS: [string, string][] = [
  ["with-intermediates", "Leaf and intermediates"],
  ["leaf", "Leaf only"],
  ["with-root", "Leaf, intermediates and root"],
];
export interface Certificate {
  id: string;
  fingerprint: string;
  notBefore: string;
  notAfter: string;
  issuedAt: string;
}
export interface ApiKey {
  id: string;
  /** A user's key is its person's; an Organization's belongs to the Organization and outlives whoever made it. */
  type: "user" | "organization";
  name: string;
  /** Who made an Organization's key. */
  createdBy: { id: string; email: string } | null;
  /** The first characters of the key, to tell keys apart; the key itself is shown only when it is made. */
  start: string | null;
  expiresAt: string | null;
  createdAt: string;
}
export interface NewManagedCertificate {
  names: string[];
  keyAlgorithm: string;
  csr: string;
  environment: "staging" | "production";
  owners?: OwnerRef[];
}
export interface Team {
  id: string;
  name: string;
  members: { userId: string; email: string }[];
}

// The organization endpoints are Better Auth's own, served under /api/auth/organization (see the allowlist in
// server/src/organization-changes.ts). The one exception is the Teams overview, which Better Auth cannot provide.
const BA = "/api/auth/organization";
export const api = {
  me: () => call<Me>("/api/me"),
  signIn: (email: string, password: string) => call("/api/auth/sign-in/email", { body: { email, password } }),
  signUp: (email: string, password: string, name: string) =>
    call("/api/auth/sign-up/email", { body: { email, password, name } }),
  signOut: () => call("/api/auth/sign-out", { method: "POST", body: {} }),
  acceptInvitation: (invitationId: string) => call(`${BA}/accept-invitation`, { body: { invitationId } }),
  managedCertificates: (orgId: string, filters: InventoryFilters = {}) => {
    const query = new URLSearchParams(Object.entries(filters).filter(([, v]) => v).map(([k, v]) => [k, v === true ? "true" : String(v)]));
    return call<{ items: ManagedCertificate[] }>(`/api/organizations/${orgId}/managed-certificates${query.size ? `?${query}` : ""}`);
  },
  addOwner: (orgId: string, id: string, owner: OwnerRef) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}/owners`, { body: owner }),
  removeOwner: (orgId: string, id: string, owner: OwnerRef) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}/owners/${owner.type}/${encodeURIComponent(owner.id)}`, { method: "DELETE" }),
  history: (orgId: string, id: string) => call<{ items: HistoryEntry[] }>(`/api/organizations/${orgId}/managed-certificates/${id}/history`),
  createManagedCertificate: (orgId: string, body: NewManagedCertificate) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates`, { body }),
  approvalQueue: (orgId: string) => call<{ items: ManagedCertificate[] }>(`/api/organizations/${orgId}/approvals`),
  approve: (orgId: string, id: string, reason?: string) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}/approve`, { body: { reason } }),
  reject: (orgId: string, id: string, reason: string) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}/reject`, { body: { reason } }),
  retryIssuance: (orgId: string, id: string) =>
    call<Issuance>(`/api/organizations/${orgId}/managed-certificates/${id}/issuances`, { method: "POST", body: {} }),
  setRenewalPolicy: (orgId: string, id: string, policy: RenewalPolicy) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}/renewal-policy`, { method: "PUT", body: policy }),
  renewNow: (orgId: string, id: string) =>
    call<Issuance>(`/api/organizations/${orgId}/managed-certificates/${id}/renewals`, { method: "POST", body: {} }),
  uploadCsr: (orgId: string, id: string, csr: string) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}/csr`, { body: { csr } }),
  certificates: (orgId: string, id: string) => call<{ items: Certificate[] }>(`/api/organizations/${orgId}/managed-certificates/${id}/certificates`),
  /** Where a Certificate downloads from: the current one, or the one with `certificateId`. */
  certificateDownloadUrl: (orgId: string, id: string, form: { format: string; chain: string }, certificateId?: string) =>
    `/api/organizations/${orgId}/managed-certificates/${id}/${certificateId ? `certificates/${certificateId}/download` : "certificate"}?${new URLSearchParams(form)}`,
  apiKeys: (orgId: string) => call<{ items: ApiKey[] }>(`/api/organizations/${orgId}/api-keys`),
  createApiKey: (orgId: string, body: { name: string; type: ApiKey["type"]; expiresInDays?: number }) =>
    call<ApiKey & { key: string }>(`/api/organizations/${orgId}/api-keys`, { body }),
  revokeApiKey: (orgId: string, keyId: string) => call(`/api/organizations/${orgId}/api-keys/${keyId}`, { method: "DELETE" }),
  platformOrganizations: () => call<{ items: { id: string; name: string; slug: string }[] }>("/api/platform/organizations"),
  createOrganization: (body: { name: string; slug: string; adminEmail: string }) =>
    call<{ id: string; invitationId: string }>("/api/platform/organizations", { body }),
  members: async (orgId: string) => {
    const res = await call<{ members: { id: string; userId: string; role: string; user: { email: string; name: string } }[] }>(
      `${BA}/list-members?organizationId=${orgId}`,
    );
    return { items: res.members.map((m): OrgMember => ({ id: m.id, userId: m.userId, email: m.user.email, name: m.user.name, role: m.role })) };
  },
  changeRole: (orgId: string, memberId: string, role: string) =>
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
  invite: (orgId: string, email: string, role: string) => call(`${BA}/invite-member`, { body: { email, role, organizationId: orgId } }),
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
