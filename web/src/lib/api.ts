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
  user: {
    id: string;
    email: string;
    name: string;
    isPlatformOperator: boolean;
    /** Whether they have an authenticator app, and whether an Organization of theirs holds them up until they set one up. */
    mfa: { enabled: boolean; enrollmentRequired: boolean };
  };
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
  /** Whether it waits for the Agent that holds the key to make a new one, as a Renewal of a key an Agent holds begins. */
  awaitingKey: boolean;
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
  agentOffline?: boolean;
  pendingApproval?: boolean;
  noOwners?: boolean;
  archived?: boolean;
  keyCustody?: ManagedCertificate["keyCustody"];
  /** Any of these. */
  environment?: ManagedCertificate["environment"][];
  /** Any of these. */
  keyAlgorithm?: string[];
}
/** One page of a list the server pages; `total` is how many there are in all. */
export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}
/** A change of a Managed Certificate's names waiting for Approval. */
export interface PendingNameChange {
  names: string[];
  proposedBy: { id: string; email: string };
  proposedAt: string;
}
/** That the CA was told to revoke a Certificate, by whom and why. */
export interface Revocation {
  reason: string;
  revokedAt: string;
  revokedBy: { id: string; email: string };
}
/** The reasons a Certificate may be revoked for (RFC 5280), by the name the server takes. */
export const REVOCATION_REASONS: [string, string][] = [
  ["keyCompromise", "Key compromise"],
  ["superseded", "Superseded"],
  ["cessationOfOperation", "Cessation of operation"],
  ["unspecified", "Unspecified"],
];
export const revocationReasonLabel = (reason: string) => REVOCATION_REASONS.find(([value]) => value === reason)?.[1] ?? reason;
export type HistoryEntry =
  | {
      kind:
        | "created"
        | "proposed"
        | "approved"
        | "rejected"
        | "names_change_proposed"
        | "names_change_approved"
        | "names_change_rejected"
        | "names_change_withdrawn"
        | "names_change_discarded"
        | "names_changed"
        | "archived"
        | "certificate_revoked";
      at: string;
      actor: { id: string; email: string } | null;
      reason: string | null;
      /** The names before and after, for a name change. */
      names: { from: string[]; to: string[] } | null;
    }
  | { kind: "certificate_issued"; at: string; certificate: { fingerprint: string; notBefore: string; notAfter: string; names: string[]; revocation: Revocation | null } };
export interface RenewalPolicy {
  mode: "automatic" | "manual";
  daysBeforeExpiry: number;
}
export interface Renewal {
  policy: RenewalPolicy;
  /** When the scheduler will renew it; none for a manual one or one with no Certificate yet. */
  dueAt: string | null;
  /** What makes it due then: its days before expiry, or the CA's suggested window (ARI). */
  dueBecause: "policy" | "ari" | null;
  /** What the CA's ARI last said about the current Certificate. */
  ari: { window: { start: string; end: string } | null; checkedAt: string | null; nextCheckAt: string } | null;
  /** Set while the latest Renewal has failed. */
  failing: { failures: number; lastFailure: { code: string; message: string; at: string }; nextAttemptAt: string | null } | null;
}
export interface ManagedCertificate {
  id: string;
  names: string[];
  keyAlgorithm: string;
  /** Who holds the private key: the Owner, who submitted a CSR, or one Agent, through its one Deployment. */
  keyCustody: "owner" | "agent";
  environment: "staging" | "production";
  /** When it was archived: it then neither issues, renews nor deploys. */
  archivedAt: string | null;
  owners: Owner[];
  approval: Approval;
  /** Until it is approved, Renewal uses `names`. */
  pendingNameChange: PendingNameChange | null;
  renewal: Renewal;
  issuance: Issuance | null;
  /** The most recently issued Certificate. */
  currentCertificate: Certificate | null;
  /** For a key an Agent holds, that Agent and whether it is online; an offline one holds up the Renewal. */
  agent: { id: string; hostName: string; status: "online" | "offline" | "revoked" } | null;
}
export interface QueuedNameChange extends PendingNameChange {
  managedCertificateId: string;
  currentNames: string[];
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
  /** SHA-256 of the certificate, lower-case hex. */
  fingerprint: string;
  serial: string;
  notBefore: string;
  notAfter: string;
  names: string[];
  ca: string;
  environment: "staging" | "production";
  acmeAccountId: string;
  issuedAt: string;
  revocation: Revocation | null;
}
/** An Organization's account with a CA; its key is never returned. */
export interface AcmeAccount {
  id: string;
  environment: "staging" | "production";
  accountUrl: string;
  contactEmail: string | null;
}
export const TSIG_ALGORITHMS = ["hmac-sha256", "hmac-sha384", "hmac-sha512", "hmac-sha1", "hmac-md5"] as const;
export interface Rfc2136Settings {
  server: string;
  port: number;
  zone: string;
  keyName: string;
  algorithm: (typeof TSIG_ALGORITHMS)[number];
}
export interface InfobloxSettings {
  url: string;
  zone: string;
  view: string;
  caCertificate?: string;
}
/** An Organization's connection to a DNS service; its secret (a TSIG key, a WAPI password) is never returned. */
export type DnsProvider = { id: string; name: string; relayAgentIds: string[] } & (
  | { type: "rfc2136"; settings: Rfc2136Settings }
  | { type: "infoblox"; settings: InfobloxSettings }
);
export type DnsProviderType = DnsProvider["type"];
export type DnsProviderSettings = DnsProvider["settings"];
/** One version of a Deployment Script, identified by the SHA-256 of its content. */
export interface DeploymentScriptVersion {
  version: number;
  hash: string;
  size: number;
  uploadedBy: string;
  uploadedAt: string;
}
/** A script in the Organization's library, with its newest version. */
export interface DeploymentScript {
  id: string;
  name: string;
  interpreter: "bash" | "powershell";
  latestVersion: DeploymentScriptVersion;
}
/** One execution of a Deployment: when, which Certificate, and how the script went. */
export interface DeploymentRun {
  id: string;
  deploymentId: string;
  status: "succeeded" | "failed";
  trigger: "issuance" | "rerun";
  startedAt: string;
  finishedAt: string;
  /** None when the script was not started: it did not match its hash. */
  exitCode: number | null;
  output: string;
  outputTruncated: boolean;
  certificate: { id: string; fingerprint: string };
  script: { version: number; hash: string };
}
export type DeploymentState = "awaiting_key" | "key_failed" | "issuing" | "issuance_failed" | "awaiting_deployment" | "deployed" | "deployment_failed";
/** An Agent making the key for a Managed Certificate and running a Deployment Script with each of its Certificates. */
export interface Deployment {
  id: string;
  managedCertificateId: string;
  names: string[];
  keyAlgorithm: string;
  agent: { id: string; hostName: string };
  script: { id: string; name: string; interpreter: DeploymentScript["interpreter"]; version: number; hash: string };
  createdAt: string;
  createdBy: string;
  state: DeploymentState;
  keyFailure: string | null;
  /** The Agent has been asked to run the script and has not yet reported. */
  runPending: boolean;
  lastRun: DeploymentRun | null;
}
export interface NewDeployment {
  agentId: string;
  scriptId: string;
  scriptVersion?: number;
  names: string[];
  keyAlgorithm: string;
  environment: "staging" | "production";
  renewalPolicy: RenewalPolicy;
}
/** An Agent as the Agents list shows it. */
export interface Agent {
  id: string;
  hostName: string;
  os: "linux" | "windows" | "macos";
  arch: "amd64" | "arm64";
  version: string;
  /** Older than the latest version the platform knows of. */
  outdated: boolean;
  status: "online" | "offline" | "revoked";
  registeredAt: string;
  lastContactAt: string;
  revokedAt: string | null;
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
export interface NotificationChannel {
  id: string;
  name: string;
  kind: "email" | "webhook";
  /** Where an email channel sends; none for a webhook. */
  email: string | null;
  /** The host a webhook posts to: its URL is write-only, so never shown. */
  webhookHost: string | null;
  createdAt: string;
}
export type NewNotificationChannel = { name: string; kind: "email"; email: string } | { name: string; kind: "webhook"; url: string };
export type Subscriber =
  | { type: "user"; id: string; email: string }
  | { type: "team"; id: string; name: string }
  | { type: "channel"; id: string; name: string; kind: NotificationChannel["kind"] };
export type SubscriberRef = { type: Subscriber["type"]; id: string };
/** A Subscriber as one string, for a form control's value, and back. */
export const subscriberKey = (s: SubscriberRef) => `${s.type}:${s.id}`;
export const subscriberFromKey = (key: string): SubscriberRef => ({ type: key.slice(0, key.indexOf(":")) as Subscriber["type"], id: key.slice(key.indexOf(":") + 1) });
export const subscriberLabel = (s: Subscriber) =>
  s.type === "user" ? s.email : s.type === "team" ? `${s.name} (Team)` : `${s.name} (${s.kind === "email" ? "email" : "webhook"} channel)`;
export interface AuditEvent {
  /** Rising: a later event has a greater id. */
  id: string;
  occurredAt: string;
  /** Both are null when the platform itself or an Organization's API key made the change. */
  actor: { id: string | null; email: string | null };
  action: string;
  target: { type: string; id: string | null };
  detail: Record<string, unknown>;
}
/** What the audit log is searched by; every filter given must match. `action` may be a prefix, such as `team.*`. */
export interface AuditFilters {
  actor?: string;
  action?: string;
  targetType?: string;
  targetId?: string;
  /** ISO times: from inclusive, to exclusive. */
  from?: string;
  to?: string;
}
export interface AuditForwarder {
  id: string;
  name: string;
  kind: "webhook" | "syslog";
  /** A webhook's host (its URL is write-only, so never shown), or the syslog receiver. */
  host: string;
  /** The syslog receiver's port; none for a webhook. */
  port: number | null;
  createdAt: string;
  /** How many Audit Events wait to be delivered to it. */
  backlog: number;
  lastDeliveredAt: string | null;
  /** Why the last try failed; none once it delivers again. */
  lastError: string | null;
  /** When it is tried again after failing; none while it is not failing. */
  nextAttemptAt: string | null;
}
/** What an Organization asks of its users' sign-in. */
export interface LoginPolicy {
  requireMfa: boolean;
}
export type NewAuditForwarder = { name: string; kind: "webhook"; url: string; authorization?: string } | { name: string; kind: "syslog"; host: string; port?: number };
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
  signUp: (email: string, password: string, name: string) =>
    call("/api/auth/sign-up/email", { body: { email, password, name } }),
  signOut: () => call("/api/auth/sign-out", { method: "POST", body: {} }),
  acceptInvitation: (invitationId: string) => call(`${BA}/accept-invitation`, { body: { invitationId } }),
  /** `page` is from 1. */
  managedCertificates: (orgId: string, filters: InventoryFilters = {}, paging: { page: number; pageSize: number }) => {
    const query = new URLSearchParams(
      Object.entries({ ...filters, ...paging })
        .filter(([, v]) => (Array.isArray(v) ? v.length > 0 : v))
        .map(([k, v]) => [k, Array.isArray(v) ? v.join(",") : v === true ? "true" : String(v)]),
    );
    return call<Page<ManagedCertificate>>(`/api/organizations/${orgId}/managed-certificates?${query}`);
  },
  managedCertificate: (orgId: string, id: string) => call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}`),
  addOwner: (orgId: string, id: string, owner: OwnerRef) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}/owners`, { body: owner }),
  subscribers: (orgId: string, id: string) => call<{ items: Subscriber[] }>(`/api/organizations/${orgId}/managed-certificates/${id}/subscribers`),
  addSubscriber: (orgId: string, id: string, subscriber: SubscriberRef) =>
    call<{ items: Subscriber[] }>(`/api/organizations/${orgId}/managed-certificates/${id}/subscribers`, { body: subscriber }),
  removeSubscriber: (orgId: string, id: string, subscriber: SubscriberRef) =>
    call<{ items: Subscriber[] }>(`/api/organizations/${orgId}/managed-certificates/${id}/subscribers/${subscriber.type}/${encodeURIComponent(subscriber.id)}`, { method: "DELETE" }),
  /** A page of the audit log, newest first, that matches `filters`; `cursor` is where the page before ended. */
  auditEvents: (orgId: string, filters: AuditFilters, cursor?: string, limit = 50) => {
    const query = new URLSearchParams({ order: "desc", limit: String(limit) });
    for (const [key, value] of Object.entries(filters)) if (value) query.set(key, value);
    if (cursor) query.set("cursor", cursor);
    return call<{ items: AuditEvent[]; nextCursor: string | null }>(`/api/organizations/${orgId}/audit-events?${query}`);
  },
  loginPolicy: (orgId: string) => call<LoginPolicy>(`/api/organizations/${orgId}/login-policy`),
  setLoginPolicy: (orgId: string, policy: LoginPolicy) => call<LoginPolicy>(`/api/organizations/${orgId}/login-policy`, { method: "PUT", body: policy }),
  auditForwarders: (orgId: string) => call<{ items: AuditForwarder[] }>(`/api/organizations/${orgId}/audit-forwarders`),
  addAuditForwarder: (orgId: string, forwarder: NewAuditForwarder) => call<AuditForwarder>(`/api/organizations/${orgId}/audit-forwarders`, { body: forwarder }),
  deleteAuditForwarder: (orgId: string, forwarderId: string) => call(`/api/organizations/${orgId}/audit-forwarders/${forwarderId}`, { method: "DELETE" }),
  notificationChannels: (orgId: string) => call<{ items: NotificationChannel[] }>(`/api/organizations/${orgId}/notification-channels`),
  addNotificationChannel: (orgId: string, channel: NewNotificationChannel) => call<NotificationChannel>(`/api/organizations/${orgId}/notification-channels`, { body: channel }),
  deleteNotificationChannel: (orgId: string, channelId: string) => call(`/api/organizations/${orgId}/notification-channels/${channelId}`, { method: "DELETE" }),
  removeOwner: (orgId: string, id: string, owner: OwnerRef) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}/owners/${owner.type}/${encodeURIComponent(owner.id)}`, { method: "DELETE" }),
  history: (orgId: string, id: string) => call<{ items: HistoryEntry[] }>(`/api/organizations/${orgId}/managed-certificates/${id}/history`),
  createManagedCertificate: (orgId: string, body: NewManagedCertificate) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates`, { body }),
  approvalQueue: (orgId: string) => call<{ items: ManagedCertificate[]; nameChanges: QueuedNameChange[] }>(`/api/organizations/${orgId}/approvals`),
  approve: (orgId: string, id: string, reason?: string) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}/approve`, { body: { reason } }),
  reject: (orgId: string, id: string, reason: string) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}/reject`, { body: { reason } }),
  /** An Organization Administrator's change applies at once; anyone else's is proposed and waits for Approval. */
  changeNames: (orgId: string, id: string, body: { names: string[]; csr: string }) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}/name-change`, { body }),
  withdrawNameChange: (orgId: string, id: string) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}/name-change/withdraw`, { method: "POST", body: {} }),
  approveNameChange: (orgId: string, id: string, reason?: string) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}/name-change/approve`, { body: { reason } }),
  rejectNameChange: (orgId: string, id: string, reason: string) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}/name-change/reject`, { body: { reason } }),
  retryIssuance: (orgId: string, id: string) =>
    call<Issuance>(`/api/organizations/${orgId}/managed-certificates/${id}/issuances`, { method: "POST", body: {} }),
  setRenewalPolicy: (orgId: string, id: string, policy: RenewalPolicy) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}/renewal-policy`, { method: "PUT", body: policy }),
  renewNow: (orgId: string, id: string) =>
    call<Issuance>(`/api/organizations/${orgId}/managed-certificates/${id}/renewals`, { method: "POST", body: {} }),
  uploadCsr: (orgId: string, id: string, csr: string) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}/csr`, { body: { csr } }),
  archive: (orgId: string, id: string) =>
    call<ManagedCertificate>(`/api/organizations/${orgId}/managed-certificates/${id}/archive`, { method: "POST", body: {} }),
  revokeCertificate: (orgId: string, id: string, certificateId: string, reason: string) =>
    call<Certificate>(`/api/organizations/${orgId}/managed-certificates/${id}/certificates/${certificateId}/revocation`, { body: { reason } }),
  certificates: (orgId: string, id: string) => call<{ items: Certificate[] }>(`/api/organizations/${orgId}/managed-certificates/${id}/certificates`),
  /** Where a Certificate downloads from: the current one, or the one with `certificateId`. */
  certificateDownloadUrl: (orgId: string, id: string, form: { format: string; chain: string }, certificateId?: string) =>
    `/api/organizations/${orgId}/managed-certificates/${id}/${certificateId ? `certificates/${certificateId}/download` : "certificate"}?${new URLSearchParams(form)}`,
  /** One page of the API keys the caller may see, oldest first; `page` is from 1. */
  apiKeys: (orgId: string, paging: { page: number; pageSize: number }) =>
    call<Page<ApiKey>>(`/api/organizations/${orgId}/api-keys?${new URLSearchParams({ page: String(paging.page), pageSize: String(paging.pageSize) })}`),
  createApiKey: (orgId: string, body: { name: string; type: ApiKey["type"]; expiresInDays?: number }) =>
    call<ApiKey & { key: string }>(`/api/organizations/${orgId}/api-keys`, { body }),
  revokeApiKey: (orgId: string, keyId: string) => call(`/api/organizations/${orgId}/api-keys/${keyId}`, { method: "DELETE" }),
  /** One page of the Agents, oldest first, narrowed to those that are any of `status` and run any of `os`, and to the outdated if asked; `page` is from 1. */
  agents: (orgId: string, filters: { status: string[]; os: string[]; outdated: boolean }, paging: { page: number; pageSize: number }) => {
    const query = new URLSearchParams({ page: String(paging.page), pageSize: String(paging.pageSize) });
    if (filters.status.length > 0) query.set("status", filters.status.join(","));
    if (filters.os.length > 0) query.set("os", filters.os.join(","));
    if (filters.outdated) query.set("outdated", "true");
    return call<Page<Agent> & { latestVersion: string }>(`/api/organizations/${orgId}/agents?${query}`);
  },
  createAgentRegistrationToken: (orgId: string) =>
    call<{ token: string; expiresAt: string }>(`/api/organizations/${orgId}/agent-registration-tokens`, { method: "POST", body: {} }),
  revokeAgent: (orgId: string, agentId: string) => call<Agent>(`/api/organizations/${orgId}/agents/${agentId}/revoke`, { method: "POST", body: {} }),
  /** One page of the Deployment Scripts, oldest first; `page` is from 1. */
  deploymentScripts: (orgId: string, paging: { page: number; pageSize: number }) =>
    call<Page<DeploymentScript>>(`/api/organizations/${orgId}/deployment-scripts?${new URLSearchParams({ page: String(paging.page), pageSize: String(paging.pageSize) })}`),
  deploymentScript: (orgId: string, scriptId: string) =>
    call<DeploymentScript & { versions: DeploymentScriptVersion[] }>(`/api/organizations/${orgId}/deployment-scripts/${scriptId}`),
  deploymentScriptVersion: (orgId: string, scriptId: string, hash: string) =>
    call<DeploymentScriptVersion & { content: string }>(`/api/organizations/${orgId}/deployment-scripts/${scriptId}/versions/${hash}`),
  uploadDeploymentScript: (orgId: string, body: { name: string; interpreter: DeploymentScript["interpreter"]; content: string }) =>
    call<DeploymentScript>(`/api/organizations/${orgId}/deployment-scripts`, { body }),
  uploadDeploymentScriptVersion: (orgId: string, scriptId: string, content: string) =>
    call<DeploymentScript>(`/api/organizations/${orgId}/deployment-scripts/${scriptId}/versions`, { body: { content } }),
  /** One page of the Deployments, newest first; `page` is from 1. */
  deployments: (orgId: string, paging: { page: number; pageSize: number }) =>
    call<Page<Deployment>>(`/api/organizations/${orgId}/deployments?${new URLSearchParams({ page: String(paging.page), pageSize: String(paging.pageSize) })}`),
  createDeployment: (orgId: string, body: NewDeployment) => call<Deployment>(`/api/organizations/${orgId}/deployments`, { body }),
  /** One page of a Deployment's runs, newest first; `page` is from 1. */
  deploymentRuns: (orgId: string, id: string, paging: { page: number; pageSize: number }) =>
    call<Page<DeploymentRun>>(`/api/organizations/${orgId}/deployments/${id}/runs?${new URLSearchParams({ page: String(paging.page), pageSize: String(paging.pageSize) })}`),
  runDeploymentAgain: (orgId: string, id: string) => call<Deployment>(`/api/organizations/${orgId}/deployments/${id}/runs`, { method: "POST", body: {} }),
  acmeAccounts: (orgId: string) => call<{ items: AcmeAccount[] }>(`/api/organizations/${orgId}/acme-accounts`),
  registerAcmeAccount: (orgId: string, body: { environment: AcmeAccount["environment"]; contactEmail?: string }) =>
    call<AcmeAccount>(`/api/organizations/${orgId}/acme-accounts`, { body: { ...body, termsOfServiceAgreed: true } }),
  testAcmeAccount: (orgId: string, accountId: string) =>
    call<{ ok: boolean; error?: string }>(`/api/organizations/${orgId}/acme-accounts/${accountId}/test`, { method: "POST", body: {} }),
  dnsProviders: (orgId: string) => call<{ items: DnsProvider[] }>(`/api/organizations/${orgId}/dns-providers`),
  createDnsProvider: (orgId: string, body: { name: string; type: DnsProviderType; settings: DnsProviderSettings; secret: string; relayAgentIds: string[] }) =>
    call<DnsProvider>(`/api/organizations/${orgId}/dns-providers`, { body }),
  changeDnsProvider: (orgId: string, providerId: string, body: { name: string; settings: DnsProviderSettings }) =>
    call<DnsProvider>(`/api/organizations/${orgId}/dns-providers/${providerId}`, { method: "PUT", body }),
  replaceDnsProviderSecret: (orgId: string, providerId: string, secret: string) =>
    call<DnsProvider>(`/api/organizations/${orgId}/dns-providers/${providerId}/secret`, { method: "PUT", body: { secret } }),
  setDnsProviderRelay: (orgId: string, providerId: string, agentIds: string[]) =>
    call<DnsProvider>(`/api/organizations/${orgId}/dns-providers/${providerId}/relay`, { method: "PUT", body: { agentIds } }),
  testDnsProvider: (orgId: string, providerId: string) =>
    call<{ ok: boolean; error?: string }>(`/api/organizations/${orgId}/dns-providers/${providerId}/test`, { method: "POST", body: {} }),
  platformOrganizations: () => call<{ items: { id: string; name: string; slug: string }[] }>("/api/platform/organizations"),
  createOrganization: (body: { name: string; slug: string; adminEmail: string }) =>
    call<{ id: string; invitationId: string }>("/api/platform/organizations", { body }),
  members: async (orgId: string) => {
    const res = await call<{ members: { id: string; userId: string; role: string; user: { email: string; name: string } }[] }>(
      `${BA}/list-members?organizationId=${orgId}`,
    );
    return { items: res.members.map((m): OrgMember => ({ id: m.id, userId: m.userId, email: m.user.email, name: m.user.name, role: m.role })) };
  },
  /** One page of the members, oldest first, narrowed to those holding any of `roles`; `page` is from 1. */
  membersPage: async (orgId: string, roles: string[], paging: { page: number; pageSize: number }): Promise<Page<OrgMember>> => {
    const query = new URLSearchParams({ organizationId: orgId, sortBy: "createdAt", limit: String(paging.pageSize), offset: String((paging.page - 1) * paging.pageSize) });
    if (roles.length > 0) {
      query.set("filterField", "role");
      // Better Auth reads one value as equal to it, and several (a repeated key) as any of them.
      if (roles.length > 1) query.set("filterOperator", "in");
      for (const role of roles) query.append("filterValue", role);
    }
    const res = await call<{ members: { id: string; userId: string; role: string; user: { email: string; name: string } }[]; total: number }>(`${BA}/list-members?${query}`);
    return { items: res.members.map((m): OrgMember => ({ id: m.id, userId: m.userId, email: m.user.email, name: m.user.name, role: m.role })), total: res.total, ...paging };
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
  /** The Teams as a list to choose from: the first page of the largest size the server allows. */
  teams: (orgId: string) => call<Page<Team>>(`/api/organizations/${orgId}/teams?pageSize=100`),
  /** One page of the Teams, oldest first, narrowed to those with (or without) members; `page` is from 1. */
  teamsPage: (orgId: string, membership: "empty" | "populated" | undefined, paging: { page: number; pageSize: number }) =>
    call<Page<Team>>(`/api/organizations/${orgId}/teams?${new URLSearchParams({ ...(membership && { membership }), page: String(paging.page), pageSize: String(paging.pageSize) })}`),
  createTeam: (orgId: string, name: string) => call(`${BA}/create-team`, { body: { name, organizationId: orgId } }),
  renameTeam: (orgId: string, teamId: string, name: string) =>
    call(`${BA}/update-team`, { body: { teamId, data: { name, organizationId: orgId } } }),
  deleteTeam: (orgId: string, teamId: string) => call(`${BA}/remove-team`, { body: { teamId, organizationId: orgId } }),
  addTeamMember: (orgId: string, teamId: string, userId: string) =>
    call(`${BA}/add-team-member`, { body: { teamId, userId, organizationId: orgId } }),
  removeTeamMember: (orgId: string, teamId: string, userId: string) =>
    call(`${BA}/remove-team-member`, { body: { teamId, userId, organizationId: orgId } }),
};
