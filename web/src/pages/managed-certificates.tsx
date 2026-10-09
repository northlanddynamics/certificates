import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { NameChange } from "./name-change-controls";
import { Renewal } from "./renewal-controls";
import {
  EXPORT_CHAINS,
  EXPORT_FORMATS,
  api,
  can,
  ownerFromKey,
  ownerKey,
  ownerLabel,
  type HistoryEntry,
  type InventoryFilters,
  type ManagedCertificate,
  type Me,
  type OwnerRef,
} from "@/lib/api";

const KEY_ALGORITHMS: [string, string][] = [
  ["ecdsa-p256", "ECDSA P-256"],
  ["ecdsa-p384", "ECDSA P-384"],
  ["rsa-2048", "RSA 2048"],
  ["rsa-3072", "RSA 3072"],
  ["rsa-4096", "RSA 4096"],
];

/** What a Managed Certificate's latest Issuance has come to, in words. */
function status(m: ManagedCertificate) {
  if (m.approval.status === "pending") return "Awaiting Approval";
  if (m.approval.status === "rejected") return "Rejected";
  if (m.issuance?.status === "running") return m.currentCertificate ? "Renewing…" : "Issuing…";
  if (m.renewal.failing) return "Renewal failing";
  if (m.issuance?.status === "failed") return "Issuance failed";
  return m.currentCertificate ? `Issued, valid until ${new Date(m.currentCertificate.notAfter).toLocaleDateString()}` : "Not issued";
}

/** The Key Custody filter's "no filter": a select item cannot have an empty value. */
const ANY = "any";
const FILTERS: [keyof Omit<InventoryFilters, "keyCustody">, string][] = [
  ["expiringSoon", "Expiring soon"],
  ["renewalFailing", "Renewal failing"],
  ["pendingApproval", "Awaiting Approval"],
  ["noOwners", "No Owners"],
  ["archived", "Archived"],
];

export function ManagedCertificates({ org }: { org: Me["organizations"][number] }) {
  const queryClient = useQueryClient();
  const [filters, setFilters] = useState<InventoryFilters>({});
  const me = useQuery({ queryKey: ["me"], queryFn: api.me });
  const inventory = useQuery({
    queryKey: ["inventory", org.id, filters],
    queryFn: () => api.managedCertificates(org.id, filters),
    // Issuance runs in the background: look again until none is running.
    refetchInterval: (query) => (query.state.data?.items.some((m) => m.issuance?.status === "running") ? 2000 : false),
  });
  // A change to one may change the other: a proposal joins the queue, a decision leaves it.
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["approvals", org.id] });
    return queryClient.invalidateQueries({ queryKey: ["inventory", org.id] });
  };
  const retry = useMutation({ mutationFn: (id: string) => api.retryIssuance(org.id, id), onSuccess: refresh });
  const items = inventory.data?.items ?? [];

  return (
    <div className="flex flex-col gap-4">
      <fieldset className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
        <legend className="sr-only">Filter the inventory</legend>
        {FILTERS.map(([name, label]) => (
          <Label key={name} className="gap-2 font-normal">
            <Checkbox checked={Boolean(filters[name])} onCheckedChange={(checked) => setFilters({ ...filters, [name]: checked === true || undefined })} />
            {label}
          </Label>
        ))}
        <Label className="gap-2 font-normal">
          Key Custody
          <Select
            value={filters.keyCustody ?? ANY}
            onValueChange={(value) => setFilters({ ...filters, keyCustody: value === ANY ? undefined : (value as InventoryFilters["keyCustody"]) })}
          >
            <SelectTrigger size="sm" aria-label="Key Custody">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ANY}>Any</SelectItem>
              <SelectItem value="owner">Owner</SelectItem>
            </SelectContent>
          </Select>
        </Label>
      </fieldset>
      {inventory.data && items.length === 0 && (
        <p className="text-muted-foreground">
          {Object.values(filters).some(Boolean) ? "No Managed Certificates match." : can(org, "managedCertificate", "read") ? "No Managed Certificates yet." : "You do not own any Managed Certificates yet."}
        </p>
      )}
      <ul className="flex flex-col gap-3 text-sm">
        {items.map((m) => (
          <li key={m.id} className="flex flex-col gap-1 rounded-md border p-3">
            <span className="font-medium">{m.names.join(", ")}</span>
            <span className="text-muted-foreground">
              {m.keyAlgorithm}, {m.environment}: {status(m)}
            </span>
            {m.approval.status === "rejected" && (
              <span className="text-destructive">
                Rejected by {m.approval.decidedBy?.email}: {m.approval.reason}
              </span>
            )}
            {m.issuance?.failure && (
              <span className="text-destructive">
                {m.issuance.failure.message}
              </span>
            )}
            <NameChange org={org} m={m} userId={me.data?.user.id} onChanged={refresh} />
            <Renewal org={org} m={m} userId={me.data?.user.id} onChanged={refresh} />
            <Owners org={org} m={m} userId={me.data?.user.id} onChanged={refresh} />
            <span className="flex gap-3">
              {m.issuance?.status === "failed" && !m.currentCertificate && can(org, "managedCertificate", "issue") && (
                <Button variant="link" size="sm" className="h-auto p-0" onClick={() => retry.mutate(m.id)}>
                  Try again
                </Button>
              )}
            </span>
            {m.currentCertificate && can(org, "managedCertificate", "download") && <Download org={org} m={m} />}
            <History org={org} m={m} />
          </li>
        ))}
      </ul>
      {retry.error && <p className="text-sm text-destructive">{retry.error.message}</p>}
      {can(org, "approval", "read") && <ApprovalQueue org={org} onDecided={refresh} />}
      {(can(org, "managedCertificate", "create") || can(org, "managedCertificate", "propose")) && (
        <NewManagedCertificate org={org} onCreated={refresh} />
      )}
    </div>
  );
}

/** Who owns a Managed Certificate, and, for those who may change that, the means to. */
function Owners({ org, m, userId, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; userId?: string; onChanged: () => void }) {
  // The server decides; this only keeps the controls from those who surely may not (a Team's members may, too).
  const mayChange = can(org, "managedCertificate", "changeOwners") || m.owners.some((o) => o.type === "user" && o.id === userId);
  const add = useMutation({ mutationFn: (owner: OwnerRef) => api.addOwner(org.id, m.id, owner), onSuccess: onChanged });
  const remove = useMutation({ mutationFn: (owner: OwnerRef) => api.removeOwner(org.id, m.id, owner), onSuccess: onChanged });
  const people = useQuery({ queryKey: ["members", org.id], queryFn: () => api.members(org.id), enabled: mayChange });
  const teams = useQuery({ queryKey: ["teams", org.id], queryFn: () => api.teams(org.id), enabled: mayChange });
  const taken = new Set(m.owners.map(ownerKey));
  const [choice, setChoice] = useState("");
  const error = add.error ?? remove.error;

  return (
    <div className="flex flex-col gap-1">
      <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="text-muted-foreground">Owners:</span>
        {m.owners.length === 0 && <span>none</span>}
        {m.owners.map((o) => (
          <span key={ownerKey(o)} className="flex items-center gap-1">
            {ownerLabel(o)}
            {mayChange && (
              <Button variant="link" size="sm" className="h-auto p-0" aria-label={`Remove ${ownerLabel(o)} as an Owner`} disabled={remove.isPending} onClick={() => remove.mutate(o)}>
                Remove
              </Button>
            )}
          </span>
        ))}
      </span>
      {mayChange && (
        <form
          className="flex items-center gap-2"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            if (choice) add.mutate(ownerFromKey(choice), { onSuccess: () => setChoice("") });
          }}
        >
          <Select value={choice} onValueChange={setChoice}>
            <SelectTrigger size="sm" aria-label={`Add an Owner of ${m.names.join(", ")}`}>
              <SelectValue placeholder="Add an Owner…" />
            </SelectTrigger>
            <SelectContent>
              {teams.data?.items.filter((t) => !taken.has(`team:${t.id}`)).map((t) => (
                <SelectItem key={t.id} value={`team:${t.id}`}>
                  {t.name} (Team)
                </SelectItem>
              ))}
              {people.data?.items.filter((p) => !taken.has(`user:${p.userId}`)).map((p) => (
                <SelectItem key={p.userId} value={`user:${p.userId}`}>
                  {p.email}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button type="submit" size="sm" variant="outline" disabled={!choice || add.isPending}>
            Add
          </Button>
        </form>
      )}
      {error && <span className="text-destructive">{error.message}</span>}
    </div>
  );
}

/** The "current" Certificate in the Download's choice of one: a select item cannot have an empty value. */
const CURRENT = "current";

function ChoiceSelect({ label, value, onChange, choices }: { label: string; value: string; onChange: (value: string) => void; choices: [string, string][] }) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger size="sm" aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {choices.map(([v, text]) => (
          <SelectItem key={v} value={v}>
            {text}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

/** Downloads a Certificate of the Managed Certificate, the current one unless another is chosen, in the form chosen. */
function Download({ org, m }: { org: Me["organizations"][number]; m: ManagedCertificate }) {
  const [format, setFormat] = useState("pem");
  const [chain, setChain] = useState("with-intermediates");
  const [which, setWhich] = useState(CURRENT);
  const [open, setOpen] = useState(false);
  // Fetched when opened; the current one is the newest.
  const certificates = useQuery({ queryKey: ["certificates", org.id, m.id, m.currentCertificate?.fingerprint], queryFn: () => api.certificates(org.id, m.id), enabled: open });
  const label = m.names.join(", ");
  return (
    <details onToggle={(e) => setOpen(e.currentTarget.open)}>
      <summary className="cursor-pointer underline">Download</summary>
      <div className="mt-1 flex flex-wrap items-center gap-2">
        <ChoiceSelect label={`Format of ${label}`} value={format} onChange={setFormat} choices={EXPORT_FORMATS} />
        <ChoiceSelect label={`Chain of ${label}`} value={chain} onChange={setChain} choices={EXPORT_CHAINS} />
        <Select value={which} onValueChange={setWhich}>
          <SelectTrigger size="sm" aria-label={`Certificate of ${label}`}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={CURRENT}>Current Certificate</SelectItem>
            {certificates.data?.items.slice(1).map((c) => (
              <SelectItem key={c.id} value={c.id}>
                Issued {new Date(c.issuedAt).toLocaleDateString()} ({c.fingerprint.slice(0, 8)})
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <a className="underline" href={api.certificateDownloadUrl(org.id, m.id, { format, chain }, which === CURRENT ? undefined : which)}>
          Download
        </a>
      </div>
    </details>
  );
}

const HISTORY_WORDS = {
  created: "Created",
  proposed: "Proposed",
  approved: "Approved",
  rejected: "Rejected",
  names_change_proposed: "Name change proposed",
  names_change_approved: "Name change approved",
  names_change_rejected: "Name change rejected",
  names_change_withdrawn: "Name change withdrawn",
  names_change_discarded: "Name change discarded",
  names_changed: "Names changed",
} as const;
const historyLine = (e: HistoryEntry) =>
  e.kind === "certificate_issued"
    ? `Certificate issued, valid until ${new Date(e.certificate.notAfter).toLocaleDateString()} (${e.certificate.fingerprint.slice(0, 16)}…)`
    : `${HISTORY_WORDS[e.kind]}${e.actor ? ` by ${e.actor.email}` : ""}${e.names ? ` (${e.names.from.join(", ")} to ${e.names.to.join(", ")})` : ""}${e.reason ? `: ${e.reason}` : ""}`;

/** How a Managed Certificate got to where it is: its Approvals and Certificates, oldest first; fetched when opened. */
function History({ org, m }: { org: Me["organizations"][number]; m: ManagedCertificate }) {
  const [open, setOpen] = useState(false);
  const history = useQuery({ queryKey: ["history", org.id, m.id, m.currentCertificate?.fingerprint, m.approval.status, m.names, m.pendingNameChange?.proposedAt], queryFn: () => api.history(org.id, m.id), enabled: open });
  return (
    <details onToggle={(e) => setOpen(e.currentTarget.open)}>
      <summary className="cursor-pointer text-muted-foreground">History</summary>
      <ol className="mt-1 flex flex-col gap-1">
        {history.data?.items.map((e, i) => (
          <li key={`${e.at}-${i}`}>
            <span className="text-muted-foreground">{new Date(e.at).toLocaleString()}</span> {historyLine(e)}
          </li>
        ))}
        {history.error && <li className="text-destructive">{history.error.message}</li>}
      </ol>
    </details>
  );
}

function ApprovalQueue({ org, onDecided: decided }: { org: Me["organizations"][number]; onDecided: () => void }) {
  const queue = useQuery({ queryKey: ["approvals", org.id], queryFn: () => api.approvalQueue(org.id) });
  const approve = useMutation({ mutationFn: (id: string) => api.approve(org.id, id), onSuccess: decided });
  const reject = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) => api.reject(org.id, id, reason),
    onSuccess: decided,
  });
  const approveNames = useMutation({ mutationFn: (id: string) => api.approveNameChange(org.id, id), onSuccess: decided });
  const rejectNames = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) => api.rejectNameChange(org.id, id, reason),
    onSuccess: decided,
  });
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const items = queue.data?.items ?? [];
  const nameChanges = queue.data?.nameChanges ?? [];
  const busy = approve.isPending || reject.isPending || approveNames.isPending || rejectNames.isPending;
  const error = approve.error ?? reject.error ?? approveNames.error ?? rejectNames.error;

  return (
    <div className="flex flex-col gap-3">
      <h3 className="font-medium">Awaiting Approval</h3>
      {queue.data && items.length === 0 && nameChanges.length === 0 && <p className="text-sm text-muted-foreground">Nothing is waiting for Approval.</p>}
      <ul className="flex flex-col gap-3 text-sm">
        {items.map((m) => (
          <li key={m.id} className="flex flex-col gap-2 rounded-md border p-3">
            <span className="font-medium">{m.names.join(", ")}</span>
            <span className="text-muted-foreground">
              {m.keyAlgorithm}, {m.environment}, proposed by {m.approval.proposedBy?.email}
            </span>
            <Textarea
              aria-label={`Reason for ${m.names.join(", ")}`}
              placeholder="Reason (required to reject)"
              rows={2}
              value={reasons[m.id] ?? ""}
              onChange={(e) => setReasons({ ...reasons, [m.id]: e.target.value })}
            />
            <span className="flex gap-2">
              <Button size="sm" disabled={busy} onClick={() => approve.mutate(m.id)}>
                Approve
              </Button>
              <Button size="sm" variant="outline" disabled={busy || !(reasons[m.id] ?? "").trim()} onClick={() => reject.mutate({ id: m.id, reason: reasons[m.id]! })}>
                Reject
              </Button>
            </span>
          </li>
        ))}
        {nameChanges.map((n) => {
          const key = `names:${n.managedCertificateId}`;
          const label = `name change of ${n.currentNames.join(", ")}`;
          return (
            <li key={key} className="flex flex-col gap-2 rounded-md border p-3">
              <span className="font-medium">Name change: {n.currentNames.join(", ")}</span>
              <span className="text-muted-foreground">
                to {n.names.join(", ")}, proposed by {n.proposedBy.email}
              </span>
              <Textarea aria-label={`Reason for ${label}`} placeholder="Reason (required to reject)" rows={2} value={reasons[key] ?? ""} onChange={(e) => setReasons({ ...reasons, [key]: e.target.value })} />
              <span className="flex gap-2">
                <Button size="sm" disabled={busy} onClick={() => approveNames.mutate(n.managedCertificateId)}>
                  Approve
                </Button>
                <Button size="sm" variant="outline" disabled={busy || !(reasons[key] ?? "").trim()} onClick={() => rejectNames.mutate({ id: n.managedCertificateId, reason: reasons[key]! })}>
                  Reject
                </Button>
              </span>
            </li>
          );
        })}
      </ul>
      {error && <p className="text-sm text-destructive">{error.message}</p>}
    </div>
  );
}

function NewManagedCertificate({ org, onCreated }: { org: Me["organizations"][number]; onCreated: () => void }) {
  const [names, setNames] = useState("");
  const [keyAlgorithm, setKeyAlgorithm] = useState("ecdsa-p256");
  const [environment, setEnvironment] = useState<"staging" | "production">("staging");
  const [csr, setCsr] = useState("");
  const [owners, setOwners] = useState<string[]>([]);
  const people = useQuery({ queryKey: ["members", org.id], queryFn: () => api.members(org.id) });
  const teams = useQuery({ queryKey: ["teams", org.id], queryFn: () => api.teams(org.id) });
  const direct = can(org, "managedCertificate", "create");
  const create = useMutation({
    mutationFn: () =>
      api.createManagedCertificate(org.id, {
        names: names.split(/[\s,]+/).filter(Boolean),
        keyAlgorithm,
        csr,
        environment,
        owners: owners.map(ownerFromKey),
      }),
    onSuccess: () => {
      setNames("");
      setCsr("");
      setOwners([]);
      onCreated();
    },
  });

  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        create.mutate();
      }}
    >
      <h3 className="font-medium">{direct ? "New Managed Certificate" : "Propose a Managed Certificate"}</h3>
      {!direct && <p className="text-sm text-muted-foreground">An Approver must approve it before any Certificate is issued.</p>}
      <div className="flex flex-col gap-2">
        <Label htmlFor={`names-${org.id}`}>Names (one per line; wildcards as *.example.com)</Label>
        <Textarea id={`names-${org.id}`} value={names} onChange={(e) => setNames(e.target.value)} required />
      </div>
      <div className="flex gap-4">
        <div className="flex flex-col gap-2">
          <Label htmlFor={`algorithm-${org.id}`}>Key algorithm</Label>
          <Select value={keyAlgorithm} onValueChange={setKeyAlgorithm}>
            <SelectTrigger id={`algorithm-${org.id}`}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {KEY_ALGORITHMS.map(([value, label]) => (
                <SelectItem key={value} value={value}>
                  {label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor={`environment-${org.id}`}>ACME environment</Label>
          <Select value={environment} onValueChange={(value) => setEnvironment(value as "staging" | "production")}>
            <SelectTrigger id={`environment-${org.id}`}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="staging">Staging</SelectItem>
              <SelectItem value="production">Production</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor={`csr-${org.id}`}>CSR (PEM, for a key you keep; it must ask for exactly these names)</Label>
        <Textarea id={`csr-${org.id}`} className="font-mono text-xs" rows={6} value={csr} onChange={(e) => setCsr(e.target.value)} required />
      </div>
      <fieldset className="flex flex-col gap-2">
        <legend className="text-sm font-medium">Owners (optional; the users and Teams accountable for it)</legend>
        <div className="flex max-h-40 flex-col gap-2 overflow-y-auto rounded-md border p-2">
          {[
            ...(teams.data?.items.map((t) => ({ key: ownerKey({ type: "team", id: t.id }), label: `${t.name} (Team)` })) ?? []),
            ...(people.data?.items.map((p) => ({ key: ownerKey({ type: "user", id: p.userId }), label: p.email })) ?? []),
          ].map(({ key, label }) => (
            <Label key={key} className="gap-2 font-normal">
              <Checkbox
                checked={owners.includes(key)}
                onCheckedChange={(checked) => setOwners(checked === true ? [...owners, key] : owners.filter((o) => o !== key))}
              />
              {label}
            </Label>
          ))}
        </div>
      </fieldset>
      {create.error && <p className="text-sm text-destructive">{create.error.message}</p>}
      <Button type="submit" disabled={create.isPending}>
        {direct ? "Create and issue" : "Propose"}
      </Button>
    </form>
  );
}
