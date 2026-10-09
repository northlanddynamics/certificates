import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
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

const KEY_ALGORITHMS = [
  ["ecdsa-p256", "ECDSA P-256"],
  ["ecdsa-p384", "ECDSA P-384"],
  ["rsa-2048", "RSA 2048"],
  ["rsa-3072", "RSA 3072"],
  ["rsa-4096", "RSA 4096"],
];
const selectClass = "h-9 rounded-md border border-input bg-transparent px-2 text-sm";

/** What a Managed Certificate's latest Issuance has come to, in words. */
function status(m: ManagedCertificate) {
  if (m.approval.status === "pending") return "Awaiting Approval";
  if (m.approval.status === "rejected") return "Rejected";
  if (m.issuance?.status === "running") return "Issuing…";
  if (m.issuance?.status === "failed") return "Issuance failed";
  return m.currentCertificate ? `Issued, valid until ${new Date(m.currentCertificate.notAfter).toLocaleDateString()}` : "Not issued";
}

const FILTERS: [keyof Omit<InventoryFilters, "keyCustody">, string][] = [
  ["expiringSoon", "Expiring soon"],
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
          <label key={name} className="flex items-center gap-1">
            <input type="checkbox" checked={Boolean(filters[name])} onChange={(e) => setFilters({ ...filters, [name]: e.target.checked || undefined })} />
            {label}
          </label>
        ))}
        <label className="flex items-center gap-1">
          Key Custody
          <select
            className={selectClass}
            value={filters.keyCustody ?? ""}
            onChange={(e) => setFilters({ ...filters, keyCustody: (e.target.value || undefined) as InventoryFilters["keyCustody"] })}
          >
            <option value="">Any</option>
            <option value="owner">Owner</option>
          </select>
        </label>
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
            <Owners org={org} m={m} userId={me.data?.user.id} onChanged={refresh} />
            <span className="flex gap-3">
              {m.currentCertificate && (
                <a className="underline" href={api.certificateDownloadUrl(org.id, m.id)}>
                  Download PEM (full chain)
                </a>
              )}
              {m.issuance?.status === "failed" && can(org, "managedCertificate", "issue") && (
                <Button variant="link" size="sm" className="h-auto p-0" onClick={() => retry.mutate(m.id)}>
                  Try again
                </Button>
              )}
            </span>
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
          <select aria-label={`Add an Owner of ${m.names.join(", ")}`} className={selectClass} value={choice} onChange={(e) => setChoice(e.target.value)}>
            <option value="">Add an Owner…</option>
            {teams.data?.items.filter((t) => !taken.has(`team:${t.id}`)).map((t) => (
              <option key={t.id} value={`team:${t.id}`}>
                {t.name} (Team)
              </option>
            ))}
            {people.data?.items.filter((p) => !taken.has(`user:${p.userId}`)).map((p) => (
              <option key={p.userId} value={`user:${p.userId}`}>
                {p.email}
              </option>
            ))}
          </select>
          <Button type="submit" size="sm" variant="outline" disabled={!choice || add.isPending}>
            Add
          </Button>
        </form>
      )}
      {error && <span className="text-destructive">{error.message}</span>}
    </div>
  );
}

const HISTORY_WORDS = { created: "Created", proposed: "Proposed", approved: "Approved", rejected: "Rejected" } as const;
const historyLine = (e: HistoryEntry) =>
  e.kind === "certificate_issued"
    ? `Certificate issued, valid until ${new Date(e.certificate.notAfter).toLocaleDateString()} (${e.certificate.fingerprint.slice(0, 16)}…)`
    : `${HISTORY_WORDS[e.kind]}${e.actor ? ` by ${e.actor.email}` : ""}${e.reason ? `: ${e.reason}` : ""}`;

/** How a Managed Certificate got to where it is: its Approvals and Certificates, oldest first; fetched when opened. */
function History({ org, m }: { org: Me["organizations"][number]; m: ManagedCertificate }) {
  const [open, setOpen] = useState(false);
  const history = useQuery({ queryKey: ["history", org.id, m.id, m.currentCertificate?.fingerprint, m.approval.status], queryFn: () => api.history(org.id, m.id), enabled: open });
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
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const items = queue.data?.items ?? [];
  const error = approve.error ?? reject.error;

  return (
    <div className="flex flex-col gap-3">
      <h3 className="font-medium">Awaiting Approval</h3>
      {queue.data && items.length === 0 && <p className="text-sm text-muted-foreground">Nothing is waiting for Approval.</p>}
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
              <Button size="sm" disabled={approve.isPending || reject.isPending} onClick={() => approve.mutate(m.id)}>
                Approve
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={approve.isPending || reject.isPending || !(reasons[m.id] ?? "").trim()}
                onClick={() => reject.mutate({ id: m.id, reason: reasons[m.id]! })}
              >
                Reject
              </Button>
            </span>
          </li>
        ))}
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
          <select id={`algorithm-${org.id}`} className={selectClass} value={keyAlgorithm} onChange={(e) => setKeyAlgorithm(e.target.value)}>
            {KEY_ALGORITHMS.map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor={`environment-${org.id}`}>ACME environment</Label>
          <select
            id={`environment-${org.id}`}
            className={selectClass}
            value={environment}
            onChange={(e) => setEnvironment(e.target.value as "staging" | "production")}
          >
            <option value="staging">Staging</option>
            <option value="production">Production</option>
          </select>
        </div>
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor={`csr-${org.id}`}>CSR (PEM, for a key you keep; it must ask for exactly these names)</Label>
        <Textarea id={`csr-${org.id}`} className="font-mono text-xs" rows={6} value={csr} onChange={(e) => setCsr(e.target.value)} required />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor={`owners-${org.id}`}>Owners (optional; the users and Teams accountable for it)</Label>
        <select
          id={`owners-${org.id}`}
          multiple
          className="rounded-md border border-input bg-transparent px-2 py-1 text-sm"
          value={owners}
          onChange={(e) => setOwners([...e.currentTarget.selectedOptions].map((o) => o.value))}
        >
          {teams.data?.items.map((t) => (
            <option key={t.id} value={`team:${t.id}`}>
              {t.name} (Team)
            </option>
          ))}
          {people.data?.items.map((p) => (
            <option key={p.userId} value={`user:${p.userId}`}>
              {p.email}
            </option>
          ))}
        </select>
      </div>
      {create.error && <p className="text-sm text-destructive">{create.error.message}</p>}
      <Button type="submit" disabled={create.isPending}>
        {direct ? "Create and issue" : "Propose"}
      </Button>
    </form>
  );
}
