import { useMutation } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { api, can, type ManagedCertificate, type Me, type RenewalPolicy } from "@/lib/api";

const when = (iso: string) => new Date(iso).toLocaleString();

/** What the Renewal Policy comes to for this Managed Certificate, in words: when it renews, or why it is not. */
function summary(m: ManagedCertificate) {
  const { policy, dueAt, failing } = m.renewal;
  if (policy.mode === "manual") return "Renewed by hand only";
  const days = `${policy.daysBeforeExpiry} day${policy.daysBeforeExpiry === 1 ? "" : "s"} before expiry`;
  return dueAt ? `Renews automatically ${days}, from ${when(failing?.nextAttemptAt ?? dueAt)}` : `Renews automatically ${days}`;
}

/** A Managed Certificate's Renewal: its policy, how it is going, and for those who may, the means to change the policy, renew now and upload a new CSR. */
export function Renewal({ org, m, userId, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; userId?: string; onChanged: () => void }) {
  // The server decides; this only keeps the controls from those who surely may not (a Team's members may, too).
  const owns = m.owners.some((o) => o.type === "user" && o.id === userId);
  const mayPolicy = can(org, "managedCertificate", "setRenewalPolicy") || owns;
  const mayRenew = can(org, "managedCertificate", "renew") || owns;
  const mayCsr = can(org, "managedCertificate", "replaceCsr") || owns;
  const settled = m.approval.status !== "pending" && m.approval.status !== "rejected";

  const [mode, setMode] = useState<RenewalPolicy["mode"]>(m.renewal.policy.mode);
  const [days, setDays] = useState(String(m.renewal.policy.daysBeforeExpiry));
  const [csr, setCsr] = useState("");
  const savePolicy = useMutation({ mutationFn: (policy: RenewalPolicy) => api.setRenewalPolicy(org.id, m.id, policy), onSuccess: onChanged });
  const renew = useMutation({ mutationFn: () => api.renewNow(org.id, m.id), onSuccess: onChanged });
  const upload = useMutation({
    mutationFn: () => api.uploadCsr(org.id, m.id, csr),
    onSuccess: () => {
      setCsr("");
      onChanged();
    },
  });
  const error = savePolicy.error ?? renew.error ?? upload.error;
  const label = m.names.join(", ");
  const changed = mode !== m.renewal.policy.mode || Number(days) !== m.renewal.policy.daysBeforeExpiry;

  if (!settled) return null;
  return (
    <div className="flex flex-col gap-1">
      <span className="text-muted-foreground">{summary(m)}</span>
      {m.renewal.failing && (
        <span className="text-destructive">
          Renewal failed {m.renewal.failing.failures} time{m.renewal.failing.failures === 1 ? "" : "s"}: {m.renewal.failing.lastFailure.message}
          {m.renewal.failing.nextAttemptAt ? `. Next attempt ${when(m.renewal.failing.nextAttemptAt)}` : ""}
        </span>
      )}
      {m.currentCertificate && mayRenew && (
        <span className="flex gap-3">
          <Button variant="link" size="sm" className="h-auto p-0" disabled={renew.isPending || m.issuance?.status === "running"} onClick={() => renew.mutate()}>
            Renew now
          </Button>
        </span>
      )}
      {(mayPolicy || mayCsr) && (
        <details>
          <summary className="cursor-pointer underline">Renewal settings</summary>
          <div className="mt-1 flex flex-col gap-3">
            {mayPolicy && (
              <form
                className="flex flex-wrap items-center gap-2"
                onSubmit={(e: FormEvent) => {
                  e.preventDefault();
                  savePolicy.mutate({ mode, daysBeforeExpiry: Number(days) });
                }}
              >
                <Select value={mode} onValueChange={(value) => setMode(value as RenewalPolicy["mode"])}>
                  <SelectTrigger size="sm" aria-label={`Renewal of ${label}`}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="automatic">Automatic</SelectItem>
                    <SelectItem value="manual">Manual</SelectItem>
                  </SelectContent>
                </Select>
                <Label className="gap-2 font-normal">
                  Days before expiry
                  <Input type="number" min={1} max={365} step={1} className="w-20" aria-label={`Days before expiry of ${label}`} value={days} onChange={(e) => setDays(e.target.value)} />
                </Label>
                <Button type="submit" size="sm" variant="outline" disabled={!changed || savePolicy.isPending}>
                  Save
                </Button>
              </form>
            )}
            {mayCsr && (
              <form
                className="flex flex-col gap-2"
                onSubmit={(e: FormEvent) => {
                  e.preventDefault();
                  upload.mutate();
                }}
              >
                <Label className="font-normal" htmlFor={`new-csr-${m.id}`}>
                  New CSR for the next Renewal (same key algorithm and names)
                </Label>
                <Textarea id={`new-csr-${m.id}`} className="font-mono text-xs" rows={5} value={csr} onChange={(e) => setCsr(e.target.value)} />
                <span>
                  <Button type="submit" size="sm" variant="outline" disabled={!csr.trim() || upload.isPending}>
                    Upload CSR
                  </Button>
                </span>
              </form>
            )}
          </div>
        </details>
      )}
      {error && <span className="text-destructive">{error.message}</span>}
    </div>
  );
}
