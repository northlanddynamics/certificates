import { useMutation } from "@tanstack/react-query";
import { RefreshCwIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api, can, type ManagedCertificate, type Me, type RenewalPolicy } from "@/lib/api";
import { isOwner } from "@/lib/managed-certificate";

const when = (iso: string) => new Date(iso).toLocaleString();

/** What the Renewal Policy comes to for this Managed Certificate, in words: when it renews, or why it is not. */
function summary(m: ManagedCertificate) {
  const { policy, dueAt, dueBecause, failing } = m.renewal;
  if (policy.mode === "manual") return "Renewed by hand only";
  const days = `${policy.daysBeforeExpiry} day${policy.daysBeforeExpiry === 1 ? "" : "s"} before expiry`;
  if (!dueAt) return `Renews automatically ${days}`;
  // The CA's own window, when it is the one that is due first, is the reason to name.
  const why = dueBecause === "ari" ? "when the CA suggests" : days;
  return `Renews automatically ${why}, from ${when(failing?.nextAttemptAt ?? dueAt)}`;
}

/** Starts a Renewal at once, for those who may: an Owner or an Organization Administrator, of one that has a Certificate and is approved and not archived. */
export function RenewNowButton({ org, m, userId, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; userId?: string; onChanged: () => void }) {
  // The server decides; this only keeps the button from those who surely may not (a Team's members may, too).
  const owns = isOwner(m, userId);
  const renew = useMutation({ mutationFn: () => api.renewNow(org.id, m.id), onSuccess: onChanged });
  if (m.archivedAt || !m.currentCertificate || m.approval.status === "pending" || m.approval.status === "rejected" || !(can(org, "managedCertificate", "renew") || owns)) return null;
  return (
    <>
      <Button disabled={renew.isPending || m.issuance?.status === "running"} onClick={() => renew.mutate()}>
        <RefreshCwIcon />
        Renew now
      </Button>
      {renew.error && <span className="text-sm text-destructive">{renew.error.message}</span>}
    </>
  );
}

/** A Managed Certificate's Renewal: its policy, how it is going, and for those who may, the means to change the policy. A new CSR is the Key and CSR card's. */
export function Renewal({ org, m, userId, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; userId?: string; onChanged: () => void }) {
  // The server decides; this only keeps the controls from those who surely may not (a Team's members may, too).
  const owns = isOwner(m, userId);
  const mayPolicy = can(org, "managedCertificate", "setRenewalPolicy") || owns;
  const settled = m.approval.status !== "pending" && m.approval.status !== "rejected";

  const [mode, setMode] = useState<RenewalPolicy["mode"]>(m.renewal.policy.mode);
  const [days, setDays] = useState(String(m.renewal.policy.daysBeforeExpiry));
  const savePolicy = useMutation({ mutationFn: (policy: RenewalPolicy) => api.setRenewalPolicy(org.id, m.id, policy), onSuccess: onChanged });
  const error = savePolicy.error;
  const label = m.names.join(", ");
  const changed = mode !== m.renewal.policy.mode || Number(days) !== m.renewal.policy.daysBeforeExpiry;

  if (!settled) return null;
  return (
    <div className="flex flex-col gap-1">
      <span className="text-muted-foreground">{summary(m)}</span>
      {m.renewal.ari?.window && (
        <span className="text-muted-foreground">
          The CA suggests renewing between {when(m.renewal.ari.window.start)} and {when(m.renewal.ari.window.end)}
        </span>
      )}
      {mayPolicy && (
        <details>
          <summary className="cursor-pointer underline">Renewal settings</summary>
          <form
            className="mt-1 flex flex-wrap items-center gap-2"
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
        </details>
      )}
      {error && <span className="text-destructive">{error.message}</span>}
    </div>
  );
}
