import { useMutation } from "@tanstack/react-query";
import { RefreshCwIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api, can, type ManagedCertificate, type Me, type RenewalPolicy } from "@/lib/api";
import { isOwner } from "@/lib/managed-certificate";
import { renewalWindowOpens } from "@/lib/renewal-urgency";
import { date } from "@/lib/utils";

const when = (iso: string) => new Date(iso).toLocaleString();

const daysBefore = (n: number) => `${n} day${n === 1 ? "" : "s"} before expiry`;

/**
 * When a Managed Certificate renews next, or why it does not, in a few words and a line more; `problem` when it is not
 * renewing as it should.
 */
export function nextRenewal(m: ManagedCertificate): { headline: string; detail: string | null; problem: boolean } {
  const { policy, dueAt, dueBecause, failing, blocked } = m.renewal;
  if (m.archivedAt) return { headline: "None", detail: "Archived Managed Certificates are not renewed", problem: false };
  if (policy.mode === "manual") return { headline: "Manual", detail: "Renewed only when asked", problem: false };
  if (blocked) return { headline: "Blocked", detail: `The Certificate Profile ${blocked.profile.name} is disabled`, problem: true };
  if (failing) return { headline: "Failing", detail: failing.nextAttemptAt ? `Next attempt ${when(failing.nextAttemptAt)}` : "No further attempt is scheduled", problem: true };
  if (!dueAt) return { headline: "Automatic", detail: daysBefore(policy.daysBeforeExpiry), problem: false };
  // The CA's own window, when it is the one that is due first, is the reason to name.
  return { headline: `Automatic, ${date(dueAt)}`, detail: dueBecause === "ari" ? "In the CA's suggested window" : daysBefore(policy.daysBeforeExpiry), problem: false };
}

/**
 * Whether the caller may start a Renewal at once: an Owner or an Organization Administrator, of one that has a Certificate
 * and is approved and not archived. The server decides; this only keeps the controls from those who surely may not (a
 * Team's members may, too).
 */
export const mayRenewNow = (org: Me["organizations"][number], m: ManagedCertificate, userId?: string) =>
  !m.archivedAt && m.currentCertificate !== null && m.approval.status !== "pending" && m.approval.status !== "rejected" && (can(org, "managedCertificate", "renew") || isOwner(m, userId));

/** Starts a Renewal at once, for those who may: the page's first action while renewing is the thing to do (`renewalUrgent`). */
export function RenewNowButton({ org, m, userId, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; userId?: string; onChanged: () => void }) {
  const renew = useMutation({
    mutationFn: () => api.renewNow(org.id, m.id),
    onSuccess: onChanged,
    onError: (error) => toast.error(`${m.names.join(", ")} was not renewed`, { description: error.message }),
  });
  if (!mayRenewNow(org, m, userId)) return null;
  return (
    <Button disabled={renew.isPending || m.issuance?.status === "running"} onClick={() => renew.mutate()}>
      <RefreshCwIcon />
      Renew now
    </Button>
  );
}

/** Asks before renewing one that is not yet due, as the "⋯" menu offers it then: a new Certificate early is seldom wanted. */
export function RenewEarlyDialog({ org, m, open, onOpenChange, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; open: boolean; onOpenChange: (open: boolean) => void; onChanged: () => void }) {
  const renew = useMutation({
    mutationFn: () => api.renewNow(org.id, m.id),
    onSuccess: () => {
      onOpenChange(false);
      onChanged();
    },
  });
  const opens = renewalWindowOpens(m);
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title="Renew before it is due?"
      description={
        <>
          {opens ? `It is not due to renew until ${date(opens.toISOString())}. ` : ""}Renewing now issues a new Certificate at once, which then has to be deployed wherever the
          current one is used.
        </>
      }
      confirmLabel="Renew now"
      dismissLabel="Not now"
      destructive={false}
      pending={renew.isPending}
      error={renew.error}
      onConfirm={() => renew.mutate()}
    />
  );
}

/**
 * A Managed Certificate's Renewal, as a section of its page: its policy, how it is going, and for those who may, the means
 * to change the policy. A new CSR is the key sheet's. Nothing shows for a Proposal, or one that was rejected.
 */
export function Renewal({ org, m, userId, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; userId?: string; onChanged: () => void }) {
  // The server decides; this only keeps the controls from those who surely may not (a Team's members may, too).
  const owns = isOwner(m, userId);
  const mayPolicy = can(org, "managedCertificate", "setRenewalPolicy") || owns;
  const settled = m.approval.status !== "pending" && m.approval.status !== "rejected";

  const [editing, setEditing] = useState(false);
  const [mode, setMode] = useState<RenewalPolicy["mode"]>(m.renewal.policy.mode);
  const [days, setDays] = useState(String(m.renewal.policy.daysBeforeExpiry));
  const savePolicy = useMutation({
    mutationFn: (policy: RenewalPolicy) => api.setRenewalPolicy(org.id, m.id, policy),
    onSuccess: () => {
      setEditing(false);
      onChanged();
    },
  });
  const error = savePolicy.error;
  const label = m.names.join(", ");
  const changed = mode !== m.renewal.policy.mode || Number(days) !== m.renewal.policy.daysBeforeExpiry;

  if (!settled) return null;
  const { policy } = m.renewal;
  return (
    <section aria-labelledby={`renewal-${m.id}`} className="flex flex-col gap-1">
      <div className="flex items-center justify-between gap-2">
        <h3 id={`renewal-${m.id}`} className="font-medium">
          Renewal
        </h3>
        {mayPolicy && !editing && (
          <Button variant="ghost" size="sm" aria-label={`Edit the Renewal Policy of ${label}`} onClick={() => setEditing(true)}>
            Edit
          </Button>
        )}
      </div>
      <span>{policy.mode === "manual" ? "Manual: renewed only when asked" : `Automatic, at the latest ${daysBefore(policy.daysBeforeExpiry)}`}</span>
      {policy.mode === "automatic" && <NextRenewalLine m={m} />}
      {m.renewal.ari?.window && (
        <span className="text-muted-foreground">
          The CA suggests renewing between {when(m.renewal.ari.window.start)} and {when(m.renewal.ari.window.end)}
        </span>
      )}
      {editing && (
        <form
          className="mt-2 flex flex-wrap items-center gap-2"
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
          <div className="flex gap-2">
            <Button type="submit" size="sm" disabled={!changed || savePolicy.isPending}>
              Save
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={() => {
                setEditing(false);
                setMode(policy.mode);
                setDays(String(policy.daysBeforeExpiry));
                savePolicy.reset();
              }}
            >
              Cancel
            </Button>
          </div>
        </form>
      )}
      {error && <span className="text-destructive">{error.message}</span>}
    </section>
  );
}

/** When an automatic Renewal happens next, or why it does not. */
function NextRenewalLine({ m }: { m: ManagedCertificate }) {
  const { dueAt, dueBecause, failing, blocked } = m.renewal;
  if (blocked) return <span className="text-destructive">Blocked: the Certificate Profile {blocked.profile.name} is disabled</span>;
  if (failing) return <span className="text-destructive">Failing{failing.nextAttemptAt && `; next attempt ${when(failing.nextAttemptAt)}`}</span>;
  if (!dueAt) return null;
  return (
    <span className="text-muted-foreground">
      Next {when(dueAt)}
      {dueBecause === "ari" && ", when the CA suggests"}
    </span>
  );
}
