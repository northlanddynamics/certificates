import { useMutation } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { CircleAlertIcon, ClockIcon } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Field, FieldLabel } from "@/components/ui/field";
import { Textarea } from "@/components/ui/textarea";
import { api, can, type ManagedCertificate, type Me } from "@/lib/api";
import { ISSUANCE_KIND_WORDS, isOwner } from "@/lib/managed-certificate";
import { chosenValidityLabel } from "@/lib/private-ca";
import { cn } from "@/lib/utils";
import { NamesDiff } from "./key-change-sheet";

const when = (iso: string) => new Date(iso).toLocaleString();

/** Asks why, for a rejection, which cannot be made without one. */
function RejectDialog({ open, onOpenChange, title, pending, onReject }: { open: boolean; onOpenChange: (open: boolean) => void; title: string; pending: boolean; onReject: (reason: string) => void }) {
  const [reason, setReason] = useState("");
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form
          className="flex flex-col gap-4"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            if (reason.trim()) onReject(reason.trim());
          }}
        >
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription>The proposer is told why.</DialogDescription>
          </DialogHeader>
          <Field>
            <FieldLabel htmlFor="reject-reason">Reason</FieldLabel>
            <Textarea id="reject-reason" value={reason} onChange={(e) => setReason(e.target.value)} required autoFocus />
          </Field>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" variant="destructive" disabled={pending || !reason.trim()}>
              Reject
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** One thing that needs attention: what it is, and beside it the action that resolves it. */
function Item({ icon, tone, title, children, actions }: { icon: ReactNode; tone: "problem" | "waiting"; title: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <li className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-3 px-4 py-4 sm:grid-cols-[auto_minmax(0,1fr)_auto]">
      <span
        className={cn(
          "flex size-7 items-center justify-center rounded-full [&_svg]:size-4",
          tone === "problem" ? "bg-destructive/10 text-destructive" : "bg-warning/10 text-warning dark:bg-warning/15",
        )}
      >
        {icon}
      </span>
      <div className="flex min-w-0 flex-col gap-1.5">
        <h3 className={cn("font-medium", tone === "problem" && "text-destructive")}>{title}</h3>
        {children}
      </div>
      {actions && <div className="col-start-2 flex flex-wrap gap-2 sm:col-start-3 sm:justify-end">{actions}</div>}
    </li>
  );
}

/** Something waiting for Approval: decided by an Approver who did not propose it, and only waited for by whoever did. */
function Pending({ title, children, mayDecide, proposedByMe, onApprove, onReject, onWithdraw, busy, rejectTitle }: {
  title: string;
  children: ReactNode;
  mayDecide: boolean;
  proposedByMe: boolean;
  onApprove: () => void;
  onReject: (reason: string) => void;
  /** For whoever proposed it, taking it back; not every Proposal can be. */
  onWithdraw?: () => void;
  busy: boolean;
  rejectTitle: string;
}) {
  const [rejecting, setRejecting] = useState(false);
  return (
    <Item
      icon={<ClockIcon />}
      tone="waiting"
      title={mayDecide ? `${title} awaiting your Approval` : `${title} awaiting Approval`}
      actions={
        mayDecide ? (
          <>
            <Button size="sm" variant="outline" disabled={busy} onClick={() => setRejecting(true)}>
              Reject…
            </Button>
            <Button size="sm" disabled={busy} onClick={onApprove}>
              Approve
            </Button>
          </>
        ) : proposedByMe && onWithdraw ? (
          <Button size="sm" variant="outline" disabled={busy} onClick={onWithdraw}>
            Withdraw
          </Button>
        ) : undefined
      }
    >
      {children}
      {proposedByMe && <p className="text-muted-foreground">An Approver other than you must decide it.</p>}
      <RejectDialog
        open={rejecting}
        onOpenChange={setRejecting}
        title={rejectTitle}
        pending={busy}
        onReject={(reason) => {
          onReject(reason);
          setRejecting(false);
        }}
      />
    </Item>
  );
}

/**
 * What needs attention before anything else on a Managed Certificate, most urgent first: a Renewal blocked by a disabled
 * Certificate Profile, an Agent that holds up a Renewal, the automation's latest failure, with the means to try again, and a
 * Proposal or Name Change waiting for Approval, with the means to decide it (or, for whoever proposed a Name Change, to
 * withdraw it). Nothing shows when there is none.
 */
export function AlertStrip({ org, m, userId, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; userId?: string; onChanged: () => void }) {
  const owns = isOwner(m, userId);
  const mayIssue = can(org, "managedCertificate", "issue");
  const mayRenew = can(org, "managedCertificate", "renew") || owns;
  const mayDecide = can(org, "approval", "decide");

  // One that has a Certificate is tried again as a Renewal, which its Owners may ask for; one with none, as its first Issuance.
  const renewing = m.currentCertificate !== null;
  // A decision takes what it decided off the strip, so a toast says what became of it; a refusal is a toast, too.
  const names = m.names.join(", ");
  const done = (what: string) => () => {
    toast.success(what);
    onChanged();
  };
  const refused = (what: string) => (error: Error) => toast.error(what, { description: error.message });
  const retry = useMutation({
    mutationFn: () => (renewing ? api.renewNow(org.id, m.id) : api.retryIssuance(org.id, m.id)),
    onSuccess: onChanged,
    onError: refused(`${names} was not ${renewing ? "renewed" : "issued"}`),
  });
  const approve = useMutation({ mutationFn: () => api.approve(org.id, m.id), onSuccess: done(`${names} approved`), onError: refused(`${names} was not approved`) });
  const reject = useMutation({ mutationFn: (reason: string) => api.reject(org.id, m.id, reason), onSuccess: done(`${names} rejected`), onError: refused(`${names} was not rejected`) });
  const approveNames = useMutation({
    mutationFn: () => api.approveNameChange(org.id, m.id),
    onSuccess: done(`The name change of ${names} was approved`),
    onError: refused(`The name change of ${names} was not approved`),
  });
  const rejectNames = useMutation({
    mutationFn: (reason: string) => api.rejectNameChange(org.id, m.id, reason),
    onSuccess: done(`The name change of ${names} was rejected`),
    onError: refused(`The name change of ${names} was not rejected`),
  });
  const withdrawNames = useMutation({
    mutationFn: () => api.withdrawNameChange(org.id, m.id),
    onSuccess: done(`The name change of ${names} was withdrawn`),
    onError: refused(`The name change of ${names} was not withdrawn`),
  });

  // The latest attempt is the newest: its failure stands until a later attempt succeeds, which replaces it.
  const failed = m.issuance?.status === "failed" ? m.issuance : null;
  const failure = m.renewal.failing?.lastFailure ?? failed?.failure ?? null;
  const failedAt = m.renewal.failing?.lastFailure.at ?? failed?.finishedAt ?? null;
  const mayRetry = renewing ? mayRenew : mayIssue;
  const proposal = m.approval.status === "pending" ? m.approval : null;
  const nameChange = m.pendingNameChange;
  const heldUp = m.issuance?.awaitingKey && m.agent?.status === "offline" ? m.agent : null;
  const blocked = m.renewal.blocked;
  const showFailure = !!failure && m.issuance?.status !== "running";

  if (m.archivedAt) return null;
  const count = [blocked, heldUp, showFailure, proposal, nameChange].filter(Boolean).length;
  if (count === 0) return null;
  return (
    <section aria-labelledby={`attention-${m.id}`} className="overflow-hidden rounded-lg border bg-card text-sm">
      <h2 id={`attention-${m.id}`} className="border-b bg-muted/50 px-4 py-2.5 font-semibold">
        Needs attention <span className="font-normal text-muted-foreground">· {count}</span>
      </h2>
      <ul className="divide-y">
        {blocked && (
          <Item icon={<CircleAlertIcon />} tone="problem" title="Renewal blocked">
            <p>
              It was due for Renewal {when(blocked.since)}, but the Certificate Profile {blocked.profile.name} it was made from is disabled, so nothing is issued under it. It
              renews once an Organization Administrator enables the profile again, or detaches it from the profile.
            </p>
          </Item>
        )}
        {heldUp && (
          <Item icon={<CircleAlertIcon />} tone="problem" title="Agent offline">
            <p>The Renewal waits for {heldUp.hostName} to make the new key, and goes on once the Agent is back in touch.</p>
          </Item>
        )}
        {failure && showFailure && (
          <Item
            icon={<CircleAlertIcon />}
            tone="problem"
            title={
              m.renewal.failing && failed?.kind !== "name_change"
                ? `Renewal failed ${m.renewal.failing.failures} time${m.renewal.failing.failures === 1 ? "" : "s"}`
                : `${ISSUANCE_KIND_WORDS[failed?.kind ?? "first_issue"]} failed`
            }
            actions={
              <>
                <Button size="sm" variant="ghost" asChild>
                  <Link to="/organizations/$orgId/certificates/$id/activity" params={{ orgId: org.id, id: m.id }}>
                    View in Activity
                  </Link>
                </Button>
                {mayRetry && (
                  <Button size="sm" disabled={retry.isPending} onClick={() => retry.mutate()}>
                    Try again
                  </Button>
                )}
              </>
            }
          >
            <p className="break-words">{failure.message}</p>
            <p className="flex flex-wrap gap-x-4 text-muted-foreground">
              <span className="font-mono text-xs leading-5">{failure.code}</span>
              {failedAt && <span>Last attempt {when(failedAt)}</span>}
              {m.renewal.failing?.nextAttemptAt && <span>Next attempt {when(m.renewal.failing.nextAttemptAt)}</span>}
            </p>
          </Item>
        )}
        {proposal && (
          <Pending
            title="Proposal"
            mayDecide={mayDecide && proposal.proposedBy?.id !== userId}
            proposedByMe={proposal.proposedBy?.id === userId}
            onApprove={() => approve.mutate()}
            onReject={(reason) => reject.mutate(reason)}
            busy={approve.isPending || reject.isPending}
            rejectTitle={`Reject ${m.names.join(", ")}`}
          >
            <p>Proposed by {proposal.proposedBy?.email}. No Certificate is issued until it is approved; approving starts its first Issuance.</p>
            <ul className="flex flex-col gap-0.5 font-mono text-xs">
              {m.names.map((name) => (
                <li key={name}>{name}</li>
              ))}
            </ul>
          </Pending>
        )}
        {nameChange && (
          <Pending
            title="Name change"
            mayDecide={mayDecide && nameChange.proposedBy.id !== userId}
            proposedByMe={nameChange.proposedBy.id === userId}
            onApprove={() => approveNames.mutate()}
            onReject={(reason) => rejectNames.mutate(reason)}
            onWithdraw={() => withdrawNames.mutate()}
            busy={approveNames.isPending || rejectNames.isPending || withdrawNames.isPending}
            rejectTitle={`Reject the name change of ${m.names.join(", ")}`}
          >
            <p>
              Proposed by {nameChange.proposedBy.email} {when(nameChange.proposedAt)}
              {nameChange.validityDays !== m.validityDays && `, valid for ${chosenValidityLabel(nameChange.validityDays)}`}. Renewal continues with the current names until it is
              decided.
            </p>
            <div className="max-w-md">
              <NamesDiff before={m.names} after={nameChange.names} />
            </div>
          </Pending>
        )}
      </ul>
    </section>
  );
}
