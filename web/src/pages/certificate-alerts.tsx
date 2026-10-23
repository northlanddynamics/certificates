import { useMutation } from "@tanstack/react-query";
import { CircleAlertIcon, ClockIcon } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Field, FieldLabel } from "@/components/ui/field";
import { Textarea } from "@/components/ui/textarea";
import { api, can, type ManagedCertificate, type Me } from "@/lib/api";
import { ISSUANCE_KIND_WORDS, isOwner } from "@/lib/managed-certificate";

const when = (iso: string) => new Date(iso).toLocaleString();

/** Asks why, for a rejection, which cannot be made without one. */
function RejectDialog({ open, onOpenChange, title, pending, error, onReject }: { open: boolean; onOpenChange: (open: boolean) => void; title: string; pending: boolean; error: Error | null; onReject: (reason: string) => void }) {
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
          {error && <p className="text-sm text-destructive">{error.message}</p>}
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

/** Something waiting for Approval: decided by an Approver who did not propose it, and only waited for by whoever did. */
function Pending({ title, children, mayDecide, proposedByMe, onApprove, onReject, busy, error, rejectTitle }: {
  title: string;
  children: ReactNode;
  mayDecide: boolean;
  proposedByMe: boolean;
  onApprove: () => void;
  onReject: (reason: string) => void;
  busy: boolean;
  error: Error | null;
  rejectTitle: string;
}) {
  const [rejecting, setRejecting] = useState(false);
  return (
    <Alert>
      <ClockIcon />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>
        {children}
        {proposedByMe && <p>Awaiting Approval: an Approver other than you must decide it.</p>}
        {error && !rejecting && <p className="text-destructive">{error.message}</p>}
      </AlertDescription>
      {mayDecide && (
        <AlertAction className="flex gap-2">
          <Button size="sm" disabled={busy} onClick={onApprove}>
            Approve
          </Button>
          <Button size="sm" variant="outline" disabled={busy} onClick={() => setRejecting(true)}>
            Reject
          </Button>
        </AlertAction>
      )}
      <RejectDialog
        open={rejecting}
        onOpenChange={setRejecting}
        title={rejectTitle}
        pending={busy}
        error={error}
        onReject={(reason) => {
          onReject(reason);
          setRejecting(false);
        }}
      />
    </Alert>
  );
}

/**
 * What needs attention before anything else on a Managed Certificate: a Renewal blocked by a disabled Certificate Profile,
 * the automation's latest failure, with the means to try again, and a Proposal or Name Change waiting for Approval, with
 * the means to decide it. Nothing shows when there is none.
 */
export function AlertStrip({ org, m, userId, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; userId?: string; onChanged: () => void }) {
  const owns = isOwner(m, userId);
  const mayIssue = can(org, "managedCertificate", "issue");
  const mayRenew = can(org, "managedCertificate", "renew") || owns;
  const mayDecide = can(org, "approval", "decide");

  // One that has a Certificate is tried again as a Renewal, which its Owners may ask for; one with none, as its first Issuance.
  const renewing = m.currentCertificate !== null;
  const retry = useMutation({ mutationFn: () => (renewing ? api.renewNow(org.id, m.id) : api.retryIssuance(org.id, m.id)), onSuccess: onChanged });
  const approve = useMutation({ mutationFn: () => api.approve(org.id, m.id), onSuccess: onChanged });
  const reject = useMutation({ mutationFn: (reason: string) => api.reject(org.id, m.id, reason), onSuccess: onChanged });
  const approveNames = useMutation({ mutationFn: () => api.approveNameChange(org.id, m.id), onSuccess: onChanged });
  const rejectNames = useMutation({ mutationFn: (reason: string) => api.rejectNameChange(org.id, m.id, reason), onSuccess: onChanged });

  // The latest attempt is the newest: its failure stands until a later attempt succeeds, which replaces it.
  const failed = m.issuance?.status === "failed" ? m.issuance : null;
  const failure = m.renewal.failing?.lastFailure ?? failed?.failure ?? null;
  const failedAt = m.renewal.failing?.lastFailure.at ?? failed?.finishedAt ?? null;
  const mayRetry = renewing ? mayRenew : mayIssue;
  const proposal = m.approval.status === "pending" ? m.approval : null;
  const nameChange = m.pendingNameChange;
  const heldUp = m.issuance?.awaitingKey && m.agent?.status === "offline" ? m.agent : null;
  const blocked = m.renewal.blocked;

  if (m.archivedAt) return null;
  if (!failure && !proposal && !nameChange && !heldUp && !blocked) return null;
  return (
    <div className="flex flex-col gap-2">
      {blocked && (
        <Alert variant="destructive">
          <CircleAlertIcon />
          <AlertTitle>Renewal blocked</AlertTitle>
          <AlertDescription>
            It was due for Renewal {when(blocked.since)}, but the Certificate Profile {blocked.profile.name} it was made from is disabled, so nothing is issued under it. It renews
            once an Organization Administrator enables the profile again, or detaches it from the profile.
          </AlertDescription>
        </Alert>
      )}
      {heldUp && (
        <Alert variant="destructive">
          <CircleAlertIcon />
          <AlertTitle>Agent offline</AlertTitle>
          <AlertDescription>The Renewal waits for {heldUp.hostName} to make the new key, and goes on once the Agent is back in touch.</AlertDescription>
        </Alert>
      )}
      {failure && m.issuance?.status !== "running" && (
        <Alert variant="destructive">
          <CircleAlertIcon />
          <AlertTitle>
            {m.renewal.failing && failed?.kind !== "name_change"
              ? `Renewal failed ${m.renewal.failing.failures} time${m.renewal.failing.failures === 1 ? "" : "s"}`
              : `${ISSUANCE_KIND_WORDS[failed?.kind ?? "first_issue"]} failed`}
          </AlertTitle>
          <AlertDescription>
            <p>
              {failure.message}
              {failedAt && <span className="text-muted-foreground"> ({when(failedAt)})</span>}
            </p>
            {m.renewal.failing?.nextAttemptAt && <p>Next attempt {when(m.renewal.failing.nextAttemptAt)}.</p>}
            {retry.error && <p>{retry.error.message}</p>}
          </AlertDescription>
          {mayRetry && (
            <AlertAction>
              <Button size="sm" variant="outline" disabled={retry.isPending} onClick={() => retry.mutate()}>
                Try again
              </Button>
            </AlertAction>
          )}
        </Alert>
      )}
      {proposal && (
        <Pending
          title="Proposal awaiting Approval"
          mayDecide={mayDecide && proposal.proposedBy?.id !== userId}
          proposedByMe={proposal.proposedBy?.id === userId}
          onApprove={() => approve.mutate()}
          onReject={(reason) => reject.mutate(reason)}
          busy={approve.isPending || reject.isPending}
          error={approve.error ?? reject.error}
          rejectTitle={`Reject ${m.names.join(", ")}`}
        >
          Proposed by {proposal.proposedBy?.email}. No Certificate is issued until it is approved.
        </Pending>
      )}
      {nameChange && (
        <Pending
          title="Name change awaiting Approval"
          mayDecide={mayDecide && nameChange.proposedBy.id !== userId}
          proposedByMe={nameChange.proposedBy.id === userId}
          onApprove={() => approveNames.mutate()}
          onReject={(reason) => rejectNames.mutate(reason)}
          busy={approveNames.isPending || rejectNames.isPending}
          error={approveNames.error ?? rejectNames.error}
          rejectTitle={`Reject the name change of ${m.names.join(", ")}`}
        >
          Proposed by {nameChange.proposedBy.email}, to {nameChange.names.join(", ")}. Renewal continues with the current names until it is approved.
        </Pending>
      )}
    </div>
  );
}
