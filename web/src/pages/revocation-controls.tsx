import { useMutation } from "@tanstack/react-query";
import { BanIcon } from "lucide-react";
import { useState } from "react";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Field, FieldLabel } from "@/components/ui/field";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api, can, revocationReasonLabel, revocationReasonsFor, type Certificate, type ManagedCertificate, type Me, type Revocation } from "@/lib/api";
import { isOwner } from "@/lib/managed-certificate";

const when = (iso: string) => new Date(iso).toLocaleString();

/** Whether the caller may Archive a Managed Certificate: Organization Administrators may, not its Owners. */
export const mayArchive = (org: Me["organizations"][number], m: ManagedCertificate) => !m.archivedAt && can(org, "managedCertificate", "archive");

/** Archiving a Managed Certificate, which asks again first. */
export function ArchiveDialog({ org, m, open, onOpenChange, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; open: boolean; onOpenChange: (open: boolean) => void; onChanged: () => void }) {
  const archive = useMutation({
    mutationFn: () => api.archive(org.id, m.id),
    onSuccess: () => {
      onOpenChange(false);
      onChanged();
    },
  });
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(next) => {
        onOpenChange(next);
        archive.reset();
      }}
      title={`Archive ${m.names.join(", ")}?`}
      description="It stops issuing, renewing and deploying, and is kept with its Certificates and history. Nothing is revoked."
      confirmLabel="Archive"
      pending={archive.isPending}
      error={archive.error}
      onConfirm={() => archive.mutate()}
    />
  );
}

/**
 * Revokes one Certificate of a Managed Certificate with an RFC 5280 reason, for Organization Administrators and its
 * Owners, archived or not (Archive never blocks Revocation). The CA is told first, so a refusal is shown and nothing changes.
 */
export function RevokeDialog({ org, m, certificate, userId, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; certificate: Certificate; userId?: string; onChanged: () => void }) {
  // The server decides; this only keeps the control from those who surely may not (a Team's members may, too).
  const owns = isOwner(m, userId);
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const revoke = useMutation({
    mutationFn: () => api.revokeCertificate(org.id, m.id, certificate.id, reason),
    onSuccess: () => {
      setOpen(false);
      onChanged();
    },
  });
  const selectId = `revocation-reason-${certificate.id}`;

  if (certificate.revocation || !(can(org, "managedCertificate", "revoke") || owns)) return null;
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (next) {
          setReason("");
          revoke.reset();
        }
      }}
    >
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          <BanIcon />
          Revoke
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Revoke this Certificate?</DialogTitle>
          <DialogDescription>
            Issued {new Date(certificate.issuedAt).toLocaleDateString()}, serial <span className="font-mono">{certificate.serial}</span>. The CA is told at once; a revocation cannot be undone.
          </DialogDescription>
        </DialogHeader>
        <Field>
          <FieldLabel htmlFor={selectId}>Reason</FieldLabel>
          <Select value={reason} onValueChange={setReason}>
            <SelectTrigger id={selectId} className="w-full">
              <SelectValue placeholder="Choose a reason (RFC 5280)" />
            </SelectTrigger>
            <SelectContent>
              {revocationReasonsFor(certificate).map(([value, text]) => (
                <SelectItem key={value} value={value}>
                  {text}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
        {revoke.error && <p className="text-sm text-destructive">{revoke.error.message}</p>}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button variant="destructive" disabled={!reason || revoke.isPending} onClick={() => revoke.mutate()}>
            Revoke
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** What a Certificate's revocation comes to, in words, for the line that says how the Managed Certificate stands. */
export const revokedLine = (revocation: Revocation) =>
  `Revoked ${when(revocation.revokedAt)} by ${revocation.revokedBy.email}: ${revocationReasonLabel(revocation.reason)}`;
