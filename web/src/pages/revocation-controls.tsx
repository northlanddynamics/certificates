import { useMutation } from "@tanstack/react-query";
import { ArchiveIcon, BanIcon, EllipsisIcon } from "lucide-react";
import { useState } from "react";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Field, FieldLabel } from "@/components/ui/field";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { REVOCATION_REASONS, api, can, revocationReasonLabel, type Certificate, type ManagedCertificate, type Me, type Revocation } from "@/lib/api";
import { isOwner } from "@/lib/managed-certificate";

const when = (iso: string) => new Date(iso).toLocaleString();

/** The "⋯" menu of a Managed Certificate's page, holding Archive for those who may (Organization Administrators, not its Owners), which asks again first. */
export function ArchiveMenu({ org, m, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; onChanged: () => void }) {
  const [confirming, setConfirming] = useState(false);
  const archive = useMutation({
    mutationFn: () => api.archive(org.id, m.id),
    onSuccess: () => {
      setConfirming(false);
      onChanged();
    },
  });

  if (m.archivedAt || !can(org, "managedCertificate", "archive")) return null;
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="icon" aria-label="More actions">
            <EllipsisIcon />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem
            onSelect={() => {
              archive.reset();
              setConfirming(true);
            }}
          >
            <ArchiveIcon />
            Archive
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title={`Archive ${m.names.join(", ")}?`}
        description="It stops issuing, renewing and deploying, and is kept with its Certificates and history. Nothing is revoked."
        confirmLabel="Archive"
        pending={archive.isPending}
        error={archive.error}
        onConfirm={() => archive.mutate()}
      />
    </>
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
              {REVOCATION_REASONS.map(([value, text]) => (
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
