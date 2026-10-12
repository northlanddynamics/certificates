import { useMutation, useQuery } from "@tanstack/react-query";
import { ArchiveIcon, EllipsisIcon } from "lucide-react";
import { useState } from "react";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { REVOCATION_REASONS, api, can, revocationReasonLabel, type ManagedCertificate, type Me, type Revocation } from "@/lib/api";
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
 * Revokes one of a Managed Certificate's Certificates with a reason, for Organization Administrators and its Owners, after
 * asking once more. The CA is told first, so a refusal is shown and nothing changes. Certificates are fetched when opened.
 */
export function Revoke({ org, m, userId, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; userId?: string; onChanged: () => void }) {
  // The server decides; this only keeps the control from those who surely may not (a Team's members may, too).
  const owns = isOwner(m, userId);
  const [open, setOpen] = useState(false);
  const [certificateId, setCertificateId] = useState("");
  const [reason, setReason] = useState("");
  const [confirming, setConfirming] = useState(false);
  const certificates = useQuery({ queryKey: ["certificates", org.id, m.id, m.currentCertificate?.fingerprint, m.currentCertificate?.revocation?.revokedAt], queryFn: () => api.certificates(org.id, m.id), enabled: open });
  const revoke = useMutation({
    mutationFn: () => api.revokeCertificate(org.id, m.id, certificateId, reason),
    onSuccess: () => {
      setCertificateId("");
      setReason("");
      setConfirming(false);
      onChanged();
    },
  });
  const label = m.names.join(", ");
  const revocable = certificates.data?.items.filter((c) => !c.revocation) ?? [];

  if (!m.currentCertificate || !(can(org, "managedCertificate", "revoke") || owns)) return null;
  return (
    <details onToggle={(e) => setOpen(e.currentTarget.open)}>
      <summary className="cursor-pointer underline">Revoke</summary>
      <div className="mt-1 flex flex-col gap-2">
        {certificates.data && revocable.length === 0 && <span className="text-muted-foreground">Every Certificate is revoked.</span>}
        {revocable.length > 0 && (
          <span className="flex flex-wrap items-center gap-2">
            <Select value={certificateId} onValueChange={setCertificateId}>
              <SelectTrigger size="sm" aria-label={`Certificate of ${label} to revoke`}>
                <SelectValue placeholder="Certificate…" />
              </SelectTrigger>
              <SelectContent>
                {revocable.map((c) => (
                  <SelectItem key={c.id} value={c.id}>
                    {c.id === m.currentCertificate?.id ? "Current, " : ""}issued {new Date(c.issuedAt).toLocaleDateString()} ({c.fingerprint.slice(0, 8)})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={reason} onValueChange={setReason}>
              <SelectTrigger size="sm" aria-label={`Reason for revoking ${label}`}>
                <SelectValue placeholder="Reason…" />
              </SelectTrigger>
              <SelectContent>
                {REVOCATION_REASONS.map(([value, text]) => (
                  <SelectItem key={value} value={value}>
                    {text}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {confirming ? (
              <>
                <span>The CA is told at once; a revocation cannot be undone.</span>
                <Button size="sm" variant="destructive" disabled={revoke.isPending} onClick={() => revoke.mutate()}>
                  Revoke now
                </Button>
                <Button size="sm" variant="link" onClick={() => setConfirming(false)}>
                  Cancel
                </Button>
              </>
            ) : (
              <Button size="sm" variant="outline" disabled={!certificateId || !reason} onClick={() => setConfirming(true)}>
                Revoke…
              </Button>
            )}
          </span>
        )}
        {revoke.error && <span className="text-destructive">{revoke.error.message}</span>}
      </div>
    </details>
  );
}

/** What a Certificate's revocation comes to, in words, for the line that says how the Managed Certificate stands. */
export const revokedLine = (revocation: Revocation) =>
  `Revoked ${when(revocation.revokedAt)} by ${revocation.revokedBy.email}: ${revocationReasonLabel(revocation.reason)}`;
