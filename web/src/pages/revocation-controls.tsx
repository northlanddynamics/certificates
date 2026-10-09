import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { REVOCATION_REASONS, api, can, revocationReasonLabel, type ManagedCertificate, type Me, type Revocation } from "@/lib/api";

const when = (iso: string) => new Date(iso).toLocaleString();

/** Archives a Managed Certificate, for those who may (Organization Administrators, not its Owners), after asking once more. */
export function Archive({ org, m, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; onChanged: () => void }) {
  const [confirming, setConfirming] = useState(false);
  const archive = useMutation({ mutationFn: () => api.archive(org.id, m.id), onSuccess: onChanged });

  if (m.archivedAt) return <span className="text-muted-foreground">Archived {when(m.archivedAt)}: it no longer renews, and its Certificates stay valid until they end or are revoked</span>;
  if (!can(org, "managedCertificate", "archive")) return null;
  return (
    <div className="flex flex-col gap-1">
      {confirming ? (
        <span className="flex flex-wrap items-center gap-2">
          <span>Archive it? It stops renewing and deploying, and is kept. Nothing is revoked.</span>
          <Button size="sm" variant="outline" disabled={archive.isPending} onClick={() => archive.mutate()}>
            Archive {m.names.join(", ")}
          </Button>
          <Button size="sm" variant="link" onClick={() => setConfirming(false)}>
            Cancel
          </Button>
        </span>
      ) : (
        <span>
          <Button variant="link" size="sm" className="h-auto p-0" onClick={() => setConfirming(true)}>
            Archive
          </Button>
        </span>
      )}
      {archive.error && <span className="text-destructive">{archive.error.message}</span>}
    </div>
  );
}

/**
 * Revokes one of a Managed Certificate's Certificates with a reason, for Organization Administrators and its Owners, after
 * asking once more. The CA is told first, so a refusal is shown and nothing changes. Certificates are fetched when opened.
 */
export function Revoke({ org, m, userId, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; userId?: string; onChanged: () => void }) {
  // The server decides; this only keeps the control from those who surely may not (a Team's members may, too).
  const owns = m.owners.some((o) => o.type === "user" && o.id === userId);
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
