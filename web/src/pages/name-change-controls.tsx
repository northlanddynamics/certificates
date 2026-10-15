import { useMutation, useQuery } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { api, can, type ManagedCertificate, type Me } from "@/lib/api";
import { isOwner } from "@/lib/managed-certificate";
import { chosenValidityLabel, daysLabel, isValidityDays, issuingCaTitle, permitsOnlyLabel } from "@/lib/private-ca";

/** A Managed Certificate's name change: the one waiting for Approval, and for those who may, the means to make one. */
export function NameChange({ org, m, userId, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; userId?: string; onChanged: () => void }) {
  // The server decides; this only keeps the form from those who surely may not (a Team's members may, too).
  const owns = isOwner(m, userId);
  const direct = can(org, "managedCertificate", "changeNames");
  const mayChange = (direct || can(org, "managedCertificate", "proposeNameChange") || owns) && m.approval.status !== "pending" && m.approval.status !== "rejected";
  const [names, setNames] = useState("");
  const [csr, setCsr] = useState("");
  // For a Private CA, the validity it is to have, in days: its own to begin with, and empty for the Private CA's default.
  const current = m.validityDays === null ? "" : String(m.validityDays);
  const [validity, setValidity] = useState(current);
  const validityDays = validity.trim() === "" ? null : Number(validity);
  const change = useMutation({
    mutationFn: () =>
      api.changeNames(org.id, m.id, {
        names: names.split(/[\s,]+/).filter(Boolean),
        csr,
        // Sent only when changed, so that the Managed Certificate otherwise keeps its own.
        ...(m.issuer.kind === "private_ca" && validityDays !== m.validityDays && { validityDays }),
      }),
    onSuccess: () => {
      setNames("");
      setCsr("");
      onChanged();
    },
  });

  // An Issuing CA issues only for its permitted names, which the new names must keep within.
  const issuingCaId = m.issuer.kind === "private_ca" ? m.issuer.issuingCa.id : null;
  const issuingCa = useQuery({
    queryKey: ["private-cas", org.id],
    queryFn: () => api.privateCas(org.id),
    enabled: issuingCaId !== null && mayChange && can(org, "privateCa", "read"),
    select: (cas) => {
      for (const ca of cas.items) {
        const issuing = ca.issuingCas.find((i) => i.id === issuingCaId);
        if (issuing) return { ...issuing, name: issuingCaTitle(ca.name, issuing.subject) };
      }
      return undefined;
    },
  }).data;

  const withdraw = useMutation({ mutationFn: () => api.withdrawNameChange(org.id, m.id), onSuccess: onChanged });

  if (!m.pendingNameChange && !mayChange) return null;
  return (
    <div className="flex flex-col gap-1">
      {m.pendingNameChange && (
        <span className="text-muted-foreground">
          Name change awaiting Approval, proposed by {m.pendingNameChange.proposedBy.email}: {m.pendingNameChange.names.join(", ")}
          {m.pendingNameChange.validityDays !== m.validityDays && `, valid for ${chosenValidityLabel(m.pendingNameChange.validityDays)}`}. Renewal continues with the names above.
        </span>
      )}
      {m.pendingNameChange?.proposedBy.id === userId && (
        <span>
          <Button variant="link" size="sm" className="h-auto p-0" disabled={withdraw.isPending} onClick={() => withdraw.mutate()}>
            Withdraw the name change
          </Button>
        </span>
      )}
      {mayChange && !m.pendingNameChange && (
        <details>
          <summary className="cursor-pointer underline">{direct ? "Change names" : "Propose a name change"}</summary>
          <form
            className="mt-1 flex flex-col gap-2"
            onSubmit={(e: FormEvent) => {
              e.preventDefault();
              change.mutate();
            }}
          >
            {!direct && <p className="text-muted-foreground">An Approver must approve it before the new names are issued.</p>}
            <Label className="font-normal" htmlFor={`new-names-${m.id}`}>
              All the names it is to have (one per line)
            </Label>
            <Textarea id={`new-names-${m.id}`} value={names} onChange={(e) => setNames(e.target.value)} required />
            {issuingCa && <p className="text-muted-foreground">{permitsOnlyLabel(issuingCa)}</p>}
            {m.issuer.kind === "private_ca" && (
              <>
                <Label className="font-normal" htmlFor={`name-change-validity-${m.id}`}>
                  Validity (days)
                </Label>
                <Input
                  id={`name-change-validity-${m.id}`}
                  type="number"
                  min={1}
                  max={issuingCa?.validity.maximumDays}
                  className="w-32"
                  value={validity}
                  placeholder={issuingCa ? String(issuingCa.validity.defaultDays) : undefined}
                  onChange={(e) => setValidity(e.target.value)}
                />
                <p className="text-muted-foreground">
                  {issuingCa
                    ? `Leave empty for ${issuingCa.name}'s default of ${daysLabel(issuingCa.validity.defaultDays)}; at most ${daysLabel(issuingCa.validity.maximumDays)}.`
                    : "Leave empty for the Issuing CA's default."}
                </p>
              </>
            )}
            <Label className="font-normal" htmlFor={`name-change-csr-${m.id}`}>
              CSR for the new names (same key algorithm)
            </Label>
            <Textarea id={`name-change-csr-${m.id}`} className="font-mono text-xs" rows={5} value={csr} onChange={(e) => setCsr(e.target.value)} required />
            <span>
              <Button type="submit" size="sm" variant="outline" disabled={change.isPending || (validityDays !== null && !isValidityDays(validity, issuingCa?.validity.maximumDays))}>
                {direct ? "Change names" : "Propose"}
              </Button>
            </span>
          </form>
        </details>
      )}
      {(change.error ?? withdraw.error) && <span className="text-destructive">{(change.error ?? withdraw.error)!.message}</span>}
    </div>
  );
}
