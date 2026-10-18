import { useMutation } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { api, type ManagedCertificate, type Me } from "@/lib/api";
import { chosenValidityLabel } from "@/lib/private-ca";

/**
 * A Managed Certificate's name change waiting for Approval, and for whoever proposed it, the means to withdraw it.
 * Making one is the Key and CSR card's (`key-and-csr-card.tsx`), since it needs a CSR for the new names.
 */
export function NameChange({ org, m, userId, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; userId?: string; onChanged: () => void }) {
  const withdraw = useMutation({ mutationFn: () => api.withdrawNameChange(org.id, m.id), onSuccess: onChanged });

  if (!m.pendingNameChange) return null;
  return (
    <div className="flex flex-col gap-1">
      <span className="text-muted-foreground">
        Name change awaiting Approval, proposed by {m.pendingNameChange.proposedBy.email}: {m.pendingNameChange.names.join(", ")}
        {m.pendingNameChange.validityDays !== m.validityDays && `, valid for ${chosenValidityLabel(m.pendingNameChange.validityDays)}`}. Renewal continues with the names above.
      </span>
      {m.pendingNameChange.proposedBy.id === userId && (
        <span>
          <Button variant="link" size="sm" className="h-auto p-0" disabled={withdraw.isPending} onClick={() => withdraw.mutate()}>
            Withdraw the name change
          </Button>
        </span>
      )}
      {withdraw.error && <span className="text-destructive">{withdraw.error.message}</span>}
    </div>
  );
}
