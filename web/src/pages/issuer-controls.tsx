import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Field, FieldContent, FieldDescription, FieldLabel, FieldTitle } from "@/components/ui/field";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { api, can, type ManagedCertificate, type Me } from "@/lib/api";
import { commonNameOf, findIssuingCa, permittedNamesLabel, validityLabel } from "@/lib/private-ca";
import { useAction } from "@/lib/use-action";

/**
 * Whether the caller may repoint a Managed Certificate issued from a Private CA to another Issuing CA, under the same root
 * or another: how an Issuing CA is rolled over. Only Organization Administrators may; it needs no Approval and issues
 * nothing, and its next Issuance, by Renewal or asked for, comes from the new one.
 */
export const mayRepoint = (org: Me["organizations"][number], m: ManagedCertificate) =>
  m.issuer.kind === "private_ca" && can(org, "managedCertificate", "changeIssuer") && !m.archivedAt && m.approval.status !== "rejected";

/** That a Managed Certificate's Issuing CA no longer issues, when it does not, and who can do something about it; nothing otherwise. */
export function IssuingCaStopped({ org, m }: { org: Me["organizations"][number]; m: ManagedCertificate }) {
  const privateCas = useQuery({ queryKey: ["private-cas", org.id], queryFn: () => api.privateCas(org.id), enabled: m.issuer.kind === "private_ca" && can(org, "privateCa", "read") });
  if (m.issuer.kind !== "private_ca") return null;
  const current = findIssuingCa(privateCas.data?.items ?? [], m.issuer.issuingCa.id);
  const stopped = current && current.status !== "active" ? current.status : undefined;
  if (!stopped) return null;
  return (
    <p className="text-sm text-destructive">
      Its Issuing CA is {stopped}, so it can no longer be issued or renewed{mayRepoint(org, m) ? "; change its Issuing CA" : " until an Organization Administrator repoints it"}.
    </p>
  );
}

/** Repointing a Managed Certificate issued from a Private CA to another Issuing CA, for those `mayRepoint` lets. */
export function RepointDialog({ org, m, open, onOpenChange, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; open: boolean; onOpenChange: (open: boolean) => void; onChanged: () => void }) {
  if (m.issuer.kind !== "private_ca") return null;
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Change Issuing CA</DialogTitle>
          <DialogDescription>
            Its next Certificate, by Renewal or when you renew it now, comes from the Issuing CA you choose, which must permit its names. No Approval is needed, and its current
            Certificate is unchanged. Under the same root, nothing that trusts the root needs anything new.
          </DialogDescription>
        </DialogHeader>
        {/* Only mounted while open, so each opening starts from a clean choice. */}
        {open && (
          <RepointForm
            org={org}
            m={m}
            currentId={m.issuer.issuingCa.id}
            onDone={() => {
              onOpenChange(false);
              onChanged();
            }}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

function RepointForm({ org, m, currentId, onDone }: { org: Me["organizations"][number]; m: ManagedCertificate; currentId: string; onDone: () => void }) {
  const [chosen, setChosen] = useState("");
  const privateCas = useQuery({ queryKey: ["private-cas", org.id], queryFn: () => api.privateCas(org.id) });
  const repoint = useAction(() => api.changeIssuer(org.id, m.id, chosen), ["private-cas"], onDone);
  // The Issuing CAs that issue, other than its own, grouped by their Private CA: active, under an active root, not ended, and taking its key algorithm.
  const now = Date.now();
  const offered = (privateCas.data?.items ?? [])
    .filter((ca) => ca.status === "active" && (ca.certificateKeyAlgorithms as string[]).includes(m.keyAlgorithm))
    .map((ca) => ({ ...ca, issuingCas: ca.issuingCas.filter((i) => i.status === "active" && i.id !== currentId && i.notAfter !== null && Date.parse(i.notAfter) > now) }))
    .filter((ca) => ca.issuingCas.length > 0);
  const chosenCa = chosen ? findIssuingCa(offered, chosen) : undefined;
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        repoint.mutate(undefined);
      }}
    >
      {privateCas.isPending ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : offered.length === 0 ? (
        <p className="text-sm text-muted-foreground">There is no other active Issuing CA. Add one under a Private CA's root first.</p>
      ) : (
        <RadioGroup value={chosen} onValueChange={setChosen}>
          {offered.map((ca) => (
            <div key={ca.id} role="group" aria-labelledby={`repoint-ca-${ca.id}`} className="flex flex-col gap-3">
              <p id={`repoint-ca-${ca.id}`} className="pt-2 text-sm font-medium">
                Private CA {ca.name}
              </p>
              {ca.issuingCas.map((issuing) => (
                <FieldLabel key={issuing.id} htmlFor={`repoint-issuing-${issuing.id}`}>
                  <Field orientation="horizontal">
                    <FieldContent>
                      <FieldTitle>{commonNameOf(issuing.subject)}</FieldTitle>
                      <FieldDescription>Permitted names: {permittedNamesLabel(issuing.permittedNames)}.</FieldDescription>
                      <FieldDescription>Validity: {validityLabel(issuing.validity)}.</FieldDescription>
                      {issuing.notAfter && <FieldDescription>Expires {new Date(issuing.notAfter).toLocaleDateString()}.</FieldDescription>}
                    </FieldContent>
                    <RadioGroupItem value={issuing.id} id={`repoint-issuing-${issuing.id}`} />
                  </Field>
                </FieldLabel>
              ))}
            </div>
          ))}
        </RadioGroup>
      )}
      {repoint.error && <p className="text-sm text-destructive">{repoint.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={!chosenCa || repoint.isPending}>
          Change
        </Button>
      </DialogFooter>
    </form>
  );
}
