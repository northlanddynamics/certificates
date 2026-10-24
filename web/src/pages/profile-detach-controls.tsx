import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { api, can, type ManagedCertificate, type Me } from "@/lib/api";
import { useAction } from "@/lib/use-action";

/**
 * Whether the caller may detach a Managed Certificate from the Certificate Profile it was made from: Organization
 * Administrators may, of one that is not archived. A Proposal stays linked to its profile, so is offered no Detach.
 */
export const mayDetach = (org: Me["organizations"][number], m: ManagedCertificate) =>
  !!m.profile && can(org, "managedCertificate", "detachProfile") && !m.archivedAt && m.approval.status !== "pending" && m.approval.status !== "rejected";

/**
 * Detaching a Managed Certificate from its Certificate Profile: it becomes an ordinary Managed Certificate, keeping its
 * settings and Owners, and the profile's name rules and disabled state no longer apply to it.
 */
export function DetachDialog({ org, m, open, onOpenChange, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; open: boolean; onOpenChange: (open: boolean) => void; onChanged: () => void }) {
  const detach = useAction(() => api.detachProfile(org.id, m.id), ["certificate-profiles"], () => {
    onOpenChange(false);
    onChanged();
  });
  const profile = m.profile;
  if (!profile) return null;
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        onOpenChange(next);
        detach.reset();
      }}
    >
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Detach from {profile.name}</DialogTitle>
          <DialogDescription>
            It becomes an ordinary Managed Certificate. Its issuer, validity, key algorithm, Renewal Policy, names and Owners stay as they are, but its Name Changes are no longer checked
            against the profile's name rules{profile.enabled ? "" : ", and it renews again although the profile is disabled"}. It cannot be attached to the profile again.
          </DialogDescription>
        </DialogHeader>
        {detach.error && <p className="text-sm text-destructive">{detach.error.message}</p>}
        <DialogFooter>
          <DialogClose asChild>
            <Button type="button" variant="outline">
              Cancel
            </Button>
          </DialogClose>
          <Button type="button" variant="destructive" disabled={detach.isPending} onClick={() => detach.mutate(undefined)}>
            Detach
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
