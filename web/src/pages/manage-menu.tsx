import { ArchiveIcon, EllipsisIcon, KeyRoundIcon, LandmarkIcon, PencilIcon, RefreshCwIcon, UnlinkIcon } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import type { ManagedCertificate, Me } from "@/lib/api";
import { mayRepoint, RepointDialog } from "./issuer-controls";
import { KeyChangeSheet, keyChanges, type KeyChange } from "./key-change-sheet";
import { DetachDialog, mayDetach } from "./profile-detach-controls";
import { mayRenewNow, RenewEarlyDialog } from "./renewal-controls";
import { ArchiveDialog, mayArchive } from "./revocation-controls";

type Open = KeyChange | "renew" | "issuer" | "detach" | "archive";

/**
 * The "⋯" menu of a Managed Certificate's page: every change to it that is not Download, each for those who may, with
 * Archive last and apart; Renew now is here, asking first, while it is not the page's first action (`renewEarly`). The
 * menu is not shown to someone who may make none of them.
 */
export function ManageMenu({ org, m, userId, renewEarly, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; userId?: string; renewEarly: boolean; onChanged: () => void }) {
  const [open, setOpen] = useState<Open | null>(null);
  const renew = renewEarly && mayRenewNow(org, m, userId);
  const { mayReplace, mayChangeNames, direct } = keyChanges(org, m, userId);
  const repoint = mayRepoint(org, m);
  const detach = mayDetach(org, m);
  const archive = mayArchive(org, m);
  if (!renew && !mayReplace && !mayChangeNames && !repoint && !detach && !archive) return null;

  const dismiss = (next: boolean) => !next && setOpen(null);
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="icon" aria-label="More actions">
            <EllipsisIcon />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="min-w-52">
          {renew && (
            <>
              <DropdownMenuItem onSelect={() => setOpen("renew")} disabled={m.issuance?.status === "running"}>
                <RefreshCwIcon />
                Renew now…
              </DropdownMenuItem>
              {(mayChangeNames || mayReplace || repoint || detach) && <DropdownMenuSeparator />}
            </>
          )}
          {mayChangeNames && (
            <DropdownMenuItem onSelect={() => setOpen("names")}>
              <PencilIcon />
              {direct ? "Change names…" : "Propose a name change…"}
            </DropdownMenuItem>
          )}
          {mayReplace && (
            <DropdownMenuItem onSelect={() => setOpen("replace")}>
              <KeyRoundIcon />
              Replace key…
            </DropdownMenuItem>
          )}
          {repoint && (
            <DropdownMenuItem onSelect={() => setOpen("issuer")}>
              <LandmarkIcon />
              Change Issuing CA…
            </DropdownMenuItem>
          )}
          {detach && (
            <DropdownMenuItem onSelect={() => setOpen("detach")}>
              <UnlinkIcon />
              Detach from profile…
            </DropdownMenuItem>
          )}
          {archive && (
            <>
              {(renew || mayChangeNames || mayReplace || repoint || detach) && <DropdownMenuSeparator />}
              <DropdownMenuItem variant="destructive" onSelect={() => setOpen("archive")}>
                <ArchiveIcon />
                Archive…
              </DropdownMenuItem>
            </>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
      <KeyChangeSheet org={org} m={m} userId={userId} change={open === "names" || open === "replace" ? open : null} onClose={() => setOpen(null)} onChanged={onChanged} />
      {renew && <RenewEarlyDialog org={org} m={m} open={open === "renew"} onOpenChange={dismiss} onChanged={onChanged} />}
      {repoint && <RepointDialog org={org} m={m} open={open === "issuer"} onOpenChange={dismiss} onChanged={onChanged} />}
      {detach && <DetachDialog org={org} m={m} open={open === "detach"} onOpenChange={dismiss} onChanged={onChanged} />}
      {archive && <ArchiveDialog org={org} m={m} open={open === "archive"} onOpenChange={dismiss} onChanged={onChanged} />}
    </>
  );
}
