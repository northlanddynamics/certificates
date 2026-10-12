import { useMutation, useQuery } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { isOwner } from "@/lib/managed-certificate";
import { api, can, ownerFromKey, ownerKey, ownerLabel, type ManagedCertificate, type Me, type OwnerRef } from "@/lib/api";

/**
 * Who owns a Managed Certificate, each Team with its members, and, for those who may change that and while it is not archived,
 * the means to. Having no Owners is said outright.
 */
export function Owners({ org, m, userId, onChanged }: { org: Me["organizations"][number]; m: ManagedCertificate; userId?: string; onChanged: () => void }) {
  // The server decides; this only keeps the controls from those who surely may not (a Team's members may, too).
  const mayChange = !m.archivedAt && (can(org, "managedCertificate", "changeOwners") || isOwner(m, userId));
  const add = useMutation({ mutationFn: (owner: OwnerRef) => api.addOwner(org.id, m.id, owner), onSuccess: onChanged });
  const remove = useMutation({ mutationFn: (owner: OwnerRef) => api.removeOwner(org.id, m.id, owner), onSuccess: onChanged });
  const people = useQuery({ queryKey: ["members", org.id], queryFn: () => api.members(org.id), enabled: mayChange });
  const teams = useQuery({ queryKey: ["teams", org.id], queryFn: () => api.teams(org.id) });
  const taken = new Set(m.owners.map(ownerKey));
  const [choice, setChoice] = useState("");
  const error = add.error ?? remove.error;

  return (
    <div className="flex flex-col gap-3 text-sm">
      {m.owners.length === 0 ? (
        <p className="text-muted-foreground">No Owners</p>
      ) : (
        <ul className="flex flex-col gap-2">
          {m.owners.map((o) => {
            const members = o.type === "team" ? (teams.data?.items.find((t) => t.id === o.id)?.members ?? []) : [];
            return (
              <li key={ownerKey(o)} className="flex items-start justify-between gap-2">
                <div className="flex flex-col">
                  <span className="font-medium">{ownerLabel(o)}</span>
                  {o.type === "team" && <span className="text-muted-foreground">{members.length === 0 ? "No members" : members.map((member) => member.email).join(", ")}</span>}
                </div>
                {mayChange && (
                  <Button variant="ghost" size="sm" aria-label={`Remove ${ownerLabel(o)} as an Owner`} disabled={remove.isPending} onClick={() => remove.mutate(o)}>
                    Remove
                  </Button>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {mayChange && (
        <form
          className="flex items-center gap-2"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            if (choice) add.mutate(ownerFromKey(choice), { onSuccess: () => setChoice("") });
          }}
        >
          <Select value={choice} onValueChange={setChoice}>
            <SelectTrigger size="sm" aria-label={`Add an Owner of ${m.names.join(", ")}`}>
              <SelectValue placeholder="Add an Owner…" />
            </SelectTrigger>
            <SelectContent>
              {teams.data?.items.filter((t) => !taken.has(`team:${t.id}`)).map((t) => (
                <SelectItem key={t.id} value={`team:${t.id}`}>
                  {t.name} (Team)
                </SelectItem>
              ))}
              {people.data?.items.filter((p) => !taken.has(`user:${p.userId}`)).map((p) => (
                <SelectItem key={p.userId} value={`user:${p.userId}`}>
                  {p.email}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button type="submit" size="sm" variant="outline" disabled={!choice || add.isPending}>
            Add
          </Button>
        </form>
      )}
      {error && <p className="text-destructive">{error.message}</p>}
    </div>
  );
}
