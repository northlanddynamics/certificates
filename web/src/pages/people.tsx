import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api, roleLabel, type Team } from "@/lib/api";

/** Mutation that refetches the given query keys on success and shows its error. */
function useAction<A>(fn: (arg: A) => Promise<unknown>, invalidate: string[], onDone?: () => void) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: async () => {
      onDone?.();
      await Promise.all(invalidate.map((k) => queryClient.invalidateQueries({ queryKey: [k] })));
    },
  });
}

function ErrorLine({ error }: { error: Error | null }) {
  return error ? <p className="text-sm text-destructive">{error.message}</p> : null;
}

export function PeoplePage() {
  const { orgId } = useParams({ from: "/organizations/$orgId/people" });
  return (
    <div className="flex flex-col gap-6">
      <Link to="/" className="text-sm underline">
        Back
      </Link>
      <MembersCard orgId={orgId} />
      <TeamsCard orgId={orgId} />
    </div>
  );
}

function MembersCard({ orgId }: { orgId: string }) {
  const members = useQuery({ queryKey: ["members", orgId], queryFn: () => api.members(orgId) });
  const invitations = useQuery({ queryKey: ["invitations", orgId], queryFn: () => api.invitations(orgId) });
  const roles = useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.roles }).data ?? [];
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("member");
  const invite = useAction(() => api.invite(orgId, email, role), ["invitations"], () => setEmail(""));
  const changeRole = useAction((a: { id: string; role: string }) => api.changeRole(orgId, a.id, a.role), ["members"]);
  const remove = useAction((id: string) => api.removeMember(orgId, id), ["members", "teams"]);
  const cancel = useAction((id: string) => api.cancelInvitation(orgId, id), ["invitations"]);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Members</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <ul className="flex flex-col gap-2 text-sm">
          {members.data?.items.map((m) => (
            <li key={m.id} className="flex items-center justify-between gap-2">
              <span>{m.email}</span>
              <span className="flex items-center gap-2">
                <Select value={m.role} onValueChange={(value) => changeRole.mutate({ id: m.id, role: value })}>
                  <SelectTrigger size="sm" aria-label={`Role of ${m.email}`}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {roles.map((r) => (
                      <SelectItem key={r} value={r}>
                        {roleLabel(r)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Button variant="outline" size="sm" onClick={() => remove.mutate(m.id)}>
                  Remove
                </Button>
              </span>
            </li>
          ))}
        </ul>
        <ErrorLine error={changeRole.error ?? remove.error} />

        {invitations.data && invitations.data.items.length > 0 && (
          <div className="flex flex-col gap-2">
            <h3 className="text-sm font-medium">Pending invitations</h3>
            <ul className="flex flex-col gap-2 text-sm">
              {invitations.data.items.map((i) => (
                <li key={i.id} className="flex items-center justify-between gap-2">
                  <span>
                    {i.email} <span className="text-muted-foreground">({roleLabel(i.role)})</span>
                  </span>
                  <Button variant="outline" size="sm" onClick={() => cancel.mutate(i.id)}>
                    Cancel
                  </Button>
                </li>
              ))}
            </ul>
          </div>
        )}

        <form
          className="flex flex-col gap-3"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            invite.mutate(undefined);
          }}
        >
          <div className="flex flex-col gap-2">
            <Label htmlFor="invite-email">Invite by email</Label>
            <Input id="invite-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="invite-role">Role</Label>
            <Select value={role} onValueChange={setRole}>
              <SelectTrigger id="invite-role">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {roles.map((r) => (
                  <SelectItem key={r} value={r}>
                    {roleLabel(r)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <ErrorLine error={invite.error} />
          <Button type="submit" disabled={invite.isPending}>
            Send invitation
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

function TeamsCard({ orgId }: { orgId: string }) {
  const teams = useQuery({ queryKey: ["teams", orgId], queryFn: () => api.teams(orgId) });
  const members = useQuery({ queryKey: ["members", orgId], queryFn: () => api.members(orgId) });
  const [name, setName] = useState("");
  const create = useAction(() => api.createTeam(orgId, name), ["teams"], () => setName(""));

  return (
    <Card>
      <CardHeader>
        <CardTitle>Teams</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {teams.data?.items.length === 0 && <p className="text-sm text-muted-foreground">No Teams yet.</p>}
        {teams.data?.items.map((t) => (
          <TeamRow key={t.id} orgId={orgId} team={t} candidates={members.data?.items ?? []} />
        ))}
        <form
          className="flex items-end gap-2"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            create.mutate(undefined);
          }}
        >
          <div className="flex flex-1 flex-col gap-2">
            <Label htmlFor="team-name">New Team</Label>
            <Input id="team-name" value={name} onChange={(e) => setName(e.target.value)} required />
          </div>
          <Button type="submit" disabled={create.isPending}>
            Create
          </Button>
        </form>
        <ErrorLine error={create.error} />
      </CardContent>
    </Card>
  );
}

function TeamRow({ orgId, team, candidates }: { orgId: string; team: Team; candidates: { userId: string; email: string }[] }) {
  const [name, setName] = useState(team.name);
  const rename = useAction(() => api.renameTeam(orgId, team.id, name), ["teams"]);
  const del = useAction(() => api.deleteTeam(orgId, team.id), ["teams"]);
  const add = useAction((userId: string) => api.addTeamMember(orgId, team.id, userId), ["teams"]);
  const removeMember = useAction((userId: string) => api.removeTeamMember(orgId, team.id, userId), ["teams"]);
  const inTeam = new Set(team.members.map((m) => m.userId));
  const addable = candidates.filter((c) => !inTeam.has(c.userId));

  return (
    <div className="flex flex-col gap-2 rounded-md border p-3">
      <form
        className="flex items-center gap-2"
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          rename.mutate(undefined);
        }}
      >
        <Input aria-label={`Name of Team ${team.name}`} value={name} onChange={(e) => setName(e.target.value)} required />
        <Button type="submit" variant="outline" size="sm" disabled={name === team.name}>
          Rename
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={() => del.mutate(undefined)}>
          Delete
        </Button>
      </form>
      <ul className="flex flex-col gap-1 text-sm">
        {team.members.map((m) => (
          <li key={m.userId} className="flex items-center justify-between">
            {m.email}
            <Button variant="ghost" size="sm" onClick={() => removeMember.mutate(m.userId)}>
              Remove
            </Button>
          </li>
        ))}
      </ul>
      {addable.length > 0 && (
        <Select value="" onValueChange={(userId) => add.mutate(userId)}>
          <SelectTrigger size="sm" aria-label={`Add a user to ${team.name}`}>
            <SelectValue placeholder="Add a user…" />
          </SelectTrigger>
          <SelectContent>
            {addable.map((c) => (
              <SelectItem key={c.userId} value={c.userId}>
                {c.email}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
      <ErrorLine error={rename.error ?? del.error ?? add.error ?? removeMember.error} />
    </div>
  );
}
