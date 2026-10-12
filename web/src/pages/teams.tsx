import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { createColumnHelper, rowExpandingFeature, rowPaginationFeature, tableFeatures, useTable, type PaginationState } from "@tanstack/react-table";
import { MoreHorizontalIcon, PlusIcon, XIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { DataTable } from "@/components/data-table/data-table";
import { DataTableFacetedFilter } from "@/components/data-table/data-table-faceted-filter";
import { DataTablePagination } from "@/components/data-table/data-table-pagination";
import { ExpandButton } from "@/components/data-table/expand-button";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api, type Team } from "@/lib/api";
import { useAction } from "@/lib/use-action";

const ROUTE = "/app/organizations/$orgId/teams";

// Paging and narrowing are the server's (Page<Team>); the table lays out the page it was given, and a row opens to its members.
const features = tableFeatures({ rowPaginationFeature, rowExpandingFeature });
const columnHelper = createColumnHelper<typeof features, Team>();
const columns = columnHelper.columns([
  columnHelper.display({
    id: "expand",
    header: () => <span className="sr-only">Members</span>,
    cell: ({ row }) => <ExpandButton open={row.getIsExpanded()} what={`Team ${row.original.name}`} onToggle={() => row.toggleExpanded()} />,
  }),
  columnHelper.accessor("name", { header: "Name", cell: ({ cell }) => <span className="font-medium">{cell.getValue()}</span> }),
  columnHelper.accessor((t) => t.members.length, { id: "members", header: "Members", cell: ({ row }) => <MembersSummary team={row.original} /> }),
  columnHelper.display({ id: "actions", header: () => <span className="sr-only">Actions</span>, cell: ({ row }) => <TeamActions team={row.original} /> }),
]);
const noRows: Team[] = [];

const MEMBERSHIP_FACETS = [
  { value: "empty", label: "No members" },
  { value: "populated", label: "Has members" },
];

export function TeamsPage() {
  const { orgId } = useParams({ from: ROUTE });
  const [membership, setMembership] = useState<string[]>([]);
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 25 });
  // Both, like neither, leaves the Teams as they are.
  const narrowedTo = membership.length === 1 ? (membership[0] as "empty" | "populated") : undefined;
  const teams = useQuery({
    queryKey: ["teams", orgId, "page", narrowedTo, pagination],
    queryFn: () => api.teamsPage(orgId, narrowedTo, { page: pagination.pageIndex + 1, pageSize: pagination.pageSize }),
    placeholderData: keepPreviousData,
  });
  const people = useQuery({ queryKey: ["members", orgId], queryFn: () => api.members(orgId) });
  const table = useTable({
    features,
    columns,
    data: teams.data?.items ?? noRows,
    rowCount: teams.data?.total,
    manualPagination: true,
    state: { pagination },
    onPaginationChange: setPagination,
    getRowId: (t) => t.id,
    getRowCanExpand: () => true,
  });
  const narrow = (next: string[]) => {
    setMembership(next);
    setPagination({ ...pagination, pageIndex: 0 });
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">Teams</h1>
        <NewTeamDialog orgId={orgId} />
      </div>
      <div className="flex flex-col gap-4">
        <div className="flex flex-wrap items-center gap-2">
          <DataTableFacetedFilter title="Members" options={MEMBERSHIP_FACETS} value={membership} onChange={narrow} />
          {membership.length > 0 && (
            <Button variant="ghost" size="sm" onClick={() => narrow([])}>
              Reset
              <XIcon />
            </Button>
          )}
        </div>
        <DataTable
          table={table}
          empty={teams.isPending ? "Loading…" : membership.length > 0 ? "No Teams match." : "No Teams yet."}
          details={(team) => <TeamMembers orgId={orgId} team={team} candidates={people.data?.items ?? []} />}
        />
        <DataTablePagination
          pageIndex={pagination.pageIndex}
          pageSize={pagination.pageSize}
          rowCount={teams.data?.total ?? 0}
          onPageIndexChange={(pageIndex) => setPagination({ ...pagination, pageIndex })}
          onPageSizeChange={(pageSize) => setPagination({ pageIndex: 0, pageSize })}
        />
        {teams.error && <p className="text-sm text-destructive">{teams.error.message}</p>}
      </div>
    </div>
  );
}

function MembersSummary({ team }: { team: Team }) {
  if (team.members.length === 0) return <span className="text-muted-foreground">None</span>;
  return (
    <span className="block max-w-72 truncate text-muted-foreground" title={team.members.map((m) => m.email).join(", ")}>
      {team.members.length} · {team.members.map((m) => m.email).join(", ")}
    </span>
  );
}

/** A Team's name in a dialog, to make a Team or to rename one. */
function TeamNameDialog({
  title,
  description,
  submitLabel,
  initialName,
  open,
  onOpenChange,
  pending,
  error,
  onSubmit,
  trigger,
}: {
  title: string;
  description: string;
  submitLabel: string;
  initialName: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  pending: boolean;
  error: Error | null;
  onSubmit: (name: string) => void;
  trigger?: React.ReactNode;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {trigger && <DialogTrigger asChild>{trigger}</DialogTrigger>}
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        {/* Mounted only while open, so the name starts as it should each time. */}
        <TeamNameForm initialName={initialName} submitLabel={submitLabel} pending={pending} error={error} onSubmit={onSubmit} />
      </DialogContent>
    </Dialog>
  );
}

function TeamNameForm({ initialName, submitLabel, pending, error, onSubmit }: { initialName: string; submitLabel: string; pending: boolean; error: Error | null; onSubmit: (name: string) => void }) {
  const [name, setName] = useState(initialName);
  return (
    <form
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        onSubmit(name);
      }}
    >
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor="team-name">Name</FieldLabel>
          <Input id="team-name" value={name} onChange={(e) => setName(e.target.value)} required />
        </Field>
        {error && <FieldError>{error.message}</FieldError>}
      </FieldGroup>
      <DialogFooter className="mt-6">
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={pending || (initialName !== "" && name === initialName)}>
          {submitLabel}
        </Button>
      </DialogFooter>
    </form>
  );
}

function NewTeamDialog({ orgId }: { orgId: string }) {
  const [open, setOpen] = useState(false);
  const create = useAction((name: string) => api.createTeam(orgId, name), ["teams"], () => setOpen(false));
  return (
    <TeamNameDialog
      title="New Team"
      description="Teams can own Managed Certificates, so the people on one answer for them together."
      submitLabel="Create"
      initialName=""
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) create.reset();
      }}
      pending={create.isPending}
      error={create.error}
      onSubmit={(name) => create.mutate(name)}
      trigger={
        <Button>
          <PlusIcon />
          New Team
        </Button>
      }
    />
  );
}

function TeamActions({ team }: { team: Team }) {
  const { orgId } = useParams({ from: ROUTE });
  const [renaming, setRenaming] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const rename = useAction((name: string) => api.renameTeam(orgId, team.id, name), ["teams"], () => setRenaming(false));
  const del = useAction(() => api.deleteTeam(orgId, team.id), ["teams"], () => setDeleting(false));
  return (
    <div className="flex justify-end">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon-sm" aria-label={`Actions for Team ${team.name}`}>
            <MoreHorizontalIcon />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onSelect={() => setRenaming(true)}>Rename…</DropdownMenuItem>
          <DropdownMenuItem variant="destructive" onSelect={() => setDeleting(true)}>
            Delete…
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <TeamNameDialog
        title={`Rename ${team.name}`}
        description="Its members and what it owns stay as they are."
        submitLabel="Rename"
        initialName={team.name}
        open={renaming}
        onOpenChange={(next) => {
          setRenaming(next);
          if (!next) rename.reset();
        }}
        pending={rename.isPending}
        error={rename.error}
        onSubmit={(name) => rename.mutate(name)}
      />
      <ConfirmDialog
        open={deleting}
        onOpenChange={(next) => {
          setDeleting(next);
          if (!next) del.reset();
        }}
        title={`Delete ${team.name}?`}
        description="The Team is removed, and its members are no longer on it."
        confirmLabel="Delete"
        pending={del.isPending}
        error={del.error}
        onConfirm={() => del.mutate(undefined)}
      />
    </div>
  );
}

/** Who is on a Team, and the means to add and remove them. */
function TeamMembers({ orgId, team, candidates }: { orgId: string; team: Team; candidates: { userId: string; email: string }[] }) {
  const add = useAction((userId: string) => api.addTeamMember(orgId, team.id, userId), ["teams"]);
  const remove = useAction((userId: string) => api.removeTeamMember(orgId, team.id, userId), ["teams"]);
  const inTeam = new Set(team.members.map((m) => m.userId));
  const addable = candidates.filter((c) => !inTeam.has(c.userId));
  const error = add.error ?? remove.error;
  return (
    <div className="flex flex-col gap-2 text-sm">
      {team.members.length === 0 && <span className="text-muted-foreground">No one is on this Team yet.</span>}
      <ul className="flex flex-col gap-1">
        {team.members.map((m) => (
          <li key={m.userId} className="flex items-center justify-between gap-2">
            {m.email}
            <Button variant="ghost" size="sm" aria-label={`Remove ${m.email} from ${team.name}`} disabled={remove.isPending} onClick={() => remove.mutate(m.userId)}>
              Remove
            </Button>
          </li>
        ))}
      </ul>
      {addable.length > 0 && (
        <Select value="" onValueChange={(userId) => add.mutate(userId)}>
          <SelectTrigger size="sm" className="w-64" aria-label={`Add a user to ${team.name}`}>
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
      {error && <span className="text-destructive">{error.message}</span>}
    </div>
  );
}
