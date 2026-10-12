import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { createColumnHelper, rowPaginationFeature, tableFeatures, useTable, type PaginationState } from "@tanstack/react-table";
import { PlusIcon, XIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useParams } from "@tanstack/react-router";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { DataTable } from "@/components/data-table/data-table";
import { DataTableFacetedFilter } from "@/components/data-table/data-table-faceted-filter";
import { DataTablePagination } from "@/components/data-table/data-table-pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, roleLabel, type OrgMember, type PendingInvitation } from "@/lib/api";
import { useAction } from "@/lib/use-action";

const ROUTE = "/app/organizations/$orgId/members";

// Paging and narrowing are Better Auth's (list-members); the table lays out the page it was given.
const features = tableFeatures({ rowPaginationFeature });
const columnHelper = createColumnHelper<typeof features, OrgMember>();
const columns = columnHelper.columns([
  columnHelper.accessor("email", { header: "Email", cell: ({ cell }) => <span className="font-medium">{cell.getValue()}</span> }),
  columnHelper.accessor("name", { header: "Name" }),
  columnHelper.accessor("role", { header: "Role", cell: ({ row }) => <RoleSelect member={row.original} /> }),
  columnHelper.display({ id: "actions", header: () => <span className="sr-only">Actions</span>, cell: ({ row }) => <RemoveMember member={row.original} /> }),
]);
const noRows: OrgMember[] = [];

/** The roles the server accepts, as a list to choose from. */
function useRoles() {
  return useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.roles }).data ?? [];
}

export function MembersPage() {
  const { orgId } = useParams({ from: ROUTE });
  const roles = useRoles();
  const [roleFacet, setRoleFacet] = useState<string[]>([]);
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 25 });
  const members = useQuery({
    queryKey: ["members", orgId, "page", roleFacet, pagination],
    queryFn: () => api.membersPage(orgId, roleFacet, { page: pagination.pageIndex + 1, pageSize: pagination.pageSize }),
    placeholderData: keepPreviousData,
  });
  // The same query the Pending tab reads, for how many are waiting.
  const pending = useQuery({ queryKey: ["invitations", orgId], queryFn: () => api.invitations(orgId) }).data?.items.length ?? 0;
  const table = useTable({
    features,
    columns,
    data: members.data?.items ?? noRows,
    rowCount: members.data?.total,
    manualPagination: true,
    state: { pagination },
    onPaginationChange: setPagination,
    getRowId: (m) => m.id,
  });

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">Members</h1>
        <InviteDialog orgId={orgId} roles={roles} />
      </div>
      <Tabs defaultValue="members" className="gap-4">
        <TabsList>
          <TabsTrigger value="members">Members</TabsTrigger>
          <TabsTrigger value="pending">
            Pending
            {pending > 0 && <Badge variant="secondary">{pending}</Badge>}
          </TabsTrigger>
        </TabsList>
        <TabsContent value="members" className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center gap-2">
            <DataTableFacetedFilter
              title="Role"
              options={roles.map((value) => ({ value, label: roleLabel(value) }))}
              value={roleFacet}
              onChange={(next) => {
                setRoleFacet(next);
                setPagination({ ...pagination, pageIndex: 0 });
              }}
            />
            {roleFacet.length > 0 && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setRoleFacet([]);
                  setPagination({ ...pagination, pageIndex: 0 });
                }}
              >
                Reset
                <XIcon />
              </Button>
            )}
          </div>
          <DataTable table={table} empty={members.isPending ? "Loading…" : roleFacet.length > 0 ? "No members match." : "No members."} />
          <DataTablePagination
            pageIndex={pagination.pageIndex}
            pageSize={pagination.pageSize}
            rowCount={members.data?.total ?? 0}
            onPageIndexChange={(pageIndex) => setPagination({ ...pagination, pageIndex })}
            onPageSizeChange={(pageSize) => setPagination({ pageIndex: 0, pageSize })}
          />
          {members.error && <p className="text-sm text-destructive">{members.error.message}</p>}
        </TabsContent>
        <TabsContent value="pending">
          <PendingInvitations orgId={orgId} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function RoleSelect({ member }: { member: OrgMember }) {
  const { orgId } = useParams({ from: ROUTE });
  const roles = useRoles();
  const changeRole = useAction((role: string) => api.changeRole(orgId, member.id, role), ["members"]);
  return (
    <div className="flex flex-col gap-1">
      <Select value={member.role} onValueChange={(role) => changeRole.mutate(role)}>
        <SelectTrigger size="sm" aria-label={`Role of ${member.email}`}>
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
      {changeRole.error && <span className="text-xs text-destructive">{changeRole.error.message}</span>}
    </div>
  );
}

function RemoveMember({ member }: { member: OrgMember }) {
  const { orgId } = useParams({ from: ROUTE });
  const [open, setOpen] = useState(false);
  const remove = useAction(() => api.removeMember(orgId, member.id), ["members", "teams"], () => setOpen(false));
  return (
    <div className="flex justify-end">
      <Button variant="outline" size="sm" aria-label={`Remove ${member.email}`} onClick={() => setOpen(true)}>
        Remove
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) remove.reset();
        }}
        title={`Remove ${member.email}?`}
        description="They lose access to this Organization and are removed from its Teams."
        confirmLabel="Remove"
        pending={remove.isPending}
        error={remove.error}
        onConfirm={() => remove.mutate(undefined)}
      />
    </div>
  );
}

function InviteDialog({ orgId, roles }: { orgId: string; roles: string[] }) {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("member");
  const invite = useAction(() => api.invite(orgId, email, role), ["invitations"], () => {
    setOpen(false);
    setEmail("");
  });
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) invite.reset();
      }}
    >
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          Invite member
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Invite a member</DialogTitle>
          <DialogDescription>They are emailed a link to join this Organization with the role you choose.</DialogDescription>
        </DialogHeader>
        <form
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            invite.mutate(undefined);
          }}
        >
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="invite-email">Email</FieldLabel>
              <Input id="invite-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </Field>
            <Field>
              <FieldLabel htmlFor="invite-role">Role</FieldLabel>
              <Select value={role} onValueChange={setRole}>
                <SelectTrigger id="invite-role" className="w-full">
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
            </Field>
            {invite.error && <FieldError>{invite.error.message}</FieldError>}
          </FieldGroup>
          <DialogFooter className="mt-6">
            <DialogClose asChild>
              <Button type="button" variant="outline">
                Cancel
              </Button>
            </DialogClose>
            <Button type="submit" disabled={invite.isPending}>
              Send invitation
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** The invitations not yet accepted. There are few of them at a time, so they are not paged. */
function PendingInvitations({ orgId }: { orgId: string }) {
  const invitations = useQuery({ queryKey: ["invitations", orgId], queryFn: () => api.invitations(orgId) });
  const roles = useRoles();
  const [roleFacet, setRoleFacet] = useState<string[]>([]);
  const [search, setSearch] = useState("");
  const all = invitations.data?.items ?? [];
  // The server gives every pending invitation at once, so they are searched and narrowed here.
  const needle = search.trim().toLowerCase();
  const items = all.filter((i) => (roleFacet.length === 0 || roleFacet.includes(i.role)) && (!needle || i.email.toLowerCase().includes(needle)));
  const narrowed = roleFacet.length > 0 || needle !== "";
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Input type="search" aria-label="Search invitations by email" placeholder="Search by email…" className="h-8 w-56" value={search} onChange={(e) => setSearch(e.target.value)} />
        <DataTableFacetedFilter title="Role" options={roles.map((value) => ({ value, label: roleLabel(value) }))} value={roleFacet} onChange={setRoleFacet} />
        {narrowed && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setRoleFacet([]);
              setSearch("");
            }}
          >
            Reset
            <XIcon />
          </Button>
        )}
      </div>
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Email</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Expires</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.length === 0 && (
              <TableRow>
                <TableCell colSpan={4} className="h-24 text-center text-muted-foreground">
                  {invitations.isPending ? "Loading…" : narrowed ? "No pending invitations match." : "No pending invitations."}
                </TableCell>
              </TableRow>
            )}
            {items.map((i) => (
              <TableRow key={i.id}>
                <TableCell className="font-medium">{i.email}</TableCell>
                <TableCell>{roleLabel(i.role)}</TableCell>
                <TableCell>{new Date(i.expiresAt).toLocaleDateString()}</TableCell>
                <TableCell className="text-right">
                  <CancelInvitation orgId={orgId} invitation={i} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

function CancelInvitation({ orgId, invitation }: { orgId: string; invitation: PendingInvitation }) {
  const [open, setOpen] = useState(false);
  const cancel = useAction(() => api.cancelInvitation(orgId, invitation.id), ["invitations"], () => {
    setOpen(false);
    toast.success(`Invitation to ${invitation.email} cancelled`);
  });
  return (
    <>
      <Button variant="outline" size="sm" aria-label={`Cancel the invitation of ${invitation.email}`} onClick={() => setOpen(true)}>
        Cancel
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) cancel.reset();
        }}
        title={`Cancel the invitation to ${invitation.email}?`}
        description="The link in their email stops working. You can invite them again."
        confirmLabel="Cancel invitation"
        dismissLabel="Keep invitation"
        pending={cancel.isPending}
        error={cancel.error}
        onConfirm={() => cancel.mutate(undefined)}
      />
    </>
  );
}
