import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { createColumnHelper, rowPaginationFeature, tableFeatures, useTable, type PaginationState } from "@tanstack/react-table";
import { PlusIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { DataTable } from "@/components/data-table/data-table";
import { DataTablePagination } from "@/components/data-table/data-table-pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ActionLabel, PageHeader } from "@/components/page-header";
import { api, can, type ApiKey } from "@/lib/api";
import { useOrg } from "@/lib/use-org";
import { useAction } from "@/lib/use-action";

const ROUTE = "/app/organizations/$orgId/api-keys";
const TYPE_LABEL: Record<ApiKey["type"], string> = { user: "Yours", organization: "Organization's" };
const date = (iso: string) => <time dateTime={iso}>{new Date(iso).toLocaleDateString()}</time>;

// Paging is the server's (Page<ApiKey>); the table lays out the page it was given.
const features = tableFeatures({ rowPaginationFeature });
const columnHelper = createColumnHelper<typeof features, ApiKey>();
const columns = columnHelper.columns([
  columnHelper.accessor("name", { header: "Name", cell: ({ cell }) => <span className="font-medium">{cell.getValue()}</span> }),
  columnHelper.accessor("start", { header: "Key", cell: ({ cell }) => <span className="font-mono text-xs text-muted-foreground">{cell.getValue()}…</span> }),
  columnHelper.accessor("type", { header: "Whose", cell: ({ cell }) => <Badge variant={cell.getValue() === "organization" ? "default" : "secondary"}>{TYPE_LABEL[cell.getValue()]}</Badge> }),
  columnHelper.accessor((k) => k.createdBy?.email, { id: "createdBy", header: "Made by", cell: ({ cell }) => cell.getValue() ?? <span className="text-muted-foreground">You</span> }),
  columnHelper.accessor("createdAt", { header: "Made", cell: ({ cell }) => date(cell.getValue()) }),
  columnHelper.accessor("expiresAt", { header: "Expires", cell: ({ cell }) => (cell.getValue() ? date(cell.getValue()!) : <span className="text-muted-foreground">Never</span>) }),
  columnHelper.display({ id: "actions", header: () => <span className="sr-only">Actions</span>, cell: ({ row }) => <RevokeKey apiKey={row.original} /> }),
]);
const noRows: ApiKey[] = [];

/**
 * API keys for an Organization: your own, which act as you there, and, for an Organization Administrator, the
 * Organization's, which belong to it and outlive whoever made them. So far a key downloads Certificates.
 */
export function ApiKeysPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 25 });
  const keys = useQuery({
    queryKey: ["api-keys", orgId, pagination],
    queryFn: () => api.apiKeys(orgId, { page: pagination.pageIndex + 1, pageSize: pagination.pageSize }),
    placeholderData: keepPreviousData,
  });
  const table = useTable({
    features,
    columns,
    data: keys.data?.items ?? noRows,
    rowCount: keys.data?.total,
    manualPagination: true,
    state: { pagination },
    onPaginationChange: setPagination,
    getRowId: (k) => k.id,
  });

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="API keys"
        action={<MakeKeyDialog orgId={orgId} mayMakeOrganizationKeys={org ? can(org, "apiKey", "create") : false} />}
        description={
          <>
            A key is sent in the <code>x-api-key</code> header and, so far, downloads Certificates.
          </>
        }
        howItWorks={
          <p>
            Your own key acts as you in this Organization, for what you may see and do, and every use is recorded under your name. An Organization's key belongs to the
            Organization: it downloads every Managed Certificate in it, keeps working when whoever made it leaves, and each use is recorded with the key and who made it.
          </p>
        }
      />
      <div className="flex flex-col gap-4">
        <DataTable table={table} empty={keys.isPending ? "Loading…" : "You have no API keys here."} />
        <DataTablePagination
          pageIndex={pagination.pageIndex}
          pageSize={pagination.pageSize}
          rowCount={keys.data?.total ?? 0}
          onPageIndexChange={(pageIndex) => setPagination({ ...pagination, pageIndex })}
          onPageSizeChange={(pageSize) => setPagination({ pageIndex: 0, pageSize })}
        />
        {keys.error && <p className="text-sm text-destructive">{keys.error.message}</p>}
      </div>
    </div>
  );
}

function RevokeKey({ apiKey }: { apiKey: ApiKey }) {
  const { orgId } = useParams({ from: ROUTE });
  const [open, setOpen] = useState(false);
  const revoke = useAction(() => api.revokeApiKey(orgId, apiKey.id), ["api-keys"], () => setOpen(false));
  return (
    <div className="flex justify-end">
      <Button variant="outline" size="sm" aria-label={`Revoke ${apiKey.name}`} onClick={() => setOpen(true)}>
        Revoke
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) revoke.reset();
        }}
        title={`Revoke ${apiKey.name}?`}
        description="Whatever uses this key stops working at once. This cannot be undone: a new key has a new value."
        confirmLabel="Revoke"
        pending={revoke.isPending}
        error={revoke.error}
        onConfirm={() => revoke.mutate(undefined)}
      />
    </div>
  );
}

function MakeKeyDialog({ orgId, mayMakeOrganizationKeys }: { orgId: string; mayMakeOrganizationKeys: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          <ActionLabel>Make an API key</ActionLabel>
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Make an API key</DialogTitle>
          <DialogDescription>The key is shown once, when it is made, and never again.</DialogDescription>
        </DialogHeader>
        {/* Only mounted while open, so each opening starts from a clean form and a made key is gone when the dialog closes. */}
        {open && <MakeKeyForm orgId={orgId} mayMakeOrganizationKeys={mayMakeOrganizationKeys} />}
      </DialogContent>
    </Dialog>
  );
}

function MakeKeyForm({ orgId, mayMakeOrganizationKeys }: { orgId: string; mayMakeOrganizationKeys: boolean }) {
  const [type, setType] = useState<ApiKey["type"]>("user");
  const [name, setName] = useState("");
  const [days, setDays] = useState("");
  const [made, setMade] = useState<{ name: string; key: string } | null>(null);
  const create = useMutation({ mutationFn: () => api.createApiKey(orgId, { name, type: mayMakeOrganizationKeys ? type : "user", ...(days && { expiresInDays: Number(days) }) }) });
  const queryClient = useQueryClient();

  if (made) {
    return (
      <div className="flex flex-col gap-4">
        <div role="status" className="flex flex-col gap-1 rounded-md border p-3 text-sm">
          <span>
            Key <strong>{made.name}</strong> is made. Copy it now: it is not shown again.
          </span>
          <code className="break-all font-mono">{made.key}</code>
        </div>
        <DialogFooter>
          <DialogClose asChild>
            <Button type="button" variant="outline">
              Close
            </Button>
          </DialogClose>
        </DialogFooter>
      </div>
    );
  }
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        create.mutate(undefined, {
          onSuccess: (created) => {
            setMade({ name: created.name, key: created.key });
            void queryClient.invalidateQueries({ queryKey: ["api-keys"] });
          },
        });
      }}
    >
      {mayMakeOrganizationKeys && (
        <div className="flex flex-col gap-2">
          <Label htmlFor="key-type">Whose key</Label>
          <Select value={type} onValueChange={(value) => setType(value as ApiKey["type"])}>
            <SelectTrigger id="key-type">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="user">Mine: acts as me</SelectItem>
              <SelectItem value="organization">The Organization's: outlives me</SelectItem>
            </SelectContent>
          </Select>
        </div>
      )}
      <div className="flex flex-col gap-2">
        <Label htmlFor="key-name">Name (what the key is for)</Label>
        <Input id="key-name" value={name} maxLength={32} onChange={(e) => setName(e.target.value)} required />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="key-days">Expires after (days, optional)</Label>
        <Input id="key-days" type="number" min={1} max={365} value={days} onChange={(e) => setDays(e.target.value)} />
      </div>
      {create.error && <p className="text-sm text-destructive">{create.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={!name.trim() || create.isPending}>
          Make
        </Button>
      </DialogFooter>
    </form>
  );
}
