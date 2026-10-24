import { keepPreviousData, useMutation, useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { createColumnHelper, rowPaginationFeature, tableFeatures, useTable, type PaginationState } from "@tanstack/react-table";
import { PlusIcon, XIcon } from "lucide-react";
import { useState } from "react";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { DataTable } from "@/components/data-table/data-table";
import { DataTableFacetedFilter } from "@/components/data-table/data-table-faceted-filter";
import { DataTablePagination } from "@/components/data-table/data-table-pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { api, can, type Agent } from "@/lib/api";
import { useOrg } from "@/lib/use-org";
import { useAction } from "@/lib/use-action";

const ROUTE = "/app/organizations/$orgId/agents";
const STATUS_LABEL: Record<Agent["status"], string> = { online: "Online", offline: "Offline", revoked: "Revoked" };
const STATUS_VARIANT: Record<Agent["status"], "default" | "secondary" | "destructive"> = { online: "default", offline: "secondary", revoked: "destructive" };
const OS_LABEL: Record<Agent["os"], string> = { linux: "Linux", windows: "Windows", macos: "macOS" };

// Paging and narrowing are the server's (Page<Agent>); the table lays out the page it was given.
const features = tableFeatures({ rowPaginationFeature });
const columnHelper = createColumnHelper<typeof features, Agent>();
const columns = columnHelper.columns([
  columnHelper.accessor("hostName", { header: "Host", cell: ({ cell }) => <span className="font-medium">{cell.getValue()}</span> }),
  columnHelper.accessor((a) => `${OS_LABEL[a.os]} ${a.arch}`, { id: "os", header: "OS" }),
  columnHelper.accessor("version", {
    header: "Version",
    cell: ({ row }) => (
      <span className="flex items-center gap-2">
        {row.original.version}
        {row.original.outdated && <Badge variant="outline" className="border-amber-500">Outdated</Badge>}
      </span>
    ),
  }),
  columnHelper.accessor("lastContactAt", {
    header: "Last contact",
    cell: ({ cell }) => <time dateTime={cell.getValue()}>{new Date(cell.getValue()).toLocaleString()}</time>,
  }),
  columnHelper.accessor("status", { header: "Status", cell: ({ cell }) => <Badge variant={STATUS_VARIANT[cell.getValue()]}>{STATUS_LABEL[cell.getValue()]}</Badge> }),
  columnHelper.display({ id: "actions", header: () => <span className="sr-only">Actions</span>, cell: ({ row }) => <RevokeAgent agent={row.original} /> }),
]);
const noRows: Agent[] = [];

const STATUS_FACETS = (Object.keys(STATUS_LABEL) as Agent["status"][]).map((value) => ({ value, label: STATUS_LABEL[value] }));
const OS_FACETS = (Object.keys(OS_LABEL) as Agent["os"][]).map((value) => ({ value, label: OS_LABEL[value] }));
const VERSION_FACETS = [{ value: "outdated", label: "Outdated" }];

/**
 * The Organization's Agents: each with its host, operating system, version, last contact and whether it is online, those
 * running an old version flagged. An Organization Administrator makes the single-use token an Agent registers with, and
 * revokes an Agent whose host is decommissioned or compromised.
 */
export function AgentsPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const [status, setStatus] = useState<string[]>([]);
  const [os, setOs] = useState<string[]>([]);
  const [version, setVersion] = useState<string[]>([]);
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 25 });
  const filters = { status, os, outdated: version.includes("outdated") };
  const agents = useQuery({
    queryKey: ["agents", orgId, filters, pagination],
    queryFn: () => api.agents(orgId, filters, { page: pagination.pageIndex + 1, pageSize: pagination.pageSize }),
    enabled: org ? can(org, "agent", "read") : false,
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  });
  const table = useTable({
    features,
    columns,
    data: agents.data?.items ?? noRows,
    rowCount: agents.data?.total,
    manualPagination: true,
    state: { pagination },
    onPaginationChange: setPagination,
    getRowId: (a) => a.id,
  });
  const narrowed = status.length > 0 || os.length > 0 || version.length > 0;
  // A new narrowing starts again from the first page.
  const narrow = (set: (values: string[]) => void) => (values: string[]) => {
    set(values);
    setPagination({ ...pagination, pageIndex: 0 });
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">Agents</h1>
        {org && can(org, "agent", "register") && <RegisterAgentDialog orgId={orgId} />}
      </div>
      <p className="text-sm text-muted-foreground">
        An Agent runs on a host inside your network and only ever connects out to the platform. It registers once with a single-use token, and then authenticates with a
        credential that it replaces by itself. An Agent that has not been in touch for two minutes is shown as offline.
        {agents.data && <> The latest version is {agents.data.latestVersion}.</>}
      </p>
      {org && !can(org, "agent", "read") ? (
        <p className="text-sm text-muted-foreground">Only Organization Administrators see the Agents.</p>
      ) : (
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center gap-2">
            <DataTableFacetedFilter title="Status" options={STATUS_FACETS} value={status} onChange={narrow(setStatus)} />
            <DataTableFacetedFilter title="OS" options={OS_FACETS} value={os} onChange={narrow(setOs)} />
            <DataTableFacetedFilter title="Version" options={VERSION_FACETS} value={version} onChange={narrow(setVersion)} />
            {narrowed && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setStatus([]);
                  setOs([]);
                  setVersion([]);
                  setPagination({ ...pagination, pageIndex: 0 });
                }}
              >
                Reset
                <XIcon />
              </Button>
            )}
          </div>
          <DataTable table={table} empty={agents.isPending ? "Loading…" : narrowed ? "No Agents match." : "No Agent has registered yet."} />
          <DataTablePagination
            pageIndex={pagination.pageIndex}
            pageSize={pagination.pageSize}
            rowCount={agents.data?.total ?? 0}
            onPageIndexChange={(pageIndex) => setPagination({ ...pagination, pageIndex })}
            onPageSizeChange={(pageSize) => setPagination({ pageIndex: 0, pageSize })}
          />
          {agents.error && <p className="text-sm text-destructive">{agents.error.message}</p>}
        </div>
      )}
    </div>
  );
}

function RevokeAgent({ agent }: { agent: Agent }) {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const [open, setOpen] = useState(false);
  const revoke = useAction(() => api.revokeAgent(orgId, agent.id), ["agents"], () => setOpen(false));
  if (!org || !can(org, "agent", "revoke") || agent.status === "revoked") return null;
  return (
    <div className="flex justify-end">
      <Button variant="outline" size="sm" aria-label={`Revoke ${agent.hostName}`} onClick={() => setOpen(true)}>
        Revoke
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) revoke.reset();
        }}
        title={`Revoke ${agent.hostName}?`}
        description="Its credential is accepted no more. This cannot be undone: a new Agent registers with a new token."
        confirmLabel="Revoke"
        pending={revoke.isPending}
        error={revoke.error}
        onConfirm={() => revoke.mutate(undefined)}
      />
    </div>
  );
}

function RegisterAgentDialog({ orgId }: { orgId: string }) {
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          Register an Agent
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Register an Agent</DialogTitle>
          <DialogDescription>
            A token registers one Agent, once, into this Organization, and expires after seven days. Pass it to the Agent as <code>AGENT_REGISTRATION_TOKEN</code>.
          </DialogDescription>
        </DialogHeader>
        <RegistrationToken orgId={orgId} />
        <DialogFooter>
          <DialogClose asChild>
            <Button type="button" variant="outline">
              Close
            </Button>
          </DialogClose>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// Only mounted while the dialog is open, so a token is gone from the page as soon as it is closed: it is shown once, when it is made.
function RegistrationToken({ orgId }: { orgId: string }) {
  const [made, setMade] = useState<{ token: string; expiresAt: string } | null>(null);
  const makeToken = useMutation({ mutationFn: () => api.createAgentRegistrationToken(orgId), onSuccess: setMade });
  return (
    <div className="flex flex-col gap-3 text-sm">
      {made && (
        <div role="status" className="flex flex-col gap-1 rounded-md border p-3">
          <span>Copy the token now: it is not shown again. It expires {new Date(made.expiresAt).toLocaleDateString()}.</span>
          <code className="break-all font-mono">{made.token}</code>
        </div>
      )}
      {makeToken.error && <p className="text-destructive">{makeToken.error.message}</p>}
      {!made && (
        <div>
          <Button disabled={makeToken.isPending} onClick={() => makeToken.mutate()}>
            Make a registration token
          </Button>
        </div>
      )}
    </div>
  );
}
