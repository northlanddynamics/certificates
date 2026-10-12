import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { createColumnHelper, rowPaginationFeature, tableFeatures, useTable, type PaginationState } from "@tanstack/react-table";
import { XIcon } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { DataTable } from "@/components/data-table/data-table";
import { DataTableFacetedFilter } from "@/components/data-table/data-table-faceted-filter";
import { DataTablePagination } from "@/components/data-table/data-table-pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, can, ownerLabel, type InventoryFilters, type ManagedCertificate, type Me } from "@/lib/api";
import { KEY_ALGORITHMS, KEY_ALGORITHM_LABELS } from "@/lib/csr-generator";
import { keyAlgorithmLabel, status } from "@/lib/managed-certificate";

type Org = Me["organizations"][number];

// Paging, narrowing and ordering are the server's (Page<T>); the table lays out the page it was given, and a row opens to its details.
const features = tableFeatures({ rowPaginationFeature });
const columnHelper = createColumnHelper<typeof features, ManagedCertificate>();
const makeColumns = (orgId: string) => columnHelper.columns([
  columnHelper.accessor((m) => m.names.join(", "), {
    id: "names",
    header: "Names",
    cell: ({ cell, row }) => <ManagedCertificateLink orgId={orgId} id={row.original.id}>{cell.getValue()}</ManagedCertificateLink>,
  }),
  columnHelper.accessor("environment", { header: "Environment", cell: ({ cell }) => <Badge variant="outline" className="capitalize">{cell.getValue()}</Badge> }),
  columnHelper.accessor((m) => keyAlgorithmLabel(m.keyAlgorithm), { id: "keyAlgorithm", header: "Key algorithm" }),
  columnHelper.accessor((m) => status(m).label, {
    id: "status",
    header: "Status",
    cell: ({ row }) => <Badge variant={status(row.original).variant}>{status(row.original).label}</Badge>,
  }),
  columnHelper.accessor((m) => (m.currentCertificate ? new Date(m.currentCertificate.notAfter).toLocaleDateString() : "—"), { id: "validUntil", header: "Valid until" }),
  columnHelper.accessor((m) => (m.owners.length === 0 ? "None" : m.owners.map(ownerLabel).join(", ")), {
    id: "owners",
    header: "Owners",
    cell: ({ cell }) => <span className="block max-w-56 truncate text-muted-foreground">{cell.getValue()}</span>,
  }),
]);
const noRows: ManagedCertificate[] = [];

/** A Managed Certificate's names, as the way to its page. */
function ManagedCertificateLink({ orgId, id, children }: { orgId: string; id: string; children: ReactNode }) {
  return (
    <Link to="/organizations/$orgId/certificates/$id" params={{ orgId, id }} className="font-medium underline-offset-4 hover:underline">
      {children}
    </Link>
  );
}

/** The inventory's facets: each is a list of values, and the filter the server takes for them. */
const STATUS_FACETS: [keyof Omit<InventoryFilters, "keyCustody" | "environment" | "keyAlgorithm">, string][] = [
  ["expiringSoon", "Expiring soon"],
  ["renewalFailing", "Renewal failing"],
  ["pendingApproval", "Awaiting Approval"],
  ["noOwners", "No Owners"],
  ["archived", "Archived"],
];
interface Facets {
  status: string[];
  environment: string[];
  keyAlgorithm: string[];
  keyCustody: string[];
}
const NO_FACETS: Facets = { status: [], environment: [], keyAlgorithm: [], keyCustody: [] };
const toFilters = (facets: Facets): InventoryFilters => ({
  ...Object.fromEntries(facets.status.map((name) => [name, true])),
  environment: facets.environment as InventoryFilters["environment"],
  keyAlgorithm: facets.keyAlgorithm,
  keyCustody: facets.keyCustody[0] as InventoryFilters["keyCustody"],
});

export function ManagedCertificates({ org }: { org: Org }) {
  const queryClient = useQueryClient();
  const [facets, setFacets] = useState<Facets>(NO_FACETS);
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 25 });
  const filters = toFilters(facets);
  const inventory = useQuery({
    queryKey: ["inventory", org.id, filters, pagination],
    queryFn: () => api.managedCertificates(org.id, filters, { page: pagination.pageIndex + 1, pageSize: pagination.pageSize }),
    placeholderData: keepPreviousData,
    // Issuance runs in the background: look again until none is running.
    refetchInterval: (query) => (query.state.data?.items.some((m) => m.issuance?.status === "running") ? 2000 : false),
  });
  // A change to one may change the other: a proposal joins the queue, a decision leaves it.
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["approvals", org.id] });
    return queryClient.invalidateQueries({ queryKey: ["inventory", org.id] });
  };
  const columns = useMemo(() => makeColumns(org.id), [org.id]);
  const table = useTable({
    features,
    columns,
    data: inventory.data?.items ?? noRows,
    rowCount: inventory.data?.total,
    manualPagination: true,
    state: { pagination },
    onPaginationChange: setPagination,
    getRowId: (m) => m.id,
  });
  const narrowed = Object.values(facets).some((values) => values.length > 0);
  // A new narrowing starts again from the first page.
  const narrow = (next: Partial<Facets>) => {
    setFacets({ ...facets, ...next });
    setPagination({ ...pagination, pageIndex: 0 });
  };

  const mayApprove = can(org, "approval", "read");
  // The same query the queue reads, for how many are waiting.
  const queue = useQuery({ queryKey: ["approvals", org.id], queryFn: () => api.approvalQueue(org.id), enabled: mayApprove });
  const waiting = (queue.data?.items.length ?? 0) + (queue.data?.nameChanges.length ?? 0);

  const certificates = (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <DataTableFacetedFilter
          title="Status"
          options={STATUS_FACETS.map(([value, label]) => ({ value, label }))}
          value={facets.status}
          onChange={(status) => narrow({ status })}
          hint="Shows those that match all you choose."
        />
        <DataTableFacetedFilter
          title="Environment"
          options={[
            { value: "staging", label: "Staging" },
            { value: "production", label: "Production" },
          ]}
          value={facets.environment}
          onChange={(environment) => narrow({ environment })}
        />
        <DataTableFacetedFilter
          title="Key algorithm"
          options={KEY_ALGORITHMS.map((value) => ({ value, label: KEY_ALGORITHM_LABELS[value] }))}
          value={facets.keyAlgorithm}
          onChange={(keyAlgorithm) => narrow({ keyAlgorithm })}
        />
        <DataTableFacetedFilter title="Key Custody" options={[{ value: "owner", label: "Owner" }]} value={facets.keyCustody} onChange={(keyCustody) => narrow({ keyCustody })} />
        {narrowed && (
          <Button variant="ghost" size="sm" onClick={() => narrow(NO_FACETS)}>
            Reset
            <XIcon />
          </Button>
        )}
      </div>
      <DataTable
        table={table}
        empty={
          inventory.isPending
            ? "Loading…"
            : narrowed
              ? "No Managed Certificates match."
              : can(org, "managedCertificate", "read")
                ? "No Managed Certificates yet."
                : "You do not own any Managed Certificates yet."
        }
      />
      <DataTablePagination
        pageIndex={pagination.pageIndex}
        pageSize={pagination.pageSize}
        rowCount={inventory.data?.total ?? 0}
        onPageIndexChange={(pageIndex) => setPagination({ ...pagination, pageIndex })}
        onPageSizeChange={(pageSize) => setPagination({ pageIndex: 0, pageSize })}
      />
      {inventory.error && <p className="text-sm text-destructive">{inventory.error.message}</p>}
    </div>
  );
  // Only those who may decide see what is waiting.
  if (!mayApprove) return certificates;
  return (
    <Tabs defaultValue="certificates" className="gap-4">
      <TabsList>
        <TabsTrigger value="certificates">Certificates</TabsTrigger>
        <TabsTrigger value="approval">
          Awaiting approval
          {waiting > 0 && <Badge variant="secondary">{waiting}</Badge>}
        </TabsTrigger>
      </TabsList>
      <TabsContent value="certificates">{certificates}</TabsContent>
      <TabsContent value="approval">
        <ApprovalQueue org={org} onDecided={refresh} />
      </TabsContent>
    </Tabs>
  );
}

function ApprovalQueue({ org, onDecided: decided }: { org: Org; onDecided: () => void }) {
  const queue = useQuery({ queryKey: ["approvals", org.id], queryFn: () => api.approvalQueue(org.id) });
  const approve = useMutation({ mutationFn: (id: string) => api.approve(org.id, id), onSuccess: decided });
  const reject = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) => api.reject(org.id, id, reason),
    onSuccess: decided,
  });
  const approveNames = useMutation({ mutationFn: (id: string) => api.approveNameChange(org.id, id), onSuccess: decided });
  const rejectNames = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) => api.rejectNameChange(org.id, id, reason),
    onSuccess: decided,
  });
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const items = queue.data?.items ?? [];
  const nameChanges = queue.data?.nameChanges ?? [];
  const busy = approve.isPending || reject.isPending || approveNames.isPending || rejectNames.isPending;
  const error = approve.error ?? reject.error ?? approveNames.error ?? rejectNames.error;

  // New Managed Certificates and name changes wait in one queue, and are decided the same way.
  const rows = [
    ...items.map((m) => ({
      key: m.id,
      id: m.id,
      names: m.names.join(", "),
      request: "New",
      detail: `${keyAlgorithmLabel(m.keyAlgorithm)}, ${m.environment}`,
      proposedBy: m.approval.proposedBy?.email,
      label: m.names.join(", "),
      approve: () => approve.mutate(m.id),
      reject: (reason: string) => reject.mutate({ id: m.id, reason }),
    })),
    ...nameChanges.map((n) => ({
      key: `names:${n.managedCertificateId}`,
      id: n.managedCertificateId,
      names: n.currentNames.join(", "),
      request: "Name change",
      detail: `to ${n.names.join(", ")}`,
      proposedBy: n.proposedBy.email,
      label: `name change of ${n.currentNames.join(", ")}`,
      approve: () => approveNames.mutate(n.managedCertificateId),
      reject: (reason: string) => rejectNames.mutate({ id: n.managedCertificateId, reason }),
    })),
  ];

  return (
    <div className="flex flex-col gap-3">
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Names</TableHead>
              <TableHead>Request</TableHead>
              <TableHead>Details</TableHead>
              <TableHead>Proposed by</TableHead>
              <TableHead>Reason</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center text-muted-foreground">
                  {queue.isPending ? "Loading…" : "Nothing is waiting for Approval."}
                </TableCell>
              </TableRow>
            )}
            {rows.map((r) => {
              const reason = (reasons[r.key] ?? "").trim();
              return (
                <TableRow key={r.key}>
                  <TableCell>
                    <ManagedCertificateLink orgId={org.id} id={r.id}>
                      {r.names}
                    </ManagedCertificateLink>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{r.request}</Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{r.detail}</TableCell>
                  <TableCell className="text-muted-foreground">{r.proposedBy}</TableCell>
                  <TableCell>
                    <Input
                      aria-label={`Reason for ${r.label}`}
                      placeholder="Required to reject"
                      className="min-w-48"
                      value={reasons[r.key] ?? ""}
                      onChange={(e) => setReasons({ ...reasons, [r.key]: e.target.value })}
                    />
                  </TableCell>
                  <TableCell>
                    <div className="flex justify-end gap-2">
                      <Button size="sm" disabled={busy} onClick={r.approve}>
                        Approve
                      </Button>
                      <Button size="sm" variant="outline" disabled={busy || !reason} onClick={() => r.reject(reasons[r.key]!)}>
                        Reject
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
      {error && <p className="text-sm text-destructive">{error.message}</p>}
    </div>
  );
}
