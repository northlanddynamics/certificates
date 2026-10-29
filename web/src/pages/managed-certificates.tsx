import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { createColumnHelper, rowPaginationFeature, tableFeatures, useTable, type PaginationState } from "@tanstack/react-table";
import { SearchIcon, XIcon } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { toast } from "sonner";
import { DataTable } from "@/components/data-table/data-table";
import { DataTableFacetedFilter } from "@/components/data-table/data-table-faceted-filter";
import { DataTablePagination } from "@/components/data-table/data-table-pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, can, ownerLabel, type AcmeCa, type AcmeCaTag, type InventoryFilters, type ManagedCertificate, type Me } from "@/lib/api";
import { KEY_ALGORITHMS, KEY_ALGORITHM_LABELS } from "@/lib/csr-generator";
import { AcmeCaTagBadge } from "@/components/acme-ca-tag";
import { ACME_CA_TAG_LABELS, useAcmeCas } from "@/lib/acme-cas";
import { issuerLabel, keyAlgorithmLabel, primaryName, profileLabel, status } from "@/lib/managed-certificate";
import { chosenValidityLabel } from "@/lib/private-ca";
import { expiryTone } from "@/lib/renewal-urgency";

type Org = Me["organizations"][number];

// Paging, narrowing and ordering are the server's (Page<T>); the table lays out the page it was given, and a row opens to its details.
const features = tableFeatures({ rowPaginationFeature });
const columnHelper = createColumnHelper<typeof features, ManagedCertificate>();
const makeColumns = (orgId: string, acmeCas: AcmeCa[] | undefined) => columnHelper.columns([
  // The common name (else the first name), then how many others, which a tooltip lists.
  columnHelper.accessor((m) => m.names.join(", "), {
    id: "names",
    header: "Names",
    cell: ({ row }) => <Names orgId={orgId} m={row.original} />,
  }),
  // The tag of its ACME CA, as that CA has it now; a Private CA's are all private.
  columnHelper.accessor((m) => (m.acmeCaId ? (acmeCas?.find((ca) => ca.id === m.acmeCaId)?.tag ?? null) : null), {
    id: "tag",
    header: "Environment tag",
    cell: ({ cell, row }) => {
      const { issuer } = row.original;
      if (issuer.kind === "private_ca") {
        return (
          <Badge variant="outline" title={issuerLabel(issuer, acmeCas)}>
            Private
          </Badge>
        );
      }
      return <AcmeCaTagBadge tag={cell.getValue()} />;
    },
  }),
  columnHelper.accessor((m) => keyAlgorithmLabel(m.keyAlgorithm), { id: "keyAlgorithm", header: "Key algorithm" }),
  columnHelper.accessor((m) => status(m).label, {
    id: "status",
    header: "Status",
    cell: ({ row }) => <Badge variant={status(row.original).variant}>{status(row.original).label}</Badge>,
  }),
  // Amber once its renewal window has opened, red once it has ended.
  columnHelper.accessor((m) => (m.currentCertificate ? new Date(m.currentCertificate.notAfter).toLocaleDateString() : "—"), {
    id: "validUntil",
    header: "Valid until",
    cell: ({ cell, row }) => <span className={TONE_TEXT[expiryTone(row.original, new Date()) ?? "none"]}>{cell.getValue()}</span>,
  }),
  columnHelper.accessor((m) => (m.owners.length === 0 ? "None" : m.owners.map(ownerLabel).join(", ")), {
    id: "owners",
    header: "Owners",
    // Nobody to tell when it needs attention, nor to hold its key: worth noticing.
    cell: ({ cell, row }) =>
      row.original.owners.length === 0 ? (
        <span className="text-warning">None</span>
      ) : (
        <span className="block max-w-56 truncate text-muted-foreground" title={cell.getValue()}>
          {cell.getValue()}
        </span>
      ),
  }),
]);
const noRows: ManagedCertificate[] = [];
const TONE_TEXT = { warning: "text-warning", danger: "text-destructive", none: undefined };

function Names({ orgId, m }: { orgId: string; m: ManagedCertificate }) {
  const primary = primaryName(m);
  const others = m.names.filter((name) => name !== primary);
  return (
    <span className="flex items-center gap-2">
      <ManagedCertificateLink orgId={orgId} id={m.id}>
        {primary}
      </ManagedCertificateLink>
      {others.length > 0 && (
        <Tooltip>
          <TooltipTrigger asChild>
            <span tabIndex={0} className="cursor-default text-xs text-muted-foreground" aria-label={`${others.length} more: ${others.join(", ")}`}>
              +{others.length}
            </span>
          </TooltipTrigger>
          <TooltipContent className="font-mono">
            {others.map((name) => (
              <div key={name}>{name}</div>
            ))}
          </TooltipContent>
        </Tooltip>
      )}
    </span>
  );
}

/** A Managed Certificate's names, as the way to its page. */
function ManagedCertificateLink({ orgId, id, children }: { orgId: string; id: string; children: ReactNode }) {
  return (
    <Link to="/organizations/$orgId/certificates/$id" params={{ orgId, id }} className="font-medium underline-offset-4 hover:underline">
      {children}
    </Link>
  );
}

/** The inventory's facets: each is a list of values, and the filter the server takes for them. */
const STATUS_FACETS: [keyof Omit<InventoryFilters, "keyCustody" | "tag" | "keyAlgorithm">, string][] = [
  ["expiringSoon", "Expiring soon"],
  ["renewalFailing", "Renewal failing"],
  ["agentOffline", "Agent offline"],
  ["pendingApproval", "Awaiting Approval"],
  ["noOwners", "No Owners"],
  ["archived", "Archived"],
];
interface Facets {
  status: string[];
  tag: string[];
  keyAlgorithm: string[];
  keyCustody: string[];
}
const NO_FACETS: Facets = { status: [], tag: [], keyAlgorithm: [], keyCustody: [] };
const toFilters = (facets: Facets, q: string): InventoryFilters => ({
  q: q || undefined,
  ...Object.fromEntries(facets.status.map((name) => [name, true])),
  tag: facets.tag as AcmeCaTag[],
  keyAlgorithm: facets.keyAlgorithm,
  keyCustody: facets.keyCustody[0] as InventoryFilters["keyCustody"],
});

const SEARCH_DELAY_MS = 300;
const ROUTE = "/app/organizations/$orgId/certificates";

export function ManagedCertificates({ org }: { org: Org }) {
  const queryClient = useQueryClient();
  const navigate = useNavigate({ from: "/organizations/$orgId/certificates" });
  const { q = "", status: opened, tab } = useSearch({ from: ROUTE });
  const [typed, setTyped] = useState(q);
  // A link may open it narrowed by Status facets; those it does not know are ignored.
  const [facets, setFacets] = useState<Facets>(() => ({ ...NO_FACETS, status: (opened ?? "").split(",").filter((name) => STATUS_FACETS.some(([value]) => value === name)) }));
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 25 });
  const search = (next: string) => navigate({ search: (prev) => ({ ...prev, q: next || undefined }), replace: true });
  // The address follows the box once typing pauses, and a new search starts again from the first page.
  useEffect(() => {
    const settled = typed.trim();
    if (settled === q) return;
    const timer = setTimeout(() => {
      void search(settled);
      setPagination((p) => ({ ...p, pageIndex: 0 }));
    }, SEARCH_DELAY_MS);
    return () => clearTimeout(timer);
  }, [typed, q]);
  // ...and the box follows the address, when Back changes it.
  useEffect(() => setTyped((t) => (t.trim() === q ? t : q)), [q]);
  const filters = toFilters(facets, q);
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
  const acmeCas = useAcmeCas(org.id).data?.items;
  const columns = useMemo(() => makeColumns(org.id, acmeCas), [org.id, acmeCas]);
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
  const narrowed = q !== "" || Object.values(facets).some((values) => values.length > 0);
  // A new narrowing starts again from the first page.
  const narrow = (next: Partial<Facets>) => {
    setFacets({ ...facets, ...next });
    setPagination({ ...pagination, pageIndex: 0 });
  };
  const reset = () => {
    setTyped("");
    void search("");
    narrow(NO_FACETS);
  };

  const mayApprove = can(org, "approval", "read");
  // The same query the queue reads, for how many are waiting.
  const queue = useQuery({ queryKey: ["approvals", org.id], queryFn: () => api.approvalQueue(org.id), enabled: mayApprove });
  const waiting = (queue.data?.items.length ?? 0) + (queue.data?.nameChanges.length ?? 0);

  const certificates = (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <InputGroup className="w-full bg-card sm:w-72">
          <InputGroupAddon>
            <SearchIcon />
          </InputGroupAddon>
          <InputGroupInput aria-label="Search Managed Certificates" placeholder="Search names" value={typed} onChange={(e) => setTyped(e.target.value)} />
        </InputGroup>
        <DataTableFacetedFilter
          title="Status"
          options={STATUS_FACETS.map(([value, label]) => ({ value, label }))}
          value={facets.status}
          onChange={(status) => narrow({ status })}
          hint="Shows those that match all you choose."
        />
        <DataTableFacetedFilter
          title="Environment tag"
          options={Object.entries(ACME_CA_TAG_LABELS).map(([value, label]) => ({ value, label }))}
          value={facets.tag}
          onChange={(tag) => narrow({ tag })}
        />
        <DataTableFacetedFilter
          title="Key algorithm"
          options={KEY_ALGORITHMS.map((value) => ({ value, label: KEY_ALGORITHM_LABELS[value] }))}
          value={facets.keyAlgorithm}
          onChange={(keyAlgorithm) => narrow({ keyAlgorithm })}
        />
        <DataTableFacetedFilter title="Key Custody" options={[{ value: "owner", label: "Owner" }, { value: "agent", label: "Agent" }]} value={facets.keyCustody} onChange={(keyCustody) => narrow({ keyCustody })} />
        {narrowed && (
          <Button variant="ghost" size="sm" onClick={reset}>
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
              ? (
                  <div className="flex flex-col items-center gap-2">
                    {q ? <>No Managed Certificate matches “{q}”.</> : "No Managed Certificates match."}
                    <Button variant="outline" size="sm" onClick={reset}>
                      Clear
                    </Button>
                  </div>
                )
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
    <Tabs defaultValue={tab ?? "certificates"} className="gap-4">
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
  const acmeCas = useAcmeCas(org.id).data?.items;
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
  // A decision takes its row away, so a toast says what became of it; a refusal is a toast, too.
  const told = (label: string, verb: "approve" | "reject") => ({
    onSuccess: () => toast.success(`${verb === "approve" ? "Approved" : "Rejected"} ${label}`),
    onError: (error: Error) => toast.error(`Could not ${verb} ${label}`, { description: error.message }),
  });

  // New Managed Certificates and name changes wait in one queue, and are decided the same way.
  const rows = [
    ...items.map((m) => ({
      key: m.id,
      id: m.id,
      names: m.names.join(", "),
      request: "New",
      detail: `${m.profile ? `Through the profile ${profileLabel(m.profile)}: ` : ""}${keyAlgorithmLabel(m.keyAlgorithm)}, ${issuerLabel(m.issuer, acmeCas)}${m.issuer.kind === "private_ca" ? `, valid for ${chosenValidityLabel(m.validityDays)}` : ""}`,
      proposedBy: m.approval.proposedBy?.email,
      label: m.names.join(", "),
      approve: () => approve.mutate(m.id, told(m.names.join(", "), "approve")),
      reject: (reason: string) => reject.mutate({ id: m.id, reason }, told(m.names.join(", "), "reject")),
    })),
    ...nameChanges.map((n) => ({
      key: `names:${n.managedCertificateId}`,
      id: n.managedCertificateId,
      names: n.currentNames.join(", "),
      request: "Name change",
      detail: `${n.profile ? `Through the profile ${profileLabel(n.profile)}: ` : ""}to ${n.names.join(", ")}${n.validityDays !== n.currentValidityDays ? `; validity from ${chosenValidityLabel(n.currentValidityDays)} to ${chosenValidityLabel(n.validityDays)}` : ""}`,
      proposedBy: n.proposedBy.email,
      label: `name change of ${n.currentNames.join(", ")}`,
      approve: () => approveNames.mutate(n.managedCertificateId, told(`the name change of ${n.currentNames.join(", ")}`, "approve")),
      reject: (reason: string) => rejectNames.mutate({ id: n.managedCertificateId, reason }, told(`the name change of ${n.currentNames.join(", ")}`, "reject")),
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
    </div>
  );
}
