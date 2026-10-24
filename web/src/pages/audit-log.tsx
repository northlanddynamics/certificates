import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { createColumnHelper, rowExpandingFeature, tableFeatures, useTable } from "@tanstack/react-table";
import { SearchIcon, XIcon } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { DataTable } from "@/components/data-table/data-table";
import { DataTableFacetedFilter } from "@/components/data-table/data-table-faceted-filter";
import { ExpandButton } from "@/components/data-table/expand-button";
import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api, can, type AuditEvent } from "@/lib/api";
import { AUDIT_RANGES, auditFiltersOf, targetTypeLabel, type AuditRange, type AuditSearch } from "@/lib/audit-search";
import { useOrg } from "@/lib/use-org";

const ROUTE = "/app/organizations/$orgId/audit-log";

// The server pages by cursor; the page shows what has been loaded and loads older events on asking. An event with
// detail opens, on a click on its row, to show it underneath.
const features = tableFeatures({ rowExpandingFeature });
const columnHelper = createColumnHelper<typeof features, AuditEvent>();
const hasDetail = (event: AuditEvent) => Object.keys(event.detail).length > 0;
const columns = columnHelper.columns([
  columnHelper.display({
    id: "expand",
    header: () => <span className="sr-only">Detail</span>,
    cell: ({ row }) =>
      row.getCanExpand() ? <ExpandButton open={row.getIsExpanded()} what={`the ${row.original.action} event`} onToggle={() => row.toggleExpanded()} /> : null,
  }),
  columnHelper.accessor("occurredAt", { header: "When", cell: ({ cell }) => <span className="whitespace-nowrap">{new Date(cell.getValue()).toLocaleString()}</span> }),
  columnHelper.display({
    id: "actor",
    header: "Actor",
    cell: ({ row }) => <span className="break-all">{row.original.actor.email ?? <span className="text-muted-foreground">The platform or an API key</span>}</span>,
  }),
  columnHelper.accessor("action", { header: "Action", cell: ({ cell }) => <Badge variant="secondary">{cell.getValue()}</Badge> }),
  columnHelper.display({
    id: "target",
    header: "Target",
    cell: ({ row }) => (
      <span className="break-all">
        {row.original.target.type}
        {row.original.target.id && <span className="text-muted-foreground"> {row.original.target.id}</span>}
      </span>
    ),
  }),
]);
const noRows: AuditEvent[] = [];

/** An ISO time as a `datetime-local` input shows it, in local time; and back. */
const localOf = (iso: string | undefined) => {
  if (!iso) return "";
  const d = new Date(iso);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
};
const isoOf = (local: string) => (local ? new Date(local).toISOString() : undefined);

const RANGE_LABEL: Record<AuditRange | "all", string> = { all: "All time", "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days", custom: "Custom range" };
const SEARCH_DELAY_MS = 300;

/**
 * The Organization's audit log, newest first: every change to its state, who made it and what it was done to, kept for
 * ever. Organization Administrators search it by part of an actor's email or an action, narrow it to types of target
 * and a time range, all kept in the address.
 */
export function AuditLogPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const allowed = org ? can(org, "audit", "read") : false;
  const search = useSearch({ from: ROUTE });
  const navigate = useNavigate({ from: "/organizations/$orgId/audit-log" });
  const change = (next: AuditSearch) => navigate({ search: next, replace: true });
  // A quick range counts back from when it was chosen, not from each refetch.
  const filters = useMemo(() => auditFiltersOf(search, new Date()), [search]);
  const events = useInfiniteQuery({
    queryKey: ["audit-events", orgId, filters],
    queryFn: ({ pageParam }) => api.auditEvents(orgId, filters, pageParam),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    enabled: allowed,
  });
  const targetTypes = useQuery({ queryKey: ["audit-target-types", orgId], queryFn: () => api.auditTargetTypes(orgId), enabled: allowed });
  const rows = events.data?.pages.flatMap((p) => p.items) ?? noRows;
  const table = useTable({ features, columns, data: rows, getRowId: (e) => e.id, getRowCanExpand: (row) => hasDetail(row.original) });

  // The box follows typing, and the address follows the box once typing pauses (and the box the address, on Back).
  const [typed, setTyped] = useState(search.q ?? "");
  useEffect(() => {
    const settled = typed.trim();
    if (settled === (search.q ?? "")) return;
    const timer = setTimeout(() => void change({ ...search, q: settled || undefined }), SEARCH_DELAY_MS);
    return () => clearTimeout(timer);
  }, [typed, search]);
  useEffect(() => setTyped((t) => (t.trim() === (search.q ?? "") ? t : (search.q ?? ""))), [search.q]);
  const narrowed = Object.keys(search).length > 0;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Audit log"
        description="Every change to the Organization, newest first."
        howItWorks={<p>Audit Events are kept for ever and cannot be changed or deleted. To send them to a SIEM, see Audit forwarding.</p>}
      />
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <InputGroup className="w-full bg-card sm:w-72">
            <InputGroupAddon>
              <SearchIcon />
            </InputGroupAddon>
            <InputGroupInput aria-label="Search the audit log" placeholder="Actor's email or action" value={typed} onChange={(e) => setTyped(e.target.value)} />
          </InputGroup>
          <DataTableFacetedFilter
            title="Target"
            options={(targetTypes.data?.items ?? []).map((value) => ({ value, label: targetTypeLabel(value) }))}
            value={search.types ?? []}
            onChange={(types) => void change({ ...search, types: types.length > 0 ? types : undefined })}
          />
          <Select
            value={search.range ?? "all"}
            onValueChange={(value) => void change({ ...search, range: value === "all" ? undefined : (value as AuditRange), from: undefined, to: undefined })}
          >
            <SelectTrigger size="sm" className="w-40 bg-card" aria-label="Time range">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {(["all", ...AUDIT_RANGES] as const).map((range) => (
                <SelectItem key={range} value={range}>
                  {RANGE_LABEL[range]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {narrowed && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setTyped("");
                void change({});
              }}
            >
              Reset
              <XIcon />
            </Button>
          )}
        </div>
        {search.range === "custom" && (
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex flex-col gap-2">
              <Label htmlFor="audit-from">From</Label>
              <Input id="audit-from" type="datetime-local" className="w-56 bg-card" value={localOf(search.from)} onChange={(e) => void change({ ...search, from: isoOf(e.target.value) })} />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="audit-to">Until</Label>
              <Input id="audit-to" type="datetime-local" className="w-56 bg-card" value={localOf(search.to)} onChange={(e) => void change({ ...search, to: isoOf(e.target.value) })} />
            </div>
          </div>
        )}
      </div>
      <DataTable
        table={table}
        empty={events.isPending && allowed ? "Loading…" : "No Audit Event matches."}
        details={(event) => <pre className="text-xs break-all whitespace-pre-wrap">{JSON.stringify(event.detail, null, 2)}</pre>}
        openOnClick
      />
      {events.error && <p className="text-sm text-destructive">{events.error.message}</p>}
      {events.hasNextPage && (
        <div className="flex justify-center">
          <Button variant="outline" disabled={events.isFetchingNextPage} onClick={() => events.fetchNextPage()}>
            {events.isFetchingNextPage ? "Loading…" : "Load older events"}
          </Button>
        </div>
      )}
    </div>
  );
}
