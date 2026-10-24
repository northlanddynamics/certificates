import { useInfiniteQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { createColumnHelper, rowExpandingFeature, tableFeatures, useTable } from "@tanstack/react-table";
import { useState, type ComponentProps, type FormEvent } from "react";
import { DataTable } from "@/components/data-table/data-table";
import { ExpandButton } from "@/components/data-table/expand-button";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/page-header";
import { api, can, type AuditEvent, type AuditFilters } from "@/lib/api";
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

/** A local date and time from a `datetime-local` input, as an ISO time; none if empty. */
const isoOf = (local: string) => (local ? new Date(local).toISOString() : undefined);

/**
 * The Organization's audit log, newest first: every change to its state, who made it and what it was done to, kept for
 * ever. Organization Administrators search it by actor, action (or every action of a resource, as `team.*`), target and
 * time range.
 */
export function AuditLogPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const allowed = org ? can(org, "audit", "read") : false;
  const [filters, setFilters] = useState<AuditFilters>({});
  const events = useInfiniteQuery({
    queryKey: ["audit-events", orgId, filters],
    queryFn: ({ pageParam }) => api.auditEvents(orgId, filters, pageParam),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    enabled: allowed,
  });
  const rows = events.data?.pages.flatMap((p) => p.items) ?? noRows;
  const table = useTable({ features, columns, data: rows, getRowId: (e) => e.id, getRowCanExpand: (row) => hasDetail(row.original) });

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Audit log"
        description="Every change to the Organization, newest first."
        howItWorks={<p>Audit Events are kept for ever and cannot be changed or deleted. To send them to a SIEM, see Audit forwarding.</p>}
      />
      <AuditFilterForm onSearch={setFilters} />
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

function AuditFilterForm({ onSearch }: { onSearch: (filters: AuditFilters) => void }) {
  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");
  const [targetType, setTargetType] = useState("");
  const [targetId, setTargetId] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const field = (id: string, label: string, value: string, set: (v: string) => void, props: Partial<ComponentProps<typeof Input>> = {}) => (
    <div className="flex flex-col gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Input id={id} value={value} onChange={(e) => set(e.target.value)} {...props} />
    </div>
  );
  return (
    <form
      className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        onSearch({ actor: actor.trim(), action: action.trim(), targetType: targetType.trim(), targetId: targetId.trim(), from: isoOf(from), to: isoOf(to) });
      }}
    >
      {field("audit-actor", "Actor", actor, setActor, { placeholder: "Email or user id", autoComplete: "off" })}
      {field("audit-action", "Action", action, setAction, { placeholder: "team.created, or team.*", autoComplete: "off" })}
      {field("audit-target-type", "Target type", targetType, setTargetType, { placeholder: "managed_certificate", autoComplete: "off" })}
      {field("audit-target-id", "Target id", targetId, setTargetId, { autoComplete: "off" })}
      {field("audit-from", "From", from, setFrom, { type: "datetime-local" })}
      {field("audit-to", "Until", to, setTo, { type: "datetime-local" })}
      <div className="flex gap-2 sm:col-span-2 lg:col-span-3">
        <Button type="submit">Search</Button>
        <Button
          type="button"
          variant="outline"
          onClick={() => {
            for (const set of [setActor, setAction, setTargetType, setTargetId, setFrom, setTo]) set("");
            onSearch({});
          }}
        >
          Clear
        </Button>
      </div>
    </form>
  );
}
