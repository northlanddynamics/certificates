import { useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { createColumnHelper, tableFeatures, useTable } from "@tanstack/react-table";
import { PlusIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { DataTable } from "@/components/data-table/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, can, type AuditForwarder } from "@/lib/api";
import { useOrg } from "@/lib/use-org";
import { useAction } from "@/lib/use-action";

const ROUTE = "/app/organizations/$orgId/audit-forwarding";
const KIND_LABEL: Record<AuditForwarder["kind"], string> = { webhook: "Webhook", syslog: "Syslog (TLS)" };

// The server lists every forwarder, so there is nothing to page.
const features = tableFeatures({});
const columnHelper = createColumnHelper<typeof features, AuditForwarder>();
const columns = columnHelper.columns([
  columnHelper.accessor("name", { header: "Name", cell: ({ cell }) => <span className="font-medium">{cell.getValue()}</span> }),
  columnHelper.accessor("kind", { header: "Kind", cell: ({ cell }) => <Badge variant="secondary">{KIND_LABEL[cell.getValue()]}</Badge> }),
  columnHelper.display({
    id: "target",
    header: "Sends to",
    cell: ({ row }) => (
      <span className="break-all" title={row.original.kind === "webhook" ? "The URL is write-only; only its host is shown." : undefined}>
        {row.original.port === null ? row.original.host : `${row.original.host}:${row.original.port}`}
      </span>
    ),
  }),
  columnHelper.display({ id: "status", header: "Delivery", cell: ({ row }) => <DeliveryStatus forwarder={row.original} /> }),
  columnHelper.display({ id: "actions", header: () => <span className="sr-only">Actions</span>, cell: ({ row }) => <ForwarderActions forwarder={row.original} /> }),
]);
const noRows: AuditForwarder[] = [];

function DeliveryStatus({ forwarder: f }: { forwarder: AuditForwarder }) {
  if (f.lastError !== null) {
    return (
      <div className="flex flex-col gap-1 text-sm">
        <Badge variant="destructive">Failing</Badge>
        <span className="break-all text-muted-foreground">{f.lastError}</span>
        <span className="text-muted-foreground">
          {f.backlog} waiting{f.nextAttemptAt && `; tried again ${new Date(f.nextAttemptAt).toLocaleString()}`}
        </span>
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-1 text-sm">
      <span>{f.backlog === 0 ? "Up to date" : `${f.backlog} waiting`}</span>
      {f.lastDeliveredAt && <span className="text-muted-foreground">Last delivered {new Date(f.lastDeliveredAt).toLocaleString()}</span>}
    </div>
  );
}

/**
 * Where the Organization's Audit Events are forwarded: a SIEM's webhook (such as an HTTP event collector) or syslog receiver.
 * Every event recorded after a forwarder is added is delivered at least once, in the schema `certificate-platform.audit/1`;
 * one that cannot be reached is tried again until it can. Only Organization Administrators configure them, and doing so is audited.
 */
export function AuditForwardingPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const allowed = org ? can(org, "auditForwarder", "read") : false;
  const mayConfigure = org ? can(org, "auditForwarder", "create") : false;
  const forwarders = useQuery({ queryKey: ["audit-forwarders", orgId], queryFn: () => api.auditForwarders(orgId), enabled: allowed, refetchInterval: 30_000 });
  const table = useTable({ features, columns, data: forwarders.data?.items ?? noRows, getRowId: (f) => f.id });

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">Audit forwarding</h1>
        {mayConfigure && <AddForwarderDialog orgId={orgId} />}
      </div>
      <p className="text-sm text-muted-foreground">
        Send every Audit Event to your SIEM as JSON, by webhook or by syslog over TLS. Each event recorded after a forwarder is added is delivered at least once; a receiver that cannot
        be reached is tried again until it can.
      </p>
      <DataTable table={table} empty={forwarders.isPending && allowed ? "Loading…" : "Audit Events are not forwarded anywhere yet."} />
      {forwarders.error && <p className="text-sm text-destructive">{forwarders.error.message}</p>}
    </div>
  );
}

function ForwarderActions({ forwarder }: { forwarder: AuditForwarder }) {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  return <div className="flex justify-end">{org && can(org, "auditForwarder", "delete") && <RemoveForwarder orgId={orgId} forwarder={forwarder} />}</div>;
}

function RemoveForwarder({ orgId, forwarder }: { orgId: string; forwarder: AuditForwarder }) {
  const [open, setOpen] = useState(false);
  const remove = useAction(() => api.deleteAuditForwarder(orgId, forwarder.id), ["audit-forwarders", "audit-events"], () => setOpen(false));
  return (
    <>
      <Button variant="ghost" size="sm" aria-label={`Remove ${forwarder.name}`} onClick={() => setOpen(true)}>
        Remove
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title={`Stop forwarding to ${forwarder.name}?`}
        description="Audit Events not yet delivered to it are not sent. The audit log itself is kept."
        confirmLabel="Remove"
        pending={remove.isPending}
        error={remove.error}
        onConfirm={() => remove.mutate(undefined)}
      />
    </>
  );
}

function AddForwarderDialog({ orgId }: { orgId: string }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          Add a forwarder
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Forward Audit Events</DialogTitle>
          <DialogDescription>A webhook is posted each event as JSON; a syslog receiver must accept TLS. A webhook's URL and Authorization header cannot be read back once added.</DialogDescription>
        </DialogHeader>
        {/* Only mounted while open, so each opening starts from a clean form. */}
        {open && <AddForwarderForm orgId={orgId} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function AddForwarderForm({ orgId, onDone }: { orgId: string; onDone: () => void }) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<AuditForwarder["kind"]>("webhook");
  const [url, setUrl] = useState("");
  const [authorization, setAuthorization] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("6514");
  const add = useAction(
    () =>
      api.addAuditForwarder(
        orgId,
        kind === "webhook"
          ? { name: name.trim(), kind, url: url.trim(), ...(authorization.trim() && { authorization: authorization.trim() }) }
          : { name: name.trim(), kind, host: host.trim(), port: Number(port) },
      ),
    ["audit-forwarders", "audit-events"],
    onDone,
  );
  const complete = name.trim() && (kind === "webhook" ? url.trim() : host.trim() && Number(port) > 0);
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        add.mutate(undefined);
      }}
    >
      <div className="flex flex-col gap-2">
        <Label htmlFor="forwarder-name">Name</Label>
        <Input id="forwarder-name" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="forwarder-kind">Kind</Label>
        <select id="forwarder-kind" className="h-9 rounded-md border bg-transparent px-3 text-sm" value={kind} onChange={(e) => setKind(e.target.value as AuditForwarder["kind"])}>
          <option value="webhook">Webhook</option>
          <option value="syslog">Syslog over TLS</option>
        </select>
      </div>
      {kind === "webhook" ? (
        <>
          <div className="flex flex-col gap-2">
            <Label htmlFor="forwarder-url">Webhook URL</Label>
            <Input id="forwarder-url" type="url" autoComplete="off" placeholder="e.g. https://siem.example.com/services/collector" value={url} onChange={(e) => setUrl(e.target.value)} />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="forwarder-authorization">Authorization header (optional)</Label>
            <Input id="forwarder-authorization" type="password" autoComplete="off" placeholder="Bearer …" value={authorization} onChange={(e) => setAuthorization(e.target.value)} />
          </div>
        </>
      ) : (
        <div className="grid grid-cols-[1fr_7rem] gap-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="forwarder-host">Host</Label>
            <Input id="forwarder-host" autoComplete="off" placeholder="e.g. collector.example.com" value={host} onChange={(e) => setHost(e.target.value)} />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="forwarder-port">Port</Label>
            <Input id="forwarder-port" type="number" min={1} max={65535} value={port} onChange={(e) => setPort(e.target.value)} />
          </div>
        </div>
      )}
      {add.error && <p className="text-sm text-destructive">{add.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={!complete || add.isPending}>
          Add
        </Button>
      </DialogFooter>
    </form>
  );
}
