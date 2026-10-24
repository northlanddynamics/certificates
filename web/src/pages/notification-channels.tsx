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
import { ActionLabel, PageHeader } from "@/components/page-header";
import { api, can, type NotificationChannel } from "@/lib/api";
import { useOrg } from "@/lib/use-org";
import { useAction } from "@/lib/use-action";

const ROUTE = "/app/organizations/$orgId/notification-channels";
const KIND_LABEL: Record<NotificationChannel["kind"], string> = { email: "Email", webhook: "Webhook" };

// The server lists every channel, so there is nothing to page.
const features = tableFeatures({});
const columnHelper = createColumnHelper<typeof features, NotificationChannel>();
const columns = columnHelper.columns([
  columnHelper.accessor("name", { header: "Name", cell: ({ cell }) => <span className="font-medium">{cell.getValue()}</span> }),
  columnHelper.accessor("kind", { header: "Kind", cell: ({ cell }) => <Badge variant="secondary">{KIND_LABEL[cell.getValue()]}</Badge> }),
  columnHelper.display({
    id: "target",
    header: "Sends to",
    cell: ({ row }) =>
      row.original.kind === "email" ? (
        <span className="break-all">{row.original.email}</span>
      ) : (
        <span className="break-all" title="The URL is write-only; only its host is shown.">
          {row.original.webhookHost}
        </span>
      ),
  }),
  columnHelper.display({ id: "actions", header: () => <span className="sr-only">Actions</span>, cell: ({ row }) => <ChannelActions channel={row.original} /> }),
]);
const noRows: NotificationChannel[] = [];

/**
 * The Organization's notification channels: email addresses and webhooks (Microsoft Teams, Slack, ticketing, a SIEM) that
 * Owners and Organization Administrators can subscribe to a Managed Certificate's notices. Only Organization Administrators
 * configure them. A webhook's URL is write-only: once added, only its host is shown.
 */
export function NotificationChannelsPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const allowed = org ? can(org, "notificationChannel", "read") : false;
  const mayConfigure = org ? can(org, "notificationChannel", "create") : false;
  const channels = useQuery({ queryKey: ["notification-channels", orgId], queryFn: () => api.notificationChannels(orgId), enabled: allowed });
  const table = useTable({ features, columns, data: channels.data?.items ?? noRows, getRowId: (c) => c.id });

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Notification channels"
        action={mayConfigure && <AddChannelDialog orgId={orgId} />}
        description="Besides people and Teams, a Managed Certificate's notices can go to a shared mailbox or to a webhook."
        howItWorks={<p>A webhook receives each notice as JSON. A channel is told only of the Managed Certificates it is subscribed to; nothing is subscribed by default.</p>}
      />
      <DataTable table={table} empty={channels.isPending ? "Loading…" : "No notification channel is configured yet."} />
      {channels.error && <p className="text-sm text-destructive">{channels.error.message}</p>}
    </div>
  );
}

function ChannelActions({ channel }: { channel: NotificationChannel }) {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  return <div className="flex justify-end">{org && can(org, "notificationChannel", "delete") && <RemoveChannel orgId={orgId} channel={channel} />}</div>;
}

function RemoveChannel({ orgId, channel }: { orgId: string; channel: NotificationChannel }) {
  const [open, setOpen] = useState(false);
  const remove = useAction(() => api.deleteNotificationChannel(orgId, channel.id), ["notification-channels", "managed-certificate"], () => setOpen(false));
  return (
    <>
      <Button variant="ghost" size="sm" aria-label={`Remove ${channel.name}`} onClick={() => setOpen(true)}>
        Remove
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title={`Remove ${channel.name}?`}
        description="It stops being a Subscriber of every Managed Certificate, and notices not yet sent to it are dropped."
        confirmLabel="Remove"
        pending={remove.isPending}
        error={remove.error}
        onConfirm={() => remove.mutate(undefined)}
      />
    </>
  );
}

function AddChannelDialog({ orgId }: { orgId: string }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          <ActionLabel>Add a channel</ActionLabel>
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add a notification channel</DialogTitle>
          <DialogDescription>An email address, or a webhook that is posted each notice as JSON. A webhook's URL cannot be read back once added.</DialogDescription>
        </DialogHeader>
        {/* Only mounted while open, so each opening starts from a clean form. */}
        {open && <AddChannelForm orgId={orgId} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function AddChannelForm({ orgId, onDone }: { orgId: string; onDone: () => void }) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<NotificationChannel["kind"]>("email");
  const [target, setTarget] = useState("");
  const add = useAction(
    () => api.addNotificationChannel(orgId, kind === "email" ? { name: name.trim(), kind, email: target.trim() } : { name: name.trim(), kind, url: target.trim() }),
    ["notification-channels"],
    onDone,
  );
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        add.mutate(undefined);
      }}
    >
      <div className="flex flex-col gap-2">
        <Label htmlFor="channel-name">Name</Label>
        <Input id="channel-name" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="channel-kind">Kind</Label>
        <select id="channel-kind" className="h-9 rounded-md border bg-transparent px-3 text-sm" value={kind} onChange={(e) => setKind(e.target.value as NotificationChannel["kind"])}>
          <option value="email">Email</option>
          <option value="webhook">Webhook</option>
        </select>
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="channel-target">{kind === "email" ? "Email address" : "Webhook URL"}</Label>
        <Input
          id="channel-target"
          type={kind === "email" ? "email" : "url"}
          autoComplete="off"
          placeholder={kind === "email" ? "certificates@example.com" : "https://hooks.example.com/…"}
          value={target}
          onChange={(e) => setTarget(e.target.value)}
        />
      </div>
      {add.error && <p className="text-sm text-destructive">{add.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={!name.trim() || !target.trim() || add.isPending}>
          Add
        </Button>
      </DialogFooter>
    </form>
  );
}
