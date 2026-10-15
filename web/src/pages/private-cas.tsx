import { useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { createColumnHelper, tableFeatures, useTable } from "@tanstack/react-table";
import { DownloadIcon, PlusIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { DataTable } from "@/components/data-table/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, can, type PrivateCa } from "@/lib/api";
import { KEY_ALGORITHMS, KEY_ALGORITHM_LABELS, type KeyAlgorithm } from "@/lib/csr-generator";
import { keyAlgorithmLabel } from "@/lib/managed-certificate";
import { useAction } from "@/lib/use-action";

const ROUTE = "/app/organizations/$orgId/private-cas";
const STATUS_LABEL: Record<PrivateCa["status"], string> = { awaiting_signature: "Awaiting signature", active: "Active", retired: "Retired", revoked: "Revoked" };
const date = (iso: string) => new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });

// The server lists every Private CA, and an Organization has few, so there is nothing to page.
const features = tableFeatures({});
const columnHelper = createColumnHelper<typeof features, PrivateCa>();
const columns = columnHelper.columns([
  columnHelper.accessor("name", { header: "Name", cell: ({ cell }) => <span className="font-medium">{cell.getValue()}</span> }),
  columnHelper.accessor("subject", { header: "Issuing CA", cell: ({ cell }) => <span className="break-all font-mono text-xs">{cell.getValue()}</span> }),
  columnHelper.accessor("keyAlgorithm", { header: "Key", cell: ({ cell }) => keyAlgorithmLabel(cell.getValue()) }),
  columnHelper.accessor("status", {
    header: "Status",
    cell: ({ cell }) => <Badge variant={cell.getValue() === "active" ? "default" : "secondary"}>{STATUS_LABEL[cell.getValue()]}</Badge>,
  }),
  columnHelper.accessor("notAfter", { header: "Expires", cell: ({ cell }) => (cell.getValue() ? date(cell.getValue()!) : <span className="text-muted-foreground">None yet</span>) }),
  columnHelper.display({ id: "actions", header: () => <span className="sr-only">Actions</span>, cell: ({ row }) => <DownloadChain ca={row.original} /> }),
]);
const noRows: PrivateCa[] = [];

/**
 * The Organization's Private CAs: its own CAs, whose keys the platform holds only in a KMS. A Managed Certificate can be
 * issued from an active one, with no DCV; whatever must trust its Certificates needs the root from its chain.
 */
export function PrivateCasPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.organizations.find((o) => o.id === orgId) }).data;
  const allowed = org ? can(org, "privateCa", "read") : false;
  const cas = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId), enabled: allowed });
  const table = useTable({ features, columns, data: cas.data?.items ?? noRows, getRowId: (ca) => ca.id });

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">Private CAs</h1>
        {org && can(org, "privateCa", "create") && <CreatePrivateCaDialog orgId={orgId} />}
      </div>
      <p className="text-sm text-muted-foreground">
        The Organization's own CAs, for internal names a public CA will not validate. The platform makes a root and an Issuing CA under it, each with its own key in the KMS,
        which never leaves it. A Managed Certificate issued from one needs no DCV; download the chain to install its root wherever its Certificates must be trusted.
      </p>
      {org && !allowed ? (
        <p className="text-sm text-muted-foreground">You may not see the Private CAs.</p>
      ) : (
        <div className="flex flex-col gap-4">
          <DataTable table={table} empty={cas.isPending ? "Loading…" : "No Private CA yet."} />
          {cas.error && <p className="text-sm text-destructive">{cas.error.message}</p>}
        </div>
      )}
    </div>
  );
}

function DownloadChain({ ca }: { ca: PrivateCa }) {
  const { orgId } = useParams({ from: ROUTE });
  if (!ca.notAfter) return null;
  return (
    <div className="flex justify-end">
      <Button variant="outline" size="sm" asChild>
        <a href={api.privateCaChainUrl(orgId, ca.id)} download aria-label={`Download the chain of ${ca.name}`}>
          <DownloadIcon />
          Chain
        </a>
      </Button>
    </div>
  );
}

function CreatePrivateCaDialog({ orgId }: { orgId: string }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          New Private CA
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>New Private CA</DialogTitle>
          <DialogDescription>The platform makes a root and an Issuing CA under it, with separate keys in the KMS. It can issue at once.</DialogDescription>
        </DialogHeader>
        {/* Only mounted while open, so each opening starts from a clean form. */}
        {open && <CreatePrivateCaForm orgId={orgId} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function CreatePrivateCaForm({ orgId, onDone }: { orgId: string; onDone: () => void }) {
  const [name, setName] = useState("");
  const [subject, setSubject] = useState("");
  const [keyAlgorithm, setKeyAlgorithm] = useState<KeyAlgorithm>("ecdsa-p256");
  const [lifetimeYears, setLifetimeYears] = useState("10");
  const create = useAction(() => api.createPrivateCa(orgId, { name: name.trim(), subject: subject.trim(), keyAlgorithm, lifetimeYears: Number(lifetimeYears) }), ["private-cas"], onDone);
  const ready = name.trim() !== "" && subject.trim() !== "" && Number.isInteger(Number(lifetimeYears)) && Number(lifetimeYears) >= 1 && Number(lifetimeYears) <= 30;
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        create.mutate(undefined);
      }}
    >
      <div className="flex flex-col gap-2">
        <Label htmlFor="private-ca-name">Name</Label>
        <Input id="private-ca-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Internal TLS" />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="private-ca-subject">Subject</Label>
        <Input id="private-ca-subject" className="font-mono text-xs" value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="CN=Acme Internal TLS, O=Acme" />
        <p className="text-xs text-muted-foreground">The Issuing CA's distinguished name, with a common name. The root's is the same, with "Root" after the common name.</p>
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="private-ca-algorithm">Key algorithm</Label>
        <select
          id="private-ca-algorithm"
          className="h-9 rounded-md border bg-transparent px-3 text-sm"
          value={keyAlgorithm}
          onChange={(e) => setKeyAlgorithm(e.target.value as KeyAlgorithm)}
        >
          {KEY_ALGORITHMS.map((value) => (
            <option key={value} value={value}>
              {KEY_ALGORITHM_LABELS[value]}
            </option>
          ))}
        </select>
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="private-ca-lifetime">Lifetime (years)</Label>
        <Input id="private-ca-lifetime" type="number" min={1} max={30} value={lifetimeYears} onChange={(e) => setLifetimeYears(e.target.value)} />
        <p className="text-xs text-muted-foreground">How long the root and the Issuing CA are valid for. No Certificate it issues outlives it.</p>
      </div>
      {create.error && <p className="text-sm text-destructive">{create.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={!ready || create.isPending}>
          Create
        </Button>
      </DialogFooter>
    </form>
  );
}
