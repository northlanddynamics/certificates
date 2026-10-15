import { useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { createColumnHelper, createExpandedRowModel, rowExpandingFeature, tableFeatures, useTable } from "@tanstack/react-table";
import { MoreHorizontalIcon, PlusIcon } from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";
import { DataTable } from "@/components/data-table/data-table";
import { ExpandButton } from "@/components/data-table/expand-button";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { api, can, type PermittedNames, type PrivateCa, type PrivateCaValidity } from "@/lib/api";
import { KEY_ALGORITHMS, KEY_ALGORITHM_LABELS, type KeyAlgorithm } from "@/lib/csr-generator";
import { splitNames } from "@/lib/csr-names";
import { keyAlgorithmLabel } from "@/lib/managed-certificate";
import { DEFAULT_VALIDITY_DAYS, MAX_VALIDITY_DAYS, isValidityDays, permittedNamesLabel, rootSubjectOf } from "@/lib/private-ca";
import { useAction } from "@/lib/use-action";

const ROUTE = "/app/organizations/$orgId/private-cas";
const STATUS_LABEL: Record<PrivateCa["status"], string> = { awaiting_signature: "Awaiting signature", active: "Active", retired: "Retired", revoked: "Revoked" };
const date = (iso: string) => new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });

/** A CA in a Private CA's hierarchy: its root, which opens to the intermediates it signs, or one of those. */
type CaRow = {
  id: string;
  ca: PrivateCa;
  level: "root" | "intermediate";
  subject: string | undefined;
  notAfter: string | undefined;
  subRows?: CaRow[];
};
const rowsOf = (ca: PrivateCa): CaRow => ({
  id: ca.id,
  ca,
  level: "root",
  subject: ca.root?.subject,
  notAfter: ca.root?.notAfter,
  subRows: [{ id: `${ca.id}-issuing`, ca, level: "intermediate", subject: ca.subject, notAfter: ca.notAfter ?? undefined }],
});

// The server lists every Private CA, and an Organization has few, so there is nothing to page.
const features = tableFeatures({ rowExpandingFeature, expandedRowModel: createExpandedRowModel() });
const columnHelper = createColumnHelper<typeof features, CaRow>();
const columns = columnHelper.columns([
  columnHelper.display({
    id: "expand",
    header: () => <span className="sr-only">Intermediates</span>,
    cell: ({ row }) =>
      row.getCanExpand() ? <ExpandButton open={row.getIsExpanded()} what={`the root of ${row.original.ca.name}`} onToggle={() => row.toggleExpanded()} /> : null,
  }),
  columnHelper.display({
    id: "name",
    header: "Name",
    cell: ({ row }) =>
      row.original.level === "root" ? (
        <span className="flex items-center gap-2">
          <span className="font-medium">{row.original.ca.name}</span>
          <Badge variant="outline">Root CA</Badge>
        </span>
      ) : (
        <span className="flex items-center gap-2 pl-4">
          <span className="text-muted-foreground">└</span>
          <Badge variant="outline">Issuing CA</Badge>
        </span>
      ),
  }),
  columnHelper.accessor("subject", {
    header: "Subject",
    cell: ({ cell }) => (cell.getValue() ? <span className="block max-w-64 whitespace-normal break-all font-mono text-xs">{cell.getValue()}</span> : <span className="text-muted-foreground">The Organization's own</span>),
  }),
  columnHelper.display({ id: "key", header: "Key", cell: ({ row }) => keyAlgorithmLabel(row.original.ca.keyAlgorithm) }),
  columnHelper.display({
    id: "permittedNames",
    header: "Permitted names",
    cell: ({ row }) => (row.original.level === "intermediate" ? <span className="block max-w-56 whitespace-normal break-all text-xs">{permittedNamesLabel(row.original.ca.permittedNames)}</span> : null),
  }),
  columnHelper.display({
    id: "status",
    header: "Status",
    cell: ({ row }) =>
      row.original.level === "root" ? <Badge variant={row.original.ca.status === "active" ? "default" : "secondary"}>{STATUS_LABEL[row.original.ca.status]}</Badge> : null,
  }),
  columnHelper.accessor("notAfter", { header: "Expires", cell: ({ cell }) => (cell.getValue() ? date(cell.getValue()!) : <span className="text-muted-foreground">Unknown</span>) }),
  columnHelper.display({
    id: "actions",
    header: () => <span className="sr-only">Actions</span>,
    cell: ({ row }) => (row.original.level === "root" ? <PrivateCaActions ca={row.original.ca} /> : null),
  }),
]);
const noRows: CaRow[] = [];

/**
 * The Organization's Private CAs: its own CAs, whose keys the platform holds only in a KMS. A Managed Certificate can be
 * issued from an active one, with no DCV; whatever must trust its Certificates needs the root from its chain.
 */
export function PrivateCasPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.organizations.find((o) => o.id === orgId) }).data;
  const allowed = org ? can(org, "privateCa", "read") : false;
  const cas = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId), enabled: allowed });
  const rows = useMemo(() => cas.data?.items.map(rowsOf) ?? noRows, [cas.data]);
  const table = useTable({ features, columns, data: rows, getRowId: (row) => row.id, getSubRows: (row) => row.subRows });

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">Private CAs</h1>
        {org && can(org, "privateCa", "create") && <CreatePrivateCaDialog orgId={orgId} />}
      </div>
      <p className="text-sm text-muted-foreground">
        The Organization's own CAs, for internal names a public CA will not validate. Each is a root and an Issuing CA under it, each with its own key in the KMS, which never
        leaves it. A Managed Certificate issued from one needs no DCV; download the chain to install its root wherever its Certificates must be trusted.
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

function PrivateCaActions({ ca }: { ca: PrivateCa }) {
  const { orgId } = useParams({ from: ROUTE });
  const org = useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.organizations.find((o) => o.id === orgId) }).data;
  const [editing, setEditing] = useState<"names" | "validity" | null>(null);
  const mayUpdate = org ? can(org, "privateCa", "update") : false;
  if (!mayUpdate && !ca.notAfter) return null;
  return (
    <div className="flex justify-end">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${ca.name}`}>
            <MoreHorizontalIcon />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-44">
          {mayUpdate && (
            <>
              <DropdownMenuItem onSelect={() => setEditing("names")}>Permitted names…</DropdownMenuItem>
              <DropdownMenuItem onSelect={() => setEditing("validity")}>Validity…</DropdownMenuItem>
            </>
          )}
          {mayUpdate && ca.notAfter && <DropdownMenuSeparator />}
          {ca.notAfter && (
            <DropdownMenuItem asChild>
              <a href={api.privateCaChainUrl(orgId, ca.id)} download>
                Download chain
              </a>
            </DropdownMenuItem>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
      <EditPermittedNamesDialog orgId={orgId} ca={ca} open={editing === "names"} onOpenChange={(open) => setEditing(open ? "names" : null)} />
      <EditValidityDialog orgId={orgId} ca={ca} open={editing === "validity"} onOpenChange={(open) => setEditing(open ? "validity" : null)} />
    </div>
  );
}

/** Permitted name rules as they are typed: names and zones, a name to a line or a comma. */
type RulesText = { exact: string; zones: string };
const rulesOf = (text: RulesText): PermittedNames => ({ exact: splitNames(text.exact), zones: splitNames(text.zones) });
const hasRules = (text: RulesText) => splitNames(text.exact).length + splitNames(text.zones).length > 0;

/** The fields for a Private CA's permitted name rules. */
function PermittedNamesFields({ id, value, onChange }: { id: string; value: RulesText; onChange: (value: RulesText) => void }) {
  return (
    <>
      <div className="flex flex-col gap-2">
        <Label htmlFor={`${id}-zones`}>Permitted zones</Label>
        <Textarea id={`${id}-zones`} rows={3} value={value.zones} onChange={(e) => onChange({ ...value, zones: e.target.value })} placeholder="internal.example" />
        <p className="text-xs text-muted-foreground">Each zone permits its name and every name beneath it, wildcards included. One to a line.</p>
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor={`${id}-exact`}>Permitted names</Label>
        <Textarea id={`${id}-exact`} rows={3} value={value.exact} onChange={(e) => onChange({ ...value, exact: e.target.value })} placeholder="app.example.com" />
        <p className="text-xs text-muted-foreground">Each permits that name alone; a wildcard such as *.svc.example.com permits that wildcard alone. No IP addresses.</p>
      </div>
    </>
  );
}

/** Validity limits as they are typed: days, as text. */
type ValidityText = { maximumDays: string; defaultDays: string };
const validityTextOf = (v: PrivateCaValidity): ValidityText => ({ maximumDays: String(v.maximumDays), defaultDays: String(v.defaultDays) });
const validityOfText = (text: ValidityText): PrivateCaValidity => ({ maximumDays: Number(text.maximumDays), defaultDays: Number(text.defaultDays) });
/** Why the limits typed cannot be saved; none when they can. */
function validityProblem(text: ValidityText) {
  if (!isValidityDays(text.maximumDays) || !isValidityDays(text.defaultDays)) return `Each is a whole number of days from 1 to ${MAX_VALIDITY_DAYS}.`;
  if (Number(text.defaultDays) > Number(text.maximumDays)) return "The default cannot be above the maximum.";
  return undefined;
}

/** The fields for a Private CA's validity limits. */
function ValidityFields({ id, value, onChange }: { id: string; value: ValidityText; onChange: (value: ValidityText) => void }) {
  const problem = validityProblem(value);
  return (
    <div className="flex flex-col gap-2">
      <div className="flex gap-4">
        <div className="flex flex-col gap-2">
          <Label htmlFor={`${id}-default`}>Default validity (days)</Label>
          <Input id={`${id}-default`} type="number" min={1} max={MAX_VALIDITY_DAYS} className="w-32" value={value.defaultDays} onChange={(e) => onChange({ ...value, defaultDays: e.target.value })} />
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor={`${id}-maximum`}>Maximum validity (days)</Label>
          <Input id={`${id}-maximum`} type="number" min={1} max={MAX_VALIDITY_DAYS} className="w-32" value={value.maximumDays} onChange={(e) => onChange({ ...value, maximumDays: e.target.value })} />
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        A Managed Certificate may choose a validity up to the maximum, and otherwise gets the default. No Certificate outlives the Issuing CA.
      </p>
      {problem && <p className="text-xs text-destructive">{problem}</p>}
    </div>
  );
}

type EditDialogProps = { orgId: string; ca: PrivateCa; open: boolean; onOpenChange: (open: boolean) => void };

function EditValidityDialog({ orgId, ca, open, onOpenChange }: EditDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Validity of {ca.name}</DialogTitle>
          <DialogDescription>
            How long the Certificates it issues from now on are valid for; Certificates already issued are unaffected. A Managed Certificate that chose more than a lowered maximum
            gets the maximum.
          </DialogDescription>
        </DialogHeader>
        {open && <EditValidityForm orgId={orgId} ca={ca} onDone={() => onOpenChange(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function EditValidityForm({ orgId, ca, onDone }: { orgId: string; ca: PrivateCa; onDone: () => void }) {
  const [validity, setValidity] = useState<ValidityText>(validityTextOf(ca.validity));
  const save = useAction(() => api.updatePrivateCa(orgId, ca.id, { validity: validityOfText(validity) }), ["private-cas"], onDone);
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        save.mutate(undefined);
      }}
    >
      <ValidityFields id={`private-ca-${ca.id}-validity`} value={validity} onChange={setValidity} />
      {save.error && <p className="text-sm text-destructive">{save.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={validityProblem(validity) !== undefined || save.isPending}>
          Save
        </Button>
      </DialogFooter>
    </form>
  );
}

function EditPermittedNamesDialog({ orgId, ca, open, onOpenChange }: EditDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Permitted names of {ca.name}</DialogTitle>
          <DialogDescription>
            What it issues for from now on; Certificates already issued are unaffected. Its Issuing CA keeps the name constraints it was made with, which relying parties enforce, so
            permitting names beyond them needs a new Issuing CA.
          </DialogDescription>
        </DialogHeader>
        {open && <EditPermittedNamesForm orgId={orgId} ca={ca} onDone={() => onOpenChange(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function EditPermittedNamesForm({ orgId, ca, onDone }: { orgId: string; ca: PrivateCa; onDone: () => void }) {
  const [rules, setRules] = useState<RulesText>({ exact: ca.permittedNames.exact.join("\n"), zones: ca.permittedNames.zones.join("\n") });
  const save = useAction(() => api.updatePrivateCa(orgId, ca.id, { permittedNames: rulesOf(rules) }), ["private-cas"], onDone);
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        save.mutate(undefined);
      }}
    >
      <PermittedNamesFields id={`private-ca-${ca.id}`} value={rules} onChange={setRules} />
      {save.error && <p className="text-sm text-destructive">{save.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={!hasRules(rules) || save.isPending}>
          Save
        </Button>
      </DialogFooter>
    </form>
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
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
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
  const [rules, setRules] = useState<RulesText>({ exact: "", zones: "" });
  const [validity, setValidity] = useState<ValidityText>(validityTextOf({ maximumDays: DEFAULT_VALIDITY_DAYS, defaultDays: DEFAULT_VALIDITY_DAYS }));
  const create = useAction(
    () =>
      api.createPrivateCa(orgId, {
        name: name.trim(),
        subject: subject.trim(),
        keyAlgorithm,
        lifetimeYears: Number(lifetimeYears),
        permittedNames: rulesOf(rules),
        validity: validityOfText(validity),
      }),
    ["private-cas"],
    onDone,
  );
  const ready = name.trim() !== "" && subject.trim() !== "" && hasRules(rules) && validityProblem(validity) === undefined && Number.isInteger(Number(lifetimeYears)) && Number(lifetimeYears) >= 1 && Number(lifetimeYears) <= 30;
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
      <div className="flex gap-4">
        <div className="flex flex-1 flex-col gap-2">
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
          <Input id="private-ca-lifetime" type="number" min={1} max={30} className="w-32" value={lifetimeYears} onChange={(e) => setLifetimeYears(e.target.value)} />
        </div>
      </div>
      <p className="-mt-2 text-xs text-muted-foreground">For both the root and the Issuing CA, each with its own key. No Certificate outlives them.</p>
      <fieldset className="flex flex-col gap-1 rounded-md border p-3">
        <legend className="px-1 text-sm font-medium">Root CA</legend>
        <span className="break-all font-mono text-xs">{subject.trim() ? rootSubjectOf(subject.trim()) : <span className="font-sans text-muted-foreground">From the Issuing CA's subject</span>}</span>
        <p className="text-xs text-muted-foreground">Self-signed. Its subject is the Issuing CA's, with "Root" after the common name.</p>
      </fieldset>
      <fieldset className="ml-3 flex flex-col gap-4 rounded-md border p-3">
        <legend className="px-1 text-sm font-medium">Issuing CA, signed by the root</legend>
        <div className="flex flex-col gap-2">
          <Label htmlFor="private-ca-subject">Subject</Label>
          <Input id="private-ca-subject" className="font-mono text-xs" value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="CN=Acme Internal TLS, O=Acme" />
          <p className="text-xs text-muted-foreground">A distinguished name, with a common name.</p>
        </div>
        <PermittedNamesFields id="private-ca-new" value={rules} onChange={setRules} />
        <p className="-mt-2 text-xs text-muted-foreground">
          The Issuing CA carries them as name constraints, which relying parties enforce. You can change the names later, but not those constraints without a new Issuing CA, so
          prefer broad zones.
        </p>
        <ValidityFields id="private-ca-new-validity" value={validity} onChange={setValidity} />
      </fieldset>
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
