import { useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { createColumnHelper, tableFeatures, useTable } from "@tanstack/react-table";
import { BookOpenIcon, CalendarClockIcon, ClipboardCheckIcon, FingerprintIcon, GlobeIcon, KeyRoundIcon, MoreHorizontalIcon, NetworkIcon, PlusIcon } from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { DataTable } from "@/components/data-table/data-table";
import { GuideLink } from "@/components/guide";
import { PublicationCheck, PublicationSummary } from "@/components/pki-publication";
import { TrustRootDialog } from "@/components/trust-root-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { SteppedForm, STEPPED_DIALOG, type Missing, type Step } from "@/components/stepped-form";
import { SummaryRows } from "@/components/summary-rows";
import { useCertificateText } from "@/components/use-certificate-text";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api, can, issuingCaRevocationReasons, type IssuingCa, type PermittedNames, type PrivateCa, type PrivateCaValidity } from "@/lib/api";
import { useOrg } from "@/lib/use-org";
import { KEY_ALGORITHM_LABELS, isMlDsa, type KeyAlgorithm } from "@/lib/csr-generator";
import { useKeyAlgorithms } from "@/components/issuer-choice";
import { ActionLabel, PageHeader } from "@/components/page-header";
import { splitNames } from "@/lib/csr-names";
import { keyAlgorithmLabel } from "@/lib/managed-certificate";
import { DEFAULT_VALIDITY_DAYS, MAX_LIFETIME_YEARS, MAX_VALIDITY_DAYS, commonNameOf, daysLabel, isValidityDays, rootSubjectOf, validityLabel } from "@/lib/private-ca";
import { useAction } from "@/lib/use-action";

const ROUTE = "/app/organizations/$orgId/private-cas";
const STATUS_LABEL: Record<IssuingCa["status"], string> = { awaiting_signature: "Awaiting signature", active: "Active", retired: "Retired", revoked: "Revoked" };
const date = (iso: string) => new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });

/** A CA in a Private CA's hierarchy: its root, or one of the Issuing CAs it signs, which are always listed beneath it. */
type CaRow =
  | { id: string; ca: PrivateCa; level: "root"; subject: string | undefined; notAfter: string | undefined }
  | { id: string; ca: PrivateCa; level: "issuing"; issuing: IssuingCa; subject: string; notAfter: string | undefined };
const rowsOf = (ca: PrivateCa): CaRow[] => [
  { id: ca.id, ca, level: "root", subject: ca.root?.subject, notAfter: ca.root?.notAfter },
  ...ca.issuingCas.map((issuing): CaRow => ({ id: issuing.id, ca, level: "issuing", issuing, subject: issuing.subject, notAfter: issuing.notAfter ?? undefined })),
];

const StatusBadge = ({ status }: { status: IssuingCa["status"] }) => <Badge variant={status === "active" ? "success" : status === "revoked" ? "destructive" : status === "awaiting_signature" ? "warning" : "neutral"}>{STATUS_LABEL[status]}</Badge>;

// The server lists every Private CA, and an Organization has few, so there is nothing to page.
const features = tableFeatures({});
const columnHelper = createColumnHelper<typeof features, CaRow>();
const columns = columnHelper.columns([
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
          <span>{commonNameOf(row.original.issuing.subject)}</span>
          <Badge variant="outline">Issuing CA</Badge>
        </span>
      ),
  }),
  columnHelper.accessor("subject", {
    header: "Subject",
    cell: ({ cell }) =>
      cell.getValue() ? (
        <span className="block max-w-64 whitespace-normal break-all font-mono text-xs">{cell.getValue()}</span>
      ) : (
        <span className="text-muted-foreground">The Organization's own, not uploaded yet</span>
      ),
  }),
  columnHelper.display({ id: "key", header: "Key", cell: ({ row }) => keyAlgorithmLabel(row.original.ca.keyAlgorithm) }),
  columnHelper.display({
    id: "permittedNames",
    header: "Permitted names",
    cell: ({ row }) =>
      row.original.level === "issuing" ? (
        <span className="flex flex-col gap-1">
          <PermittedNamesChips names={row.original.issuing.permittedNames} />
          {row.original.ca.kind === "organization_root" && row.original.issuing.status !== "awaiting_signature" && <RootNameConstraints constraints={row.original.issuing.nameConstraints} />}
        </span>
      ) : null,
  }),
  columnHelper.display({
    id: "status",
    header: "Status",
    cell: ({ row }) => <StatusBadge status={row.original.level === "root" ? row.original.ca.status : row.original.issuing.status} />,
  }),
  columnHelper.accessor("notAfter", {
    header: "Expires",
    cell: ({ row, cell }) =>
      cell.getValue() ? (
        <span className="flex items-center gap-2">
          {date(cell.getValue()!)}
          {row.original.level === "issuing" && <RolloverDue issuing={row.original.issuing} />}
        </span>
      ) : (
        <span className="text-muted-foreground">Unknown</span>
      ),
  }),
  columnHelper.display({
    id: "actions",
    header: () => <span className="sr-only">Actions</span>,
    cell: ({ row }) => (row.original.level === "root" ? <RootActions ca={row.original.ca} /> : <IssuingCaActions ca={row.original.ca} issuing={row.original.issuing} />),
  }),
]);
const noRows: CaRow[] = [];

/**
 * The Organization's Private CAs: its own CAs, whose keys the platform holds only in a KMS, each a root and its Issuing CAs.
 * A Managed Certificate can be issued from an active Issuing CA, with no DCV; whatever must trust its Certificates needs the root.
 */
export function PrivateCasPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const allowed = org ? can(org, "privateCa", "read") : false;
  const cas = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId), enabled: allowed });
  const rows = useMemo(() => cas.data?.items.flatMap(rowsOf) ?? noRows, [cas.data]);
  const table = useTable({ features, columns, data: rows, getRowId: (row) => row.id });

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Private CAs"
        guide="private-cas"
        action={
          <>
            <Button variant="outline" asChild>
              <GuideLink orgId={orgId} guide="private-cas" className="">
                <BookOpenIcon />
                <ActionLabel>Publishing guide</ActionLabel>
              </GuideLink>
            </Button>
            {org && can(org, "privateCa", "create") && <CreatePrivateCaDialog orgId={orgId} />}
          </>
        }
        description="The Organization's own CAs, for internal names a public CA will not validate."
        howItWorks={
          <>
            <p>Each is a root and one or more Issuing CAs under it, each with its own key in the KMS, which never leaves it.</p>
            <p>A Managed Certificate is issued from one Issuing CA and needs no DCV; download the root to install it wherever its Certificates must be trusted.</p>
            <p>Add an Issuing CA under the same root, for other names or to roll over, and nothing that trusts the root needs anything new.</p>
          </>
        }
      />
      {org && !allowed ? (
        <p className="text-sm text-muted-foreground">You may not see the Private CAs.</p>
      ) : (
        <div className="flex flex-col gap-4">
          {cas.data && <PublicationSummary publication={cas.data.publication} orgId={orgId} />}
          <DataTable table={table} empty={cas.isPending ? "Loading…" : "No Private CA yet."} />
          {cas.error && <p className="text-sm text-destructive">{cas.error.message}</p>}
        </div>
      )}
    </div>
  );
}

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * A warning on an active Issuing CA that ends sooner than its maximum validity: the Certificates it issues from now on are
 * cut short at its end, so it is time to add another under the root, repoint its Managed Certificates and retire it.
 */
function RolloverDue({ issuing }: { issuing: IssuingCa }) {
  if (issuing.status !== "active" || !issuing.notAfter) return null;
  const left = Math.floor((new Date(issuing.notAfter).getTime() - Date.now()) / DAY_MS);
  if (left >= issuing.validity.maximumDays) return null;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge variant="destructive" tabIndex={0}>
          {left <= 0 ? "Ended" : "Roll over"}
        </Badge>
      </TooltipTrigger>
      <TooltipContent className="max-w-72">
        {left <= 0
          ? "It has ended and issues nothing. Repoint its Managed Certificates to another Issuing CA."
          : `It ends in ${daysLabel(left)}, sooner than its maximum validity of ${daysLabel(issuing.validity.maximumDays)}, so what it issues now is cut short. Add another Issuing CA under the root, repoint its Managed Certificates to it, and retire this one.`}
      </TooltipContent>
    </Tooltip>
  );
}

/** An Issuing CA's permitted name rules as chips: the first, then "+n" with the rest on hover. */
function PermittedNamesChips({ names }: { names: PermittedNames }) {
  const rules = [...names.zones.map((zone) => `${zone} (zone)`), ...names.exact];
  if (rules.length === 0) return <span className="text-muted-foreground">Not set</span>;
  const [first, ...rest] = rules;
  return (
    <span className="flex items-center gap-1">
      <Badge variant="secondary" className="font-normal">
        {first}
      </Badge>
      {rest.length > 0 && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="outline" tabIndex={0} aria-label={`All permitted names: ${rules.join(", ")}`}>
              +{rest.length}
            </Badge>
          </TooltipTrigger>
          <TooltipContent>
            <ul className="flex flex-col gap-0.5">
              {rules.map((rule) => (
                <li key={rule}>{rule}</li>
              ))}
            </ul>
          </TooltipContent>
        </Tooltip>
      )}
    </span>
  );
}

/**
 * The name constraints the Organization's own root put in an Issuing CA, which relying parties enforce: the platform
 * enforces the Issuing CA's permitted names, which may be narrower, and never these.
 */
function RootNameConstraints({ constraints }: { constraints: IssuingCa["nameConstraints"] }) {
  if (!constraints) return <span className="text-xs text-muted-foreground">The root put no name constraints in it</span>;
  const all = [...constraints.permitted.map((c) => `permits ${c}`), ...constraints.excluded.map((c) => `excludes ${c}`)];
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="text-xs text-muted-foreground underline decoration-dotted" tabIndex={0} aria-label={`Name constraints from the root: ${all.join(", ")}`}>
          Root's name constraints ({all.length})
        </span>
      </TooltipTrigger>
      <TooltipContent>
        <p className="mb-1">What the root put in it, which relying parties enforce:</p>
        <ul className="flex flex-col gap-0.5 font-mono">
          {all.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
      </TooltipContent>
    </Tooltip>
  );
}

/** The Organization of the page, as /api/me reports it, and whether its user may change, retire and revoke its Private CAs. */
function usePrivateCaPermissions() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const may = (action: string) => (org ? can(org, "privateCa", action) : false);
  return { orgId, mayUpdate: may("update"), mayRetire: may("retire"), mayRevoke: may("revoke") };
}

/** A root's menu: add an Issuing CA under it, and download it. */
function RootActions({ ca }: { ca: PrivateCa }) {
  const { orgId, mayUpdate } = usePrivateCaPermissions();
  const [adding, setAdding] = useState(false);
  const [trusting, setTrusting] = useState(false);
  // The page's own list, already fetched: for where the root's CRLs are served.
  const publication = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId) }).data?.publication;
  // Under an active root only: the platform's signs the new one at once, the Organization's own signs its CSR later.
  const mayAdd = mayUpdate && ca.status === "active";
  if (!mayAdd && !ca.root) return null;
  return (
    <div className="flex justify-end">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${ca.name}`}>
            <MoreHorizontalIcon />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-44">
          {mayAdd && <DropdownMenuItem onSelect={() => setAdding(true)}>Add Issuing CA…</DropdownMenuItem>}
          {mayAdd && ca.root && <DropdownMenuSeparator />}
          {ca.root && <DropdownMenuItem onSelect={() => setTrusting(true)}>Trust this root…</DropdownMenuItem>}
        </DropdownMenuContent>
      </DropdownMenu>
      <AddIssuingCaDialog orgId={orgId} ca={ca} open={adding} onOpenChange={setAdding} />
      {ca.root && <TrustRootDialog orgId={orgId} ca={ca} publication={publication} open={trusting} onOpenChange={setTrusting} />}
    </div>
  );
}

/** An Issuing CA's menu: under the Organization's own root, its CSR and the upload of what that root signed; its permitted names and validity; its chain; and retiring or revoking it. */
function IssuingCaActions({ ca, issuing }: { ca: PrivateCa; issuing: IssuingCa }) {
  const { orgId, mayUpdate, mayRetire, mayRevoke } = usePrivateCaPermissions();
  const [editing, setEditing] = useState<"names" | "validity" | "upload" | "retire" | "revoke" | null>(null);
  const retirable = mayRetire && issuing.status === "active";
  // Only the platform's own root revokes; the Organization's root revokes what it signed itself.
  const revocable = mayRevoke && ca.kind === "platform_root" && (issuing.status === "active" || issuing.status === "retired");
  const signedByOrganization = ca.kind === "organization_root";
  const awaiting = issuing.status === "awaiting_signature";
  if (!mayUpdate && !issuing.notAfter) return null;
  const name = commonNameOf(issuing.subject);
  return (
    <div className="flex justify-end">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${name} of ${ca.name}`}>
            <MoreHorizontalIcon />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-52">
          {mayUpdate && signedByOrganization && (
            <>
              <DropdownMenuItem asChild>
                <a href={api.issuingCaCsrUrl(orgId, ca.id, issuing.id)} download>
                  Download CSR
                </a>
              </DropdownMenuItem>
              {awaiting && <DropdownMenuItem onSelect={() => setEditing("upload")}>Upload signed certificate…</DropdownMenuItem>}
              <DropdownMenuSeparator />
            </>
          )}
          {mayUpdate && (
            <>
              <DropdownMenuItem onSelect={() => setEditing("names")}>Permitted names…</DropdownMenuItem>
              <DropdownMenuItem onSelect={() => setEditing("validity")}>Validity…</DropdownMenuItem>
            </>
          )}
          {mayUpdate && issuing.notAfter && <DropdownMenuSeparator />}
          {issuing.notAfter && (
            <DropdownMenuItem asChild>
              <a href={api.issuingCaChainUrl(orgId, ca.id, issuing.id)} download>
                Download chain
              </a>
            </DropdownMenuItem>
          )}
          {(retirable || revocable) && <DropdownMenuSeparator />}
          {retirable && <DropdownMenuItem onSelect={() => setEditing("retire")}>Retire…</DropdownMenuItem>}
          {revocable && (
            <DropdownMenuItem variant="destructive" onSelect={() => setEditing("revoke")}>
              Revoke…
            </DropdownMenuItem>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
      <EditPermittedNamesDialog orgId={orgId} ca={ca} issuing={issuing} open={editing === "names"} onOpenChange={(open) => setEditing(open ? "names" : null)} />
      <EditValidityDialog orgId={orgId} ca={ca} issuing={issuing} open={editing === "validity"} onOpenChange={(open) => setEditing(open ? "validity" : null)} />
      {signedByOrganization && <UploadCertificateDialog orgId={orgId} ca={ca} issuing={issuing} open={editing === "upload"} onOpenChange={(open) => setEditing(open ? "upload" : null)} />}
      {retirable && <RetireDialog orgId={orgId} ca={ca} issuing={issuing} open={editing === "retire"} onOpenChange={(open) => setEditing(open ? "retire" : null)} />}
      {revocable && <RevokeIssuingCaDialog orgId={orgId} ca={ca} issuing={issuing} open={editing === "revoke"} onOpenChange={(open) => setEditing(open ? "revoke" : null)} />}
    </div>
  );
}

function RetireDialog({ orgId, ca, issuing, open, onOpenChange }: EditDialogProps) {
  const retire = useAction(() => api.retireIssuingCa(orgId, ca.id, issuing.id), ["private-cas"], () => {
    onOpenChange(false);
    toast.success(`${commonNameOf(issuing.subject)} was retired`);
  });
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(next) => {
        if (next) retire.reset();
        onOpenChange(next);
      }}
      title={`Retire ${commonNameOf(issuing.subject)}?`}
      description="It issues nothing more, and its Managed Certificates cannot renew until they are repointed to another Issuing CA. Its Certificates stay valid, and it keeps publishing its CRL until the last of them expires. The other Issuing CAs under the root are unaffected. It cannot be made active again."
      confirmLabel="Retire"
      pending={retire.isPending}
      error={retire.error}
      onConfirm={() => retire.mutate(undefined)}
    />
  );
}

function RevokeIssuingCaDialog({ orgId, ca, issuing, open, onOpenChange }: EditDialogProps) {
  const [reason, setReason] = useState("");
  const revoke = useAction(() => api.revokeIssuingCa(orgId, ca.id, issuing.id, reason), ["private-cas"], () => {
    onOpenChange(false);
    toast.success(`${commonNameOf(issuing.subject)} was revoked`);
  });
  const selectId = `issuing-ca-${issuing.id}-revocation-reason`;
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next) {
          setReason("");
          revoke.reset();
        }
        onOpenChange(next);
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Revoke {commonNameOf(issuing.subject)}?</DialogTitle>
          <DialogDescription>
            The root's CRL lists it at once, so relying parties distrust it and every Certificate it issued. It issues nothing more, and its Managed Certificates cannot renew until
            they are repointed to another Issuing CA. The other Issuing CAs under the root are unaffected. A revocation cannot be undone.
          </DialogDescription>
        </DialogHeader>
        <Field>
          <FieldLabel htmlFor={selectId}>Reason</FieldLabel>
          <Select value={reason} onValueChange={setReason}>
            <SelectTrigger id={selectId} className="w-full">
              <SelectValue placeholder="Choose a reason (RFC 5280)" />
            </SelectTrigger>
            <SelectContent>
              {issuingCaRevocationReasons().map(([value, text]) => (
                <SelectItem key={value} value={value}>
                  {text}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
        {revoke.error && <p className="text-sm text-destructive">{revoke.error.message}</p>}
        <DialogFooter>
          <DialogClose asChild>
            <Button type="button" variant="outline">
              Cancel
            </Button>
          </DialogClose>
          <Button variant="destructive" disabled={!reason || revoke.isPending} onClick={() => revoke.mutate(undefined)}>
            Revoke
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** Permitted name rules as they are typed: names and zones, a name to a line or a comma. */
type RulesText = { exact: string; zones: string };
const rulesOf = (text: RulesText): PermittedNames => ({ exact: splitNames(text.exact), zones: splitNames(text.zones) });
const hasRules = (text: RulesText) => splitNames(text.exact).length + splitNames(text.zones).length > 0;

/** The fields for an Issuing CA's permitted name rules. */
function PermittedNamesFields({ id, value, onChange }: { id: string; value: RulesText; onChange: (value: RulesText) => void }) {
  return (
    <>
      <div className="flex flex-col gap-2">
        <Label htmlFor={`${id}-zones`}>Permitted zones</Label>
        <Textarea id={`${id}-zones`} rows={3} value={value.zones} onChange={(e) => onChange({ ...value, zones: e.target.value })} placeholder="e.g. internal.example" />
        <p className="text-xs text-muted-foreground">Each zone permits its name and every name beneath it, wildcards included. One to a line.</p>
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor={`${id}-exact`}>Permitted names</Label>
        <Textarea id={`${id}-exact`} rows={3} value={value.exact} onChange={(e) => onChange({ ...value, exact: e.target.value })} placeholder="e.g. app.example.com" />
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

/** The fields for an Issuing CA's validity limits. */
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

type EditDialogProps = { orgId: string; ca: PrivateCa; issuing: IssuingCa; open: boolean; onOpenChange: (open: boolean) => void };
type EditFormProps = { orgId: string; ca: PrivateCa; issuing: IssuingCa; onDone: () => void };

function EditValidityDialog({ orgId, ca, issuing, open, onOpenChange }: EditDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Validity of {commonNameOf(issuing.subject)}</DialogTitle>
          <DialogDescription>
            How long the Certificates it issues from now on are valid for; Certificates already issued are unaffected. A Managed Certificate that chose more than a lowered maximum
            gets the maximum.
          </DialogDescription>
        </DialogHeader>
        {open && <EditValidityForm orgId={orgId} ca={ca} issuing={issuing} onDone={() => onOpenChange(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function EditValidityForm({ orgId, ca, issuing, onDone }: EditFormProps) {
  const [validity, setValidity] = useState<ValidityText>(validityTextOf(issuing.validity));
  const save = useAction(() => api.updateIssuingCa(orgId, ca.id, issuing.id, { validity: validityOfText(validity) }), ["private-cas"], onDone);
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        save.mutate(undefined);
      }}
    >
      <ValidityFields id={`issuing-ca-${issuing.id}-validity`} value={validity} onChange={setValidity} />
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

function EditPermittedNamesDialog({ orgId, ca, issuing, open, onOpenChange }: EditDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Permitted names of {commonNameOf(issuing.subject)}</DialogTitle>
          <DialogDescription>
            {ca.kind === "platform_root"
              ? "What it issues for from now on; Certificates already issued are unaffected. It keeps the name constraints it was made with, which relying parties enforce, so permitting names beyond them needs a new Issuing CA, which you can add under the same root."
              : "What it issues for from now on; Certificates already issued are unaffected. Relying parties also enforce whatever name constraints the Organization's root put in it, which these do not change."}
          </DialogDescription>
        </DialogHeader>
        {open && <EditPermittedNamesForm orgId={orgId} ca={ca} issuing={issuing} onDone={() => onOpenChange(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function EditPermittedNamesForm({ orgId, ca, issuing, onDone }: EditFormProps) {
  const [rules, setRules] = useState<RulesText>({ exact: issuing.permittedNames.exact.join("\n"), zones: issuing.permittedNames.zones.join("\n") });
  const save = useAction(() => api.updateIssuingCa(orgId, ca.id, issuing.id, { permittedNames: rulesOf(rules) }), ["private-cas"], onDone);
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        save.mutate(undefined);
      }}
    >
      <PermittedNamesFields id={`issuing-ca-${issuing.id}`} value={rules} onChange={setRules} />
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

/** A PEM field, typed or pasted, or read from a file chosen. */
function PemField({ id, label, value, onChange, placeholder, hint }: { id: string; label: string; value: string; onChange: (value: string) => void; placeholder: string; hint: string }) {
  const { accept, notice } = useCertificateText(onChange);
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between gap-2">
        <Label htmlFor={id}>{label}</Label>
        <Input
          type="file"
          accept=".pem,.crt,.cer,.txt"
          aria-label={`${label} from a file`}
          className="h-8 w-56 text-xs"
          onChange={async (e) => {
            const file = e.target.files?.[0];
            if (file) accept(await file.text());
          }}
        />
      </div>
      <Textarea id={id} rows={4} className="font-mono text-xs" value={value} onChange={(e) => accept(e.target.value)} placeholder={placeholder} />
      <p className="text-xs text-muted-foreground">{hint}</p>
      {notice}
    </div>
  );
}

const PEM_PLACEHOLDER = "-----BEGIN CERTIFICATE-----";

function UploadCertificateDialog({ orgId, ca, issuing, open, onOpenChange }: EditDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Upload the signed certificate of {commonNameOf(issuing.subject)}</DialogTitle>
          <DialogDescription>
            The certificate your root signed for its CSR. It is refused unless it is a CA certificate for the CSR's key and subject that verifies up to the root
            {ca.root ? `, ${commonNameOf(ca.root.subject)}, which ${ca.name} already has` : ""}. Once accepted it issues at once.
          </DialogDescription>
        </DialogHeader>
        {open && <UploadCertificateForm orgId={orgId} ca={ca} issuing={issuing} onDone={() => onOpenChange(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function UploadCertificateForm({ orgId, ca, issuing, onDone }: EditFormProps) {
  const [certificate, setCertificate] = useState("");
  const [root, setRoot] = useState("");
  const [chain, setChain] = useState("");
  // The root and chain above are uploaded once, with the first Issuing CA signed, and shared by the rest.
  const first = ca.root === null;
  const upload = useAction(
    () =>
      api.uploadIssuingCaCertificate(orgId, ca.id, issuing.id, {
        certificate: certificate.trim(),
        ...(first && { root: root.trim() }),
        ...(first && chain.trim() !== "" && { chain: chain.trim() }),
      }),
    ["private-cas"],
    onDone,
  );
  const ready = certificate.trim() !== "" && (!first || root.trim() !== "");
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        upload.mutate(undefined);
      }}
    >
      <PemField id={`upload-${issuing.id}-certificate`} label="Signed certificate" value={certificate} onChange={setCertificate} placeholder={PEM_PLACEHOLDER} hint="PEM, the Issuing CA's certificate alone." />
      {first && (
        <>
          <PemField
            id={`upload-${issuing.id}-root`}
            label="Root certificate"
            value={root}
            onChange={setRoot}
            placeholder={PEM_PLACEHOLDER}
            hint={`PEM, self-signed. Uploaded once: ${ca.name}'s other Issuing CAs share it.`}
          />
          <PemField
            id={`upload-${issuing.id}-chain`}
            label="Chain (optional)"
            value={chain}
            onChange={setChain}
            placeholder={PEM_PLACEHOLDER}
            hint="PEM, any CAs between the root and the Issuing CA, the one that signed it first. Leave empty when the root signed it itself."
          />
        </>
      )}
      {upload.error && <p className="text-sm text-destructive">{upload.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={!ready || upload.isPending}>
          Upload
        </Button>
      </DialogFooter>
    </form>
  );
}

const none = <span className="text-muted-foreground">None</span>;
const nameList = (names: string[]) => (names.length > 0 ? <ul className="flex flex-col gap-0.5 font-mono text-xs">{names.map((name) => <li key={name}>{name}</li>)}</ul> : none);

/** The review rows shared by both forms: an Issuing CA's permitted names and validity limits. */
const rulesRows = (rules: RulesText, validity: ValidityText) => {
  const permitted = rulesOf(rules);
  return [
    { label: "Permitted zones", value: nameList(permitted.zones) },
    { label: "Permitted names", value: nameList(permitted.exact) },
    { label: "Validity", value: validityLabel(validityOfText(validity)) },
  ];
};

const ADD_STEPS = [
  { id: "issuing", title: "Issuing CA", icon: FingerprintIcon },
  { id: "names", title: "Permitted names", icon: GlobeIcon },
  { id: "validity", title: "Validity", icon: CalendarClockIcon },
  { id: "review", title: "Review", icon: ClipboardCheckIcon },
] as const satisfies readonly Step<string>[];
type AddStepId = (typeof ADD_STEPS)[number]["id"];

function AddIssuingCaDialog({ orgId, ca, open, onOpenChange }: { orgId: string; ca: PrivateCa; open: boolean; onOpenChange: (open: boolean) => void }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className={STEPPED_DIALOG}>
        <DialogTitle className="sr-only">Add an Issuing CA to {ca.name}</DialogTitle>
        <DialogDescription className="sr-only">{addIssuingCaDescription(ca)}</DialogDescription>
        {/* Only mounted while open, so each opening starts from a clean form. */}
        {open && <AddIssuingCaForm orgId={orgId} ca={ca} onDone={() => onOpenChange(false)} />}
      </DialogContent>
    </Dialog>
  );
}

const addIssuingCaDescription = (ca: PrivateCa) =>
  ca.kind === "platform_root"
    ? "The platform makes a new key in the KMS and has the root sign it. It can issue at once, and whatever trusts the root trusts it; the other Issuing CAs are unaffected."
    : "The platform makes a new key in the KMS. Download its CSR from its row, have your root sign it, and upload the result; it issues once that is accepted. The other Issuing CAs are unaffected.";

function AddIssuingCaForm({ orgId, ca, onDone }: { orgId: string; ca: PrivateCa; onDone: () => void }) {
  const [step, setStep] = useState<AddStepId>("issuing");
  const [subject, setSubject] = useState("");
  // Empty for until the root ends.
  const [lifetimeYears, setLifetimeYears] = useState("");
  const [rules, setRules] = useState<RulesText>({ exact: "", zones: "" });
  const [validity, setValidity] = useState<ValidityText>(validityTextOf({ maximumDays: DEFAULT_VALIDITY_DAYS, defaultDays: DEFAULT_VALIDITY_DAYS }));
  const add = useAction(
    () =>
      api.addIssuingCa(orgId, ca.id, {
        subject: subject.trim(),
        ...(platformRoot && lifetimeYears.trim() !== "" && { lifetimeYears: Number(lifetimeYears) }),
        permittedNames: rulesOf(rules),
        validity: validityOfText(validity),
      }),
    ["private-cas"],
    onDone,
  );
  const platformRoot = ca.kind === "platform_root";
  const lifetimeOk = !platformRoot || lifetimeYears.trim() === "" || (/^\d+$/.test(lifetimeYears.trim()) && Number(lifetimeYears) >= 1 && Number(lifetimeYears) <= MAX_LIFETIME_YEARS);
  const untilRootEnds = `Until the root ends${ca.root ? `, ${date(ca.root.notAfter)}` : ""}`;
  const validityMissing = validityProblem(validity);
  const missing: Partial<Record<AddStepId, Missing>> = {
    issuing:
      subject.trim() === ""
        ? { reason: "Give the Issuing CA a subject, such as CN=Acme Internal TLS.", field: `add-issuing-${ca.id}-subject` }
        : !lifetimeOk
          ? { reason: `Give a lifetime of 1 to ${MAX_LIFETIME_YEARS} years, or leave it empty.`, field: `add-issuing-${ca.id}-lifetime` }
          : undefined,
    names: hasRules(rules) ? undefined : { reason: "Give at least one zone or exact name it may issue for.", field: `add-issuing-${ca.id}-zones` },
    validity: validityMissing ? { reason: validityMissing, field: `add-issuing-${ca.id}-validity-default` } : undefined,
  };
  return (
    <SteppedForm
      title={`Add an Issuing CA to ${ca.name}`}
      steps={ADD_STEPS}
      step={step}
      onStep={setStep}
      missing={missing}
      submitLabel="Add"
      pending={add.isPending}
      onSubmit={() => add.mutate(undefined)}
    >
      {step === "issuing" && (
        <FieldSet>
          <FieldLegend>The new Issuing CA</FieldLegend>
          <FieldDescription>{addIssuingCaDescription(ca)}</FieldDescription>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor={`add-issuing-${ca.id}-subject`}>Subject</FieldLabel>
              <Input
                id={`add-issuing-${ca.id}-subject`}
                className="font-mono text-xs"
                autoFocus
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                placeholder="e.g. CN=Acme Devices, O=Acme"
              />
              <FieldDescription>A distinguished name, with a common name, that no other Issuing CA of {ca.name} has.</FieldDescription>
            </Field>
            {platformRoot && (
              <Field data-invalid={!lifetimeOk}>
                <FieldLabel htmlFor={`add-issuing-${ca.id}-lifetime`}>Lifetime (years)</FieldLabel>
                {/* A Field stretches its children; the div keeps the input narrow. */}
                <div>
                  <Input
                    id={`add-issuing-${ca.id}-lifetime`}
                    type="number"
                    min={1}
                    max={MAX_LIFETIME_YEARS}
                    className="w-32"
                    value={lifetimeYears}
                    placeholder="Root's"
                    aria-invalid={!lifetimeOk}
                    onChange={(e) => setLifetimeYears(e.target.value)}
                  />
                </div>
                <FieldDescription>
                  Leave empty for until the root ends{ca.root ? `, ${date(ca.root.notAfter)}` : ""}. It never outlives the root, and no Certificate outlives it.
                </FieldDescription>
                {!lifetimeOk && <FieldError>A whole number of years from 1 to {MAX_LIFETIME_YEARS}.</FieldError>}
              </Field>
            )}
          </FieldGroup>
        </FieldSet>
      )}

      {step === "names" && (
        <FieldSet>
          <FieldLegend>Permitted names</FieldLegend>
          <FieldDescription>
            {platformRoot
              ? "It carries them as name constraints, which relying parties enforce. You can change the names later, but not those constraints without another Issuing CA, so prefer broad zones."
              : "The platform issues only for these. Relying parties enforce whatever name constraints your root puts in what it signs."}
          </FieldDescription>
          <PermittedNamesFields id={`add-issuing-${ca.id}`} value={rules} onChange={setRules} />
        </FieldSet>
      )}

      {step === "validity" && (
        <FieldSet>
          <FieldLegend>Validity</FieldLegend>
          <ValidityFields id={`add-issuing-${ca.id}-validity`} value={validity} onChange={setValidity} />
        </FieldSet>
      )}

      {step === "review" && (
        <FieldGroup>
          <FieldSet>
            <FieldLegend>Review</FieldLegend>
            <FieldDescription>Use Back to change anything.</FieldDescription>
            <SummaryRows
              rows={[
                { label: "Private CA", value: ca.name },
                { label: "Subject", value: <span className="break-all font-mono text-xs">{subject.trim()}</span> },
                ...(platformRoot ? [{ label: "Lifetime", value: lifetimeYears.trim() === "" ? untilRootEnds : `${Number(lifetimeYears)} ${Number(lifetimeYears) === 1 ? "year" : "years"}` }] : []),
                ...rulesRows(rules, validity),
              ]}
            />
          </FieldSet>
          {add.error && <FieldError>{add.error.message}</FieldError>}
        </FieldGroup>
      )}
    </SteppedForm>
  );
}

const CREATE_STEPS = [
  { id: "hierarchy", title: "Hierarchy", icon: NetworkIcon },
  { id: "issuing", title: "Issuing CA", icon: FingerprintIcon },
  { id: "key", title: "Key", icon: KeyRoundIcon },
  { id: "names", title: "Permitted names", icon: GlobeIcon },
  { id: "validity", title: "Validity", icon: CalendarClockIcon },
  { id: "review", title: "Review", icon: ClipboardCheckIcon },
] as const satisfies readonly Step<string>[];
type CreateStepId = (typeof CREATE_STEPS)[number]["id"];

function CreatePrivateCaDialog({ orgId }: { orgId: string }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          <ActionLabel>New Private CA</ActionLabel>
        </Button>
      </DialogTrigger>
      <DialogContent className={STEPPED_DIALOG}>
        <DialogTitle className="sr-only">New Private CA</DialogTitle>
        <DialogDescription className="sr-only">{CREATE_DESCRIPTION}</DialogDescription>
        {/* Only mounted while open, so each opening starts from a clean form. */}
        {open && <CreatePrivateCaForm orgId={orgId} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

const CREATE_DESCRIPTION =
  "A root and a first Issuing CA under it, its key in the KMS. The platform can make the root too, or your Organization's own root can sign the Issuing CA. You can add more Issuing CAs under the root later.";

const HIERARCHIES: { value: PrivateCa["kind"]; title: string; description: string }[] = [
  { value: "platform_root", title: "Platform root", description: "The platform makes a self-signed root and signs the Issuing CA with it. It issues at once." },
  {
    value: "organization_root",
    title: "Our own root",
    description: "The platform makes only the Issuing CA's key. You download its CSR, sign it with your root (often offline), and upload the result with the root.",
  },
];

function CreatePrivateCaForm({ orgId, onDone }: { orgId: string; onDone: () => void }) {
  const [step, setStep] = useState<CreateStepId>("hierarchy");
  // Before the first Private CA, the administrator confirms that relying parties reach where its Certificates send them.
  const existing = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId) }).data;
  const first = existing?.items.length === 0;
  const [acknowledged, setAcknowledged] = useState(false);
  const [kind, setKind] = useState<PrivateCa["kind"]>("platform_root");
  const platformRoot = kind === "platform_root";
  const [name, setName] = useState("");
  // CN=<name> until the subject is edited.
  const [typedSubject, setSubject] = useState<string | null>(null);
  const subject = typedSubject ?? (name.trim() ? `CN=${name.trim()}` : "");
  const [keyAlgorithm, setKeyAlgorithm] = useState<KeyAlgorithm>("ecdsa-p256");
  // What the server says its keys may be under the kind of root chosen.
  const underRoots = useKeyAlgorithms().data?.privateCaKeyAlgorithms;
  const offered = underRoots?.[kind] ?? [keyAlgorithm];
  const [lifetimeYears, setLifetimeYears] = useState("10");
  const [rules, setRules] = useState<RulesText>({ exact: "", zones: "" });
  const [validity, setValidity] = useState<ValidityText>(validityTextOf({ maximumDays: DEFAULT_VALIDITY_DAYS, defaultDays: DEFAULT_VALIDITY_DAYS }));
  const create = useAction(
    () =>
      api.createPrivateCa(orgId, {
        name: name.trim(),
        kind,
        subject: subject.trim(),
        keyAlgorithm,
        ...(platformRoot && { lifetimeYears: Number(lifetimeYears) }),
        permittedNames: rulesOf(rules),
        validity: validityOfText(validity),
      }),
    ["private-cas"],
    onDone,
  );
  const lifetimeOk = !platformRoot || (Number.isInteger(Number(lifetimeYears)) && Number(lifetimeYears) >= 1 && Number(lifetimeYears) <= MAX_LIFETIME_YEARS);
  const validityMissing = validityProblem(validity);
  const missing: Partial<Record<CreateStepId, Missing>> = {
    hierarchy:
      name.trim() === ""
        ? { reason: "Give the Private CA a name.", field: "private-ca-name" }
        : first && !acknowledged
          ? { reason: "Confirm that relying parties can fetch the addresses its Certificates will carry.", field: "publication-acknowledged" }
          : undefined,
    issuing: subject.trim() === "" ? { reason: "Give the Issuing CA a subject, such as CN=Acme Internal TLS.", field: "private-ca-subject" } : undefined,
    key: lifetimeOk ? undefined : { reason: `Give a lifetime of 1 to ${MAX_LIFETIME_YEARS} years.`, field: "private-ca-lifetime" },
    names: hasRules(rules) ? undefined : { reason: "Give at least one zone or exact name it may issue for.", field: "private-ca-new-zones" },
    validity: validityMissing ? { reason: validityMissing, field: "private-ca-new-validity-default" } : undefined,
  };
  const hierarchy = HIERARCHIES.find((h) => h.value === kind);
  return (
    <SteppedForm
      title="New Private CA"
      steps={CREATE_STEPS}
      step={step}
      onStep={setStep}
      missing={missing}
      submitLabel="Create"
      pending={create.isPending}
      onSubmit={() => create.mutate(undefined)}
    >
      {step === "hierarchy" && first && existing && (
        <PublicationCheck orgId={orgId} publication={existing.publication} acknowledged={acknowledged} onAcknowledge={setAcknowledged} />
      )}
      {step === "hierarchy" && (
        <FieldSet>
          <FieldLegend>Name and hierarchy</FieldLegend>
          <FieldDescription>{CREATE_DESCRIPTION}</FieldDescription>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="private-ca-name">Name</FieldLabel>
              <Input id="private-ca-name" autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Internal TLS" />
            </Field>
            <Field>
              <FieldLabel>Hierarchy</FieldLabel>
              <RadioGroup
                value={kind}
                onValueChange={(value) => {
                  setKind(value as PrivateCa["kind"]);
                  // A key algorithm not taken under the other kind of root falls back to the default.
                  const taken = underRoots?.[value as PrivateCa["kind"]];
                  if (taken && !taken.includes(keyAlgorithm)) setKeyAlgorithm("ecdsa-p256");
                }}
              >
                {HIERARCHIES.map((h) => (
                  <Label key={h.value} htmlFor={`private-ca-kind-${h.value}`} className="flex items-start gap-3 rounded-md border p-3 font-normal">
                    <RadioGroupItem value={h.value} id={`private-ca-kind-${h.value}`} className="mt-0.5" />
                    <span className="flex flex-col gap-1">
                      <span className="font-medium">{h.title}</span>
                      <span className="text-xs text-muted-foreground">{h.description}</span>
                    </span>
                  </Label>
                ))}
              </RadioGroup>
            </Field>
          </FieldGroup>
        </FieldSet>
      )}

      {step === "issuing" && (
        <FieldSet>
          <FieldLegend>{platformRoot ? "Issuing CA, signed by the root" : "Issuing CA, awaiting your root's signature"}</FieldLegend>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="private-ca-subject">Subject</FieldLabel>
              <Input id="private-ca-subject" className="font-mono text-xs" autoFocus value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="e.g. CN=Acme Internal TLS, O=Acme" />
              <FieldDescription>A distinguished name, with a common name.</FieldDescription>
            </Field>
            <Field>
              <FieldLabel>Root CA</FieldLabel>
              <div className="flex flex-col gap-1 rounded-md border p-3">
                {platformRoot ? (
                  <>
                    <span className="break-all font-mono text-xs">{subject.trim() ? rootSubjectOf(subject.trim()) : <span className="font-sans text-muted-foreground">From the Issuing CA's subject</span>}</span>
                    <p className="text-xs text-muted-foreground">Self-signed. Its subject is the Issuing CA's, with "Root" after the common name.</p>
                  </>
                ) : (
                  <p className="text-xs text-muted-foreground">Your Organization's own. You upload it, with any intermediates, together with the first Issuing CA's signed certificate.</p>
                )}
              </div>
            </Field>
          </FieldGroup>
        </FieldSet>
      )}

      {step === "key" && (
        <FieldSet>
          <FieldLegend>Key</FieldLegend>
          <FieldDescription>
            {platformRoot ? "For both the root and the Issuing CA, each with its own key. No Certificate outlives them." : "Of the Issuing CA's key. Your root decides how long the Issuing CA lasts."}
          </FieldDescription>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="private-ca-algorithm">Key algorithm</FieldLabel>
              <Select value={keyAlgorithm} onValueChange={(value) => setKeyAlgorithm(value as KeyAlgorithm)}>
                <SelectTrigger id="private-ca-algorithm" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {offered.map((value) => (
                    <SelectItem key={value} value={value}>
                      {KEY_ALGORITHM_LABELS[value]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {isMlDsa(keyAlgorithm) && (
                <FieldDescription>
                  Post-quantum, but only recent clients verify ML-DSA: OpenSSL 3.5 or later, and Chrome 150 or later; Firefox and Safari do not yet. Check every client that must trust
                  this root first. Its Certificates have ML-DSA keys too.
                </FieldDescription>
              )}
            </Field>
            {platformRoot && (
              <Field data-invalid={!lifetimeOk}>
                <FieldLabel htmlFor="private-ca-lifetime">Lifetime (years)</FieldLabel>
                {/* A Field stretches its children; the div keeps the input narrow. */}
                <div>
                  <Input
                    id="private-ca-lifetime"
                    type="number"
                    min={1}
                    max={MAX_LIFETIME_YEARS}
                    className="w-32"
                    value={lifetimeYears}
                    aria-invalid={!lifetimeOk}
                    onChange={(e) => setLifetimeYears(e.target.value)}
                  />
                </div>
                {!lifetimeOk && <FieldError>A whole number of years from 1 to {MAX_LIFETIME_YEARS}.</FieldError>}
              </Field>
            )}
          </FieldGroup>
        </FieldSet>
      )}

      {step === "names" && (
        <FieldSet>
          <FieldLegend>Permitted names</FieldLegend>
          <FieldDescription>
            {platformRoot
              ? "The Issuing CA carries them as name constraints, which relying parties enforce. You can change the names later, but not those constraints without a new Issuing CA, so prefer broad zones."
              : "The platform issues only for these. Relying parties enforce whatever name constraints your root puts in what it signs."}
          </FieldDescription>
          <PermittedNamesFields id="private-ca-new" value={rules} onChange={setRules} />
        </FieldSet>
      )}

      {step === "validity" && (
        <FieldSet>
          <FieldLegend>Validity</FieldLegend>
          <ValidityFields id="private-ca-new-validity" value={validity} onChange={setValidity} />
        </FieldSet>
      )}

      {step === "review" && (
        <FieldGroup>
          <FieldSet>
            <FieldLegend>Review</FieldLegend>
            <FieldDescription>Use Back to change anything.</FieldDescription>
            <SummaryRows
              rows={[
                { label: "Name", value: name.trim() },
                { label: "Hierarchy", value: hierarchy?.title ?? kind },
                { label: "Root CA", value: platformRoot ? <span className="break-all font-mono text-xs">{rootSubjectOf(subject.trim())}</span> : "Your Organization's own, uploaded later" },
                { label: "Issuing CA", value: <span className="break-all font-mono text-xs">{subject.trim()}</span> },
                { label: "Key algorithm", value: KEY_ALGORITHM_LABELS[keyAlgorithm] },
                { label: "Lifetime", value: platformRoot ? `${Number(lifetimeYears)} ${Number(lifetimeYears) === 1 ? "year" : "years"}` : "Set by your root" },
                ...rulesRows(rules, validity),
              ]}
            />
          </FieldSet>
          {create.error && <FieldError>{create.error.message}</FieldError>}
        </FieldGroup>
      )}
    </SteppedForm>
  );
}
