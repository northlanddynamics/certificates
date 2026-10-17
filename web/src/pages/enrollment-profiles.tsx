import { useMutation, useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { createColumnHelper, tableFeatures, useTable } from "@tanstack/react-table";
import { CheckIcon, ClipboardCheckIcon, KeyRoundIcon, LandmarkIcon, MoreHorizontalIcon, PlusIcon, ScrollTextIcon, ShieldCheckIcon, type LucideIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import {
  DEFAULT_DEVICE_EXTENDED_KEY_USAGES,
  DEFAULT_DEVICE_KEY_USAGES,
  DEFAULT_DEVICE_RETENTION_DAYS,
  DEFAULT_DEVICE_VALIDITY_DAYS,
  DEVICE_EXTENDED_KEY_USAGE_NAMES,
  DEVICE_KEY_TYPES,
  DEVICE_KEY_USAGES,
  MAX_DEVICE_RETENTION_DAYS,
  MAX_DEVICE_VALIDITY_DAYS,
  type DeviceExtendedKeyUsage,
  type DeviceKeyType,
  type DeviceKeyUsage,
} from "../../../server/src/enrollment-profile-kinds";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { DataTable } from "@/components/data-table/data-table";
import { Badge } from "@/components/ui/badge";
import { Breadcrumb, BreadcrumbItem, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sidebar, SidebarContent, SidebarGroup, SidebarGroupContent, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarProvider } from "@/components/ui/sidebar";
import { api, can, type EnrollmentProfile } from "@/lib/api";
import { daysLabel, findIssuingCa, issuingCaTitle, isValidityDays } from "@/lib/private-ca";
import { useAction } from "@/lib/use-action";
import { EMPTY_NAME_RULES, NameRulesEditor, draftOf, nameRulesSummary, rulesOf, takesNameRules as kindTakesNameRules } from "./name-rules-editor";

const ROUTE = "/app/organizations/$orgId/enrollment-profiles";

const EXTENDED_KEY_USAGE_LABEL: Record<DeviceExtendedKeyUsage, string> = {
  clientAuth: "Client authentication",
  serverAuth: "Server authentication",
  emailProtection: "Email protection",
  ipsecIKE: "IPsec IKE",
  smartcardLogon: "Smart card logon",
};
const KEY_USAGE_LABEL: Record<DeviceKeyUsage, string> = {
  digitalSignature: "Digital signature",
  nonRepudiation: "Non-repudiation",
  keyEncipherment: "Key encipherment",
  dataEncipherment: "Data encipherment",
  keyAgreement: "Key agreement",
};
const STEPS = [
  { id: "issuer", title: "Issuing CA", icon: LandmarkIcon },
  { id: "certificate", title: "Certificate", icon: ScrollTextIcon },
  { id: "keys", title: "Device keys", icon: KeyRoundIcon },
  { id: "validator", title: "Enrollment Validator", icon: ShieldCheckIcon },
  { id: "review", title: "Review", icon: ClipboardCheckIcon },
] as const satisfies readonly { id: string; title: string; icon: LucideIcon }[];
type StepId = (typeof STEPS)[number]["id"];

// An Intune Enrollment Validator is configured with the Entra app that signs in to Graph and Intune: a tenant (its ID
// or a domain of it) and an app ID. The server checks them too (server/src/intune.ts).
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TENANT = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})$/i;
const VALIDATOR_LABEL: Record<string, string> = { intune: "Microsoft Intune" };
const validatorLabel = (kind: string) => VALIDATOR_LABEL[kind] ?? kind;

const KEY_TYPE_LABEL: Record<DeviceKeyType, string> = { "rsa-2048": "RSA 2048", "rsa-3072": "RSA 3072", "rsa-4096": "RSA 4096" };

// The server lists every profile; an Organization has a handful.
const features = tableFeatures({});
const columnHelper = createColumnHelper<typeof features, EnrollmentProfile>();
const columns = columnHelper.columns([
  columnHelper.accessor("name", {
    header: "Name",
    cell: ({ row }) => (
      <span className="flex items-center gap-2">
        <DeviceCertificatesLink profile={row.original} />
        {!row.original.enabled && <Badge variant="secondary">Disabled</Badge>}
      </span>
    ),
  }),
  columnHelper.accessor("scepUrl", {
    header: "SCEP URL",
    cell: ({ cell }) => <span className="break-all font-mono text-xs">{cell.getValue()}</span>,
  }),
  columnHelper.display({
    id: "issues",
    header: "Issues",
    cell: ({ row }) => <Issues profile={row.original} />,
  }),
  columnHelper.display({ id: "actions", header: () => <span className="sr-only">Actions</span>, cell: ({ row }) => <ProfileActions profile={row.original} /> }),
]);
const noRows: EnrollmentProfile[] = [];

/**
 * The Organization's Enrollment Profiles: each fixes what the Device Certificates devices obtain from an Issuing CA
 * look like, and has a SCEP URL to paste into the device management platform, with the CA certificate its trusted
 * certificate profile needs.
 */
export function EnrollmentProfilesPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.organizations.find((o) => o.id === orgId) }).data;
  const allowed = org ? can(org, "enrollmentProfile", "read") : false;
  const profiles = useQuery({ queryKey: ["enrollment-profiles", orgId], queryFn: () => api.enrollmentProfiles(orgId), enabled: allowed });
  const table = useTable({ features, columns, data: profiles.data?.items ?? noRows, getRowId: (p) => p.id });

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">Enrollment Profiles</h1>
        {org && can(org, "enrollmentProfile", "create") && <NewProfileDialog orgId={orgId} />}
      </div>
      <p className="text-sm text-muted-foreground">
        Devices enroll at a profile's SCEP URL and get a Device Certificate from its Issuing CA, with the profile's key usage, extended key usages and validity, and the
        subject and names of their own request. Paste the SCEP URL into your device management platform's SCEP profile, and give its trusted certificate profile the
        root.
      </p>
      {org && !allowed ? (
        <p className="text-sm text-muted-foreground">Only Organization Administrators see the Enrollment Profiles.</p>
      ) : (
        <div className="flex flex-col gap-4">
          <DataTable table={table} empty={profiles.isPending ? "Loading…" : "No Enrollment Profile yet."} />
          {profiles.error && <p className="text-sm text-destructive">{profiles.error.message}</p>}
        </div>
      )}
    </div>
  );
}

/**
 * What a profile issues, and from which Issuing CA; when that one no longer issues (it was retired, say), that the
 * profile refuses every device until it is pointed at an active one.
 */
function Issues({ profile }: { profile: EnrollmentProfile }) {
  const { orgId } = useParams({ from: ROUTE });
  const privateCas = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId) });
  const issuing = findIssuingCa(privateCas.data?.items ?? [], profile.issuingCaId);
  const issues = privateCas.data?.items.find((ca) => ca.id === profile.privateCaId)?.status === "active" && issuing?.status === "active";
  return (
    <span className="flex flex-col gap-1 text-sm">
      <span>
        {profile.extendedKeyUsage.map((usage) => EXTENDED_KEY_USAGE_LABEL[usage]).join(", ")} for {daysLabel(profile.validityDays)}
      </span>
      {issuing && <span className="text-xs text-muted-foreground">from {issuing.name}</span>}
      {issuing && !issues && profile.enabled && (
        <span className="max-w-72 whitespace-normal text-xs text-destructive">{issuing.status === "active" ? "Its Issuing CA's root does not issue" : `Its Issuing CA is ${issuing.status}`}, so every device is refused: point the profile at an active Issuing CA.</span>
      )}
    </span>
  );
}

/** A profile's name, as the way to its Device Certificates. */
function DeviceCertificatesLink({ profile }: { profile: EnrollmentProfile }) {
  const { orgId } = useParams({ from: ROUTE });
  return (
    <Link to="/organizations/$orgId/enrollment-profiles/$id/device-certificates" params={{ orgId, id: profile.id }} className="font-medium underline-offset-4 hover:underline">
      {profile.name}
    </Link>
  );
}

/**
 * A profile's actions: test its Enrollment Validator's connection, and a menu of its Device Certificates, its SCEP URL
 * and the certificates devices must trust, and, for those who may change it, pointing it at another Issuing CA, its
 * retention period, its Name Rules (when its validator does not vouch for names), rotating its RA certificate and
 * disabling it. A test that works is a toast, with what it could not
 * prove; one that fails stays by the buttons, where its reason can be read.
 */
function ProfileActions({ profile }: { profile: EnrollmentProfile }) {
  const { orgId } = useParams({ from: ROUTE });
  const org = useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.organizations.find((o) => o.id === orgId) }).data;
  const mayUpdate = org ? can(org, "enrollmentProfile", "update") : false;
  const mayDisable = org ? can(org, "enrollmentProfile", "disable") && profile.enabled : false;
  const kinds = useQuery({ queryKey: ["enrollment-validator-kinds", orgId], queryFn: () => api.enrollmentValidatorKinds(orgId), enabled: mayUpdate });
  const takesNameRules = kindTakesNameRules(kinds.data?.items, profile.validator.kind);
  const [editing, setEditing] = useState<"issuing-ca" | "retention" | "name-rules" | "rotate" | "disable" | null>(null);
  const openOne = (which: NonNullable<typeof editing>) => (open: boolean) => setEditing(open ? which : null);
  const test = useMutation({
    mutationFn: () => api.testEnrollmentValidator(orgId, profile.id),
    onSuccess: (result) => {
      if (result.ok) toast.success(`${profile.name}: ${validatorLabel(profile.validator.kind)} can be reached`, { description: result.note });
    },
  });
  return (
    <div className="flex flex-col items-end gap-2">
      <div className="flex items-center justify-end gap-2">
        {org && can(org, "enrollmentProfile", "update") && (
          <Button variant="outline" size="sm" disabled={test.isPending} aria-label={`Test the Enrollment Validator of ${profile.name}`} onClick={() => test.mutate()}>
            {test.isPending ? "Testing…" : "Test"}
          </Button>
        )}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${profile.name}`}>
              <MoreHorizontalIcon />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuItem asChild>
              <Link to="/organizations/$orgId/enrollment-profiles/$id/device-certificates" params={{ orgId, id: profile.id }}>
                Device Certificates
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => void navigator.clipboard.writeText(profile.scepUrl)}>Copy SCEP URL</DropdownMenuItem>
            <DropdownMenuItem asChild>
              <a href={api.enrollmentProfileCaCertificateUrl(orgId, profile.id, "root")} download>
                Download root certificate
              </a>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <a href={api.enrollmentProfileCaCertificateUrl(orgId, profile.id, "issuing")} download>
                Download Issuing CA certificate
              </a>
            </DropdownMenuItem>
            {(mayUpdate || mayDisable) && <DropdownMenuSeparator />}
            {mayUpdate && <DropdownMenuItem onSelect={() => setEditing("issuing-ca")}>Change Issuing CA…</DropdownMenuItem>}
            {mayUpdate && <DropdownMenuItem onSelect={() => setEditing("retention")}>Retention period…</DropdownMenuItem>}
            {mayUpdate && takesNameRules && <DropdownMenuItem onSelect={() => setEditing("name-rules")}>Name Rules…</DropdownMenuItem>}
            {mayUpdate && <DropdownMenuItem onSelect={() => setEditing("rotate")}>Rotate RA certificate…</DropdownMenuItem>}
            {mayDisable && (
              <DropdownMenuItem variant="destructive" onSelect={() => setEditing("disable")}>
                Disable…
              </DropdownMenuItem>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
      {mayUpdate && <IssuingCaDialog profile={profile} open={editing === "issuing-ca"} onOpenChange={openOne("issuing-ca")} />}
      {mayUpdate && <RetentionDialog profile={profile} open={editing === "retention"} onOpenChange={openOne("retention")} />}
      {mayUpdate && takesNameRules && <NameRulesDialog profile={profile} open={editing === "name-rules"} onOpenChange={openOne("name-rules")} />}
      {mayUpdate && <RotateRaDialog profile={profile} open={editing === "rotate"} onOpenChange={openOne("rotate")} />}
      {mayDisable && <DisableDialog profile={profile} open={editing === "disable"} onOpenChange={openOne("disable")} />}
      {test.data && !test.data.ok && <span role="alert" className="max-w-72 whitespace-normal break-words text-right text-sm text-destructive">{test.data.error}</span>}
      {test.error && <span role="alert" className="max-w-72 whitespace-normal break-words text-right text-sm text-destructive">{test.error.message}</span>}
    </div>
  );
}

type ProfileDialogProps = { profile: EnrollmentProfile; open: boolean; onOpenChange: (open: boolean) => void };

/** Points the profile at another active Issuing CA, as when its own is retired; the new one signs it a new RA certificate. */
function IssuingCaDialog({ profile, open, onOpenChange }: ProfileDialogProps) {
  const { orgId } = useParams({ from: ROUTE });
  const privateCas = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId), enabled: open });
  const choices = (privateCas.data?.items ?? []).flatMap((ca) =>
    ca.status === "active" ? ca.issuingCas.filter((i) => i.status === "active" && i.id !== profile.issuingCaId).map((i) => ({ id: i.id, title: issuingCaTitle(ca.name, i.subject), privateCaId: ca.id })) : [],
  );
  const [issuingCaId, setIssuingCaId] = useState("");
  const chosen = choices.find((c) => c.id === issuingCaId);
  const save = useAction(() => api.updateEnrollmentProfile(orgId, profile.id, { issuingCaId }), ["enrollment-profiles"], () => onOpenChange(false));
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next) {
          save.reset();
          setIssuingCaId("");
        }
        onOpenChange(next);
      }}
    >
      <DialogContent>
        <form
          className="flex flex-col gap-4"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            if (issuingCaId) save.mutate(undefined);
          }}
        >
          <DialogHeader>
            <DialogTitle>Change the Issuing CA of {profile.name}</DialogTitle>
            <DialogDescription>
              Devices enroll from the new Issuing CA, which signs the profile a new RA certificate. What the old one issued stays its own, and on its CRL once revoked.
            </DialogDescription>
          </DialogHeader>
          <Field>
            <FieldLabel htmlFor={`profile-${profile.id}-issuing-ca`}>Issuing CA</FieldLabel>
            <Select value={issuingCaId} onValueChange={setIssuingCaId}>
              <SelectTrigger id={`profile-${profile.id}-issuing-ca`} className="w-full">
                <SelectValue placeholder={privateCas.isPending ? "Loading…" : choices.length === 0 ? "No other active Issuing CA" : "Choose an Issuing CA"} />
              </SelectTrigger>
              <SelectContent>
                {choices.map((c) => (
                  <SelectItem key={c.id} value={c.id}>
                    {c.title}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {chosen && chosen.privateCaId !== profile.privateCaId && (
              <FieldDescription>It is under another root: give your device management platform's trusted certificate profile the new root before devices enroll again.</FieldDescription>
            )}
          </Field>
          {save.error && <FieldError>{save.error.message}</FieldError>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!issuingCaId || save.isPending}>
              Change Issuing CA
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

const isRetentionDays = (text: string) => /^\d+$/.test(text.trim()) && Number(text) <= MAX_DEVICE_RETENTION_DAYS;

/** How long after they end the profile's Device Certificates are kept before they are pruned. */
function RetentionDialog({ profile, open, onOpenChange }: ProfileDialogProps) {
  const { orgId } = useParams({ from: ROUTE });
  const [days, setDays] = useState(String(profile.retentionDays));
  const ok = isRetentionDays(days);
  const save = useAction(() => api.updateEnrollmentProfile(orgId, profile.id, { retentionDays: Number(days) }), ["enrollment-profiles"], () => onOpenChange(false));
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next) {
          save.reset();
          setDays(String(profile.retentionDays));
        }
        onOpenChange(next);
      }}
    >
      <DialogContent>
        <form
          className="flex flex-col gap-4"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            if (ok) save.mutate(undefined);
          }}
        >
          <DialogHeader>
            <DialogTitle>Retention period of {profile.name}</DialogTitle>
            <DialogDescription>A Device Certificate is deleted this long after it ends. Its Audit Events are kept.</DialogDescription>
          </DialogHeader>
          <Field data-invalid={!ok}>
            <FieldLabel htmlFor={`profile-${profile.id}-retention`}>Retention (days)</FieldLabel>
            <Input id={`profile-${profile.id}-retention`} inputMode="numeric" autoFocus value={days} onChange={(e) => setDays(e.target.value)} aria-invalid={!ok} />
            <FieldDescription>Up to {daysLabel(MAX_DEVICE_RETENTION_DAYS)}; 0 deletes them as soon as they end.</FieldDescription>
          </Field>
          {save.error && <FieldError>{save.error.message}</FieldError>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!ok || save.isPending}>
              Save
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** Adds, changes or removes the Name Rules of a profile whose validator does not vouch for names, for its next request. */
function NameRulesDialog({ profile, open, onOpenChange }: ProfileDialogProps) {
  const { orgId } = useParams({ from: ROUTE });
  const [draft, setDraft] = useState(() => draftOf(profile.nameRules));
  const parsed = rulesOf(draft);
  const save = useAction(
    () => api.updateEnrollmentProfile(orgId, profile.id, { nameRules: "rules" in parsed ? parsed.rules : null }),
    ["enrollment-profiles"],
    () => onOpenChange(false),
  );
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next) {
          save.reset();
          setDraft(draftOf(profile.nameRules));
        }
        onOpenChange(next);
      }}
    >
      <DialogContent className="sm:max-w-xl">
        <form
          className="flex flex-col gap-4"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            if ("rules" in parsed) save.mutate(undefined);
          }}
        >
          <DialogHeader>
            <DialogTitle>Name Rules of {profile.name}</DialogTitle>
            <DialogDescription>They apply from the next request on. Device Certificates already issued are kept.</DialogDescription>
          </DialogHeader>
          <NameRulesEditor id={`profile-${profile.id}-name-rules`} draft={draft} onChange={setDraft} />
          {save.error && <FieldError>{save.error.message}</FieldError>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!("rules" in parsed) || save.isPending}>
              Save
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** Has the profile's Issuing CA sign it a new RA certificate for a new key, which devices are given from then on. */
function RotateRaDialog({ profile, open, onOpenChange }: ProfileDialogProps) {
  const { orgId } = useParams({ from: ROUTE });
  const rotate = useAction(
    () => api.rotateEnrollmentProfileRa(orgId, profile.id),
    ["enrollment-profiles"],
    () => {
      onOpenChange(false);
      toast.success(`${profile.name}: the RA certificate was replaced`);
    },
  );
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(next) => {
        if (next) rotate.reset();
        onOpenChange(next);
      }}
      title={`Rotate the RA certificate of ${profile.name}?`}
      description={`Its Issuing CA signs a new RA certificate for a new key, which devices are given from now on. The current one ends ${new Date(profile.raCertificate.notAfter).toLocaleDateString()}. A device midway through enrolling with the old one enrolls again.`}
      confirmLabel="Rotate"
      pending={rotate.isPending}
      error={rotate.error}
      onConfirm={() => rotate.mutate(undefined)}
    />
  );
}

/** Disables the profile for good: it refuses every device, and keeps its Device Certificates. */
function DisableDialog({ profile, open, onOpenChange }: ProfileDialogProps) {
  const { orgId } = useParams({ from: ROUTE });
  const disable = useAction(() => api.disableEnrollmentProfile(orgId, profile.id), ["enrollment-profiles"], () => onOpenChange(false));
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(next) => {
        if (next) disable.reset();
        onOpenChange(next);
      }}
      title={`Disable ${profile.name}?`}
      description="Every device that enrolls at its SCEP URL is refused from now on. Its Device Certificates are kept, and revoked ones stay on the CRL. A disabled profile cannot be enabled again."
      confirmLabel="Disable"
      pending={disable.isPending}
      error={disable.error}
      onConfirm={() => disable.mutate(undefined)}
    />
  );
}

function NewProfileDialog({ orgId }: { orgId: string }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          New profile
        </Button>
      </DialogTrigger>
      <DialogContent className="gap-0 overflow-hidden p-0 sm:max-w-[calc(100%-2rem)] md:max-w-[760px] lg:max-w-[860px]">
        <DialogTitle className="sr-only">New Enrollment Profile</DialogTitle>
        <DialogDescription className="sr-only">The platform makes the profile's SCEP RA key, which it keeps, and has the Issuing CA sign its certificate.</DialogDescription>
        {/* Only mounted while open, so each opening starts from a clean form. */}
        {open && <NewProfileForm orgId={orgId} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

/** Checkboxes for some of `values`, at least one. */
function Choices<T extends string>({ legend, id, values, labels, chosen, onChange }: { legend: string; id: string; values: readonly T[]; labels: Record<T, string>; chosen: T[]; onChange: (chosen: T[]) => void }) {
  return (
    <FieldSet>
      <FieldLegend variant="label">{legend}</FieldLegend>
      <FieldGroup className="gap-2">
        {values.map((value) => (
          <Field key={value} orientation="horizontal">
            <Checkbox
              id={`${id}-${value}`}
              checked={chosen.includes(value)}
              onCheckedChange={(on) => onChange(on === true ? values.filter((v) => v === value || chosen.includes(v)) : chosen.filter((v) => v !== value))}
            />
            <FieldLabel htmlFor={`${id}-${value}`} className="font-normal">
              {labels[value]}
            </FieldLabel>
          </Field>
        ))}
      </FieldGroup>
      {chosen.length === 0 && <FieldError>Choose at least one.</FieldError>}
    </FieldSet>
  );
}

// Every step's state lives in the form, so moving between steps never loses what was entered.
function NewProfileForm({ orgId, onDone }: { orgId: string; onDone: () => void }) {
  const [step, setStep] = useState<StepId>("issuer");
  const privateCas = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId) });
  const kinds = useQuery({ queryKey: ["enrollment-validator-kinds", orgId], queryFn: () => api.enrollmentValidatorKinds(orgId) });
  // Only an active Issuing CA under an active root issues.
  const issuingCas = (privateCas.data?.items ?? []).flatMap((ca) => (ca.status === "active" ? ca.issuingCas.filter((i) => i.status === "active").map((i) => ({ id: i.id, title: issuingCaTitle(ca.name, i.subject) })) : []));
  const [name, setName] = useState("");
  const [issuingCaId, setIssuingCaId] = useState("");
  const [validityDays, setValidityDays] = useState(String(DEFAULT_DEVICE_VALIDITY_DAYS));
  const [retentionDays, setRetentionDays] = useState(String(DEFAULT_DEVICE_RETENTION_DAYS));
  const [extendedKeyUsage, setExtendedKeyUsage] = useState<DeviceExtendedKeyUsage[]>(DEFAULT_DEVICE_EXTENDED_KEY_USAGES);
  const [keyUsage, setKeyUsage] = useState<DeviceKeyUsage[]>(DEFAULT_DEVICE_KEY_USAGES);
  const [allowedKeyTypes, setAllowedKeyTypes] = useState<DeviceKeyType[]>([...DEVICE_KEY_TYPES]);
  const [validatorKind, setValidatorKind] = useState("");
  const kind = validatorKind || kinds.data?.items[0]?.kind || "";
  const [tenantId, setTenantId] = useState("");
  const [appId, setAppId] = useState("");
  const [appSecret, setAppSecret] = useState("");
  const intune = kind === "intune";
  // Only a validator that does not vouch for names takes Name Rules, and they stay optional.
  const takesNameRules = kindTakesNameRules(kinds.data?.items, kind);
  const [nameRulesDraft, setNameRulesDraft] = useState(EMPTY_NAME_RULES);
  const nameRules = takesNameRules ? rulesOf(nameRulesDraft) : { rules: null };
  const intuneOk = TENANT.test(tenantId.trim()) && GUID.test(appId.trim()) && appSecret !== "";
  const validator = intune ? { kind, settings: { tenantId: tenantId.trim(), appId: appId.trim() }, secret: appSecret } : { kind };
  const create = useAction(
    () => api.createEnrollmentProfile(orgId, { name: name.trim(), issuingCaId, validityDays: Number(validityDays), retentionDays: Number(retentionDays), keyUsage, extendedKeyUsage, allowedKeyTypes, validator, ...("rules" in nameRules && nameRules.rules && { nameRules: nameRules.rules }) }),
    ["enrollment-profiles"],
    onDone,
  );
  const validityOk = isValidityDays(validityDays, MAX_DEVICE_VALIDITY_DAYS);
  const retentionOk = isRetentionDays(retentionDays);

  // Whether each step holds what it needs; Review only shows what was entered.
  const complete: Record<StepId, boolean> = {
    issuer: name.trim() !== "" && issuingCaId !== "",
    certificate: validityOk && retentionOk && extendedKeyUsage.length > 0 && keyUsage.length > 0,
    keys: allowedKeyTypes.length > 0,
    validator: kind !== "" && (!intune || intuneOk) && "rules" in nameRules,
    review: true,
  };
  const index = STEPS.findIndex((s) => s.id === step);
  const last = index === STEPS.length - 1;
  // A step may be opened once every step before it is complete.
  const reachable = (i: number) => STEPS.slice(0, i).every((s) => complete[s.id]);
  const goTo = (i: number) => {
    const target = STEPS[i];
    if (target && reachable(i)) setStep(target.id);
  };

  return (
    <SidebarProvider className="h-[min(600px,85vh)] min-h-0 items-stretch">
      <Sidebar collapsible="none" className="hidden border-r md:flex">
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupContent>
              <SidebarMenu>
                {STEPS.map((s, i) => {
                  const done = i < index && complete[s.id];
                  return (
                    <SidebarMenuItem key={s.id}>
                      <SidebarMenuButton isActive={s.id === step} disabled={!reachable(i)} onClick={() => goTo(i)}>
                        {done ? <CheckIcon className="text-primary" /> : <s.icon />}
                        <span>{s.title}</span>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  );
                })}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>
      </Sidebar>
      <form
        className="flex min-w-0 flex-1 flex-col"
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          if (!last) goTo(index + 1);
          else if (STEPS.every((s) => complete[s.id])) create.mutate(undefined);
        }}
      >
        <header className="flex h-14 shrink-0 items-center justify-between gap-2 px-4 pr-12">
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem className="hidden md:block">New Enrollment Profile</BreadcrumbItem>
              <BreadcrumbSeparator className="hidden md:block" />
              <BreadcrumbItem>
                <BreadcrumbPage>{STEPS[index]?.title}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
          <span className="text-xs text-muted-foreground">
            Step {index + 1} of {STEPS.length}
          </span>
        </header>
        <div className="flex flex-1 flex-col gap-4 overflow-y-auto p-4 pt-0">
          {step === "issuer" && (
            <FieldSet>
              <FieldLegend>Name it and choose its Issuing CA</FieldLegend>
              <FieldDescription>The platform makes the profile's SCEP RA key, which it keeps, and has the Issuing CA sign its certificate.</FieldDescription>
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="profile-name">Name</FieldLabel>
                  <Input id="profile-name" autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="Wi-Fi" />
                </Field>
                <Field>
                  <FieldLabel htmlFor="profile-issuing-ca">Issuing CA</FieldLabel>
                  <Select value={issuingCaId} onValueChange={setIssuingCaId}>
                    <SelectTrigger id="profile-issuing-ca" className="w-full">
                      <SelectValue placeholder={privateCas.isPending ? "Loading…" : issuingCas.length === 0 ? "No active Issuing CA" : "Choose an Issuing CA"} />
                    </SelectTrigger>
                    <SelectContent>
                      {issuingCas.map((i) => (
                        <SelectItem key={i.id} value={i.id}>
                          {i.title}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FieldDescription>Only an active Issuing CA under an active root can be chosen.</FieldDescription>
                </Field>
              </FieldGroup>
            </FieldSet>
          )}

          {step === "certificate" && (
            <FieldGroup>
              <Field data-invalid={!validityOk}>
                <FieldLabel htmlFor="profile-validity">Validity (days)</FieldLabel>
                <Input id="profile-validity" inputMode="numeric" autoFocus value={validityDays} onChange={(e) => setValidityDays(e.target.value)} aria-invalid={!validityOk} />
                <FieldDescription>Up to {daysLabel(MAX_DEVICE_VALIDITY_DAYS)}, and never past the Issuing CA's end.</FieldDescription>
              </Field>
              <Field data-invalid={!retentionOk}>
                <FieldLabel htmlFor="profile-retention">Retention (days)</FieldLabel>
                <Input id="profile-retention" inputMode="numeric" value={retentionDays} onChange={(e) => setRetentionDays(e.target.value)} aria-invalid={!retentionOk} />
                <FieldDescription>How long after it ends a Device Certificate is kept before it is deleted; its Audit Events are kept.</FieldDescription>
              </Field>
              <div className="grid gap-6 sm:grid-cols-2">
                <Choices legend="Key usage" id="profile-ku" values={DEVICE_KEY_USAGES} labels={KEY_USAGE_LABEL} chosen={keyUsage} onChange={setKeyUsage} />
                <Choices legend="Extended key usage" id="profile-eku" values={DEVICE_EXTENDED_KEY_USAGE_NAMES} labels={EXTENDED_KEY_USAGE_LABEL} chosen={extendedKeyUsage} onChange={setExtendedKeyUsage} />
              </div>
            </FieldGroup>
          )}

          {step === "keys" && (
            <FieldGroup>
              <FieldDescription>A device whose request is for any other kind of key is refused.</FieldDescription>
              <Choices legend="Device keys allowed" id="profile-keys" values={DEVICE_KEY_TYPES} labels={KEY_TYPE_LABEL} chosen={allowedKeyTypes} onChange={setAllowedKeyTypes} />
            </FieldGroup>
          )}

          {step === "validator" && (
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="profile-validator">Enrollment Validator</FieldLabel>
                {kinds.data && kinds.data.items.length === 0 ? (
                  <FieldDescription>The platform runs no Enrollment Validator yet, so no profile can be created.</FieldDescription>
                ) : (
                  <Select value={kind} onValueChange={setValidatorKind}>
                    <SelectTrigger id="profile-validator" className="w-full">
                      <SelectValue placeholder="Loading…" />
                    </SelectTrigger>
                    <SelectContent>
                      {(kinds.data?.items ?? []).map((k) => (
                        <SelectItem key={k.kind} value={k.kind}>
                          {validatorLabel(k.kind)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              </Field>
              {intune && (
                <FieldSet>
                  <FieldLegend variant="label">Entra app</FieldLegend>
                  <FieldDescription>
                    Register an app in Microsoft Entra ID with a client secret, give it the application permissions Intune → scep_challenge_provider and Microsoft Graph →
                    Application.Read.All, and grant admin consent. Intune then validates each device's request, and is told what became of it.
                  </FieldDescription>
                  <FieldGroup>
                    <Field data-invalid={tenantId.trim() !== "" && !TENANT.test(tenantId.trim())}>
                      <FieldLabel htmlFor="intune-tenant">Tenant ID</FieldLabel>
                      <Input id="intune-tenant" autoFocus value={tenantId} onChange={(e) => setTenantId(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" />
                      <FieldDescription>The directory (tenant) ID, or a domain of it such as contoso.onmicrosoft.com.</FieldDescription>
                    </Field>
                    <Field data-invalid={appId.trim() !== "" && !GUID.test(appId.trim())}>
                      <FieldLabel htmlFor="intune-app">Application (client) ID</FieldLabel>
                      <Input id="intune-app" value={appId} onChange={(e) => setAppId(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" />
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="intune-secret">Client secret</FieldLabel>
                      <Input id="intune-secret" type="password" autoComplete="off" value={appSecret} onChange={(e) => setAppSecret(e.target.value)} />
                      <FieldDescription>Its value, not its ID. It is stored encrypted and never shown again. Test the connection from the list once the profile is created.</FieldDescription>
                    </Field>
                  </FieldGroup>
                </FieldSet>
              )}
              {takesNameRules && <NameRulesEditor id="profile-name-rules" draft={nameRulesDraft} onChange={setNameRulesDraft} />}
            </FieldGroup>
          )}

          {step === "review" && (
            <FieldGroup>
              <FieldSet>
                <FieldLegend>Review</FieldLegend>
                <FieldDescription>Use Back to change anything.</FieldDescription>
                <Summary
                  rows={[
                    { label: "Name", value: name.trim() },
                    { label: "Issuing CA", value: issuingCas.find((i) => i.id === issuingCaId)?.title ?? "" },
                    { label: "Validity", value: daysLabel(Number(validityDays)) },
                    { label: "Retention", value: `${daysLabel(Number(retentionDays))} after it ends` },
                    { label: "Extended key usage", value: extendedKeyUsage.map((u) => EXTENDED_KEY_USAGE_LABEL[u]).join(", ") },
                    { label: "Key usage", value: keyUsage.map((u) => KEY_USAGE_LABEL[u]).join(", ") },
                    { label: "Device keys", value: allowedKeyTypes.map((t) => KEY_TYPE_LABEL[t]).join(", ") },
                    { label: "Validator", value: validatorLabel(kind) },
                    ...(intune ? [{ label: "Entra tenant", value: tenantId.trim() }, { label: "Entra app", value: appId.trim() }] : []),
                    ...(takesNameRules && "rules" in nameRules ? [{ label: "Name Rules", value: nameRulesSummary(nameRules.rules) }] : []),
                  ]}
                />
              </FieldSet>
              {create.error && <FieldError>{create.error.message}</FieldError>}
            </FieldGroup>
          )}
        </div>
        <footer className="flex shrink-0 items-center justify-between gap-2 border-t bg-muted/50 p-4">
          <Button type="button" variant="outline" disabled={index === 0} onClick={() => goTo(index - 1)}>
            Back
          </Button>
          {last ? (
            <Button key="create" type="submit" disabled={create.isPending}>
              Create
            </Button>
          ) : (
            <Button key="next" type="button" disabled={!complete[step]} onClick={() => goTo(index + 1)}>
              Next
            </Button>
          )}
        </footer>
      </form>
    </SidebarProvider>
  );
}

function Summary({ rows }: { rows: { label: string; value: string }[] }) {
  return (
    <div className="rounded-md border p-4">
      <dl className="grid grid-cols-[9rem_1fr] gap-x-4 gap-y-3 text-sm">
        {rows.map(({ label, value }) => (
          <div key={label} className="col-span-2 grid grid-cols-subgrid items-baseline">
            <dt className="text-muted-foreground">{label}</dt>
            <dd className="min-w-0 break-words">{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
