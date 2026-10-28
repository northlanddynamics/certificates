import { useMutation, useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { createColumnHelper, tableFeatures, useTable } from "@tanstack/react-table";
import { BookOpenIcon, ClipboardCheckIcon, InfoIcon, KeyRoundIcon, TriangleAlertIcon, LandmarkIcon, MoreHorizontalIcon, PlusIcon, ScrollTextIcon, ShieldCheckIcon, type LucideIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import {
  DEFAULT_DEVICE_EXTENDED_KEY_USAGES,
  DEFAULT_DEVICE_KEY_TYPES,
  DEFAULT_DEVICE_KEY_USAGES,
  DEFAULT_DEVICE_RETENTION_DAYS,
  DEFAULT_DEVICE_VALIDITY_DAYS,
  DEFAULT_SHARED_CHALLENGE_VALIDITY_DAYS,
  DEVICE_EXTENDED_KEY_USAGE_NAMES,
  DEVICE_KEY_TYPE_LABELS,
  DEVICE_KEY_TYPES,
  DEVICE_KEY_USAGES,
  MAX_DEVICE_RETENTION_DAYS,
  MAX_DEVICE_VALIDITY_DAYS,
  WEAK_DEVICE_KEY_TYPE,
  type DeviceExtendedKeyUsage,
  type DeviceKeyType,
  type DeviceKeyUsage,
} from "../../../server/src/enrollment/enrollment-profile-kinds";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { CopyButton } from "@/components/copy-button";
import { GuideLink } from "@/components/guide";
import { SteppedForm, STEPPED_DIALOG, type Missing } from "@/components/stepped-form";
import { SummaryRows } from "@/components/summary-rows";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { DataTable } from "@/components/data-table/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet, FieldTitle } from "@/components/ui/field";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ActionLabel, PageHeader } from "@/components/page-header";
import { api, can, type CreatedEnrollmentProfile, type EnrollmentProfile } from "@/lib/api";
import { adcsDeviceChoices, adcsIssuerTitle, adcsRaTemplates, adcsTemplateTitle, raCertificateState, templateKeysLabel } from "@/lib/adcs-ca";
import { templateKeyAlgorithms } from "../../../server/src/adcs/adcs-kinds";
import { useOrg } from "@/lib/use-org";
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
  { id: "issuer", title: "Issuer", icon: LandmarkIcon },
  { id: "certificate", title: "Certificate", icon: ScrollTextIcon },
  { id: "keys", title: "Device keys", icon: KeyRoundIcon },
  { id: "validator", title: "Enrollment Validator", icon: ShieldCheckIcon },
  { id: "review", title: "Review", icon: ClipboardCheckIcon },
] as const satisfies readonly { id: string; title: string; icon: LucideIcon }[];
type StepId = (typeof STEPS)[number]["id"];

// An Intune Enrollment Validator is configured with the Entra app that signs in to Graph and Intune: a tenant (its ID
// or a domain of it) and an app ID. The server checks them too (server/src/enrollment/intune.ts).
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TENANT = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})$/i;
const VALIDATOR_LABEL: Record<string, string> = { intune: "Microsoft Intune", shared_challenge: "Shared Challenge" };
const validatorLabel = (kind: string) => VALIDATOR_LABEL[kind] ?? kind;
const VALIDATOR_DESCRIPTION: Record<string, string> = {
  intune: "Intune gives each device its own challenge, and checks it and the names the device asks for.",
  shared_challenge: "For Iru (formerly Kandji) and network gear, which can give no per-device challenge: every device presents the same Shared Challenge, which the platform makes.",
};

const KEY_TYPE_LABEL: Record<DeviceKeyType, string> = { ...DEVICE_KEY_TYPE_LABELS, [WEAK_DEVICE_KEY_TYPE]: `${DEVICE_KEY_TYPE_LABELS[WEAK_DEVICE_KEY_TYPE]} (weak)` };

/** How long a profile's Device Certificates are valid for, in words: on an ADCS CA, as its template decides. */
const validityLabel = (validityDays: number | null) => (validityDays === null ? "as long as its Certificate Template decides" : daysLabel(validityDays));

// The server lists every profile; an Organization has a handful.
const features = tableFeatures({});
const columnHelper = createColumnHelper<typeof features, EnrollmentProfile>();
const columns = columnHelper.columns([
  columnHelper.accessor("name", {
    header: "Name",
    cell: ({ row }) => (
      <span className="flex items-center gap-2">
        <DeviceCertificatesLink profile={row.original} />
        {!row.original.enabled && <Badge variant="neutral">Disabled</Badge>}
      </span>
    ),
  }),
  columnHelper.accessor("scepUrl", {
    header: "SCEP URL",
    cell: ({ row }) => (
      <span className="flex flex-col gap-1">
        <span className="break-all font-mono text-xs">{row.original.scepUrl}</span>
        <span className="break-all font-mono text-xs text-muted-foreground" title="The SHA-256 fingerprint of the CA certificate the SCEP URL serves">
          CA fingerprint (SHA-256) {row.original.caFingerprint}
        </span>
        {row.original.previousSharedChallenge && (
          <span className="text-xs text-muted-foreground">Previous Shared Challenge works until {new Date(row.original.previousSharedChallenge.expiresAt).toLocaleString()}</span>
        )}
      </span>
    ),
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
  const org = useOrg(orgId);
  const allowed = org ? can(org, "enrollmentProfile", "read") : false;
  const profiles = useQuery({ queryKey: ["enrollment-profiles", orgId], queryFn: () => api.enrollmentProfiles(orgId), enabled: allowed });
  const table = useTable({ features, columns, data: profiles.data?.items ?? noRows, getRowId: (p) => p.id });

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Enrollment Profiles"
        guide="enrollment-profiles"
        action={
          <>
            <Button variant="outline" asChild>
              <GuideLink orgId={orgId} guide="enrollment-profiles" className="">
                <BookOpenIcon />
                <ActionLabel>Enrollment guide</ActionLabel>
              </GuideLink>
            </Button>
            {org && can(org, "enrollmentProfile", "create") && <NewProfileDialog orgId={orgId} />}
          </>
        }
        description="Devices enroll at a profile's SCEP URL and get a Device Certificate from its Issuing CA."
        howItWorks={
          <p>
            A Device Certificate has the profile's key usage, extended key usages and validity, and the subject and names of the device's own request. Paste the SCEP URL into
            your device management platform's SCEP profile, and give its trusted certificate profile the root.
          </p>
        }
      />
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
 * profile refuses every device until it is pointed at an active one. On an ADCS CA, which template, why it is
 * unavailable while it is, and where its RA certificate stands until ADCS has issued it.
 */
function Issues({ profile }: { profile: EnrollmentProfile }) {
  if (profile.adcs) return <AdcsIssues profile={profile} adcs={profile.adcs} />;
  return <IssuingCaIssues profile={profile} issuingCaId={profile.issuingCaId!} />;
}

function AdcsIssues({ profile, adcs }: { profile: EnrollmentProfile; adcs: NonNullable<EnrollmentProfile["adcs"]> }) {
  const { orgId } = useParams({ from: ROUTE });
  const adcsCas = useQuery({ queryKey: ["adcs-cas", orgId], queryFn: () => api.adcsCas(orgId) });
  const title = adcsIssuerTitle(adcsCas.data?.items ?? [], { adcsCaId: adcs.adcsCaId, templateId: adcs.templateId });
  const raState = raCertificateState(profile);
  return (
    <span className="flex flex-col gap-1 text-sm">
      <span>Device Certificates {validityLabel(null)}</span>
      {title && <span className="text-xs text-muted-foreground">under {title}</span>}
      {adcs.templateUnavailable && profile.enabled && (
        <span className="max-w-72 whitespace-normal text-xs text-destructive">{adcs.templateUnavailable} Every device is refused until ADCS makes it available again; the profile stays enabled.</span>
      )}
      {raState && <span className="max-w-72 whitespace-normal text-xs text-muted-foreground">{raState}</span>}
    </span>
  );
}

function IssuingCaIssues({ profile, issuingCaId }: { profile: EnrollmentProfile; issuingCaId: string }) {
  const { orgId } = useParams({ from: ROUTE });
  const privateCas = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId) });
  const issuing = findIssuingCa(privateCas.data?.items ?? [], issuingCaId);
  const issues = privateCas.data?.items.find((ca) => ca.id === profile.privateCaId)?.status === "active" && issuing?.status === "active";
  return (
    <span className="flex flex-col gap-1 text-sm">
      <span>
        {profile.extendedKeyUsage.map((usage) => EXTENDED_KEY_USAGE_LABEL[usage]).join(", ")} for {validityLabel(profile.validityDays)}
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
 * retention period, its Name Rules (when its validator does not vouch for names), rotating its RA certificate, rotating
 * its Shared Challenge and retiring the previous one (when it has one), and disabling it. A test that works is a toast, with what it could not
 * prove; one that fails stays by the buttons, where its reason can be read.
 */
function ProfileActions({ profile }: { profile: EnrollmentProfile }) {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const mayUpdate = org ? can(org, "enrollmentProfile", "update") : false;
  const mayDisable = org ? can(org, "enrollmentProfile", "disable") && profile.enabled : false;
  const kinds = useQuery({ queryKey: ["enrollment-validator-kinds", orgId], queryFn: () => api.enrollmentValidatorKinds(orgId), enabled: mayUpdate });
  const takesNameRules = kindTakesNameRules(kinds.data?.items, profile.validator.kind);
  const [editing, setEditing] = useState<"intune-setup" | "issuing-ca" | "retention" | "name-rules" | "key-types" | "rotate-ra" | "rotate-challenge" | "retire-challenge" | "disable" | null>(null);
  const hasSharedChallenge = profile.sharedChallenge !== null;
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
            {profile.validator.kind === "intune" && <DropdownMenuItem onSelect={() => setEditing("intune-setup")}>Intune setup values…</DropdownMenuItem>}
            <DropdownMenuItem onSelect={() => void navigator.clipboard.writeText(profile.scepUrl)}>Copy SCEP URL</DropdownMenuItem>
            <DropdownMenuItem onSelect={() => void navigator.clipboard.writeText(profile.caFingerprint)}>Copy CA fingerprint</DropdownMenuItem>
            <DropdownMenuItem asChild>
              <a href={api.enrollmentProfileCaCertificateUrl(orgId, profile.id, "root")} download>
                Download root certificate
              </a>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <a href={api.enrollmentProfileCaCertificateUrl(orgId, profile.id, "issuing")} download>
                {profile.adcs ? "Download ADCS CA certificate" : "Download Issuing CA certificate"}
              </a>
            </DropdownMenuItem>
            {(mayUpdate || mayDisable) && <DropdownMenuSeparator />}
            {mayUpdate && !profile.adcs && <DropdownMenuItem onSelect={() => setEditing("issuing-ca")}>Change Issuing CA…</DropdownMenuItem>}
            {mayUpdate && <DropdownMenuItem onSelect={() => setEditing("retention")}>Retention period…</DropdownMenuItem>}
            {mayUpdate && takesNameRules && <DropdownMenuItem onSelect={() => setEditing("name-rules")}>Name Rules…</DropdownMenuItem>}
            {mayUpdate && <DropdownMenuItem onSelect={() => setEditing("key-types")}>Device keys…</DropdownMenuItem>}
            {mayUpdate && (
              <DropdownMenuItem disabled={profile.raRequested} onSelect={() => setEditing("rotate-ra")}>
                Rotate RA certificate…
              </DropdownMenuItem>
            )}
            {mayUpdate && hasSharedChallenge && (
              <DropdownMenuItem disabled={profile.previousSharedChallenge !== null} onSelect={() => setEditing("rotate-challenge")}>
                Rotate Shared Challenge…
              </DropdownMenuItem>
            )}
            {mayUpdate && profile.previousSharedChallenge && <DropdownMenuItem onSelect={() => setEditing("retire-challenge")}>Retire previous challenge…</DropdownMenuItem>}
            {mayDisable && (
              <DropdownMenuItem variant="destructive" onSelect={() => setEditing("disable")}>
                Disable…
              </DropdownMenuItem>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
      {profile.validator.kind === "intune" && (
        <Dialog open={editing === "intune-setup"} onOpenChange={openOne("intune-setup")}>
          <DialogContent className="sm:max-w-2xl">
            <IntuneSetupPanel orgId={orgId} profile={profile} onDone={() => setEditing(null)} />
          </DialogContent>
        </Dialog>
      )}
      {mayUpdate && !profile.adcs && <IssuingCaDialog profile={profile} open={editing === "issuing-ca"} onOpenChange={openOne("issuing-ca")} />}
      {mayUpdate && <RetentionDialog profile={profile} open={editing === "retention"} onOpenChange={openOne("retention")} />}
      {mayUpdate && takesNameRules && <NameRulesDialog profile={profile} open={editing === "name-rules"} onOpenChange={openOne("name-rules")} />}
      {mayUpdate && <AllowedKeyTypesDialog profile={profile} open={editing === "key-types"} onOpenChange={openOne("key-types")} />}
      {mayUpdate && <RotateRaDialog profile={profile} open={editing === "rotate-ra"} onOpenChange={openOne("rotate-ra")} />}
      {mayUpdate && hasSharedChallenge && <RotateSharedChallengeDialog profile={profile} open={editing === "rotate-challenge"} onOpenChange={openOne("rotate-challenge")} />}
      {mayUpdate && profile.previousSharedChallenge && <RetirePreviousSharedChallengeDialog profile={profile} open={editing === "retire-challenge"} onOpenChange={openOne("retire-challenge")} />}
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
    ca.status === "active" && !ca.enrollmentProfileRefusal ? ca.issuingCas.filter((i) => i.status === "active" && i.id !== profile.issuingCaId).map((i) => ({ id: i.id, title: issuingCaTitle(ca.name, i.subject), privateCaId: ca.id })) : [],
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

/** Changes the device keys the profile allows, for its next request. */
function AllowedKeyTypesDialog({ profile, open, onOpenChange }: ProfileDialogProps) {
  const { orgId } = useParams({ from: ROUTE });
  const [chosen, setChosen] = useState(profile.allowedKeyTypes);
  const save = useAction(() => api.updateEnrollmentProfile(orgId, profile.id, { allowedKeyTypes: chosen }), ["enrollment-profiles"], () => onOpenChange(false));
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next) {
          save.reset();
          setChosen(profile.allowedKeyTypes);
        }
        onOpenChange(next);
      }}
    >
      <DialogContent>
        <form
          className="flex flex-col gap-4"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            if (chosen.length > 0) save.mutate(undefined);
          }}
        >
          <DialogHeader>
            <DialogTitle>Device keys of {profile.name}</DialogTitle>
            <DialogDescription>They apply from the next request on; a device whose request is for any other kind of key is refused. Device Certificates already issued are kept.</DialogDescription>
          </DialogHeader>
          <KeyTypeChoices id={`profile-${profile.id}-keys`} chosen={chosen} onChange={setChosen} />
          {save.error && <FieldError>{save.error.message}</FieldError>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={chosen.length === 0 || save.isPending}>
              Save
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/**
 * Has the profile's Issuing CA sign it a new RA certificate for a new key, which devices are given from then on; on an
 * ADCS CA, has ADCS asked for one, which replaces the current one once it is issued.
 */
function RotateRaDialog({ profile, open, onOpenChange }: ProfileDialogProps) {
  const { orgId } = useParams({ from: ROUTE });
  const rotate = useAction(
    () => api.rotateEnrollmentProfileRa(orgId, profile.id),
    ["enrollment-profiles"],
    () => {
      onOpenChange(false);
      toast.success(profile.adcs ? `${profile.name}: ADCS is asked for an RA certificate` : `${profile.name}: the RA certificate was replaced`);
    },
  );
  const ends = profile.raCertificate ? ` The current one ends ${new Date(profile.raCertificate.notAfter).toLocaleDateString()}.` : "";
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(next) => {
        if (next) rotate.reset();
        onOpenChange(next);
      }}
      title={`Rotate the RA certificate of ${profile.name}?`}
      description={
        profile.adcs
          ? `An Agent asks ADCS for an RA certificate for a new key, under the profile's RA template. The current one serves until it is issued.${ends} A device midway through enrolling with the old one enrolls again.`
          : `Its Issuing CA signs a new RA certificate for a new key, which devices are given from now on.${ends} A device midway through enrolling with the old one enrolls again.`
      }
      confirmLabel="Rotate"
      pending={rotate.isPending}
      error={rotate.error}
      onConfirm={() => rotate.mutate(undefined)}
    />
  );
}

/** How long the previous Shared Challenge stays valid after a rotation unless the administrator says otherwise. */
const DEFAULT_PREVIOUS_CHALLENGE_DAYS = 14;

/** The local date `days` from today, as a date input holds it (yyyy-mm-dd). */
function localDateIn(days: number) {
  const date = new Date();
  date.setDate(date.getDate() + days);
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

/** The end of the local day `date` (yyyy-mm-dd) names, which is when a previous Shared Challenge chosen to expire "on" it stops working. */
function endOfLocalDay(date: string) {
  const [year, month, day] = date.split("-").map(Number);
  return new Date(year!, month! - 1, day! + 1);
}

/**
 * Rotates the profile's Shared Challenge: asks until when the previous one keeps working, then shows the new one once,
 * which the platform does not keep.
 */
function RotateSharedChallengeDialog({ profile, open, onOpenChange }: ProfileDialogProps) {
  const { orgId } = useParams({ from: ROUTE });
  const [expiresOn, setExpiresOn] = useState(() => localDateIn(DEFAULT_PREVIOUS_CHALLENGE_DAYS));
  // The new Shared Challenge, shown once, until the dialog closes.
  const [challenge, setChallenge] = useState<string | null>(null);
  const ok = /^\d{4}-\d{2}-\d{2}$/.test(expiresOn) && endOfLocalDay(expiresOn) > new Date();
  const rotate = useAction(
    () => api.rotateSharedChallenge(orgId, profile.id, endOfLocalDay(expiresOn).toISOString()),
    ["enrollment-profiles"],
    (rotated) => setChallenge(rotated.sharedChallenge!.challenge),
  );
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next) {
          rotate.reset();
          setExpiresOn(localDateIn(DEFAULT_PREVIOUS_CHALLENGE_DAYS));
        } else setChallenge(null);
        onOpenChange(next);
      }}
    >
      <DialogContent>
        {challenge ? (
          <div className="flex flex-col gap-4">
            <DialogHeader>
              <DialogTitle>The new Shared Challenge of {profile.name}</DialogTitle>
              <DialogDescription>
                Put it in your device management platform's SCEP profile, such as Iru's SCEP Library Item. The previous one keeps working until the end of {new Date(`${expiresOn}T00:00`).toLocaleDateString()}, or until you retire it once every device has the new one.
              </DialogDescription>
            </DialogHeader>
            <ShownOnceSharedChallenge challenge={challenge} />
            <DialogFooter>
              <Button type="button" onClick={() => onOpenChange(false)}>
                I have copied the Shared Challenge
              </Button>
            </DialogFooter>
          </div>
        ) : (
          <form
            className="flex flex-col gap-4"
            onSubmit={(e: FormEvent) => {
              e.preventDefault();
              if (ok) rotate.mutate(undefined);
            }}
          >
            <DialogHeader>
              <DialogTitle>Rotate the Shared Challenge of {profile.name}</DialogTitle>
              <DialogDescription>
                The platform makes a new Shared Challenge, shown once. The current one becomes the previous and keeps working until the day you choose, so that devices your device management platform has not yet reached keep enrolling. Once
                you rotate, you cannot rotate again until the previous one expires or you retire it.
              </DialogDescription>
            </DialogHeader>
            <Field data-invalid={!ok}>
              <FieldLabel htmlFor={`profile-${profile.id}-previous-expiry`}>Previous Shared Challenge works until the end of</FieldLabel>
              <Input id={`profile-${profile.id}-previous-expiry`} type="date" min={localDateIn(0)} required autoFocus value={expiresOn} onChange={(e) => setExpiresOn(e.target.value)} aria-invalid={!ok} />
              <FieldDescription>Long enough for every device to get the new one; you can retire the previous one sooner.</FieldDescription>
            </Field>
            {rotate.error && <FieldError>{rotate.error.message}</FieldError>}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={!ok || rotate.isPending}>
                Rotate
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

/** Retires the profile's previous Shared Challenge at once: devices presenting it are refused from then on. */
function RetirePreviousSharedChallengeDialog({ profile, open, onOpenChange }: ProfileDialogProps) {
  const { orgId } = useParams({ from: ROUTE });
  const retire = useAction(
    () => api.retirePreviousSharedChallenge(orgId, profile.id),
    ["enrollment-profiles"],
    () => {
      onOpenChange(false);
      toast.success(`${profile.name}: the previous Shared Challenge was retired`);
    },
  );
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(next) => {
        if (next) retire.reset();
        onOpenChange(next);
      }}
      title={`Retire the previous Shared Challenge of ${profile.name}?`}
      description={`Devices presenting it are refused from now on, rather than from ${new Date(profile.previousSharedChallenge?.expiresAt ?? Date.now()).toLocaleString()}. Device Certificates issued under it are kept. Retire it once your device management platform has given every device the new one: the Device Certificates list shows which challenge each was issued under.`}
      confirmLabel="Retire"
      pending={retire.isPending}
      error={retire.error}
      onConfirm={() => retire.mutate(undefined)}
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

const ENTRA_STEPS = [
  "An app registration in Microsoft Entra ID for this platform",
  "Application permission Intune → scep_challenge_provider",
  "Application permission Microsoft Graph → Application.Read.All",
  "Admin consent granted for both",
  "A client secret, its value copied",
];

/**
 * What must exist in Entra before an Intune profile can work, as a checklist for the administrator's own tracking: the
 * platform cannot see Entra's settings, so nothing here is required to go on.
 */
function EntraChecklist({ orgId }: { orgId: string }) {
  const [done, setDone] = useState<boolean[]>(ENTRA_STEPS.map(() => false));
  return (
    <div className="flex flex-col gap-2 rounded-md border bg-muted/40 p-3 text-sm">
      <span className="font-medium">In Microsoft Entra, first</span>
      {ENTRA_STEPS.map((step, i) => (
        <Field key={step} orientation="horizontal">
          <Checkbox id={`entra-step-${i}`} checked={done[i]} onCheckedChange={(on) => setDone((d) => d.map((v, j) => (j === i ? on === true : v)))} />
          <FieldLabel htmlFor={`entra-step-${i}`} className="font-normal">
            {step}
          </FieldLabel>
        </Field>
      ))}
      <span className="text-xs text-muted-foreground">
        For your own tracking: the platform cannot see Entra.{" "}
        <GuideLink orgId={orgId} guide="enrollment-profiles" section="intune">
          Step by step
        </GuideLink>
      </span>
    </div>
  );
}

function NewProfileDialog({ orgId }: { orgId: string }) {
  const [open, setOpen] = useState(false);
  // A profile just created, with its Shared Challenge (shown once) or the values for Intune, until the dialog closes.
  const [created, setCreated] = useState<CreatedEnrollmentProfile | null>(null);
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) setCreated(null);
      }}
    >
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          <ActionLabel>New profile</ActionLabel>
        </Button>
      </DialogTrigger>
      {created?.sharedChallenge ? (
        // Closed only by its own button, not by Escape or a click outside it: the Shared Challenge is not shown again.
        <DialogContent className="sm:max-w-2xl" showCloseButton={false} onInteractOutside={(e) => e.preventDefault()} onEscapeKeyDown={(e) => e.preventDefault()}>
          <SharedChallengePanel profile={created} challenge={created.sharedChallenge.challenge} onDone={() => setOpen(false)} />
        </DialogContent>
      ) : created?.validator.kind === "intune" ? (
        <DialogContent className="sm:max-w-2xl">
          <IntuneSetupPanel orgId={orgId} profile={created} onDone={() => setOpen(false)} />
        </DialogContent>
      ) : (
        <DialogContent className={STEPPED_DIALOG}>
          <DialogTitle className="sr-only">New Enrollment Profile</DialogTitle>
          <DialogDescription className="sr-only">The platform makes the profile's SCEP RA key, which it keeps, and has the Issuing CA sign its certificate.</DialogDescription>
          {/* Only mounted while open, so each opening starts from a clean form. */}
          {open && <NewProfileForm orgId={orgId} onDone={(profile) => (profile.sharedChallenge || profile.validator.kind === "intune" ? setCreated(profile) : setOpen(false))} />}
        </DialogContent>
      )}
    </Dialog>
  );
}

/** A value to paste into the device management platform, with a button that copies it. */
function CopyableValue({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-sm font-medium">{label}</span>
      <div className="flex items-center gap-2 rounded-md border bg-muted/50 px-3 py-1.5">
        <span className="min-w-0 flex-1 break-all font-mono text-xs">{value}</span>
        <CopyButton text={value} label={`Copy the ${label}`} />
      </div>
    </div>
  );
}

/** A Shared Challenge just made, with the warning that it is shown only this once. */
function ShownOnceSharedChallenge({ challenge }: { challenge: string }) {
  return (
    <>
      <Alert>
        <TriangleAlertIcon />
        <AlertTitle>Copy the Shared Challenge now</AlertTitle>
        <AlertDescription>It is shown only this once: the platform keeps only what it needs to check it. Anyone who holds it can enroll, so keep it where only your device management platform reads it.</AlertDescription>
      </Alert>
      <CopyableValue label="Shared Challenge" value={challenge} />
    </>
  );
}

/**
 * Shown once, right after a profile with a Shared Challenge is created: the challenge (which the platform does not keep,
 * so it is never shown again), the SCEP URL and the CA fingerprint, and where each goes in Iru's SCEP Library Item.
 */
function SharedChallengePanel({ profile, challenge, onDone }: { profile: CreatedEnrollmentProfile; challenge: string; onDone: () => void }) {
  return (
    <div className="flex flex-col gap-4">
      <DialogHeader>
        <DialogTitle>{profile.name} is ready for its devices</DialogTitle>
        <DialogDescription>Fill in your device management platform's SCEP profile with these values, such as Iru's SCEP Library Item.</DialogDescription>
      </DialogHeader>
      <CopyableValue label="SCEP URL" value={profile.scepUrl} />
      <ShownOnceSharedChallenge challenge={challenge} />
      <CopyableValue label="CA fingerprint (SHA-256)" value={profile.caFingerprint} />
      <div className="flex flex-col gap-2 text-sm">
        <span className="font-medium">In Iru (formerly Kandji), add a SCEP Library Item:</span>
        <ol className="flex list-decimal flex-col gap-1 pl-5 text-muted-foreground">
          <li>
            <span className="text-foreground">URL</span>: the SCEP URL.
          </li>
          <li>
            <span className="text-foreground">Challenge</span>: the Shared Challenge.
          </li>
          <li>
            <span className="text-foreground">Fingerprint</span>: the CA fingerprint, so that Macs check they reached this CA.
          </li>
          <li>
            <span className="text-foreground">Subject and subject alternative names</span>: what your Wi-Fi or VPN needs, from Iru's variables. The platform issues them as they come, within the Issuing CA's permitted names
            {profile.nameRules ? " and this profile's Name Rules" : ""}.
          </li>
          <li>
            <span className="text-foreground">Key size</span>: 2048 or more. Apple's default, 1024, is refused unless the profile allows it.
          </li>
          <li>
            <span className="text-foreground">Automatic profile redistribution</span>: on, so that Macs renew before their certificates end, {validityLabel(profile.validityDays)} after they are issued.
          </li>
        </ol>
        <span className="text-muted-foreground">Also deploy the root certificate (from the profile's actions) as a Certificate Library Item, so that Macs trust what they are issued.</span>
      </div>
      <DialogFooter>
        <Button type="button" onClick={onDone}>
          I have copied the Shared Challenge
        </Button>
      </DialogFooter>
    </div>
  );
}

/** The subject alternative name an Intune SCEP profile adds, by which Intune's revocation requests find a device's certificates. */
const INTUNE_DEVICE_SAN = "IntuneDeviceId://{{DeviceId}}";

/**
 * What to put in Intune for a profile on the Intune validator: the trusted certificate profile's certificate, and each
 * value of the SCEP certificate profile, under the names Intune gives its fields. Shown on creating one, and from its menu.
 */
function IntuneSetupPanel({ orgId, profile, onDone }: { orgId: string; profile: EnrollmentProfile | CreatedEnrollmentProfile; onDone: () => void }) {
  return (
    <div className="flex min-w-0 flex-col gap-4">
      <DialogHeader>
        <DialogTitle>Finish in Intune: {profile.name}</DialogTitle>
        <DialogDescription>Two profiles in Intune, with these values. Devices enroll once both reach them.</DialogDescription>
      </DialogHeader>
      <section className="flex flex-col gap-2 text-sm">
        <h3 className="font-medium">1 · Trusted certificate profile</h3>
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" asChild>
            <a href={api.enrollmentProfileCaCertificateUrl(orgId, profile.id, "root")} download>
              Download root certificate
            </a>
          </Button>
          <Button size="sm" variant="outline" asChild>
            <a href={api.enrollmentProfileCaCertificateUrl(orgId, profile.id, "issuing")} download>
              {profile.adcs ? "ADCS CA certificate" : "Issuing CA certificate"}
            </a>
          </Button>
        </div>
        <span className="text-muted-foreground">The root, unless your devices must trust only the Issuing CA.</span>
      </section>
      <section className="flex flex-col gap-3 text-sm">
        <h3 className="font-medium">2 · SCEP certificate profile</h3>
        <CopyableValue label="SCEP Server URLs" value={profile.scepUrl} />
        <CopyableValue label="Subject alternative name (URI)" value={INTUNE_DEVICE_SAN} />
        <SummaryRows
          rows={[
            { label: "Root Certificate", value: "The trusted certificate profile from step 1" },
            { label: "Key size (bits)", value: profile.allowedKeyTypes.map((t) => KEY_TYPE_LABEL[t]).join(", ") },
            ...(profile.adcs
              ? [{ label: "Key usage and extended key usage", value: "Any: the Certificate Template decides them" }]
              : [
                  { label: "Key usage", value: profile.keyUsage.map((u) => KEY_USAGE_LABEL[u]).join(", ") },
                  { label: "Extended key usage", value: profile.extendedKeyUsage.map((u) => EXTENDED_KEY_USAGE_LABEL[u]).join(", ") },
                ]),
            { label: "Certificate validity", value: `Ignored: the profile issues ${profile.validityDays === null ? "for as long as its Certificate Template decides" : `for ${daysLabel(profile.validityDays)}`}` },
          ]}
        />
      </section>
      <Alert>
        <InfoIcon />
        <AlertTitle>The first enrollment is the real test</AlertTitle>
        <AlertDescription>
          It is what proves <code>scep_challenge_provider</code> and admin consent. A refused one is recorded in the Audit log as <code>enrollment.refused</code>, with its reason.{" "}
          <GuideLink orgId={orgId} guide="enrollment-profiles" section="refused">
            Why devices are refused
          </GuideLink>
        </AlertDescription>
      </Alert>
      <DialogFooter>
        <Button type="button" onClick={onDone}>
          Done
        </Button>
      </DialogFooter>
    </div>
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

/** The device keys a profile allows, with a warning when a weak one is among them. */
function KeyTypeChoices({ id, chosen, onChange, values = DEVICE_KEY_TYPES }: { id: string; chosen: DeviceKeyType[]; onChange: (chosen: DeviceKeyType[]) => void; values?: readonly DeviceKeyType[] }) {
  return (
    <>
      <Choices legend="Device keys allowed" id={id} values={values} labels={KEY_TYPE_LABEL} chosen={chosen} onChange={onChange} />
      {chosen.includes(WEAK_DEVICE_KEY_TYPE) && (
        <Alert variant="destructive">
          <TriangleAlertIcon />
          <AlertTitle>1024-bit keys can be broken</AlertTitle>
          <AlertDescription>
            Someone with enough computing power can work out a 1024-bit key's private key and pose as the device. Some RADIUS servers and VPN gateways also reject them. Allow them only for devices that cannot
            make a larger key, such as Macs left on Apple's default key size; their Device Certificates are marked "Weak key".
          </AlertDescription>
        </Alert>
      )}
    </>
  );
}

// Every step's state lives in the form, so moving between steps never loses what was entered.
function NewProfileForm({ orgId, onDone }: { orgId: string; onDone: (created: CreatedEnrollmentProfile) => void }) {
  const [step, setStep] = useState<StepId>("issuer");
  const privateCas = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId) });
  const kinds = useQuery({ queryKey: ["enrollment-validator-kinds", orgId], queryFn: () => api.enrollmentValidatorKinds(orgId) });
  // Only an active Issuing CA under an active root issues, and not an ML-DSA one: SCEP clients cannot verify its RA certificate.
  const issuingCas = (privateCas.data?.items ?? []).flatMap((ca) => (ca.status === "active" && !ca.enrollmentProfileRefusal ? ca.issuingCas.filter((i) => i.status === "active").map((i) => ({ id: i.id, title: issuingCaTitle(ca.name, i.subject) })) : []));
  // An ADCS CA's templates offered for devices, each with its CA; and, once one is chosen, the templates its RA certificate may be issued under.
  const adcsCas = useQuery({ queryKey: ["adcs-cas", orgId], queryFn: () => api.adcsCas(orgId) });
  const deviceChoices = adcsDeviceChoices(adcsCas.data?.items ?? []).flatMap(({ ca, templates }) => templates.map((template) => ({ key: `${ca.id}:${template.id}`, ca, template })));
  const [name, setName] = useState("");
  const [issuerKind, setIssuerKind] = useState<"private_ca" | "adcs">("private_ca");
  const [issuingCaId, setIssuingCaId] = useState("");
  const [adcsChoice, setAdcsChoice] = useState("");
  const [raTemplateId, setRaTemplateId] = useState("");
  const adcs = issuerKind === "adcs";
  const device = deviceChoices.find((c) => c.key === adcsChoice);
  const raTemplates = device ? adcsRaTemplates(device.ca) : [];
  // The device keys a profile may allow: on an ADCS CA, those its template takes.
  const keyTypes = adcs && device ? templateKeyAlgorithms(device.template, DEVICE_KEY_TYPES) : DEVICE_KEY_TYPES;
  // None until the administrator sets one: the default then follows the validator chosen.
  const [chosenValidityDays, setChosenValidityDays] = useState<string | null>(null);
  const [retentionDays, setRetentionDays] = useState(String(DEFAULT_DEVICE_RETENTION_DAYS));
  const [extendedKeyUsage, setExtendedKeyUsage] = useState<DeviceExtendedKeyUsage[]>(DEFAULT_DEVICE_EXTENDED_KEY_USAGES);
  const [keyUsage, setKeyUsage] = useState<DeviceKeyUsage[]>(DEFAULT_DEVICE_KEY_USAGES);
  const [chosenKeyTypes, setChosenKeyTypes] = useState<DeviceKeyType[]>(DEFAULT_DEVICE_KEY_TYPES);
  const allowedKeyTypes = chosenKeyTypes.filter((type) => keyTypes.includes(type));
  const [validatorKind, setValidatorKind] = useState("");
  const kind = validatorKind || kinds.data?.items[0]?.kind || "";
  const [tenantId, setTenantId] = useState("");
  const [appId, setAppId] = useState("");
  const [appSecret, setAppSecret] = useState("");
  const intune = kind === "intune";
  const usesSharedChallenge = kinds.data?.items.find((k) => k.kind === kind)?.usesSharedChallenge === true;
  const validityDays = chosenValidityDays ?? String(usesSharedChallenge ? DEFAULT_SHARED_CHALLENGE_VALIDITY_DAYS : DEFAULT_DEVICE_VALIDITY_DAYS);
  // Only a validator that does not vouch for names takes Name Rules, and they stay optional.
  const takesNameRules = kindTakesNameRules(kinds.data?.items, kind);
  const [nameRulesDraft, setNameRulesDraft] = useState(EMPTY_NAME_RULES);
  const nameRules = takesNameRules ? rulesOf(nameRulesDraft) : { rules: null };
  const validator = intune ? { kind, settings: { tenantId: tenantId.trim(), appId: appId.trim() }, secret: appSecret } : { kind };
  const create = useAction(
    () =>
      api.createEnrollmentProfile(orgId, {
        name: name.trim(),
        ...(adcs && device ? { adcs: { adcsCaId: device.ca.id, templateId: device.template.id, raTemplateId } } : { issuingCaId, validityDays: Number(validityDays), keyUsage, extendedKeyUsage }),
        retentionDays: Number(retentionDays),
        allowedKeyTypes,
        validator,
        ...("rules" in nameRules && nameRules.rules && { nameRules: nameRules.rules }),
      }),
    ["enrollment-profiles"],
    onDone,
  );
  const validityOk = isValidityDays(validityDays, MAX_DEVICE_VALIDITY_DAYS);
  const retentionOk = isRetentionDays(retentionDays);

  // What each step still needs; Review only shows what was entered.
  const missing: Partial<Record<StepId, Missing>> = {
    issuer:
      name.trim() === ""
        ? { reason: "Give the profile a name.", field: "profile-name" }
        : !adcs && issuingCaId === ""
          ? { reason: "Choose the Issuing CA.", field: "profile-issuing-ca" }
          : adcs && !device
            ? { reason: "Choose the Certificate Template devices get theirs under.", field: "profile-adcs-template" }
            : adcs && !raTemplates.some((t) => t.id === raTemplateId)
              ? { reason: "Choose the Certificate Template the RA certificate is issued under.", field: "profile-adcs-ra-template" }
              : undefined,
    certificate: adcs
      ? retentionOk
        ? undefined
        : { reason: `Give a retention of 0 to ${MAX_DEVICE_RETENTION_DAYS} days.`, field: "profile-retention" }
      : !validityOk
      ? { reason: `Give a validity of 1 to ${MAX_DEVICE_VALIDITY_DAYS} days.`, field: "profile-validity" }
      : !retentionOk
        ? { reason: `Give a retention of 0 to ${MAX_DEVICE_RETENTION_DAYS} days.`, field: "profile-retention" }
        : keyUsage.length === 0
          ? { reason: "Choose at least one key usage.", field: `profile-ku-${DEVICE_KEY_USAGES[0]}` }
          : extendedKeyUsage.length === 0
            ? { reason: "Choose at least one extended key usage.", field: `profile-eku-${DEVICE_EXTENDED_KEY_USAGE_NAMES[0]}` }
            : undefined,
    keys: allowedKeyTypes.length > 0 ? undefined : { reason: keyTypes.length === 0 ? "The Certificate Template takes none of the device keys a profile allows." : "Allow at least one kind of device key.", field: `profile-keys-${keyTypes[0] ?? DEVICE_KEY_TYPES[0]}` },
    validator:
      kind === ""
        ? { reason: "Choose how devices are checked.", field: "profile-validator" }
        : intune && !TENANT.test(tenantId.trim())
          ? { reason: "Give the tenant as its ID or its domain.", field: "intune-tenant" }
          : intune && !GUID.test(appId.trim())
            ? { reason: "Give the app (client) ID, a GUID.", field: "intune-app" }
            : intune && appSecret === ""
              ? { reason: "Give the app's client secret.", field: "intune-secret" }
              : "error" in nameRules
                ? { reason: nameRules.error, field: "profile-name-rules-subject" }
                : undefined,
  };

  return (
    <SteppedForm
      title="New Enrollment Profile"
      steps={STEPS}
      step={step}
      onStep={setStep}
      missing={missing}
      submitLabel="Create"
      pending={create.isPending}
      onSubmit={() => create.mutate(undefined)}
    >
      {step === "issuer" && (
        <FieldSet>
          <FieldLegend>Name it and choose where its certificates come from</FieldLegend>
          <FieldDescription>
            The platform makes the profile's SCEP RA key, which it keeps, and has the Issuing CA sign its certificate; or, on an ADCS CA, has ADCS issue it through an Agent, after which the profile serves SCEP.
          </FieldDescription>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="profile-name">Name</FieldLabel>
              <Input id="profile-name" autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Wi-Fi" />
            </Field>
            {deviceChoices.length > 0 && (
              <Field>
                <FieldTitle id="profile-issuer-kind-label">Issuer</FieldTitle>
                <RadioGroup aria-labelledby="profile-issuer-kind-label" value={issuerKind} onValueChange={(kind) => setIssuerKind(kind as typeof issuerKind)} className="grid gap-2 sm:grid-cols-2">
                  {(
                    [
                      ["private_ca", "Issuing CA", "One of your Private CAs signs at once."],
                      ["adcs", "ADCS CA", "ADCS issues under a Certificate Template, through an Agent: devices are answered PENDING until it has."],
                    ] as const
                  ).map(([value, title, description]) => (
                    <FieldLabel key={value} htmlFor={`profile-issuer-kind-${value}`}>
                      <Field orientation="horizontal">
                        <FieldContent>
                          <FieldTitle>{title}</FieldTitle>
                          <FieldDescription>{description}</FieldDescription>
                        </FieldContent>
                        <RadioGroupItem value={value} id={`profile-issuer-kind-${value}`} />
                      </Field>
                    </FieldLabel>
                  ))}
                </RadioGroup>
              </Field>
            )}
            {adcs ? (
              <>
                <Field>
                  <FieldLabel htmlFor="profile-adcs-template">Certificate Template for devices</FieldLabel>
                  <Select
                    value={adcsChoice}
                    onValueChange={(key) => {
                      setAdcsChoice(key);
                      setRaTemplateId("");
                    }}
                  >
                    <SelectTrigger id="profile-adcs-template" className="w-full">
                      <SelectValue placeholder="Choose a Certificate Template" />
                    </SelectTrigger>
                    <SelectContent>
                      {deviceChoices.map((c) => (
                        <SelectItem key={c.key} value={c.key}>
                          {adcsTemplateTitle(c.ca.name, c.template)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FieldDescription>
                    {device
                      ? `It decides the validity and key usages of what devices get, and takes keys of ${templateKeysLabel(device.template)}.`
                      : "Those offered for devices: available, not hidden, with Client Authentication."}
                  </FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor="profile-adcs-ra-template">Certificate Template for the RA certificate</FieldLabel>
                  <Select value={raTemplateId} onValueChange={setRaTemplateId} disabled={!device}>
                    <SelectTrigger id="profile-adcs-ra-template" className="w-full">
                      <SelectValue placeholder={device ? "Choose a Certificate Template" : "Choose the template for devices first"} />
                    </SelectTrigger>
                    <SelectContent>
                      {raTemplates.map((t) => (
                        <SelectItem key={t.id} value={t.id}>
                          {adcsTemplateTitle(device!.ca.name, t)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FieldDescription>Any available template of the same ADCS CA, such as one for SCEP RA certificates: SCEP clients see an RA certificate that chains to your ADCS CA. It is renewed through ADCS when a third of its life is left.</FieldDescription>
                </Field>
              </>
            ) : (
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
                <FieldDescription>Only an active Issuing CA under an active root can be chosen, and not an ML-DSA one: SCEP clients cannot verify the RA certificate it would sign.</FieldDescription>
              </Field>
            )}
          </FieldGroup>
        </FieldSet>
      )}

      {step === "certificate" && adcs && (
        <FieldGroup>
          <FieldDescription>The Certificate Template decides the validity, key usage and extended key usages of what devices get.</FieldDescription>
          <Field data-invalid={!retentionOk}>
            <FieldLabel htmlFor="profile-retention">Retention (days)</FieldLabel>
            <Input id="profile-retention" inputMode="numeric" autoFocus value={retentionDays} onChange={(e) => setRetentionDays(e.target.value)} aria-invalid={!retentionOk} />
            <FieldDescription>How long after it ends a Device Certificate is kept before it is deleted; its Audit Events are kept.</FieldDescription>
          </Field>
        </FieldGroup>
      )}

      {step === "certificate" && !adcs && (
        <FieldGroup>
          <Field data-invalid={!validityOk}>
            <FieldLabel htmlFor="profile-validity">Validity (days)</FieldLabel>
            <Input id="profile-validity" inputMode="numeric" autoFocus value={validityDays} onChange={(e) => setChosenValidityDays(e.target.value)} aria-invalid={!validityOk} />
            <FieldDescription>
              Up to {daysLabel(MAX_DEVICE_VALIDITY_DAYS)}, and never past the Issuing CA's end. Unless you set it, {daysLabel(DEFAULT_DEVICE_VALIDITY_DAYS)}, or {daysLabel(DEFAULT_SHARED_CHALLENGE_VALIDITY_DAYS)} with a
              Shared Challenge.
            </FieldDescription>
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
          <FieldDescription>A device whose request is for any other kind of key is refused.{adcs && device ? " Only keys the Certificate Template takes can be allowed." : ""}</FieldDescription>
          <KeyTypeChoices id="profile-keys" values={keyTypes} chosen={allowedKeyTypes} onChange={setChosenKeyTypes} />
        </FieldGroup>
      )}

      {step === "validator" && (
        <FieldGroup>
          <Field>
            <FieldTitle id="profile-validator-label">Enrollment Validator</FieldTitle>
            {kinds.data && kinds.data.items.length === 0 ? (
              <FieldDescription>The platform runs no Enrollment Validator yet, so no profile can be created.</FieldDescription>
            ) : (
              <RadioGroup aria-labelledby="profile-validator-label" value={kind} onValueChange={setValidatorKind} className="grid gap-2 sm:grid-cols-2">
                {(kinds.data?.items ?? []).map((k) => (
                  <FieldLabel key={k.kind} htmlFor={`profile-validator-${k.kind}`}>
                    <Field orientation="horizontal">
                      <FieldContent>
                        <FieldTitle>{validatorLabel(k.kind)}</FieldTitle>
                        {VALIDATOR_DESCRIPTION[k.kind] && <FieldDescription>{VALIDATOR_DESCRIPTION[k.kind]}</FieldDescription>}
                      </FieldContent>
                      <RadioGroupItem value={k.kind} id={`profile-validator-${k.kind}`} />
                    </Field>
                  </FieldLabel>
                ))}
              </RadioGroup>
            )}
            <FieldDescription>
              <GuideLink orgId={orgId} guide="enrollment-profiles" section="choose">
                Compare them
              </GuideLink>
            </FieldDescription>
          </Field>
          {usesSharedChallenge && (
            <Alert>
              <TriangleAlertIcon />
              <AlertTitle>Anyone who holds the Shared Challenge can enroll</AlertTitle>
              <AlertDescription>
                <p>
                  It sits in the SCEP profile on every device, so whoever copies it from one can enroll under any names. The platform cannot tie a certificate to a device. What they can get is still bounded:
                </p>
                <ul className="list-disc pl-5">
                  <li>by the Issuing CA's permitted names, which keep DNS and email names to your Organization's zones;</li>
                  <li>by Name Rules, if you add them below;</li>
                  <li>by a short validity, {daysLabel(DEFAULT_SHARED_CHALLENGE_VALIDITY_DAYS)} unless you set another under Certificate, since nothing revokes these certificates automatically;</li>
                  <li>and by revoking a lost device's certificate by hand.</li>
                </ul>
                <p>The platform makes the Shared Challenge and shows it once, when the profile is created.</p>
              </AlertDescription>
            </Alert>
          )}
          {intune && (
            <FieldSet>
              <FieldLegend variant="label">Entra app</FieldLegend>
              <EntraChecklist orgId={orgId} />
              <FieldGroup>
                <Field data-invalid={tenantId.trim() !== "" && !TENANT.test(tenantId.trim())}>
                  <FieldLabel htmlFor="intune-tenant">Tenant ID</FieldLabel>
                  <Input id="intune-tenant" autoFocus value={tenantId} onChange={(e) => setTenantId(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" />
                  <FieldDescription>The directory (tenant) ID, or a domain of it such as contoso.onmicrosoft.com. In Entra: Overview.</FieldDescription>
                </Field>
                <Field data-invalid={appId.trim() !== "" && !GUID.test(appId.trim())}>
                  <FieldLabel htmlFor="intune-app">Application (client) ID</FieldLabel>
                  <Input id="intune-app" value={appId} onChange={(e) => setAppId(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" />
                  <FieldDescription>In Entra: App registrations, then the app's Overview.</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor="intune-secret">Client secret</FieldLabel>
                  <Input id="intune-secret" type="password" autoComplete="off" value={appSecret} onChange={(e) => setAppSecret(e.target.value)} />
                  <FieldDescription>Its value, not its ID, from the app's Certificates &amp; secrets. It is stored encrypted and never shown again. Test the connection from the list once the profile is created.</FieldDescription>
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
            <SummaryRows
              rows={[
                { label: "Name", value: name.trim() },
                ...(adcs && device
                  ? [
                      { label: "Certificate Template", value: adcsTemplateTitle(device.ca.name, device.template) },
                      { label: "RA certificate template", value: adcsTemplateTitle(device.ca.name, raTemplates.find((t) => t.id === raTemplateId) ?? { name: "", displayName: "" }) },
                      { label: "Validity and key usages", value: "As the Certificate Template decides" },
                      { label: "Retention", value: `${daysLabel(Number(retentionDays))} after it ends` },
                    ]
                  : [
                      { label: "Issuing CA", value: issuingCas.find((i) => i.id === issuingCaId)?.title ?? "" },
                      { label: "Validity", value: daysLabel(Number(validityDays)) },
                      { label: "Retention", value: `${daysLabel(Number(retentionDays))} after it ends` },
                      { label: "Extended key usage", value: extendedKeyUsage.map((u) => EXTENDED_KEY_USAGE_LABEL[u]).join(", ") },
                      { label: "Key usage", value: keyUsage.map((u) => KEY_USAGE_LABEL[u]).join(", ") },
                    ]),
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
    </SteppedForm>
  );
}
