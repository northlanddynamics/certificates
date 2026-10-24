import { useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { createColumnHelper, tableFeatures, useTable } from "@tanstack/react-table";
import { ClipboardCheckIcon, GlobeIcon, KeyRoundIcon, LandmarkIcon, PlusIcon, RefreshCwIcon, TagIcon, UsersIcon, type LucideIcon } from "lucide-react";
import { useState } from "react";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { DataTable } from "@/components/data-table/data-table";
import { IssuerChoiceFields, useIssuerChoice } from "@/components/issuer-choice";
import { SteppedForm, STEPPED_DIALOG, type Missing } from "@/components/stepped-form";
import { SummaryRows } from "@/components/summary-rows";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { ActionLabel, PageHeader } from "@/components/page-header";
import { acmeCaName, useAcmeCas } from "@/lib/acme-cas";
import { CERTIFICATE_PROFILE_GUIDE } from "@/lib/certificate-profile-guide";
import { api, can, type CertificateProfile, type CertificateProfileChanges, type RenewalPolicy } from "@/lib/api";
import { KEY_ALGORITHM_LABELS, type KeyAlgorithm } from "@/lib/csr-generator";
import { MAX_NAMES, splitNames } from "@/lib/csr-names";
import { chosenValidityLabel, findIssuingCa } from "@/lib/private-ca";
import { nameRulesLabel } from "@/lib/profile-choice";
import { disableConsequence } from "@/lib/profile-disable";
import { useAction } from "@/lib/use-action";
import { useOrg } from "@/lib/use-org";

const ROUTE = "/app/organizations/$orgId/certificate-profiles";
const NO_TEAM = "none";
const STEPS = [
  { id: "details", title: "Name", icon: TagIcon },
  { id: "issuer", title: "Issuer", icon: LandmarkIcon },
  { id: "keys", title: "Key algorithms", icon: KeyRoundIcon },
  { id: "names", title: "Name rules", icon: GlobeIcon },
  { id: "renewal", title: "Renewal", icon: RefreshCwIcon },
  { id: "team", title: "Co-Owner Team", icon: UsersIcon },
  { id: "review", title: "Review", icon: ClipboardCheckIcon },
] as const satisfies readonly { id: string; title: string; icon: LucideIcon }[];
type StepId = (typeof STEPS)[number]["id"];

const renewalLabel = (policy: RenewalPolicy) => (policy.mode === "manual" ? "Renewed by hand" : `Automatic, ${policy.daysBeforeExpiry} days before expiry`);

/** The profile's issuer in words: the ACME CA's name, or the Issuing CA's title; its id while the CAs are not yet read, or for one no longer listed. */
function IssuerName({ orgId, issuer }: { orgId: string; issuer: CertificateProfile["issuer"] }) {
  const acmeCas = useAcmeCas(orgId);
  const privateCas = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId), enabled: issuer.kind === "private_ca" });
  if (issuer.kind === "acme") return <>{acmeCaName(acmeCas.data?.items, issuer.acmeCaId)}</>;
  return <>{findIssuingCa(privateCas.data?.items ?? [], issuer.issuingCaId)?.name ?? issuer.issuingCaId}</>;
}

// The server lists every profile, so there is nothing to page.
const features = tableFeatures({});
const columnHelper = createColumnHelper<typeof features, CertificateProfile>();
const columns = (orgId: string, mayEdit: boolean, mayDisable: boolean) =>
  columnHelper.columns([
    columnHelper.accessor("name", {
      header: "Name",
      cell: ({ row }) => (
        <div className="flex flex-col gap-1">
          <span className="font-medium">
            {row.original.name} {!row.original.enabled && <Badge variant="secondary">Disabled</Badge>}
          </span>
          {row.original.description && <span className="text-sm text-muted-foreground">{row.original.description}</span>}
        </div>
      ),
    }),
    columnHelper.display({ id: "issuer", header: "Issuer", cell: ({ row }) => <IssuerName orgId={orgId} issuer={row.original.issuer} /> }),
    columnHelper.accessor("allowedKeyAlgorithms", { header: "Keys", cell: ({ cell }) => cell.getValue().map((algorithm) => KEY_ALGORITHM_LABELS[algorithm]).join(", ") }),
    columnHelper.display({ id: "validity", header: "Validity", cell: ({ row }) => (row.original.issuer.kind === "acme" ? "The CA's" : chosenValidityLabel(row.original.validityDays)) }),
    columnHelper.accessor("renewalPolicy", { header: "Renewal", cell: ({ cell }) => renewalLabel(cell.getValue()) }),
    columnHelper.accessor("nameRules", { header: "Names", cell: ({ cell }) => nameRulesLabel(cell.getValue()) ?? <span className="text-muted-foreground">Any the issuer takes</span> }),
    columnHelper.accessor("defaultTeam", { header: "Co-Owner", cell: ({ cell }) => cell.getValue()?.name ?? <span className="text-muted-foreground">None</span> }),
    columnHelper.display({
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      cell: ({ row }) => (
        <div className="flex justify-end gap-2">
          {mayEdit && <ProfileDialog orgId={orgId} profile={row.original} />}
          {mayDisable && (row.original.enabled ? <DisableDialog orgId={orgId} profile={row.original} /> : <EnableButton orgId={orgId} profile={row.original} />)}
        </div>
      ),
    }),
  ]);
const noRows: CertificateProfile[] = [];

/**
 * The Organization's Certificate Profiles: how it issues each kind of Managed Certificate, which members request against
 * instead of choosing a CA, a key algorithm, a validity and a Renewal Policy. Only Organization Administrators create,
 * edit, disable and enable them; editing one changes no Managed Certificate already made from it, and disabling one
 * stops anything more being issued under it until it is enabled again.
 */
export function CertificateProfilesPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const allowed = org ? can(org, "certificateProfile", "read") : false;
  const mayCreate = org ? can(org, "certificateProfile", "create") : false;
  const mayEdit = org ? can(org, "certificateProfile", "update") : false;
  const mayDisable = org ? can(org, "certificateProfile", "disable") : false;
  const profiles = useQuery({ queryKey: ["certificate-profiles", orgId], queryFn: () => api.certificateProfiles(orgId), enabled: allowed });
  const table = useTable({ features, columns: columns(orgId, mayEdit, mayDisable), data: profiles.data?.items ?? noRows, getRowId: (p) => p.id });

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Certificate Profiles"
        action={mayCreate && <ProfileDialog orgId={orgId} />}
        description="A profile says once how a kind of certificate is issued: from which CA, with which keys, for how long, and how it renews."
        howItWorksTitle="How Certificate Profiles work"
        howItWorks={<ProfileGuide />}
      />
      <DataTable table={table} empty={profiles.isPending ? "Loading…" : "No Certificate Profile yet."} />
      {profiles.error && <p className="text-sm text-destructive">{profiles.error.message}</p>}
      {mayEdit && <RequireProfileSetting orgId={orgId} />}
    </div>
  );
}

/** How profiles work: members requesting against them, setting one up, proposing through one, disabling and detaching. */
function ProfileGuide() {
  return (
    <>
      <p>Members request against a profile instead of choosing these themselves. Each Managed Certificate keeps the settings it was made with, so editing a profile changes only what is requested after.</p>
      {CERTIFICATE_PROFILE_GUIDE.map((section) => (
        <section key={section.title} className="flex flex-col gap-2 pt-2">
          <h2 className="text-sm font-medium text-foreground">{section.title}</h2>
          {section.paragraphs.map((paragraph) => (
            <p key={paragraph}>{paragraph}</p>
          ))}
        </section>
      ))}
    </>
  );
}

/** Whether those who may not create a Managed Certificate outright may propose one only through a profile; off unless turned on, and audited. */
function RequireProfileSetting({ orgId }: { orgId: string }) {
  const settings = useQuery({ queryKey: ["certificate-profile-settings", orgId], queryFn: () => api.certificateProfileSettings(orgId) });
  const change = useAction((requireProfile: boolean) => api.setCertificateProfileSettings(orgId, { requireProfile }), ["certificate-profile-settings", "me", "audit-events"]);
  return (
    <div className="flex flex-col gap-2">
      {settings.data && (
        <div className="flex items-start gap-3">
          <Checkbox
            id="require-profile"
            checked={settings.data.requireProfile}
            disabled={change.isPending}
            onCheckedChange={(checked) => change.mutate(checked === true)}
          />
          <div className="flex flex-col gap-1">
            <Label htmlFor="require-profile">Require a Certificate Profile</Label>
            <p className="text-sm text-muted-foreground">
              Whoever may not create a Managed Certificate outright may propose one only through a profile, with their API keys too, and is no longer offered Custom.
              Those who may create one outright, such as Organization Administrators, are not held to it, and Name Changes of existing Managed Certificates are not affected.
            </p>
          </div>
        </div>
      )}
      {(settings.error ?? change.error) && <p className="text-sm text-destructive">{(settings.error ?? change.error)!.message}</p>}
    </div>
  );
}

/** Asks before disabling the profile, saying what it stops: how many certificates stop renewing and how many pending decisions it holds. */
function DisableDialog({ orgId, profile }: { orgId: string; profile: CertificateProfile }) {
  const [open, setOpen] = useState(false);
  // Counted as the dialog opens, so the numbers are those of now.
  const read = useQuery({ queryKey: ["certificate-profile", orgId, profile.id], queryFn: () => api.certificateProfile(orgId, profile.id), enabled: open, staleTime: 0 });
  const disable = useAction(() => api.disableCertificateProfile(orgId, profile.id), ["certificate-profiles"], () => setOpen(false));
  return (
    <>
      <Button variant="ghost" size="sm" aria-label={`Disable ${profile.name}`} onClick={() => setOpen(true)}>
        Disable
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={(next) => {
          if (next) disable.reset();
          setOpen(next);
        }}
        title={`Disable ${profile.name}?`}
        description={read.data ? disableConsequence(read.data) : read.error ? read.error.message : "Counting what disabling it holds…"}
        confirmLabel="Disable"
        pending={disable.isPending || !read.data}
        error={disable.error}
        onConfirm={() => disable.mutate(undefined)}
      />
    </>
  );
}

/** Enables a disabled profile again: members see it, and what awaits Approval under it may be approved. */
function EnableButton({ orgId, profile }: { orgId: string; profile: CertificateProfile }) {
  const enable = useAction(() => api.enableCertificateProfile(orgId, profile.id), ["certificate-profiles"]);
  return (
    <div className="flex flex-col items-end gap-1">
      <Button variant="ghost" size="sm" aria-label={`Enable ${profile.name}`} disabled={enable.isPending} onClick={() => enable.mutate(undefined)}>
        {enable.isPending ? "Enabling…" : "Enable"}
      </Button>
      {enable.error && <span className="text-sm text-destructive">{enable.error.message}</span>}
    </div>
  );
}

/** Creates a profile, or edits `profile` when given, in steps. */
function ProfileDialog({ orgId, profile }: { orgId: string; profile?: CertificateProfile }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {profile ? (
          <Button variant="ghost" size="sm" aria-label={`Edit ${profile.name}`}>
            Edit
          </Button>
        ) : (
          <Button>
            <PlusIcon />
            <ActionLabel>New profile</ActionLabel>
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className={STEPPED_DIALOG}>
        <DialogTitle className="sr-only">{profile ? `Edit ${profile.name}` : "New Certificate Profile"}</DialogTitle>
        <DialogDescription className="sr-only">
          {profile ? "Managed Certificates already made from it keep what they were made with." : "Members will request Managed Certificates with these settings."}
        </DialogDescription>
        {/* Only mounted while open, so each opening starts from the profile as it is. */}
        {open && <ProfileForm orgId={orgId} profile={profile} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

// Every step's state lives here, so moving between steps never loses what was entered. Editing starts with every step complete, so any can be opened from the side.
function ProfileForm({ orgId, profile, onDone }: { orgId: string; profile?: CertificateProfile; onDone: () => void }) {
  const org = useOrg(orgId);
  const [step, setStep] = useState<StepId>("details");
  const [name, setName] = useState(profile?.name ?? "");
  const [description, setDescription] = useState(profile?.description ?? "");
  const choice = useIssuerChoice(orgId, { canReadPrivateCas: org ? can(org, "privateCa", "read") : false, canRegisterAcmeAccounts: org ? can(org, "acmeAccount", "create") : false, initial: profile && { issuer: profile.issuer, validityDays: profile.validityDays } });
  const [keys, setKeys] = useState<KeyAlgorithm[]>(profile?.allowedKeyAlgorithms ?? ["ecdsa-p256"]);
  const [mode, setMode] = useState<RenewalPolicy["mode"]>(profile?.renewalPolicy.mode ?? "automatic");
  const [days, setDays] = useState(String(profile?.renewalPolicy.daysBeforeExpiry ?? 30));
  const [teamId, setTeamId] = useState(profile?.defaultTeam?.id ?? NO_TEAM);
  const teams = useQuery({ queryKey: ["teams", orgId], queryFn: () => api.teams(orgId) });
  const [exactNames, setExactNames] = useState(profile?.nameRules.exact.join("\n") ?? "");
  const [zones, setZones] = useState(profile?.nameRules.zones.join("\n") ?? "");
  const [maxNames, setMaxNames] = useState(profile?.nameRules.maxNames === null || !profile ? "" : String(profile.nameRules.maxNames));
  const [wildcards, setWildcards] = useState(profile?.nameRules.wildcards ?? true);

  // Only the algorithms the chosen issuer takes count, so choosing another issuer drops those it does not.
  const allowedKeys = choice.keyAlgorithms.filter((algorithm) => keys.includes(algorithm));
  const daysOk = /^\d+$/.test(days) && Number(days) >= 1 && Number(days) <= 365;
  const maxNamesOk = maxNames.trim() === "" || (/^\d+$/.test(maxNames.trim()) && Number(maxNames) >= 1 && Number(maxNames) <= MAX_NAMES);
  const settings = {
    name: name.trim(),
    description: description.trim(),
    allowedKeyAlgorithms: allowedKeys,
    renewalPolicy: { mode, daysBeforeExpiry: Number(days) },
    defaultTeamId: teamId === NO_TEAM ? null : teamId,
    nameRules: { exact: splitNames(exactNames), zones: splitNames(zones), maxNames: maxNames.trim() === "" ? null : Number(maxNames), wildcards },
  };
  // None until an issuer is chosen, which the Issuer step asks for before Review.
  const { issuer } = choice;
  const changes: CertificateProfileChanges | null = issuer && { ...settings, issuer, validityDays: issuer.kind === "private_ca" ? choice.chosenValidity : null };
  const save = useAction(
    async () => {
      if (!changes) throw new Error("Choose where it is issued from.");
      return profile ? api.updateCertificateProfile(orgId, profile.id, changes) : api.createCertificateProfile(orgId, changes);
    },
    ["certificate-profiles", "audit-events"],
    onDone,
  );

  // What each step still needs. The Issuer step needs nothing unless its validity is out of range or its ACME CA has no account; the Co-Owner step never
  // does, a Team being optional; Review only shows what was entered.
  const missing: Partial<Record<StepId, Missing>> = {
    details: settings.name === "" ? { reason: "Give the profile a name.", field: "profile-name" } : undefined,
    issuer: !issuer
      ? { reason: "Choose where it is issued from." }
      : !choice.validityOk
      ? { reason: "Give a validity the Issuing CA allows.", field: "profile-validity" }
      : choice.registered === false
        ? { reason: "The Organization has no account with that ACME CA: choose another." }
        : undefined,
    keys: allowedKeys.length > 0 ? undefined : { reason: "Allow at least one key algorithm.", field: `profile-key-${choice.keyAlgorithms[0]}` },
    names: maxNamesOk ? undefined : { reason: `Give at most ${MAX_NAMES} names, or leave it empty for any.`, field: "profile-max-names" },
    renewal: daysOk ? undefined : { reason: "Give 1 to 365 days before expiry.", field: "profile-renewal-days" },
  };

  const title = profile ? `Edit ${profile.name}` : "New Certificate Profile";

  return (
    <SteppedForm
      title={title}
      steps={STEPS}
      step={step}
      onStep={setStep}
      missing={missing}
      submitLabel={profile ? "Save" : "Create"}
      pending={save.isPending}
      onSubmit={() => save.mutate(undefined)}
      tall
    >
      {step === "details" && (
        <FieldSet>
          <FieldLegend>Name it</FieldLegend>
          <FieldDescription>
            {profile ? "Managed Certificates already made from it keep what they were made with." : "Members will request Managed Certificates with these settings."}
          </FieldDescription>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="profile-name">Name</FieldLabel>
              <Input id="profile-name" autoFocus value={name} maxLength={100} onChange={(e) => setName(e.target.value)} placeholder="e.g. Internal web servers" />
            </Field>
            <Field>
              <FieldLabel htmlFor="profile-description">Description</FieldLabel>
              <Textarea id="profile-description" rows={3} value={description} maxLength={1000} onChange={(e) => setDescription(e.target.value)} />
              <FieldDescription>What it is for, which members read when they choose a profile.</FieldDescription>
            </Field>
          </FieldGroup>
        </FieldSet>
      )}

      {step === "issuer" && (
        <FieldSet>
          <FieldLegend>Where is it issued from?</FieldLegend>
          <IssuerChoiceFields choice={choice} idPrefix="profile" trying="a profile" />
        </FieldSet>
      )}

      {step === "keys" && (
        <FieldSet>
          <FieldLegend>Key algorithms</FieldLegend>
          <FieldDescription>The keys a requester's CSR may be for: those the issuer takes. With one, the CSR Generator is set to it.</FieldDescription>
          <div className="flex flex-col gap-3">
            {choice.keyAlgorithms.map((algorithm) => (
              <Field key={algorithm} orientation="horizontal">
                <Checkbox
                  id={`profile-key-${algorithm}`}
                  checked={keys.includes(algorithm)}
                  onCheckedChange={(checked) => setKeys((held) => (checked === true ? [...held, algorithm] : held.filter((a) => a !== algorithm)))}
                />
                <FieldLabel htmlFor={`profile-key-${algorithm}`} className="font-normal">
                  {KEY_ALGORITHM_LABELS[algorithm]}
                </FieldLabel>
              </Field>
            ))}
          </div>
        </FieldSet>
      )}

      {step === "names" && (
        <FieldSet>
          <FieldLegend>Name rules</FieldLegend>
          <FieldDescription>
            Which names members may request through it, within what the issuer allows. With no names and no zones, any name the issuer takes. Organization Administrators are
            held only to the issuer's limits, and editing the rules does not re-check pending Proposals.
          </FieldDescription>
          <FieldGroup>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field>
                <FieldLabel htmlFor="profile-exact-names">Names</FieldLabel>
                <Textarea id="profile-exact-names" rows={4} value={exactNames} onChange={(e) => setExactNames(e.target.value)} placeholder="e.g. www.example.com" />
                <FieldDescription>One per line, each allowed exactly; a wildcard as *.example.com.</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="profile-zones">Zones</FieldLabel>
                <Textarea id="profile-zones" rows={4} value={zones} onChange={(e) => setZones(e.target.value)} placeholder="e.g. internal.example.com" />
                <FieldDescription>One per line, each allowing the name and everything beneath it.</FieldDescription>
              </Field>
            </div>
            <div className="flex flex-wrap items-center gap-6">
              <div className="flex items-center gap-2">
                <Input
                  id="profile-max-names"
                  type="number"
                  min={1}
                  max={MAX_NAMES}
                  step={1}
                  className="w-20"
                  aria-invalid={!maxNamesOk}
                  value={maxNames}
                  onChange={(e) => setMaxNames(e.target.value)}
                  placeholder="Any"
                />
                <FieldLabel htmlFor="profile-max-names" className="font-normal">
                  names at most
                </FieldLabel>
              </div>
              <div className="flex items-center gap-2">
                <Checkbox id="profile-wildcards" checked={wildcards} onCheckedChange={(checked) => setWildcards(checked === true)} />
                <FieldLabel htmlFor="profile-wildcards" className="font-normal">
                  Wildcards allowed
                </FieldLabel>
              </div>
            </div>
            {!maxNamesOk && <FieldError>At most {MAX_NAMES} names, or leave it empty for any.</FieldError>}
          </FieldGroup>
        </FieldSet>
      )}

      {step === "renewal" && (
        <FieldSet>
          <FieldLegend>Starting Renewal Policy</FieldLegend>
          <FieldDescription>What each Managed Certificate made from it starts with; its Owners may change it after.</FieldDescription>
          <div className="flex flex-wrap items-center gap-2">
            <Select value={mode} onValueChange={(value) => setMode(value as RenewalPolicy["mode"])}>
              <SelectTrigger aria-label="Renewal">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="automatic">Automatic</SelectItem>
                <SelectItem value="manual">Manual</SelectItem>
              </SelectContent>
            </Select>
            <Input id="profile-renewal-days" type="number" min={1} max={365} step={1} className="w-20" aria-label="Days before expiry" aria-invalid={!daysOk} value={days} onChange={(e) => setDays(e.target.value)} />
            <span className="text-sm text-muted-foreground">days before expiry</span>
          </div>
          {!daysOk && <FieldError>Between 1 and 365 days.</FieldError>}
        </FieldSet>
      )}

      {step === "team" && (
        <FieldSet>
          <FieldLegend>Co-Owner Team</FieldLegend>
          <FieldDescription>Optional: a Team made an Owner of each certificate with the requester, so it is still looked after when they leave.</FieldDescription>
          <Field>
            <FieldLabel htmlFor="profile-team" className="sr-only">
              Co-Owner Team
            </FieldLabel>
            <Select value={teamId} onValueChange={setTeamId}>
              <SelectTrigger id="profile-team" className="w-60">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={NO_TEAM}>None</SelectItem>
                {(teams.data?.items ?? []).map((team) => (
                  <SelectItem key={team.id} value={team.id}>
                    {team.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
        </FieldSet>
      )}

      {step === "review" && (
        <FieldGroup>
          <FieldSet>
            <FieldLegend>Review</FieldLegend>
            <FieldDescription>
              {profile ? "Managed Certificates already made from it keep what they were made with." : "Members will request Managed Certificates with these settings."} Use Back to
              change anything.
            </FieldDescription>
            <SummaryRows
              rows={[
                { label: "Name", value: settings.name },
                ...(settings.description ? [{ label: "Description", value: settings.description }] : []),
                { label: "Issued from", value: choice.title ?? "" },
                ...(choice.validityText ? [{ label: "Validity", value: choice.validityText }] : []),
                { label: "Key algorithms", value: allowedKeys.map((algorithm) => KEY_ALGORITHM_LABELS[algorithm]).join(", ") },
                { label: "Names", value: nameRulesLabel(settings.nameRules) ?? <span className="text-muted-foreground">Any the issuer takes</span> },
                { label: "Renewal", value: renewalLabel(settings.renewalPolicy) },
                { label: "Co-Owner", value: teams.data?.items.find((team) => team.id === teamId)?.name ?? <span className="text-muted-foreground">None</span> },
              ]}
            />
          </FieldSet>
          {save.error && <FieldError>{save.error.message}</FieldError>}
        </FieldGroup>
      )}
    </SteppedForm>
  );
}
