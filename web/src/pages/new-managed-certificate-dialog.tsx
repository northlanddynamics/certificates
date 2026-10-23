import { useMutation, useQuery } from "@tanstack/react-query";
import { ClipboardCheckIcon, FileBadgeIcon, GlobeIcon, KeyRoundIcon, LandmarkIcon, PlusIcon, ShieldCheckIcon, UsersIcon, type LucideIcon } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { KeySource, SaveKey, csrOf, emptyKeySource, keyAtRisk, useKeySourceReady, type KeySourceState } from "@/components/csr-key-source";
import { IssuerChoiceFields, useIssuerChoice } from "@/components/issuer-choice";
import { SteppedForm, STEPPED_DIALOG } from "@/components/stepped-form";
import { SummaryRows } from "@/components/summary-rows";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet, FieldTitle } from "@/components/ui/field";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Textarea } from "@/components/ui/textarea";
import { acmeCaName } from "@/lib/acme-cas";
import { api, can, ownerFromKey, ownerKey, type CertificateProfile, type ManagedCertificate, type Me } from "@/lib/api";
import { KEY_ALGORITHM_LABELS, type KeyAlgorithm } from "@/lib/csr-generator";
import { nameProblems, splitNames } from "@/lib/csr-names";
import { daysLabel, findIssuingCa, permitsOnlyLabel } from "@/lib/private-ca";
import { CUSTOM, keyStepFor, profileOptions, stepsFor } from "@/lib/profile-choice";

type Org = Me["organizations"][number];

const ALL_STEPS = [
  // Only when the Organization has a Certificate Profile to offer.
  { id: "profile", title: "Choose a profile", icon: FileBadgeIcon },
  // Not on a profile, which fixes the issuer.
  { id: "authority", title: "Certificate Authority", icon: LandmarkIcon },
  { id: "names", title: "Domain names", icon: GlobeIcon },
  { id: "key", title: "Key and CSR", icon: KeyRoundIcon },
  // Only when the key is generated here, which is the one way the key can be lost by closing the dialog.
  { id: "save", title: "Save your key", icon: ShieldCheckIcon },
  { id: "ownership", title: "Ownership", icon: UsersIcon },
  { id: "review", title: "Review", icon: ClipboardCheckIcon },
] as const satisfies readonly { id: string; title: string; icon: LucideIcon }[];
type StepId = (typeof ALL_STEPS)[number]["id"];

/** The button for a new Managed Certificate, and the dialog it opens. Nothing shows for someone who may neither create nor propose one. */
export function NewManagedCertificateDialog({ org, onCreated }: { org: Org; onCreated: (created: ManagedCertificate) => void }) {
  const [open, setOpen] = useState(false);
  // Whether closing would lose a generated key nobody has saved, and whether we are asking about that.
  const [atRisk, setAtRisk] = useState(false);
  const [confirmingClose, setConfirmingClose] = useState(false);
  const direct = can(org, "managedCertificate", "create");
  if (!direct && !can(org, "managedCertificate", "propose")) return null;

  const close = () => {
    setAtRisk(false);
    setConfirmingClose(false);
    setOpen(false);
  };
  return (
    <>
    <ConfirmDialog
      open={confirmingClose}
      onOpenChange={setConfirmingClose}
      title="Discard the key you have not saved?"
      description="It was made in this browser and exists nowhere else. Closing throws it away, and the CSR made from it with it."
      confirmLabel="Discard it and close"
      dismissLabel="Keep editing"
      pending={false}
      error={null}
      onConfirm={close}
    />
    <Dialog open={open} onOpenChange={(next) => (next ? setOpen(true) : atRisk ? setConfirmingClose(true) : close())}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          New Managed Certificate
        </Button>
      </DialogTrigger>
      <DialogContent className={STEPPED_DIALOG}>
        <DialogTitle className="sr-only">{direct ? "New Managed Certificate" : "Propose a Managed Certificate"}</DialogTitle>
        <DialogDescription className="sr-only">
          {direct ? "Issuance starts as soon as it is created." : "An Approver must approve it before any Certificate is issued."}
        </DialogDescription>
        <NewManagedCertificateForm
          org={org}
          direct={direct}
          onAtRisk={setAtRisk}
          onCreated={(created) => {
            close();
            onCreated(created);
          }}
        />
      </DialogContent>
    </Dialog>
    </>
  );
}

// Only mounted while the dialog is open, so its form starts empty each time and the Owners are fetched only when wanted.
// Every step's state lives here, so moving between steps never loses what was entered.
function NewManagedCertificateForm({
  org,
  direct,
  onAtRisk,
  onCreated,
}: {
  org: Org;
  direct: boolean;
  onAtRisk: (atRisk: boolean) => void;
  onCreated: (created: ManagedCertificate) => void;
}) {
  const [step, setStep] = useState<StepId>("profile");
  const choice = useIssuerChoice(org.id, { canReadPrivateCas: can(org, "privateCa", "read") });
  const { chosenCa, validityOk } = choice;
  const profiles = useQuery({ queryKey: ["certificate-profiles", org.id], queryFn: () => api.certificateProfiles(org.id), enabled: can(org, "certificateProfile", "read") });
  const profileChoices = profileOptions(profiles.data?.items ?? [], true);
  // The profile step's choice: a profile's id, Custom, or none yet.
  const [profileValue, setProfileValue] = useState<string | null>(null);
  const profile = profiles.data?.items.find((p) => p.enabled && p.id === profileValue);
  const keyStep = keyStepFor(profile, choice.keyAlgorithms);
  const { keyAlgorithms } = keyStep;
  const [names, setNames] = useState("");
  const [keyAlgorithm, setKeyAlgorithm] = useState<KeyAlgorithm>("ecdsa-p256");
  // Only what the chosen CA takes is offered: choosing a CA that does not take the key algorithm chosen moves to its first.
  useEffect(() => {
    if (keyAlgorithms.length > 0 && !keyAlgorithms.includes(keyAlgorithm)) setKeyAlgorithm(keyAlgorithms[0]!);
  }, [keyAlgorithms, keyAlgorithm]);
  const [keySource, setKeySourceState] = useState<KeySourceState>(emptyKeySource());
  const setKeySource = (next: KeySourceState) => {
    setKeySourceState(next);
    onAtRisk(keyAtRisk(next));
  };
  const [owners, setOwners] = useState<string[]>([]);
  const people = useQuery({ queryKey: ["members", org.id], queryFn: () => api.members(org.id) });
  const teams = useQuery({ queryKey: ["teams", org.id], queryFn: () => api.teams(org.id) });
  const create = useMutation({
    mutationFn: () =>
      api.createManagedCertificate(org.id, {
        names: splitNames(names),
        keyAlgorithm,
        csr: csrOf(keySource, splitNames(names), keyAlgorithm),
        ...(profile ? { profileId: profile.id } : choice.request),
        owners: owners.map(ownerFromKey),
      }),
    onSuccess: onCreated,
  });
  const ownerChoices = [
    ...(teams.data?.items.map((t) => ({ key: ownerKey({ type: "team", id: t.id }), label: `${t.name} (Team)` })) ?? []),
    ...(people.data?.items.map((p) => ({ key: ownerKey({ type: "user", id: p.userId }), label: p.email })) ?? []),
  ];

  const parsedNames = splitNames(names);
  const problems = nameProblems(parsedNames);
  const generating = keySource.mode === "generate";
  const keyReady = useKeySourceReady(keySource, parsedNames, keyAlgorithm);
  const steps = stepsFor(
    ALL_STEPS.filter((s) => s.id !== "save" || generating),
    { profilesOffered: profileChoices.some((c) => c.value !== CUSTOM), profile },
  );
  // The step that is open: the first, when the one chosen is not among them (no profiles to offer after all).
  const shown = steps.some((s) => s.id === step) ? step : steps[0]!.id;
  // Whether each step holds what it needs. The Authority step does unless its validity is out of range (one CA is always chosen). The Key step does once a key is
  // generated for these names, or a CSR that matches them is pasted; the Save step once that key is saved and the user says so. The Ownership and Review steps
  // always do: Owners are optional, and Review only shows what was entered.
  const complete: Record<StepId, boolean> = {
    profile: profileValue === CUSTOM || profile !== undefined,
    authority: validityOk,
    names: problems.length === 0,
    key: generating ? csrOf(keySource, parsedNames, keyAlgorithm) !== "" : keyReady,
    save: keyReady && keySource.confirmed,
    ownership: true,
    review: true,
  };

  return (
    <SteppedForm
      title={direct ? "New Managed Certificate" : "Propose a Managed Certificate"}
      steps={steps}
      step={shown}
      onStep={setStep}
      complete={complete}
      submitLabel={direct ? "Create and issue" : "Propose"}
      pending={create.isPending}
      onSubmit={() => create.mutate()}
      tall
    >
      {shown === "profile" && (
        <FieldSet>
          <FieldLegend>Choose a profile</FieldLegend>
          <FieldDescription>
            A Certificate Profile sets where it is issued from and the key it takes, so you enter only the names and the CSR.{" "}
            {direct ? "Issuance starts as soon as it is created." : "An Approver must approve it before any Certificate is issued."}
          </FieldDescription>
          <RadioGroup value={profileValue ?? ""} onValueChange={setProfileValue}>
            {profileChoices.map(({ value, title, description }) => (
              <FieldLabel key={value} htmlFor={`new-mc-profile-${value}`}>
                <Field orientation="horizontal">
                  <FieldContent>
                    <FieldTitle>{title}</FieldTitle>
                    {description && <FieldDescription>{description}</FieldDescription>}
                  </FieldContent>
                  <RadioGroupItem value={value} id={`new-mc-profile-${value}`} />
                </Field>
              </FieldLabel>
            ))}
          </RadioGroup>
        </FieldSet>
      )}

      {shown === "authority" && (
        <FieldSet>
          <FieldLegend>Where should it be issued from?</FieldLegend>
          <FieldDescription>
            {direct ? "Issuance starts as soon as it is created." : "An Approver must approve it before any Certificate is issued."} An ACME CA issues it under the
            Organization's account with the ACME CA you choose, after checking control of the names (DCV); an Issuing CA of one of the Organization's Private CAs issues it
            with no DCV.
          </FieldDescription>
          <IssuerChoiceFields choice={choice} idPrefix="new-mc" trying="an Issuance" />
        </FieldSet>
      )}

      {shown === "names" && (
        <FieldGroup>
          <Field data-invalid={names.trim() !== "" && problems.length > 0}>
            <FieldLabel htmlFor="new-mc-names">Domain names</FieldLabel>
            <Textarea
              id="new-mc-names"
              rows={8}
              autoFocus
              value={names}
              aria-invalid={names.trim() !== "" && problems.length > 0}
              onChange={(e) => setNames(e.target.value)}
            />
            <FieldDescription>One per line; wildcards as *.example.com. The certificate is issued for exactly these names.</FieldDescription>
            {!profile && chosenCa && <FieldDescription>{permitsOnlyLabel(chosenCa)}</FieldDescription>}
            {names.trim() !== "" && problems.map((problem) => <FieldError key={problem}>{problem}</FieldError>)}
          </Field>
          {parsedNames.length > 0 && problems.length === 0 && (
            <p className="text-sm text-muted-foreground">
              {parsedNames.length} {parsedNames.length === 1 ? "name" : "names"}.
            </p>
          )}
        </FieldGroup>
      )}

      {shown === "key" && (
        <FieldSet>
          <FieldLegend>How will you provide the CSR?</FieldLegend>
          <KeySource
            names={parsedNames}
            keyAlgorithm={keyAlgorithm}
            keyAlgorithms={keyAlgorithms}
            onKeyAlgorithmChange={keyStep.chosen ? setKeyAlgorithm : undefined}
            onNamesChange={(asked) => setNames(asked.join("\n"))}
            state={keySource}
            onChange={setKeySource}
            saveInline={false}
            idPrefix="new-mc-key"
          />
        </FieldSet>
      )}

      {shown === "save" && (
        <FieldSet>
          <FieldLegend>Save your private key</FieldLegend>
          <FieldDescription>Next stays off until you have downloaded or copied it. Closing this dialog before then asks first.</FieldDescription>
          <SaveKey state={keySource} onChange={setKeySource} confirm />
        </FieldSet>
      )}

      {shown === "ownership" && (
        <FieldGroup>
          <FieldSet>
            <FieldLegend>Owners</FieldLegend>
            <FieldDescription>
              Optional: the users and Teams accountable for it.
              {profile && ` Through ${profile.name}, you${profile.defaultTeam ? ` and the Team ${profile.defaultTeam.name}` : ""} become Owners as well.`}
            </FieldDescription>
            <div className="flex max-h-72 flex-col gap-3 overflow-y-auto rounded-md border p-3">
              {ownerChoices.length === 0 && !people.isPending && !teams.isPending && <span className="text-sm text-muted-foreground">No one to choose from yet.</span>}
              {ownerChoices.map(({ key, label }) => (
                <Field key={key} orientation="horizontal">
                  <Checkbox
                    id={`new-mc-owner-${key}`}
                    checked={owners.includes(key)}
                    onCheckedChange={(checked) => setOwners(checked === true ? [...owners, key] : owners.filter((o) => o !== key))}
                  />
                  <FieldLabel htmlFor={`new-mc-owner-${key}`} className="font-normal">
                    {label}
                  </FieldLabel>
                </Field>
              ))}
            </div>
          </FieldSet>
        </FieldGroup>
      )}

      {shown === "review" && (
        <FieldGroup>
          <FieldSet>
            <FieldLegend>Review</FieldLegend>
            <FieldDescription>
              {direct ? "Issuance starts as soon as it is created." : "An Approver must approve it before any Certificate is issued."} Use Back to change anything.
            </FieldDescription>
            <Summary
              profile={profile?.name ?? null}
              issuer={profile ? profileIssuerTitle(profile, choice) : (choice.title ?? "")}
              validity={profile ? profileValidityText(profile) : choice.validityText}
              names={parsedNames}
              keyAlgorithm={keyAlgorithm}
              csr={
                generating && keySource.generated
                  ? `Generated in this browser; the key saved as ${keySource.generated.fileBase}.key.pem`
                  : keySource.mode === "command"
                    ? "Made with openssl"
                    : "Pasted"
              }
              owners={ownerChoices.filter((c) => owners.includes(c.key)).map((c) => c.label)}
            />
          </FieldSet>
          {create.error && <FieldError>{create.error.message}</FieldError>}
        </FieldGroup>
      )}
    </SteppedForm>
  );
}

/** Where a profile issues from, in words: the ACME CA by name, the Issuing CA by name where the caller may read the Private CAs. */
function profileIssuerTitle(profile: CertificateProfile, choice: ReturnType<typeof useIssuerChoice>) {
  const { issuer } = profile;
  return issuer.kind === "acme" ? acmeCaName(choice.acmeCas, issuer.acmeCaId) : (findIssuingCa(choice.activeCas, issuer.issuingCaId)?.name ?? "A Private CA of the Organization");
}

/** The validity a profile fixes, in words; none for an ACME CA, which decides its own. */
const profileValidityText = (profile: CertificateProfile) =>
  profile.issuer.kind === "acme" ? null : profile.validityDays !== null ? daysLabel(profile.validityDays) : "The Issuing CA's default";

function Summary({
  profile,
  issuer,
  validity,
  names,
  keyAlgorithm,
  csr,
  owners,
}: {
  profile: string | null;
  issuer: string;
  validity: string | null;
  names: string[];
  keyAlgorithm: KeyAlgorithm;
  csr: string;
  owners: string[];
}) {
  const rows: { label: string; value: ReactNode }[] = [
    ...(profile ? [{ label: "Certificate Profile", value: profile }] : []),
    { label: "Issued from", value: issuer },
    ...(validity ? [{ label: "Validity", value: validity }] : []),
    { label: "Domain names", value: <ul className="flex flex-col gap-0.5 font-mono text-xs">{names.map((name) => <li key={name}>{name}</li>)}</ul> },
    { label: "Key algorithm", value: KEY_ALGORITHM_LABELS[keyAlgorithm] },
    { label: "CSR", value: csr },
    { label: "Owners", value: owners.length > 0 ? owners.join(", ") : <span className="text-muted-foreground">None</span> },
  ];
  return <SummaryRows rows={rows} />;
}
