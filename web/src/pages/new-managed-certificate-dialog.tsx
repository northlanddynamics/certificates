import { useMutation, useQuery } from "@tanstack/react-query";
import { useRouterState } from "@tanstack/react-router";
import { CheckIcon, ClipboardCheckIcon, FingerprintIcon, GlobeIcon, LandmarkIcon, PlusIcon, UsersIcon, type LucideIcon } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { CsrGenerator } from "@/components/csr-generator";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { CsrSignatureWarning } from "@/components/csr-signature-warning";
import { PrototypeSwitcher, isPrototypeSwitcher, usePrototypeVariant } from "@/components/prototype-switcher";
import { IssuerChoiceFields, useIssuerChoice } from "@/components/issuer-choice";
import { Breadcrumb, BreadcrumbItem, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet, FieldTitle } from "@/components/ui/field";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sidebar, SidebarContent, SidebarGroup, SidebarGroupContent, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarProvider } from "@/components/ui/sidebar";
import { Textarea } from "@/components/ui/textarea";
import { api, can, ownerFromKey, ownerKey, type ManagedCertificate, type Me } from "@/lib/api";
import { KEY_ALGORITHMS, KEY_ALGORITHM_LABELS, type KeyAlgorithm } from "@/lib/csr-generator";
import { nameProblems, splitNames } from "@/lib/csr-names";
import { permitsOnlyLabel } from "@/lib/private-ca";
import { DIALOG_VARIANTS, PrototypeNewManagedCertificateForm } from "./new-managed-certificate-dialog.prototype";

type Org = Me["organizations"][number];

const STEPS = [
  { id: "authority", title: "Certificate Authority", icon: LandmarkIcon },
  { id: "names", title: "Domain names", icon: GlobeIcon },
  { id: "subject", title: "Subject", icon: FingerprintIcon },
  { id: "ownership", title: "Ownership", icon: UsersIcon },
  { id: "review", title: "Review", icon: ClipboardCheckIcon },
] as const satisfies readonly { id: string; title: string; icon: LucideIcon }[];
type StepId = (typeof STEPS)[number]["id"];

/** The button for a new Managed Certificate, and the dialog it opens. Nothing shows for someone who may neither create nor propose one. */
export function NewManagedCertificateDialog({ org, onCreated }: { org: Org; onCreated: (created: ManagedCertificate) => void }) {
  const [open, setOpen] = useState(false);
  // PROTOTYPE: the variant, and whether closing would lose a generated key nobody has saved.
  const variant = usePrototypeVariant(DIALOG_VARIANTS);
  const asMember = useRouterState({ select: (st) => new URLSearchParams(st.location.searchStr).has("propose") });
  const [atRisk, setAtRisk] = useState(false);
  const [confirmClose, setConfirmClose] = useState(false);
  const direct = can(org, "managedCertificate", "create") && !asMember;
  if (!direct && !can(org, "managedCertificate", "propose")) return null;

  return (
    <>
    <PrototypeSwitcher title="New Managed Certificate dialog" variants={DIALOG_VARIANTS} toggle={{ param: "propose", label: "As a Member (propose)" }} />
    <ConfirmDialog
      open={confirmClose}
      onOpenChange={setConfirmClose}
      title="Discard the key you have not saved?"
      description="It was made in this browser and exists nowhere else. Closing throws it away; a CSR made from it would be useless."
      confirmLabel="Discard it and close"
      dismissLabel="Keep editing"
      pending={false}
      error={null}
      onConfirm={() => {
        setConfirmClose(false);
        setAtRisk(false);
        setOpen(false);
      }}
    />
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next && atRisk) return setConfirmClose(true);
        setOpen(next);
      }}
    >
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          New Managed Certificate
        </Button>
      </DialogTrigger>
      <DialogContent
        className="gap-0 overflow-hidden p-0 sm:max-w-[calc(100%-2rem)] md:max-w-[760px] lg:max-w-[860px]"
        onInteractOutside={(e) => isPrototypeSwitcher(e.target) && e.preventDefault()}
      >
        <DialogTitle className="sr-only">{direct ? "New Managed Certificate" : "Propose a Managed Certificate"}</DialogTitle>
        <DialogDescription className="sr-only">
          {direct ? "Issuance starts as soon as it is created." : "An Approver must approve it before any Certificate is issued."}
        </DialogDescription>
        {variant === "A" ? (
          <NewManagedCertificateForm
            org={org}
            direct={direct}
            onCreated={(created) => {
              setOpen(false);
              onCreated(created);
            }}
          />
        ) : (
          <PrototypeNewManagedCertificateForm
            key={variant}
            org={org}
            direct={direct}
            variant={variant}
            onAtRisk={setAtRisk}
            onDone={() => {
              setAtRisk(false);
              setOpen(false);
            }}
          />
        )}
      </DialogContent>
    </Dialog>
    </>
  );
}

// Only mounted while the dialog is open, so its form starts empty each time and the Owners are fetched only when wanted.
// Every step's state lives here, so moving between steps never loses what was entered.
function NewManagedCertificateForm({ org, direct, onCreated }: { org: Org; direct: boolean; onCreated: (created: ManagedCertificate) => void }) {
  const [step, setStep] = useState<StepId>("authority");
  const choice = useIssuerChoice(org.id, { canReadAccounts: can(org, "acmeAccount", "read"), canReadPrivateCas: can(org, "privateCa", "read") });
  const { chosenCa, validityOk } = choice;
  const [names, setNames] = useState("");
  const [keyAlgorithm, setKeyAlgorithm] = useState<KeyAlgorithm>("ecdsa-p256");
  const [csr, setCsr] = useState("");
  const [generating, setGenerating] = useState(false);
  // The CSR the generator filled in, so that changing the names or key algorithm it was made for can take it back out.
  const [generated, setGenerated] = useState<string | null>(null);
  const [owners, setOwners] = useState<string[]>([]);
  const people = useQuery({ queryKey: ["members", org.id], queryFn: () => api.members(org.id) });
  const teams = useQuery({ queryKey: ["teams", org.id], queryFn: () => api.teams(org.id) });
  const create = useMutation({
    mutationFn: () =>
      api.createManagedCertificate(org.id, {
        names: splitNames(names),
        keyAlgorithm,
        csr,
        ...choice.request,
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
  // Whether each step holds what it needs. The Authority step does unless its validity is out of range (one CA is always chosen); the Ownership and Review steps always do: Owners are optional, and Review only shows what was entered.
  const complete: Record<StepId, boolean> = { authority: validityOk, names: problems.length === 0, subject: csr.trim() !== "", ownership: true, review: true };
  const index = STEPS.findIndex((s) => s.id === step);
  const last = index === STEPS.length - 1;
  // A step may be opened once every step before it is complete.
  const reachable = (i: number) => STEPS.slice(0, i).every((s) => complete[s.id]);
  const goTo = (i: number) => {
    const target = STEPS[i];
    if (target && reachable(i)) setStep(target.id);
  };

  const dropGeneratedCsr = () => {
    if (generated !== null && csr === generated) setCsr("");
    setGenerated(null);
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
          else if (STEPS.every((s) => complete[s.id])) create.mutate();
        }}
      >
        <header className="flex h-14 shrink-0 items-center justify-between gap-2 px-4 pr-12">
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem className="hidden md:block">{direct ? "New Managed Certificate" : "Propose a Managed Certificate"}</BreadcrumbItem>
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
          {step === "authority" && (
            <FieldSet>
              <FieldLegend>Where should it be issued from?</FieldLegend>
              <FieldDescription>
                {direct ? "Issuance starts as soon as it is created." : "An Approver must approve it before any Certificate is issued."} An ACME CA issues it under the
                Organization's account for the environment you choose, after checking control of the names (DCV); an Issuing CA of one of the Organization's Private CAs issues it
                with no DCV.
              </FieldDescription>
              <IssuerChoiceFields choice={choice} idPrefix="new-mc" trying="an Issuance" />
            </FieldSet>
          )}

          {step === "names" && (
            <FieldGroup>
              <Field data-invalid={names.trim() !== "" && problems.length > 0}>
                <FieldLabel htmlFor="new-mc-names">Domain names</FieldLabel>
                <Textarea
                  id="new-mc-names"
                  rows={8}
                  autoFocus
                  value={names}
                  aria-invalid={names.trim() !== "" && problems.length > 0}
                  onChange={(e) => {
                    setNames(e.target.value);
                    // Only a change to the names themselves, not to the spaces between them, makes the CSR wrong.
                    if (splitNames(e.target.value).join("\n") !== parsedNames.join("\n")) dropGeneratedCsr();
                  }}
                />
                <FieldDescription>One per line; wildcards as *.example.com. The certificate is issued for exactly these names.</FieldDescription>
                {chosenCa && <FieldDescription>{permitsOnlyLabel(chosenCa)}</FieldDescription>}
                {names.trim() !== "" && problems.map((problem) => <FieldError key={problem}>{problem}</FieldError>)}
              </Field>
              {parsedNames.length > 0 && problems.length === 0 && (
                <p className="text-sm text-muted-foreground">
                  {parsedNames.length} {parsedNames.length === 1 ? "name" : "names"}.
                </p>
              )}
            </FieldGroup>
          )}

          {step === "subject" && (
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="new-mc-algorithm">Key algorithm</FieldLabel>
                <Select
                  value={keyAlgorithm}
                  onValueChange={(value) => {
                    setKeyAlgorithm(value as KeyAlgorithm);
                    dropGeneratedCsr();
                  }}
                >
                  <SelectTrigger id="new-mc-algorithm" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {KEY_ALGORITHMS.map((value) => (
                      <SelectItem key={value} value={value}>
                        {KEY_ALGORITHM_LABELS[value]}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FieldDescription>The type of key the CSR is made for. Changing it takes back a CSR that was generated here.</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="new-mc-csr">CSR</FieldLabel>
                <Textarea id="new-mc-csr" className="font-mono text-xs" rows={6} value={csr} onChange={(e) => setCsr(e.target.value)} />
                <CsrSignatureWarning pem={csr} />
                <FieldDescription>PEM, for a key you keep; it must ask for exactly the names from the previous step.</FieldDescription>
                {generating ? (
                  <div className="flex flex-col gap-3 rounded-md border p-4">
                    <CsrGenerator
                      names={parsedNames}
                      keyAlgorithm={keyAlgorithm}
                      locked
                      onUse={(pem) => {
                        setCsr(pem);
                        setGenerated(pem);
                        setGenerating(false);
                      }}
                    />
                    <div>
                      <Button type="button" variant="ghost" size="sm" onClick={() => setGenerating(false)}>
                        Close the generator
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div>
                    <Button type="button" variant="outline" size="sm" onClick={() => setGenerating(true)}>
                      Generate a key and CSR here
                    </Button>
                  </div>
                )}
              </Field>
            </FieldGroup>
          )}

          {step === "ownership" && (
            <FieldGroup>
              <FieldSet>
                <FieldLegend>Owners</FieldLegend>
                <FieldDescription>Optional: the users and Teams accountable for it.</FieldDescription>
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

          {step === "review" && (
            <FieldGroup>
              <FieldSet>
                <FieldLegend>Review</FieldLegend>
                <FieldDescription>
                  {direct ? "Issuance starts as soon as it is created." : "An Approver must approve it before any Certificate is issued."} Use Back to change anything.
                </FieldDescription>
                <Summary
                  issuer={choice.title ?? ""}
                  validity={choice.validityText}
                  names={parsedNames}
                  keyAlgorithm={keyAlgorithm}
                  csr={generated !== null && csr === generated ? "Generated in this browser" : "Provided"}
                  owners={ownerChoices.filter((c) => owners.includes(c.key)).map((c) => c.label)}
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
              {direct ? "Create and issue" : "Propose"}
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

function Summary({ issuer, validity, names, keyAlgorithm, csr, owners }: { issuer: string; validity: string | null; names: string[]; keyAlgorithm: KeyAlgorithm; csr: string; owners: string[] }) {
  const rows: { label: string; value: ReactNode }[] = [
    { label: "Issued from", value: issuer },
    ...(validity ? [{ label: "Validity", value: validity }] : []),
    { label: "Domain names", value: <ul className="flex flex-col gap-0.5 font-mono text-xs">{names.map((name) => <li key={name}>{name}</li>)}</ul> },
    { label: "Key algorithm", value: KEY_ALGORITHM_LABELS[keyAlgorithm] },
    { label: "CSR", value: csr },
    { label: "Owners", value: owners.length > 0 ? owners.join(", ") : <span className="text-muted-foreground">None</span> },
  ];
  return (
    <div className="rounded-md border p-4">
      <dl className="grid grid-cols-[7rem_1fr] gap-x-4 gap-y-3 text-sm">
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
