import { useMutation, useQuery } from "@tanstack/react-query";
import { CheckIcon, ClipboardCheckIcon, GlobeIcon, KeyRoundIcon, LandmarkIcon, PlusIcon, ShieldCheckIcon, UsersIcon, type LucideIcon } from "lucide-react";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { KeySource, SaveKey, csrOf, emptyKeySource, keyAtRisk, useKeySourceReady, type KeySourceState } from "@/components/csr-key-source";
import { IssuerChoiceFields, useIssuerChoice } from "@/components/issuer-choice";
import { Breadcrumb, BreadcrumbItem, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet, FieldTitle } from "@/components/ui/field";
import { Sidebar, SidebarContent, SidebarGroup, SidebarGroupContent, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarProvider } from "@/components/ui/sidebar";
import { Textarea } from "@/components/ui/textarea";
import { api, can, ownerFromKey, ownerKey, type ManagedCertificate, type Me } from "@/lib/api";
import { KEY_ALGORITHM_LABELS, type KeyAlgorithm } from "@/lib/csr-generator";
import { nameProblems, splitNames } from "@/lib/csr-names";
import { permitsOnlyLabel } from "@/lib/private-ca";

type Org = Me["organizations"][number];

const ALL_STEPS = [
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
      <DialogContent className="gap-0 overflow-hidden p-0 sm:max-w-[calc(100%-2rem)] md:max-w-[760px] lg:max-w-[860px]">
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
  const [step, setStep] = useState<StepId>("authority");
  const choice = useIssuerChoice(org.id, { canReadAccounts: can(org, "acmeAccount", "read"), canReadPrivateCas: can(org, "privateCa", "read") });
  const { chosenCa, validityOk, keyAlgorithms } = choice;
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
  const generating = keySource.mode === "generate";
  const keyReady = useKeySourceReady(keySource, parsedNames, keyAlgorithm);
  const steps = ALL_STEPS.filter((s) => s.id !== "save" || generating);
  // Whether each step holds what it needs. The Authority step does unless its validity is out of range (one CA is always chosen). The Key step does once a key is
  // generated for these names, or a CSR that matches them is pasted; the Save step once that key is saved and the user says so. The Ownership and Review steps
  // always do: Owners are optional, and Review only shows what was entered.
  const complete: Record<StepId, boolean> = {
    authority: validityOk,
    names: problems.length === 0,
    key: generating ? csrOf(keySource, parsedNames, keyAlgorithm) !== "" : keyReady,
    save: keyReady && keySource.confirmed,
    ownership: true,
    review: true,
  };
  const index = Math.max(0, steps.findIndex((s) => s.id === step));
  const last = index === steps.length - 1;
  // A step may be opened once every step before it is complete.
  const reachable = (i: number) => steps.slice(0, i).every((s) => complete[s.id]);
  const goTo = (i: number) => {
    const target = steps[i];
    if (target && reachable(i)) setStep(target.id);
  };

  return (
    <SidebarProvider className="h-[min(640px,85vh)] min-h-0 items-stretch">
      <Sidebar collapsible="none" className="hidden border-r md:flex">
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupContent>
              <SidebarMenu>
                {steps.map((s, i) => {
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
          else if (steps.every((s) => complete[s.id])) create.mutate();
        }}
      >
        <header className="flex h-14 shrink-0 items-center justify-between gap-2 px-4 pr-12">
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem className="hidden md:block">{direct ? "New Managed Certificate" : "Propose a Managed Certificate"}</BreadcrumbItem>
              <BreadcrumbSeparator className="hidden md:block" />
              <BreadcrumbItem>
                <BreadcrumbPage>{steps[index]?.title}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
          <span className="text-xs text-muted-foreground">
            Step {index + 1} of {steps.length}
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
                  onChange={(e) => setNames(e.target.value)}
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

          {step === "key" && (
            <FieldSet>
              <FieldLegend>How will you provide the CSR?</FieldLegend>
              <KeySource
                names={parsedNames}
                keyAlgorithm={keyAlgorithm}
                keyAlgorithms={keyAlgorithms}
                onKeyAlgorithmChange={setKeyAlgorithm}
                onNamesChange={(asked) => setNames(asked.join("\n"))}
                state={keySource}
                onChange={setKeySource}
                saveInline={false}
                idPrefix="new-mc-key"
              />
            </FieldSet>
          )}

          {step === "save" && (
            <FieldSet>
              <FieldLegend>Save your private key</FieldLegend>
              <FieldDescription>Next stays off until you have downloaded or copied it. Closing this dialog before then asks first.</FieldDescription>
              <SaveKey state={keySource} onChange={setKeySource} confirm />
            </FieldSet>
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
