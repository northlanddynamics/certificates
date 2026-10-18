// PROTOTYPE (branch prototype/csr-ux): throwaway. Three alternatives to the New Managed Certificate dialog's CSR
// handling, switched with `?variant=` on the Certificates page (A is today's dialog). Nothing here creates anything:
// the last button shows what would have been sent.
//   B  Key step (generate / paste / command) and a "Save your key" checkpoint step
//   C  Generate on the last click: choose only the key type, the key is made and saved after Review
//   D  One scrolling page, the names and the CSR checked against each other as you type
import { useQuery } from "@tanstack/react-query";
import { CheckIcon, ClipboardCheckIcon, GlobeIcon, KeyRoundIcon, LandmarkIcon, LoaderIcon, ShieldCheckIcon, UsersIcon, type LucideIcon } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { KeyAlgorithmCards, KeySource, SaveKey, csrOf, emptyKey, keyAtRisk, makeKey, useKeyReady, type KeyState } from "@/components/csr-key-source.prototype";
import { IssuerChoiceFields, useIssuerChoice } from "@/components/issuer-choice";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Field, FieldDescription, FieldError, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Sidebar, SidebarContent, SidebarGroup, SidebarGroupContent, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarProvider } from "@/components/ui/sidebar";
import { Textarea } from "@/components/ui/textarea";
import { api, can, ownerKey, type Me } from "@/lib/api";
import { KEY_ALGORITHM_LABELS, type KeyAlgorithm } from "@/lib/csr-generator";
import { nameProblems, splitNames } from "@/lib/csr-names";
import { permitsOnlyLabel } from "@/lib/private-ca";
import { cn } from "@/lib/utils";

type Org = Me["organizations"][number];

export const DIALOG_VARIANTS = [
  { key: "A", name: "Today" },
  { key: "B", name: "Key step + save checkpoint" },
  { key: "C", name: "Generate on the last click" },
  { key: "D", name: "One page, live check" },
];

export interface PrototypeFormProps {
  org: Org;
  direct: boolean;
  variant: string;
  /** Told whenever a generated key that has not been saved would be lost by closing. */
  onAtRisk: (atRisk: boolean) => void;
  onDone: () => void;
}

export function PrototypeNewManagedCertificateForm(props: PrototypeFormProps) {
  if (props.variant === "B") return <VariantB {...props} />;
  if (props.variant === "C") return <VariantC {...props} />;
  return <VariantD {...props} />;
}

// --- What every variant asks for ------------------------------------------------------------------------------------

function useCommonState(org: Org) {
  const choice = useIssuerChoice(org.id, { canReadAccounts: can(org, "acmeAccount", "read"), canReadPrivateCas: can(org, "privateCa", "read") });
  const [names, setNames] = useState("");
  const [keyAlgorithm, setKeyAlgorithm] = useState<KeyAlgorithm>("ecdsa-p256");
  const [key, setKey] = useState<KeyState>(emptyKey());
  const [owners, setOwners] = useState<string[]>([]);
  const parsedNames = splitNames(names);
  const problems = nameProblems(parsedNames);
  return { choice, names, setNames, parsedNames, problems, keyAlgorithm, setKeyAlgorithm, key, setKey, owners, setOwners };
}
type Common = ReturnType<typeof useCommonState>;

function useReportRisk(key: KeyState, onAtRisk: (atRisk: boolean) => void) {
  const atRisk = keyAtRisk(key);
  useEffect(() => onAtRisk(atRisk), [atRisk, onAtRisk]);
}

function AuthorityBody({ c, direct }: { c: Common; direct: boolean }) {
  return (
    <FieldSet>
      <FieldLegend>Where should it be issued from?</FieldLegend>
      <FieldDescription>{direct ? "Issuance starts as soon as it is created." : "An Approver must approve it before any Certificate is issued."}</FieldDescription>
      <IssuerChoiceFields choice={c.choice} idPrefix="proto-mc" trying="an Issuance" />
    </FieldSet>
  );
}

function NamesBody({ c, rows = 8 }: { c: Common; rows?: number }) {
  const invalid = c.names.trim() !== "" && c.problems.length > 0;
  return (
    <Field data-invalid={invalid}>
      <FieldLabel htmlFor="proto-mc-names">Domain names</FieldLabel>
      <Textarea id="proto-mc-names" rows={rows} value={c.names} aria-invalid={invalid} onChange={(e) => c.setNames(e.target.value)} placeholder={"www.example.com\nexample.com"} />
      <FieldDescription>One per line; wildcards as *.example.com.</FieldDescription>
      {c.choice.chosenCa && <FieldDescription>{permitsOnlyLabel(c.choice.chosenCa)}</FieldDescription>}
      {invalid && c.problems.map((p) => <FieldError key={p}>{p}</FieldError>)}
    </Field>
  );
}

function useOwnerChoices(org: Org) {
  const people = useQuery({ queryKey: ["members", org.id], queryFn: () => api.members(org.id) });
  const teams = useQuery({ queryKey: ["teams", org.id], queryFn: () => api.teams(org.id) });
  return [
    ...(teams.data?.items.map((t) => ({ key: ownerKey({ type: "team", id: t.id }), label: `${t.name} (Team)` })) ?? []),
    ...(people.data?.items.map((p) => ({ key: ownerKey({ type: "user", id: p.userId }), label: p.email })) ?? []),
  ];
}

function OwnersBody({ c, org }: { c: Common; org: Org }) {
  const choices = useOwnerChoices(org);
  return (
    <FieldSet>
      <FieldLegend variant="label">Owners (optional)</FieldLegend>
      <div className="flex max-h-56 flex-col gap-3 overflow-y-auto rounded-md border p-3">
        {choices.length === 0 && <span className="text-sm text-muted-foreground">No one to choose from yet.</span>}
        {choices.map(({ key, label }) => (
          <Field key={key} orientation="horizontal">
            <Checkbox
              id={`proto-owner-${key}`}
              checked={c.owners.includes(key)}
              onCheckedChange={(on) => c.setOwners(on === true ? [...c.owners, key] : c.owners.filter((o) => o !== key))}
            />
            <FieldLabel htmlFor={`proto-owner-${key}`} className="font-normal">
              {label}
            </FieldLabel>
          </Field>
        ))}
      </div>
    </FieldSet>
  );
}

function Summary({ c, keyLine }: { c: Common; keyLine: ReactNode }) {
  const rows: [string, ReactNode][] = [
    ["Issued from", c.choice.title],
    ["Domain names", <ul className="font-mono text-xs">{c.parsedNames.map((n) => <li key={n}>{n}</li>)}</ul>],
    ["Key", keyLine],
    ["Owners", c.owners.length > 0 ? `${c.owners.length} chosen` : <span className="text-muted-foreground">None</span>],
  ];
  return (
    <dl className="grid grid-cols-[7rem_1fr] gap-x-4 gap-y-3 rounded-md border p-4 text-sm">
      {rows.map(([label, value]) => (
        <div key={label} className="col-span-2 grid grid-cols-subgrid items-baseline">
          <dt className="text-muted-foreground">{label}</dt>
          <dd className="min-w-0 break-words">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

const keySummary = (c: Common) =>
  c.key.mode === "later"
    ? `${KEY_ALGORITHM_LABELS[c.keyAlgorithm]}; the Owners give the CSR once the names are approved`
    : c.key.mode === "generate"
    ? `${KEY_ALGORITHM_LABELS[c.keyAlgorithm]}, made in this browser${c.key.generated ? `; saved as ${c.key.generated.fileBase}.key.pem` : ""}`
    : `${KEY_ALGORITHM_LABELS[c.keyAlgorithm]}, your own CSR (${c.key.mode === "command" ? "openssl" : "pasted"})`;

/** What would have been sent: the prototype's end. */
function WouldSend({ c, direct, onDone }: { c: Common; direct: boolean; onDone: () => void }) {
  const csr = csrOf(c.key, c.parsedNames, c.keyAlgorithm);
  const body = { names: c.parsedNames, keyAlgorithm: c.keyAlgorithm, csr: c.key.mode === "later" ? "(after approval)" : csr ? `${csr.slice(0, 64)}…` : "(none)", ...c.choice.request, owners: c.owners };
  return (
    <div className="flex flex-1 flex-col gap-4 overflow-y-auto p-6">
      <p className="flex items-center gap-2 font-medium">
        <ShieldCheckIcon className="size-5 text-emerald-600" />
        PROTOTYPE: this is where it would be {direct ? "created and issued" : "proposed"}. Nothing was sent.
      </p>
      <pre className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs">{JSON.stringify(body, null, 2)}</pre>
      <div>
        <Button onClick={onDone}>Close</Button>
      </div>
    </div>
  );
}

// --- A wizard frame, for B and C ------------------------------------------------------------------------------------

export interface Step {
  id: string;
  title: string;
  icon: LucideIcon;
  complete: boolean;
  body: ReactNode;
}

export function Wizard({ steps, title, finishLabel, finishDisabled, onFinish }: { steps: Step[]; title: string; finishLabel: string; finishDisabled?: boolean; onFinish: () => void }) {
  const [stepId, setStepId] = useState(steps[0]!.id);
  const index = Math.max(0, steps.findIndex((s) => s.id === stepId));
  const step = steps[index]!;
  const last = index === steps.length - 1;
  const reachable = (i: number) => steps.slice(0, i).every((s) => s.complete);
  const goTo = (i: number) => steps[i] && reachable(i) && setStepId(steps[i].id);
  return (
    <SidebarProvider className="h-[min(640px,85vh)] min-h-0 items-stretch">
      <Sidebar collapsible="none" className="hidden border-r md:flex">
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupContent>
              <SidebarMenu>
                {steps.map((s, i) => (
                  <SidebarMenuItem key={s.id}>
                    <SidebarMenuButton isActive={i === index} disabled={!reachable(i)} onClick={() => goTo(i)}>
                      {i < index && s.complete ? <CheckIcon className="text-primary" /> : <s.icon />}
                      <span>{s.title}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>
      </Sidebar>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center justify-between gap-2 px-4 pr-12 text-sm">
          <span>
            <span className="hidden text-muted-foreground md:inline">{title} › </span>
            {step.title}
          </span>
          <span className="text-xs text-muted-foreground">
            Step {index + 1} of {steps.length}
          </span>
        </header>
        <div className="flex flex-1 flex-col gap-4 overflow-y-auto p-4 pt-0">{step.body}</div>
        <footer className="flex shrink-0 items-center justify-between gap-2 border-t bg-muted/50 p-4">
          <Button type="button" variant="outline" disabled={index === 0} onClick={() => goTo(index - 1)}>
            Back
          </Button>
          {last ? (
            <Button type="button" disabled={finishDisabled || !steps.every((s) => s.complete)} onClick={onFinish}>
              {finishLabel}
            </Button>
          ) : (
            <Button type="button" disabled={!step.complete} onClick={() => goTo(index + 1)}>
              Next
            </Button>
          )}
        </footer>
      </div>
    </SidebarProvider>
  );
}

// --- B: Key step, then a Save-your-key checkpoint -------------------------------------------------------------------

function VariantB({ org, direct, onAtRisk, onDone }: PrototypeFormProps) {
  const c = useCommonState(org);
  useReportRisk(c.key, onAtRisk);
  const [done, setDone] = useState(false);
  const keyReady = useKeyReady(c.key, c.parsedNames, c.keyAlgorithm);
  const generatedFits = csrOf(c.key, c.parsedNames, c.keyAlgorithm) !== "";
  if (done) return <WouldSend c={c} direct={direct} onDone={onDone} />;

  const steps: Step[] = [
    { id: "authority", title: "Certificate Authority", icon: LandmarkIcon, complete: c.choice.validityOk, body: <AuthorityBody c={c} direct={direct} /> },
    { id: "names", title: "Domain names", icon: GlobeIcon, complete: c.problems.length === 0, body: <NamesBody c={c} /> },
    {
      id: "key",
      title: "Key and CSR",
      icon: KeyRoundIcon,
      complete: c.key.mode === "generate" ? generatedFits : keyReady,
      body: (
        <FieldSet>
          <FieldLegend>How will you provide the CSR?</FieldLegend>
          <KeySource
            names={c.parsedNames}
            keyAlgorithm={c.keyAlgorithm}
            onKeyAlgorithmChange={c.setKeyAlgorithm}
            onNamesChange={(names) => c.setNames(names.join("\n"))}
            allowLater={!direct}
            state={c.key}
            onChange={c.setKey}
            saveInline={false}
            idPrefix="proto-b"
          />
        </FieldSet>
      ),
    },
    ...(c.key.mode === "generate"
      ? [
          {
            id: "save",
            title: "Save your key",
            icon: ShieldCheckIcon,
            complete: c.key.keySaved && c.key.confirmed,
            body: (
              <FieldSet>
                <FieldLegend>Save your private key</FieldLegend>
                <FieldDescription>Next stays off until you have downloaded or copied it. Closing this dialog before then asks first.</FieldDescription>
                <SaveKey state={c.key} onChange={c.setKey} />
              </FieldSet>
            ),
          },
        ]
      : []),
    { id: "ownership", title: "Ownership", icon: UsersIcon, complete: true, body: <OwnersBody c={c} org={org} /> },
    { id: "review", title: "Review", icon: ClipboardCheckIcon, complete: true, body: <Summary c={c} keyLine={keySummary(c)} /> },
  ];
  return <Wizard steps={steps} title={direct ? "New Managed Certificate" : "Propose a Managed Certificate"} finishLabel={direct ? "Create and issue" : "Propose"} onFinish={() => setDone(true)} />;
}

// --- C: choose the key type; the key is made, and saved, after Review -----------------------------------------------

function VariantC({ org, direct, onAtRisk, onDone }: PrototypeFormProps) {
  const c = useCommonState(org);
  useReportRisk(c.key, onAtRisk);
  const [phase, setPhase] = useState<"form" | "generating" | "save" | "done">("form");
  const own = c.key.mode !== "generate";
  const ownReady = useKeyReady(c.key, c.parsedNames, c.keyAlgorithm);
  if (phase === "done") return <WouldSend c={c} direct={direct} onDone={onDone} />;

  if (phase === "generating" || phase === "save")
    return (
      <div className="flex h-[min(640px,85vh)] flex-col">
        <header className="flex h-14 shrink-0 items-center px-6 text-sm font-medium">Last step: save your private key</header>
        <div className="flex flex-1 flex-col gap-4 overflow-y-auto px-6">
          {phase === "generating" ? (
            <p className="flex items-center gap-2 text-sm text-muted-foreground">
              <LoaderIcon className="size-4 animate-spin" /> Making a {KEY_ALGORITHM_LABELS[c.keyAlgorithm]} key in this browser…
            </p>
          ) : (
            <>
              <p className="text-sm text-muted-foreground">
                Everything else is ready. Once the key is saved, the {direct ? "Managed Certificate is created and Issuance starts" : "proposal goes to an Approver"}.
              </p>
              <SaveKey state={c.key} onChange={c.setKey} />
            </>
          )}
        </div>
        <footer className="flex shrink-0 items-center justify-between gap-2 border-t bg-muted/50 p-4">
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              c.setKey(emptyKey());
              setPhase("form");
            }}
          >
            Discard key and go back
          </Button>
          <Button type="button" disabled={phase !== "save" || !c.key.keySaved || !c.key.confirmed} onClick={() => setPhase("done")}>
            {direct ? "Create and issue" : "Propose"}
          </Button>
        </footer>
      </div>
    );

  const steps: Step[] = [
    { id: "authority", title: "Certificate Authority", icon: LandmarkIcon, complete: c.choice.validityOk, body: <AuthorityBody c={c} direct={direct} /> },
    { id: "names", title: "Domain names", icon: GlobeIcon, complete: c.problems.length === 0, body: <NamesBody c={c} /> },
    {
      id: "key",
      title: "Key",
      icon: KeyRoundIcon,
      complete: !own || ownReady,
      body: (
        <div className="flex flex-col gap-6">
          {!own && (
            <FieldSet>
              <FieldLegend>What kind of key?</FieldLegend>
              <FieldDescription>The key is made in this browser when you finish, so changing anything before then costs nothing.</FieldDescription>
              <KeyAlgorithmCards value={c.keyAlgorithm} onChange={c.setKeyAlgorithm} idPrefix="proto-c-alg" />
            </FieldSet>
          )}
          <Field orientation="horizontal">
            <Checkbox id="proto-c-own" checked={own} onCheckedChange={(on) => c.setKey(emptyKey(on === true ? "command" : "generate"))} />
            <FieldLabel htmlFor="proto-c-own" className="font-normal">
              {direct ? "I'll make the key myself (openssl, or a CSR I already have)" : "I'll make the key myself, or give the CSR after approval"}
            </FieldLabel>
          </Field>
          {own && (
            <KeySource
              names={c.parsedNames}
              keyAlgorithm={c.keyAlgorithm}
              onKeyAlgorithmChange={c.setKeyAlgorithm}
              onNamesChange={(names) => c.setNames(names.join("\n"))}
              modes={["command", "paste", "later"]}
              allowLater={!direct}
              state={c.key}
              onChange={c.setKey}
              idPrefix="proto-c"
            />
          )}
        </div>
      ),
    },
    { id: "ownership", title: "Ownership", icon: UsersIcon, complete: true, body: <OwnersBody c={c} org={org} /> },
    {
      id: "review",
      title: "Review",
      icon: ClipboardCheckIcon,
      complete: true,
      body: (
        <>
          <Summary c={c} keyLine={own ? keySummary(c) : `${KEY_ALGORITHM_LABELS[c.keyAlgorithm]}, to be made in this browser when you click below`} />
          {!own && <p className="text-sm text-muted-foreground">Next you save the key; nothing is sent until you have.</p>}
        </>
      ),
    },
  ];
  return (
    <Wizard
      steps={steps}
      title={direct ? "New Managed Certificate" : "Propose a Managed Certificate"}
      finishLabel={own ? (direct ? "Create and issue" : "Propose") : "Generate key and continue"}
      onFinish={async () => {
        if (own) return setPhase("done");
        setPhase("generating");
        c.setKey({ ...emptyKey(), generated: await makeKey(c.parsedNames, c.keyAlgorithm) });
        setPhase("save");
      }}
    />
  );
}

// --- D: one page --------------------------------------------------------------------------------------------------

function VariantD({ org, direct, onAtRisk, onDone }: PrototypeFormProps) {
  const c = useCommonState(org);
  useReportRisk(c.key, onAtRisk);
  const [done, setDone] = useState(false);
  const keyReady = useKeyReady(c.key, c.parsedNames, c.keyAlgorithm);
  if (done) return <WouldSend c={c} direct={direct} onDone={onDone} />;
  const namesOk = c.problems.length === 0;
  const sections = [
    { id: "proto-d-authority", title: "Certificate Authority", ok: c.choice.validityOk },
    { id: "proto-d-names", title: "Domain names", ok: namesOk },
    { id: "proto-d-key", title: "Key and CSR", ok: keyReady },
    { id: "proto-d-owners", title: "Owners", ok: true },
  ];
  const ready = sections.every((s) => s.ok);
  return (
    <div className="flex h-[min(700px,90vh)] min-h-0">
      <nav className="hidden w-48 shrink-0 flex-col gap-1 border-r bg-sidebar p-3 text-sm md:flex">
        <span className="px-2 pb-2 text-xs font-medium text-muted-foreground">{direct ? "New Managed Certificate" : "Propose a Managed Certificate"}</span>
        {sections.map((s) => (
          <a key={s.id} href={`#${s.id}`} className="flex items-center gap-2 rounded-md px-2 py-1.5 hover:bg-sidebar-accent">
            <span className={cn("flex size-4 items-center justify-center rounded-full border", s.ok && "border-emerald-600 bg-emerald-600 text-white")}>
              {s.ok && <CheckIcon className="size-3" />}
            </span>
            {s.title}
          </a>
        ))}
      </nav>
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex flex-1 flex-col gap-8 overflow-y-auto scroll-smooth p-6 pr-12">
          <section id="proto-d-authority">
            <AuthorityBody c={c} direct={direct} />
          </section>
          <section id="proto-d-names" className="flex flex-col gap-2">
            <NamesBody c={c} rows={4} />
          </section>
          <section id="proto-d-key" className={cn("flex flex-col gap-4", !namesOk && "pointer-events-none opacity-50")}>
            <FieldSet>
              <FieldLegend>Key and CSR</FieldLegend>
              {!namesOk && <FieldDescription>Enter the names first: the CSR is made for exactly them.</FieldDescription>}
            </FieldSet>
            <KeySource
              names={c.parsedNames}
              keyAlgorithm={c.keyAlgorithm}
              onKeyAlgorithmChange={c.setKeyAlgorithm}
              onNamesChange={(names) => c.setNames(names.join("\n"))}
              allowLater={!direct}
              state={c.key}
              onChange={c.setKey}
              idPrefix="proto-d"
            />
          </section>
          <section id="proto-d-owners">
            <OwnersBody c={c} org={org} />
          </section>
        </div>
        <footer className="flex shrink-0 items-center justify-between gap-4 border-t bg-muted/50 p-4 text-sm">
          <span className="text-muted-foreground">
            {c.parsedNames.length} {c.parsedNames.length === 1 ? "name" : "names"} · {KEY_ALGORITHM_LABELS[c.keyAlgorithm]} ·{" "}
            {c.key.mode === "later" ? "CSR after approval" : keyReady ? "CSR ready" : c.key.mode === "generate" && c.key.generated ? "key not saved" : "no CSR yet"}
          </span>
          <Button type="button" disabled={!ready} onClick={() => setDone(true)}>
            {direct ? "Create and issue" : "Propose"}
          </Button>
        </footer>
      </div>
    </div>
  );
}
