import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BotIcon, CheckIcon, ClipboardCheckIcon, FileTerminalIcon, GlobeIcon, PlusIcon, RefreshCwIcon, type LucideIcon } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { IssuerChoiceFields, useIssuerChoice } from "@/components/issuer-choice";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet, FieldTitle } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { api, can, type Me, type RenewalPolicy } from "@/lib/api";
import { KEY_ALGORITHMS, KEY_ALGORITHM_LABELS, type KeyAlgorithm } from "@/lib/csr-generator";
import { nameProblems, splitNames } from "@/lib/csr-names";
import { permitsOnlyLabel } from "@/lib/private-ca";

const STEPS = [
  { id: "agent", title: "Agent", icon: BotIcon },
  { id: "certificate", title: "Certificate", icon: GlobeIcon },
  { id: "script", title: "Script", icon: FileTerminalIcon },
  { id: "renewal", title: "Renewal", icon: RefreshCwIcon },
  { id: "review", title: "Review", icon: ClipboardCheckIcon },
] as const satisfies readonly { id: string; title: string; icon: LucideIcon }[];
type StepId = (typeof STEPS)[number]["id"];

const LATEST = "latest";

/** The button that sets up a Deployment in one guided flow, and the dialog it opens. */
export function NewDeploymentDialog({ org }: { org: Me["organizations"][number] }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          Set up a Deployment
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Set up a Deployment</DialogTitle>
          <DialogDescription>
            The Agent makes the key on its own host and sends the platform only a CSR. No Approval is needed: the Certificate is issued and the script run as soon as the Agent
            has done its part.
          </DialogDescription>
        </DialogHeader>
        {/* Only mounted while open, so each opening starts from a clean form and the lists are fetched only when wanted. */}
        {open && <NewDeploymentForm org={org} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function NewDeploymentForm({ org, onDone }: { org: Me["organizations"][number]; onDone: () => void }) {
  const orgId = org.id;
  const queryClient = useQueryClient();
  const [step, setStep] = useState<StepId>("agent");
  const [agentId, setAgentId] = useState("");
  const [names, setNames] = useState("");
  const [keyAlgorithm, setKeyAlgorithm] = useState<KeyAlgorithm>("ecdsa-p256");
  const choice = useIssuerChoice(orgId, { canReadAccounts: can(org, "acmeAccount", "read"), canReadPrivateCas: can(org, "privateCa", "read") });
  const [scriptId, setScriptId] = useState("");
  const [version, setVersion] = useState(LATEST);
  const [mode, setMode] = useState<RenewalPolicy["mode"]>("automatic");
  const [days, setDays] = useState("30");

  const agents = useQuery({ queryKey: ["agents", orgId, "choices"], queryFn: () => api.agents(orgId, { status: [], os: [], outdated: false }, { page: 1, pageSize: 100 }) });
  const scripts = useQuery({ queryKey: ["deployment-scripts", orgId, "choices"], queryFn: () => api.deploymentScripts(orgId, { page: 1, pageSize: 100 }) });
  const script = useQuery({ queryKey: ["deployment-scripts", orgId, scriptId], queryFn: () => api.deploymentScript(orgId, scriptId), enabled: scriptId !== "" });
  const usable = agents.data?.items.filter((a) => a.status !== "revoked") ?? [];
  const chosenAgent = usable.find((a) => a.id === agentId);
  const chosenScript = scripts.data?.items.find((s) => s.id === scriptId);

  const parsedNames = splitNames(names);
  const problems = nameProblems(parsedNames);
  const daysNumber = Number(days);
  const daysValid = Number.isInteger(daysNumber) && daysNumber >= 1 && daysNumber <= 365;
  const complete: Record<StepId, boolean> = {
    agent: chosenAgent !== undefined,
    certificate: problems.length === 0 && choice.validityOk,
    script: chosenScript !== undefined,
    renewal: mode === "manual" || daysValid,
    review: true,
  };
  const index = STEPS.findIndex((s) => s.id === step);
  const last = index === STEPS.length - 1;
  const reachable = (i: number) => STEPS.slice(0, i).every((s) => complete[s.id]);
  const goTo = (i: number) => {
    const target = STEPS[i];
    if (target && reachable(i)) setStep(target.id);
  };

  const create = useMutation({
    mutationFn: () =>
      api.createDeployment(orgId, {
        agentId,
        scriptId,
        ...(version !== LATEST && { scriptVersion: Number(version) }),
        names: parsedNames,
        keyAlgorithm,
        ...choice.request,
        renewalPolicy: { mode, daysBeforeExpiry: daysValid ? daysNumber : 30 },
      }),
    onSuccess: async () => {
      await Promise.all([queryClient.invalidateQueries({ queryKey: ["deployments"] }), queryClient.invalidateQueries({ queryKey: ["inventory"] })]);
      onDone();
    },
  });
  const versions = script.data?.versions ?? [];

  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        if (!last) goTo(index + 1);
        else if (STEPS.every((s) => complete[s.id])) create.mutate();
      }}
    >
      <ol className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm" aria-label="Steps">
        {STEPS.map((s, i) => (
          <li key={s.id}>
            <button
              type="button"
              className="flex items-center gap-1.5 rounded-sm px-1 py-0.5 disabled:opacity-50 aria-[current=step]:font-semibold"
              aria-current={s.id === step ? "step" : undefined}
              disabled={!reachable(i)}
              onClick={() => goTo(i)}
            >
              {i < index && complete[s.id] ? <CheckIcon className="size-4 text-primary" /> : <s.icon className="size-4" />}
              {s.title}
            </button>
          </li>
        ))}
      </ol>

      <div className="flex min-h-64 flex-col gap-4">
        {step === "agent" && (
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="new-deployment-agent">Agent</FieldLabel>
              <Select value={agentId} onValueChange={setAgentId}>
                <SelectTrigger id="new-deployment-agent" className="w-full">
                  <SelectValue placeholder={agents.isPending ? "Loading…" : "Choose an Agent"} />
                </SelectTrigger>
                <SelectContent>
                  {usable.map((a) => (
                    <SelectItem key={a.id} value={a.id}>
                      {a.hostName} ({a.status === "online" ? "online" : "offline"})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FieldDescription>
                The Agent that makes the key and puts the Certificate to use; one Agent can serve many Deployments. An Agent that is offline does its part when it is back.
              </FieldDescription>
              {agents.data && usable.length === 0 && <FieldError>No Agent is registered yet. Register one under Agents.</FieldError>}
            </Field>
          </FieldGroup>
        )}

        {step === "certificate" && (
          <FieldGroup>
            <Field data-invalid={names.trim() !== "" && problems.length > 0}>
              <FieldLabel htmlFor="new-deployment-names">Domain names</FieldLabel>
              <Textarea id="new-deployment-names" rows={5} autoFocus value={names} aria-invalid={names.trim() !== "" && problems.length > 0} onChange={(e) => setNames(e.target.value)} />
              <FieldDescription>One per line; wildcards as *.example.com. The Certificate is issued for exactly these names.</FieldDescription>
              {choice.chosenCa && <FieldDescription>{permitsOnlyLabel(choice.chosenCa)}</FieldDescription>}
              {names.trim() !== "" && problems.map((problem) => <FieldError key={problem}>{problem}</FieldError>)}
            </Field>
            <Field>
              <FieldLabel htmlFor="new-deployment-algorithm">Key algorithm</FieldLabel>
              <Select value={keyAlgorithm} onValueChange={(value) => setKeyAlgorithm(value as KeyAlgorithm)}>
                <SelectTrigger id="new-deployment-algorithm" className="w-full">
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
              <FieldDescription>The Agent makes a key of this type on its own host.</FieldDescription>
            </Field>
            <FieldSet>
              <FieldLegend variant="label">Issued from</FieldLegend>
              <FieldDescription>An ACME CA issues it after checking control of the names (DCV); an Issuing CA of one of the Organization's Private CAs issues it with no DCV.</FieldDescription>
              <IssuerChoiceFields choice={choice} idPrefix="new-deployment" trying="a Deployment" />
            </FieldSet>
          </FieldGroup>
        )}

        {step === "script" && (
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="new-deployment-script">Deployment Script</FieldLabel>
              <Select
                value={scriptId}
                onValueChange={(value) => {
                  setScriptId(value);
                  setVersion(LATEST);
                }}
              >
                <SelectTrigger id="new-deployment-script" className="w-full">
                  <SelectValue placeholder={scripts.isPending ? "Loading…" : "Choose a script"} />
                </SelectTrigger>
                <SelectContent>
                  {scripts.data?.items.map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.name} ({s.interpreter === "bash" ? "Bash" : "PowerShell"})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FieldDescription>
                What the Agent runs with each Certificate. It finds the key, leaf, chain and full-chain files in <code>CERT_KEY_FILE</code>, <code>CERT_LEAF_FILE</code>,{" "}
                <code>CERT_CHAIN_FILE</code> and <code>CERT_FULLCHAIN_FILE</code>.
              </FieldDescription>
              {scripts.data && scripts.data.items.length === 0 && <FieldError>No Deployment Script is uploaded yet. Upload one under Deployment Scripts.</FieldError>}
            </Field>
            {chosenScript && (
              <Field>
                <FieldLabel htmlFor="new-deployment-version">Version</FieldLabel>
                <Select value={version} onValueChange={setVersion}>
                  <SelectTrigger id="new-deployment-version" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={LATEST}>Latest (version {chosenScript.latestVersion.version})</SelectItem>
                    {versions.map((v) => (
                      <SelectItem key={v.hash} value={String(v.version)}>
                        Version {v.version} ({v.hash.slice(0, 12)})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FieldDescription>The Deployment keeps to this version; a later version is not run unless you set up another Deployment.</FieldDescription>
              </Field>
            )}
          </FieldGroup>
        )}

        {step === "renewal" && (
          <FieldGroup>
            <FieldSet>
              <FieldLegend variant="label">Renewal Policy</FieldLegend>
              <FieldDescription>Every Renewal runs the script again with the new Certificate.</FieldDescription>
              <RadioGroup value={mode} onValueChange={(value) => setMode(value as RenewalPolicy["mode"])}>
                {(
                  [
                    ["automatic", "Automatic", "The platform renews it before it expires."],
                    ["manual", "Manual", "Only a person renews it."],
                  ] as const
                ).map(([value, title, description]) => (
                  <FieldLabel key={value} htmlFor={`new-deployment-mode-${value}`}>
                    <Field orientation="horizontal">
                      <FieldContent>
                        <FieldTitle>{title}</FieldTitle>
                        <FieldDescription>{description}</FieldDescription>
                      </FieldContent>
                      <RadioGroupItem value={value} id={`new-deployment-mode-${value}`} />
                    </Field>
                  </FieldLabel>
                ))}
              </RadioGroup>
            </FieldSet>
            <Field data-invalid={!daysValid}>
              <FieldLabel htmlFor="new-deployment-days">Days before expiry</FieldLabel>
              <Input id="new-deployment-days" type="number" min={1} max={365} step={1} className="w-28" value={days} aria-invalid={!daysValid} onChange={(e) => setDays(e.target.value)} />
              <FieldDescription>
                {mode === "automatic" ? "How long before its Certificate ends it is due at the latest." : "Shown with the Managed Certificate."} A whole number from 1 to 365.
              </FieldDescription>
              {!daysValid && mode === "automatic" && <FieldError>Enter a whole number of days from 1 to 365.</FieldError>}
            </Field>
          </FieldGroup>
        )}

        {step === "review" && (
          <FieldGroup>
            <FieldSet>
              <FieldLegend>Review</FieldLegend>
              <FieldDescription>Use Back to change anything. Setting it up asks the Agent to make the key now.</FieldDescription>
              <Summary
                rows={[
                  { label: "Agent", value: chosenAgent?.hostName },
                  { label: "Domain names", value: <ul className="flex flex-col gap-0.5 font-mono text-xs">{parsedNames.map((name) => <li key={name}>{name}</li>)}</ul> },
                  { label: "Key algorithm", value: KEY_ALGORITHM_LABELS[keyAlgorithm] },
                  { label: "Issued from", value: choice.title },
                  ...(choice.validityText ? [{ label: "Validity", value: choice.validityText }] : []),
                  {
                    label: "Script",
                    value: chosenScript && `${chosenScript.name}, version ${version === LATEST ? chosenScript.latestVersion.version : version}`,
                  },
                  { label: "Renewal", value: mode === "automatic" ? `Automatic, ${days} days before expiry` : "Manual" },
                ]}
              />
            </FieldSet>
            {create.error && <FieldError>{create.error.message}</FieldError>}
          </FieldGroup>
        )}
      </div>

      <div className="flex items-center justify-between gap-2 border-t pt-4">
        <Button type="button" variant="outline" disabled={index === 0} onClick={() => goTo(index - 1)}>
          Back
        </Button>
        {last ? (
          <Button key="deploy" type="submit" disabled={create.isPending}>
            Deploy
          </Button>
        ) : (
          <Button key="next" type="button" disabled={!complete[step]} onClick={() => goTo(index + 1)}>
            Next
          </Button>
        )}
      </div>
    </form>
  );
}

function Summary({ rows }: { rows: { label: string; value: ReactNode }[] }) {
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
