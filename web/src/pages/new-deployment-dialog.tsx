import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BotIcon, CheckIcon, ClipboardCheckIcon, FileTerminalIcon, GlobeIcon, PlusIcon, RefreshCwIcon, TriangleAlertIcon, type LucideIcon } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { IssuerChoiceFields, useIssuerChoice } from "@/components/issuer-choice";
import { ParameterFields, missingParameters, namesDeclared, shownValues } from "@/components/parameter-fields";
import { SummaryRows } from "@/components/summary-rows";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet, FieldTitle } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { ApiError, api, can, type Me, type RenewalPolicy } from "@/lib/api";
import { KEY_ALGORITHM_LABELS, isMlDsa, type KeyAlgorithm } from "@/lib/csr-generator";
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
  const choice = useIssuerChoice(orgId, { canReadPrivateCas: can(org, "privateCa", "read") });
  // Only what the chosen CA takes is offered, as the server says: choosing a CA that does not take the key algorithm chosen moves to its first.
  const offered = choice.keyAlgorithms.length > 0 ? choice.keyAlgorithms : [keyAlgorithm];
  useEffect(() => {
    if (choice.keyAlgorithms.length > 0 && !choice.keyAlgorithms.includes(keyAlgorithm)) setKeyAlgorithm(choice.keyAlgorithms[0]!);
  }, [choice.keyAlgorithms, keyAlgorithm]);
  const [scriptId, setScriptId] = useState("");
  const [version, setVersion] = useState(LATEST);
  // What was typed for each parameter name, kept across a version switch so a name both versions declare keeps its value.
  const [typed, setTyped] = useState<Record<string, string>>({});
  const [mode, setMode] = useState<RenewalPolicy["mode"]>("automatic");
  const [days, setDays] = useState("30");

  const agents = useQuery({ queryKey: ["agents", orgId, "choices"], queryFn: () => api.agents(orgId, { status: [], os: [], outdated: false }, { page: 1, pageSize: 100 }) });
  const scripts = useQuery({ queryKey: ["deployment-scripts", orgId, "choices"], queryFn: () => api.deploymentScripts(orgId, { page: 1, pageSize: 100 }) });
  const script = useQuery({ queryKey: ["deployment-scripts", orgId, scriptId], queryFn: () => api.deploymentScript(orgId, scriptId), enabled: scriptId !== "" });
  const usable = agents.data?.items.filter((a) => a.status !== "revoked") ?? [];
  const chosenAgent = usable.find((a) => a.id === agentId);
  const chosenScript = scripts.data?.items.find((s) => s.id === scriptId);
  const versions = script.data?.versions ?? [];
  const chosenVersion = version === LATEST ? (script.data?.latestVersion ?? chosenScript?.latestVersion) : versions.find((v) => v.version === Number(version));
  const declared = chosenVersion?.parameters ?? [];
  const parameters = shownValues(declared, typed);

  const parsedNames = splitNames(names);
  const problems = nameProblems(parsedNames);
  const daysNumber = Number(days);
  const daysValid = Number.isInteger(daysNumber) && daysNumber >= 1 && daysNumber <= 365;
  const complete: Record<StepId, boolean> = {
    agent: chosenAgent !== undefined,
    certificate: problems.length === 0 && choice.validityOk,
    script: chosenScript !== undefined && chosenVersion !== undefined && missingParameters(declared, parameters).length === 0,
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
        parameters,
        names: parsedNames,
        keyAlgorithm,
        ...choice.request,
        renewalPolicy: { mode, daysBeforeExpiry: daysValid ? daysNumber : 30 },
      }),
    onSuccess: async () => {
      await Promise.all([queryClient.invalidateQueries({ queryKey: ["deployments"] }), queryClient.invalidateQueries({ queryKey: ["inventory"] })]);
      onDone();
    },
    // The server is the authority on the values: one it refuses is shown against its field, on the step that has it.
    onError: (error) => {
      if (error instanceof ApiError && namesDeclared(declared, error.fields?.parameters)) setStep("script");
    },
  });
  const parameterProblems = create.error instanceof ApiError ? create.error.fields?.parameters : undefined;

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
                  {offered.map((value) => (
                    <SelectItem key={value} value={value}>
                      {KEY_ALGORITHM_LABELS[value]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FieldDescription>The Agent makes a key of this type on its own host. Only the types the chosen CA takes are offered.</FieldDescription>
              {isMlDsa(keyAlgorithm) && (
                <Alert>
                  <TriangleAlertIcon />
                  <AlertTitle>The Deployment Script's target must support ML-DSA</AlertTitle>
                  <AlertDescription>
                    Whatever the script installs this key and Certificate into (a web server or load balancer, with OpenSSL 3.5 or later underneath, for example) must itself support ML-DSA, and so must the
                    clients that connect to it. The platform cannot make up for that: check them before you deploy.
                  </AlertDescription>
                </Alert>
              )}
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
                  setTyped({});
                  create.reset();
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
                <Select
                  value={version}
                  onValueChange={(value) => {
                    setVersion(value);
                    create.reset();
                  }}
                >
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
            {declared.length > 0 && (
              <FieldSet>
                <FieldLegend variant="label">Parameters</FieldLegend>
                <FieldDescription>What this version asks for. The values are kept in plain text on the Deployment and given to the script at every run: put nothing secret here.</FieldDescription>
                <ParameterFields
                  declared={declared}
                  typed={typed}
                  problems={parameterProblems}
                  idPrefix="new-deployment"
                  onChange={(name, value) => {
                    setTyped((t) => ({ ...t, [name]: value }));
                    create.reset();
                  }}
                />
              </FieldSet>
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
              <SummaryRows
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
                  ...(declared.length > 0
                    ? [
                        {
                          label: "Parameters",
                          value: (
                            <ul className="flex flex-col gap-0.5 font-mono text-xs">
                              {declared.map((p) => (
                                <li key={p.name}>
                                  {p.name} = {parameters[p.name]?.trim() ? parameters[p.name] : p.default?.trim() ? `${p.default} (default)` : <span className="font-sans text-muted-foreground">not set</span>}
                                </li>
                              ))}
                            </ul>
                          ),
                        },
                      ]
                    : []),
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
