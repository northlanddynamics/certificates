import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BotIcon, ClipboardCheckIcon, FileTerminalIcon, GlobeIcon, KeyRoundIcon, LandmarkIcon, PlusIcon, RefreshCwIcon, TriangleAlertIcon, type LucideIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { IssuerChoiceFields, useIssuerChoice } from "@/components/issuer-choice";
import { SteppedForm, STEPPED_DIALOG, type Missing } from "@/components/stepped-form";
import { ParameterFields, missingParameters, namesDeclared, shownValues } from "@/components/parameter-fields";
import { ParameterHelpSheet } from "@/components/parameter-help-sheet";
import { GuideLink } from "@/components/guide";
import { SummaryRows } from "@/components/summary-rows";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet, FieldTitle } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { ActionLabel } from "@/components/page-header";
import { ApiError, api, can, type Me, type RenewalPolicy } from "@/lib/api";
import { KEY_ALGORITHM_LABELS, isMlDsa, type KeyAlgorithm } from "@/lib/csr-generator";
import { nameProblems, splitNames } from "@/lib/csr-names";
import { permitsOnlyLabel } from "@/lib/private-ca";

const STEPS = [
  { id: "agent", title: "Agent", icon: BotIcon },
  { id: "authority", title: "Certificate Authority", icon: LandmarkIcon },
  { id: "names", title: "Domain names", icon: GlobeIcon },
  { id: "key", title: "Key algorithm", icon: KeyRoundIcon },
  { id: "script", title: "Deployment Script", icon: FileTerminalIcon },
  { id: "renewal", title: "Renewal", icon: RefreshCwIcon },
  { id: "review", title: "Review", icon: ClipboardCheckIcon },
] as const satisfies readonly { id: string; title: string; icon: LucideIcon }[];
type StepId = (typeof STEPS)[number]["id"];

const LATEST = "latest";

const INTRO =
  "The Agent makes the key on its own host and sends the platform only a CSR. No Approval is needed: the Certificate is issued and the script run as soon as the Agent has done its part.";

/** The button that sets up a Deployment in one guided flow, and the dialog it opens. */
export function NewDeploymentDialog({ org }: { org: Me["organizations"][number] }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          <ActionLabel>Set up a Deployment</ActionLabel>
        </Button>
      </DialogTrigger>
      <DialogContent className={STEPPED_DIALOG}>
        <DialogTitle className="sr-only">Set up a Deployment</DialogTitle>
        <DialogDescription className="sr-only">{INTRO}</DialogDescription>
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
  const choice = useIssuerChoice(orgId, { canReadPrivateCas: can(org, "privateCa", "read"), canRegisterAcmeAccounts: can(org, "acmeAccount", "create") });
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
  const unfilled = missingParameters(declared, parameters);
  const missing: Partial<Record<StepId, Missing>> = {
    agent: chosenAgent ? undefined : { reason: "Choose the Agent that will hold the key.", field: "new-deployment-agent" },
    authority: !choice.issuer
      ? { reason: "Choose where it is issued from." }
      : choice.validityOk
        ? undefined
        : { reason: "Give a validity the Issuing CA allows.", field: "new-deployment-validity" },
    names: problems.length === 0 ? undefined : { reason: problems[0]!, field: "new-deployment-names" },
    script: !chosenScript
      ? { reason: "Choose the Deployment Script.", field: "new-deployment-script" }
      : !chosenVersion
        ? { reason: "Choose the script's version.", field: "new-deployment-version" }
        : unfilled.length > 0
          ? { reason: `Give a value for ${declared.find((p) => p.name === unfilled[0])?.label ?? unfilled[0]}.`, field: `new-deployment-parameter-${unfilled[0]}` }
          : undefined,
    renewal: mode === "manual" || daysValid ? undefined : { reason: "Give 1 to 365 days before expiry.", field: "new-deployment-days" },
  };

  const create = useMutation({
    mutationFn: async () => {
      // The Certificate Authority step asks for an issuer before Review.
      if (!choice.request) throw new Error("Choose where it is issued from.");
      return api.createDeployment(orgId, {
        agentId,
        scriptId,
        ...(version !== LATEST && { scriptVersion: Number(version) }),
        parameters,
        names: parsedNames,
        keyAlgorithm,
        ...choice.request,
        renewalPolicy: { mode, daysBeforeExpiry: daysValid ? daysNumber : 30 },
      });
    },
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
    <SteppedForm
      title="Set up a Deployment"
      steps={STEPS}
      step={step}
      onStep={setStep}
      missing={missing}
      submitLabel="Deploy"
      pending={create.isPending}
      onSubmit={() => create.mutate()}
      tall
    >
      {step === "agent" && (
        <FieldGroup>
          <FieldSet>
            <FieldLegend>Which Agent will hold the key?</FieldLegend>
            <FieldDescription>{INTRO}</FieldDescription>
          </FieldSet>
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

      {step === "authority" && (
        <FieldSet>
          <FieldLegend>Where should it be issued from?</FieldLegend>
          <FieldDescription>An ACME CA issues it after checking control of the names (DCV); an Issuing CA of one of the Organization's Private CAs issues it with no DCV.</FieldDescription>
          <IssuerChoiceFields choice={choice} idPrefix="new-deployment" trying="a Deployment" />
        </FieldSet>
      )}

      {step === "names" && (
        <FieldGroup>
          <Field data-invalid={names.trim() !== "" && problems.length > 0}>
            <FieldLabel htmlFor="new-deployment-names">Domain names</FieldLabel>
            <Textarea id="new-deployment-names" rows={8} autoFocus value={names} aria-invalid={names.trim() !== "" && problems.length > 0} onChange={(e) => setNames(e.target.value)} />
            <FieldDescription>One per line; wildcards as *.example.com. The Certificate is issued for exactly these names.</FieldDescription>
            {choice.chosenCa && <FieldDescription>{permitsOnlyLabel(choice.chosenCa)}</FieldDescription>}
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
        <FieldGroup>
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
            <FieldDescription>The Agent makes a key of this type on its own host; the private key never leaves it. Only the types the chosen CA takes are offered.</FieldDescription>
          </Field>
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
              <code>CERT_CHAIN_FILE</code> and <code>CERT_FULLCHAIN_FILE</code>.{" "}
              <GuideLink orgId={orgId} guide="deployment-scripts" section="receives">
                What a script is given
              </GuideLink>
            </FieldDescription>
            {scripts.data && scripts.data.items.length === 0 && (
              <FieldError>
                No Deployment Script is uploaded yet. Upload one under Deployment Scripts, or{" "}
                <GuideLink orgId={orgId} guide="deployment-scripts" section="example">
                  start from the guide's example
                </GuideLink>
                .
              </FieldError>
            )}
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
              <div className="flex flex-wrap items-center justify-between gap-2">
                <FieldLegend variant="label">Parameters</FieldLegend>
                {chosenScript && chosenVersion && (
                  <ParameterHelpSheet orgId={orgId} script={`${chosenScript.name} v${chosenVersion.version}`} declared={declared} values={parameters} />
                )}
              </div>
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
    </SteppedForm>
  );
}
