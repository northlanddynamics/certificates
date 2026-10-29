// The controls of an ADCS CA, which its page and the Private CAs page open: the wizard that adds or changes one, its
// Certificate Templates, and the warning of a CA without Permitted Name Rules.
import { useQuery } from "@tanstack/react-query";
import { ClipboardCheckIcon, ListChecksIcon, NetworkIcon, ServerIcon, TriangleAlertIcon } from "lucide-react";
import { useState, type ReactNode } from "react";
import { SteppedForm, STEPPED_DIALOG, type Missing } from "@/components/stepped-form";
import { SummaryRows } from "@/components/summary-rows";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { MANAGER_APPROVAL_NOTE, assignableAgents, ekuLabel, isConfigString, templateApprovalLabel, templateKeysLabel, templatePurposes } from "@/lib/adcs-ca";
import { api, can, type AdcsCa, type AdcsTemplate, type Agent } from "@/lib/api";
import { splitNames } from "@/lib/csr-names";
import { permittedNamesLabel } from "@/lib/private-ca";
import { templateGroups } from "@/lib/private-ca-list";
import { useAction } from "@/lib/use-action";
import { useOrg } from "@/lib/use-org";

const noAgents: Agent[] = [];

/** The Agents an ADCS CA may be shown with and assigned, when the caller may list them; none otherwise. */
export function useAdcsAgents(orgId: string) {
  const org = useOrg(orgId);
  // The same query as the other pages' choice of Agent, so they share what was fetched.
  const agents = useQuery({
    queryKey: ["agents", orgId, "choices"],
    queryFn: () => api.agents(orgId, { status: [], os: [], outdated: false }, { page: 1, pageSize: 100 }),
    enabled: org !== undefined && can(org, "agent", "read"),
  });
  return agents.data?.items ?? noAgents;
}

/** What an ADCS CA without Permitted Name Rules relies on: Approval alone stands between a Member and a Certificate the domain trusts. */
export function NoPermittedNames({ action }: { action?: ReactNode }) {
  return (
    <Alert className="border-warning/50 bg-warning/5">
      <TriangleAlertIcon className="text-warning" />
      <AlertTitle>No Permitted Name Rules</AlertTitle>
      <AlertDescription>
        ADCS checks its templates' permissions against the Agents' account, not against whoever asks, so Approval alone decides which names it is asked for. Give it Permitted Name Rules to refuse
        other names before anything is submitted.
        {action && <div className="mt-2">{action}</div>}
      </AlertDescription>
    </Alert>
  );
}

/** The CA's Certificate Templates as its last discovery found them, grouped: available, hidden, unavailable (with why), and hiding for those who manage it. */
export function TemplateTable({ orgId, ca, mayManage }: { orgId: string; ca: AdcsCa; mayManage: boolean }) {
  const setHidden = useAction(({ templateId, hidden }: { templateId: string; hidden: boolean }) => api.setAdcsTemplateHidden(orgId, ca.id, templateId, hidden), ["adcs-cas"]);
  if (ca.templates.length === 0) return <p className="text-sm text-muted-foreground">The CA publishes no Certificate Template.</p>;
  const groups = templateGroups(ca.templates);
  const columns = mayManage ? 7 : 6;
  const hideButton = (t: AdcsTemplate) =>
    mayManage && (
      <TableCell className="text-right">
        <Button
          variant={t.hidden ? "outline" : "ghost"}
          size="sm"
          disabled={setHidden.isPending}
          onClick={() => setHidden.mutate({ templateId: t.id, hidden: !t.hidden })}
          aria-label={`${t.hidden ? "Show" : "Hide"} ${t.name}`}
        >
          {t.hidden ? "Show" : "Hide"}
        </Button>
      </TableCell>
    );
  const name = (t: AdcsTemplate) => (
    <TableCell>
      <div className="font-medium">{t.displayName || t.name}</div>
      <div className="font-mono text-xs text-muted-foreground">{t.name}</div>
    </TableCell>
  );
  const facts = (t: AdcsTemplate) => (
    <>
      <TableCell className="whitespace-normal">{t.extendedKeyUsages.map(ekuLabel).join(", ")}</TableCell>
      <TableCell>{t.validityDays} days</TableCell>
      <TableCell className="whitespace-normal">{templateKeysLabel(t)}</TableCell>
      <TableCell className="whitespace-normal">
        {t.managerApproval ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <Badge variant="warning" tabIndex={0}>
                {templateApprovalLabel(t)}
              </Badge>
            </TooltipTrigger>
            <TooltipContent className="max-w-72">{MANAGER_APPROVAL_NOTE}</TooltipContent>
          </Tooltip>
        ) : (
          <span className="text-muted-foreground">{templateApprovalLabel(t)}</span>
        )}
      </TableCell>
    </>
  );
  const group = (label: string, items: AdcsTemplate[]) =>
    items.length > 0 && (
      <TableRow className="bg-muted/50 hover:bg-muted/50">
        <TableCell colSpan={columns} className="text-xs font-medium text-muted-foreground">
          {label} · {items.length}
        </TableCell>
      </TableRow>
    );
  return (
    <>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Template</TableHead>
            <TableHead>For</TableHead>
            <TableHead>EKUs</TableHead>
            <TableHead>Validity</TableHead>
            <TableHead>Keys</TableHead>
            <TableHead>Approval</TableHead>
            {mayManage && <TableHead className="sr-only">Hide</TableHead>}
          </TableRow>
        </TableHeader>
        <TableBody>
          {group("Available", groups.available)}
          {groups.available.map((t) => (
            <TableRow key={t.id}>
              {name(t)}
              <TableCell>{templatePurposes(t).join(", ") || <span className="text-muted-foreground">Neither</span>}</TableCell>
              {facts(t)}
              {hideButton(t)}
            </TableRow>
          ))}
          {group("Hidden by an Organization Administrator", groups.hidden)}
          {groups.hidden.map((t) => (
            <TableRow key={t.id} className="text-muted-foreground">
              {name(t)}
              <TableCell className="whitespace-normal">{t.unavailableReason ?? "Nothing while hidden"}</TableCell>
              {facts(t)}
              {hideButton(t)}
            </TableRow>
          ))}
          {group("Unavailable", groups.unavailable)}
          {groups.unavailable.map((t) => (
            <TableRow key={t.id} className="text-muted-foreground">
              {name(t)}
              <TableCell colSpan={5} className="whitespace-normal">
                <div className="text-foreground">{t.unavailableReason}</div>
                <div className="mt-1 text-xs">
                  {[t.extendedKeyUsages.map(ekuLabel).join(", "), `${t.validityDays} days`, templateKeysLabel(t)].filter(Boolean).join(" · ")}. Once ADCS makes it available, Refresh brings it back.
                </div>
              </TableCell>
              {hideButton(t)}
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {setHidden.error && <p className="text-sm text-destructive">{setHidden.error.message}</p>}
    </>
  );
}

export type AdcsWizardStep = "ca" | "agents" | "names" | "review";
type StepId = AdcsWizardStep;
const STEPS = {
  ca: { title: "The CA", icon: ServerIcon },
  agents: { title: "Agents", icon: NetworkIcon },
  names: { title: "Permitted names", icon: ListChecksIcon },
  review: { title: "Review", icon: ClipboardCheckIcon },
};

/** Changes an ADCS CA: renames it, changes its Agents and Permitted Name Rules; its config string stays. Opens at `step`. */
export function EditAdcsCaDialog({ orgId, ca, open, onOpenChange, step = "ca" }: { orgId: string; ca: AdcsCa; open: boolean; onOpenChange: (open: boolean) => void; step?: StepId }) {
  const agents = useAdcsAgents(orgId);
  const title = `Edit ${ca.name}`;
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className={STEPPED_DIALOG}>
        <DialogTitle className="sr-only">{title}</DialogTitle>
        <DialogDescription className="sr-only">Saving changes it at once.</DialogDescription>
        {open && <AdcsCaWizard orgId={orgId} agents={agents} ca={ca} title={title} initialStep={step} onDone={() => onOpenChange(false)} />}
      </DialogContent>
    </Dialog>
  );
}

/** What the dialog that adds an ADCS CA says of it, for those who cannot see the wizard. */
export const ADD_ADCS_CA_DESCRIPTION = "An assigned Agent reaches the CA when it is added; nothing is saved if none can.";

// Only mounted while the dialog is open, so the form starts clean each time.
export function AdcsCaWizard({
  orgId,
  agents,
  ca,
  title,
  initialStep = "ca",
  onDone,
}: {
  orgId: string;
  agents: Agent[];
  ca?: AdcsCa;
  title: string;
  initialStep?: StepId;
  onDone: () => void;
}) {
  const [name, setName] = useState(ca?.name ?? "");
  const [configString, setConfigString] = useState(ca?.configString ?? "");
  const [agentIds, setAgentIds] = useState<string[]>(ca?.agentIds ?? []);
  const [exact, setExact] = useState(ca?.permittedNames?.exact.join("\n") ?? "");
  const [zones, setZones] = useState(ca?.permittedNames?.zones.join("\n") ?? "");
  const [step, setStep] = useState<StepId>(initialStep);
  const steps = (["ca", "agents", "names", "review"] as const).map((id) => ({ id, ...STEPS[id] }));
  // No rule at all is none: the CA relies on Approval alone.
  const permittedNames = splitNames(exact).length + splitNames(zones).length === 0 ? null : { exact: splitNames(exact), zones: splitNames(zones) };
  const choices = assignableAgents(agents, agentIds);

  const missing: Partial<Record<StepId, Missing>> = {
    ca:
      name.trim() === ""
        ? { reason: "Give the ADCS CA a name.", field: "adcs-name" }
        : !ca && !isConfigString(configString)
          ? { reason: "Give the config string: the CA's host, a backslash and its name.", field: "adcs-config" }
          : undefined,
    agents: agentIds.length === 0 ? { reason: "Choose at least one Windows Agent." } : undefined,
  };
  const save = useAction(
    () =>
      ca
        ? api.changeAdcsCa(orgId, ca.id, { name: name.trim(), agentIds, permittedNames })
        : api.createAdcsCa(orgId, { name: name.trim(), configString: configString.trim(), agentIds, permittedNames }),
    ["adcs-cas"],
    onDone,
  );
  const hostOf = (id: string) => agents.find((a) => a.id === id)?.hostName ?? "An Agent";
  const rows: { label: string; value: ReactNode }[] = [
    { label: "Name", value: name.trim() },
    { label: "Config string", value: <span className="font-mono text-xs">{configString.trim()}</span> },
    { label: "Runs through", value: agentIds.map(hostOf).join(", ") },
    { label: "Permitted names", value: permittedNames ? permittedNamesLabel(permittedNames) : "None: Approval alone decides" },
  ];

  return (
    <SteppedForm title={title} steps={steps} step={step} onStep={setStep} missing={missing} submitLabel={ca ? "Save" : "Add"} pending={save.isPending} onSubmit={() => save.mutate(undefined)}>
      {step === "ca" && (
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="adcs-name">Name</FieldLabel>
            <Input id="adcs-name" autoFocus value={name} maxLength={100} onChange={(e) => setName(e.target.value)} required />
            <FieldDescription>What you call it here, to tell CAs apart.</FieldDescription>
          </Field>
          <Field>
            <FieldLabel htmlFor="adcs-config">Config string</FieldLabel>
            <Input
              id="adcs-config"
              className="font-mono"
              value={configString}
              placeholder="e.g. ca01.corp.example\Corp Issuing CA"
              disabled={ca !== undefined}
              onChange={(e) => setConfigString(e.target.value)}
              required
            />
            <FieldDescription>{ca ? "It cannot be changed: remove the CA and add it again." : "As certutil shows it: the CA's host, a backslash, and the CA's name."}</FieldDescription>
          </Field>
        </FieldGroup>
      )}

      {step === "agents" && (
        <FieldSet>
          <FieldLegend>Which Agents reach it?</FieldLegend>
          <FieldDescription>Agents on domain-joined Windows hosts, running as an account that may enroll on its templates. Any chosen Agent that is online carries out each operation.</FieldDescription>
          <div className="flex max-h-72 flex-col gap-3 overflow-y-auto rounded-md border p-3">
            {choices.length === 0 ? (
              <span className="text-sm text-muted-foreground">No Windows Agent is registered. Register one on a domain-joined host first.</span>
            ) : (
              choices.map((a) => (
                <Field key={a.id} orientation="horizontal">
                  <Checkbox
                    id={`adcs-agent-${a.id}`}
                    checked={agentIds.includes(a.id)}
                    onCheckedChange={(on) => setAgentIds(on === true ? [...agentIds, a.id] : agentIds.filter((id) => id !== a.id))}
                  />
                  <FieldLabel htmlFor={`adcs-agent-${a.id}`} className="font-normal">
                    {a.hostName} <span className="text-muted-foreground">({a.status})</span>
                  </FieldLabel>
                </Field>
              ))
            )}
          </div>
        </FieldSet>
      )}

      {step === "names" && (
        <FieldGroup>
          <FieldSet>
            <FieldLegend>Which names may it be asked for?</FieldLegend>
            <FieldDescription>The platform refuses any other name before anything reaches ADCS, at proposal, Name Change and Issuance. A name or zone to a line.</FieldDescription>
          </FieldSet>
          <Field>
            <FieldLabel htmlFor="adcs-zones">Permitted zones</FieldLabel>
            <Textarea id="adcs-zones" rows={3} value={zones} onChange={(e) => setZones(e.target.value)} placeholder="e.g. corp.example" />
            <FieldDescription>Each permits the name and every name beneath it, wildcards included.</FieldDescription>
          </Field>
          <Field>
            <FieldLabel htmlFor="adcs-exact">Permitted names</FieldLabel>
            <Textarea id="adcs-exact" rows={3} value={exact} onChange={(e) => setExact(e.target.value)} placeholder="e.g. portal.example.com" />
            <FieldDescription>Each permits that name alone; a wildcard permits that wildcard alone.</FieldDescription>
          </Field>
          {!permittedNames && <NoPermittedNames />}
        </FieldGroup>
      )}

      {step === "review" && (
        <FieldGroup>
          <FieldSet>
            <FieldLegend>Review</FieldLegend>
            <FieldDescription>
              {ca ? "Saving changes it at once." : "An online Agent reaches the CA now and fetches its chain and templates; nothing is saved if none can."} Use Back to change anything.
            </FieldDescription>
            <SummaryRows rows={rows} />
          </FieldSet>
          {save.error && <FieldError>{save.error.message}</FieldError>}
        </FieldGroup>
      )}
    </SteppedForm>
  );
}
