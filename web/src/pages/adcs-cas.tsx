import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { ClipboardCheckIcon, DownloadIcon, ListChecksIcon, NetworkIcon, PlusIcon, RotateCwIcon, ServerIcon, TriangleAlertIcon } from "lucide-react";
import { useState, type ReactNode } from "react";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { ActionLabel, PageHeader } from "@/components/page-header";
import { SteppedForm, STEPPED_DIALOG, type Missing } from "@/components/stepped-form";
import { SummaryRows } from "@/components/summary-rows";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { assignableAgents, ekuLabel, isConfigString, templateApprovalLabel, templatePurposes } from "@/lib/adcs-ca";
import { api, can, type AdcsCa, type Agent } from "@/lib/api";
import { splitNames } from "@/lib/csr-names";
import { permittedNamesLabel } from "@/lib/private-ca";
import { useAction } from "@/lib/use-action";
import { useOrg } from "@/lib/use-org";

const ROUTE = "/app/organizations/$orgId/adcs-cas";
const noAgents: Agent[] = [];
const dateOf = (iso: string) => new Date(iso).toLocaleDateString();

/**
 * The Organization's ADCS CAs: its Active Directory Certificate Services CAs, which the platform reaches only through the
 * Agents assigned to each. Each shows the chain its last discovery fetched, the CRL Distribution Points of its CA
 * certificate, and the Certificate Templates it publishes. Discovery runs again on Refresh and once a day; an
 * Organization Administrator may hide a template so that nobody picks it.
 */
export function AdcsCasPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const allowed = org ? can(org, "adcsCa", "read") : false;
  const mayManage = org ? can(org, "adcsCa", "update") : false;
  const cas = useQuery({ queryKey: ["adcs-cas", orgId], queryFn: () => api.adcsCas(orgId), enabled: allowed });
  // The same query as the other pages' choice of Agent, so they share what was fetched.
  const agents = useQuery({
    queryKey: ["agents", orgId, "choices"],
    queryFn: () => api.agents(orgId, { status: [], os: [], outdated: false }, { page: 1, pageSize: 100 }),
    enabled: allowed && org !== undefined && can(org, "agent", "read"),
  });
  const agentList = agents.data?.items ?? noAgents;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="ADCS CAs"
        action={org && can(org, "adcsCa", "create") && <AdcsCaDialog orgId={orgId} agents={agentList} />}
        description="The Organization's Active Directory Certificate Services CAs, which the platform reaches only through its Windows Agents."
        howItWorks={
          <p>
            Each Agent reaches ADCS as its own account (a gMSA), so ADCS's own template permissions decide what can be issued. The platform holds no AD credential and no ADCS key, and ADCS publishes its
            own CRL.
          </p>
        }
      />
      {cas.isPending && allowed && <p className="text-sm text-muted-foreground">Loading…</p>}
      {cas.error && <p className="text-sm text-destructive">{cas.error.message}</p>}
      {cas.data?.items.length === 0 && <p className="text-sm text-muted-foreground">No ADCS CA is added yet.</p>}
      {cas.data?.items.map((ca) => <AdcsCaCard key={ca.id} orgId={orgId} ca={ca} agents={agentList} mayManage={mayManage} mayDelete={org ? can(org, "adcsCa", "delete") : false} />)}
    </div>
  );
}

function AdcsCaCard({ orgId, ca, agents, mayManage, mayDelete }: { orgId: string; ca: AdcsCa; agents: Agent[]; mayManage: boolean; mayDelete: boolean }) {
  const [removing, setRemoving] = useState(false);
  const remove = useAction(() => api.deleteAdcsCa(orgId, ca.id), ["adcs-cas"], () => setRemoving(false));
  const queryClient = useQueryClient();
  // A failed discovery is recorded on the CA too, so the CA is fetched again either way.
  const refresh = useMutation({ mutationFn: () => api.refreshAdcsCa(orgId, ca.id), onSettled: () => queryClient.invalidateQueries({ queryKey: ["adcs-cas"] }) });
  const hostOf = (id: string) => agents.find((a) => a.id === id)?.hostName ?? "An Agent";
  return (
    <Card>
      <CardHeader>
        <CardTitle>{ca.name}</CardTitle>
        <CardDescription className="font-mono text-xs">{ca.configString}</CardDescription>
        <CardAction className="flex flex-wrap justify-end gap-2">
          <Button variant="outline" size="sm" asChild>
            <a href={api.adcsCaChainUrl(orgId, ca.id)} download aria-label={`Download the chain of ${ca.name}`}>
              <DownloadIcon />
              Chain
            </a>
          </Button>
          {mayManage && (
            <Button variant="outline" size="sm" onClick={() => refresh.mutate()} disabled={refresh.isPending} aria-label={`Refresh the templates of ${ca.name}`}>
              <RotateCwIcon className={refresh.isPending ? "animate-spin" : undefined} />
              Refresh
            </Button>
          )}
          {mayManage && <AdcsCaDialog orgId={orgId} agents={agents} ca={ca} />}
          {mayDelete && (
            <Button variant="outline" size="sm" onClick={() => setRemoving(true)} aria-label={`Remove ${ca.name}`}>
              Remove
            </Button>
          )}
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        {refresh.error && <p className="text-sm text-destructive">{refresh.error.message}</p>}
        {!refresh.error && ca.discoveryFailure && (
          <Alert variant="destructive">
            <AlertTitle>The last discovery failed, {new Date(ca.discoveryFailure.at).toLocaleString()}</AlertTitle>
            <AlertDescription>{ca.discoveryFailure.error} The chain and templates below are from the last discovery that worked.</AlertDescription>
          </Alert>
        )}
        {!ca.permittedNames && <NoPermittedNames />}
        <SummaryRows
          rows={[
            { label: "Runs through", value: ca.agentIds.map(hostOf).join(", ") },
            { label: "Permitted names", value: ca.permittedNames ? permittedNamesLabel(ca.permittedNames) : <span className="text-muted-foreground">None: Approval alone decides</span> },
            {
              label: "Chain",
              value: (
                <ol className="flex flex-col gap-1">
                  {ca.chain.map((c) => (
                    <li key={c.fingerprint}>
                      {c.subject} <span className="text-muted-foreground">(until {dateOf(c.notAfter)})</span>
                    </li>
                  ))}
                </ol>
              ),
            },
            {
              label: "CRL Distribution Points",
              value:
                ca.cdpUrls.length === 0 ? (
                  <span className="text-muted-foreground">None in its CA certificate</span>
                ) : (
                  <ul className="flex flex-col gap-1">
                    {ca.cdpUrls.map((url) => (
                      <li key={url} className="break-all font-mono text-xs">
                        {url}
                      </li>
                    ))}
                  </ul>
                ),
            },
            { label: "Discovered", value: new Date(ca.discoveredAt).toLocaleString() },
          ]}
        />
        <TemplateTable orgId={orgId} ca={ca} mayManage={mayManage} />
      </CardContent>
      <ConfirmDialog
        open={removing}
        onOpenChange={setRemoving}
        title={`Remove ${ca.name}?`}
        description="The platform forgets the CA and its templates. Nothing changes at ADCS. It cannot be removed while anything refers to it."
        confirmLabel="Remove"
        pending={remove.isPending}
        error={remove.error}
        onConfirm={() => remove.mutate(undefined)}
      />
    </Card>
  );
}

/** What an ADCS CA without Permitted Name Rules relies on: Approval alone stands between a Member and a Certificate the domain trusts. */
function NoPermittedNames() {
  return (
    <Alert className="border-warning/50 bg-warning/5">
      <TriangleAlertIcon className="text-warning" />
      <AlertTitle>No Permitted Name Rules</AlertTitle>
      <AlertDescription>
        ADCS checks its templates' permissions against the Agents' account, not against whoever asks, so Approval alone decides which names it is asked for. Give it Permitted Name Rules to refuse
        other names before anything is submitted.
      </AlertDescription>
    </Alert>
  );
}

/** The CA's Certificate Templates and their facts, as its last discovery found them, with hiding for those who manage it. */
function TemplateTable({ orgId, ca, mayManage }: { orgId: string; ca: AdcsCa; mayManage: boolean }) {
  const setHidden = useAction(({ templateId, hidden }: { templateId: string; hidden: boolean }) => api.setAdcsTemplateHidden(orgId, ca.id, templateId, hidden), ["adcs-cas"]);
  if (ca.templates.length === 0) return <p className="text-sm text-muted-foreground">The CA publishes no Certificate Template.</p>;
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
            <TableHead>Status</TableHead>
            {mayManage && <TableHead className="sr-only">Hide</TableHead>}
          </TableRow>
        </TableHeader>
        <TableBody>
          {ca.templates.map((t) => {
            return (
              <TableRow key={t.id}>
                <TableCell>
                  <div className="font-medium">{t.displayName || t.name}</div>
                  <div className="font-mono text-xs text-muted-foreground">{t.name}</div>
                </TableCell>
                <TableCell>{templatePurposes(t).join(", ") || <span className="text-muted-foreground">Neither</span>}</TableCell>
                <TableCell className="whitespace-normal">{t.extendedKeyUsages.map(ekuLabel).join(", ")}</TableCell>
                <TableCell>{t.validityDays} days</TableCell>
                <TableCell className="whitespace-normal">
                  {t.keyAlgorithms.join(", ")}, at least {t.minimumKeySize} bits
                </TableCell>
                <TableCell className="whitespace-normal">{templateApprovalLabel(t)}</TableCell>
                <TableCell>
                  {t.hidden && <Badge variant="outline">Hidden</Badge>}{" "}
                  {t.unavailableReason === null ? (
                    <Badge variant="secondary">Available</Badge>
                  ) : (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Badge variant="outline" tabIndex={0}>
                          Unavailable
                        </Badge>
                      </TooltipTrigger>
                      <TooltipContent>{t.unavailableReason}</TooltipContent>
                    </Tooltip>
                  )}
                </TableCell>
                {mayManage && (
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={setHidden.isPending}
                      onClick={() => setHidden.mutate({ templateId: t.id, hidden: !t.hidden })}
                      aria-label={`${t.hidden ? "Show" : "Hide"} ${t.name}`}
                    >
                      {t.hidden ? "Show" : "Hide"}
                    </Button>
                  </TableCell>
                )}
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
      {setHidden.error && <p className="text-sm text-destructive">{setHidden.error.message}</p>}
    </>
  );
}

type StepId = "ca" | "agents" | "names" | "review";
const STEPS = {
  ca: { title: "The CA", icon: ServerIcon },
  agents: { title: "Agents", icon: NetworkIcon },
  names: { title: "Permitted names", icon: ListChecksIcon },
  review: { title: "Review", icon: ClipboardCheckIcon },
};

/** Adds an ADCS CA, or with `ca` renames it and changes its Agents; its config string stays. */
function AdcsCaDialog({ orgId, agents, ca }: { orgId: string; agents: Agent[]; ca?: AdcsCa }) {
  const [open, setOpen] = useState(false);
  const title = ca ? `Edit ${ca.name}` : "Add an ADCS CA";
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {ca ? (
          <Button variant="outline" size="sm" aria-label={title}>
            Edit
          </Button>
        ) : (
          <Button>
            <PlusIcon />
            <ActionLabel>Add an ADCS CA</ActionLabel>
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className={STEPPED_DIALOG}>
        <DialogTitle className="sr-only">{title}</DialogTitle>
        <DialogDescription className="sr-only">An assigned Agent reaches the CA when it is added; nothing is saved if none can.</DialogDescription>
        {open && <AdcsCaWizard orgId={orgId} agents={agents} ca={ca} title={title} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

// Only mounted while the dialog is open, so the form starts clean each time.
function AdcsCaWizard({ orgId, agents, ca, title, onDone }: { orgId: string; agents: Agent[]; ca?: AdcsCa; title: string; onDone: () => void }) {
  const [name, setName] = useState(ca?.name ?? "");
  const [configString, setConfigString] = useState(ca?.configString ?? "");
  const [agentIds, setAgentIds] = useState<string[]>(ca?.agentIds ?? []);
  const [exact, setExact] = useState(ca?.permittedNames?.exact.join("\n") ?? "");
  const [zones, setZones] = useState(ca?.permittedNames?.zones.join("\n") ?? "");
  const [step, setStep] = useState<StepId>("ca");
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
