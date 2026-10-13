import { CheckIcon, ClipboardCheckIcon, KeyRoundIcon, NetworkIcon, PlugIcon, PlusIcon, ServerIcon, type LucideIcon } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { Breadcrumb, BreadcrumbItem, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet, FieldTitle } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sidebar, SidebarContent, SidebarGroup, SidebarGroupContent, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarProvider } from "@/components/ui/sidebar";
import { Textarea } from "@/components/ui/textarea";
import { TSIG_ALGORITHMS, api, type Agent, type DnsProvider, type DnsProviderSettings, type DnsProviderType } from "@/lib/api";
import { useAction } from "@/lib/use-action";

export const TYPE_LABEL: Record<DnsProviderType, string> = { rfc2136: "RFC 2136", infoblox: "Infoblox" };
const SECRET_LABEL: Record<DnsProviderType, string> = { rfc2136: "TSIG key secret", infoblox: "WAPI password" };
const TYPES: { value: DnsProviderType; title: string; description: string }[] = [
  { value: "rfc2136", title: "RFC 2136", description: "Dynamic DNS updates signed with a TSIG key: BIND, and other servers and appliances that accept them." },
  { value: "infoblox", title: "Infoblox", description: "An Infoblox grid, through its NIOS WAPI." },
];

/** The Agents that may be chosen to relay a provider's operations, which the page lists when the caller may see Agents. */
interface Relay {
  agents: Agent[];
}

interface Fields {
  type: DnsProviderType;
  name: string;
  zone: string;
  // RFC 2136
  server: string;
  port: string;
  keyName: string;
  algorithm: (typeof TSIG_ALGORITHMS)[number];
  // Infoblox
  url: string;
  view: string;
  caCertificate: string;
  relayAgentIds: string[];
}

function fieldsOf(provider?: DnsProvider): Fields {
  const blank: Fields = {
    type: "rfc2136",
    name: "",
    zone: "",
    server: "",
    port: "53",
    keyName: "",
    algorithm: "hmac-sha256",
    url: "",
    view: "default",
    caCertificate: "",
    relayAgentIds: [],
  };
  if (!provider) return blank;
  const common = { ...blank, type: provider.type, name: provider.name, zone: provider.settings.zone, relayAgentIds: provider.relayAgentIds };
  return provider.type === "rfc2136"
    ? { ...common, server: provider.settings.server, port: String(provider.settings.port), keyName: provider.settings.keyName, algorithm: provider.settings.algorithm }
    : { ...common, url: provider.settings.url, view: provider.settings.view, caCertificate: provider.settings.caCertificate ?? "" };
}

function settingsOf(f: Fields): DnsProviderSettings {
  return f.type === "rfc2136"
    ? { server: f.server.trim(), port: Number(f.port), zone: f.zone.trim(), keyName: f.keyName.trim(), algorithm: f.algorithm }
    : { url: f.url.trim(), zone: f.zone.trim(), view: f.view.trim(), ...(f.caCertificate.trim() && { caCertificate: f.caCertificate.trim() }) };
}


const STEPS = {
  type: { title: "Type", icon: PlugIcon },
  connection: { title: "Connection", icon: ServerIcon },
  authentication: { title: "Authentication", icon: KeyRoundIcon },
  relay: { title: "Where it runs", icon: NetworkIcon },
  review: { title: "Review", icon: ClipboardCheckIcon },
} as const satisfies Record<string, { title: string; icon: LucideIcon }>;
type StepId = keyof typeof STEPS;
const STEP_ORDER: StepId[] = ["type", "connection", "authentication", "relay", "review"];

/** The secret of a provider as one string: a TSIG key's secret, or the WAPI's `user:password`. */
const secretOf = (type: DnsProviderType, user: string, secret: string) => (type === "infoblox" ? `${user.trim()}:${secret}` : secret.trim());

/** The secret's own fields, which are empty whenever shown: the stored one is never. */
function SecretFields({ type, secret, user, onSecret, onUser }: { type: DnsProviderType; secret: string; user: string; onSecret: (s: string) => void; onUser: (u: string) => void }) {
  return (
    <>
      {type === "infoblox" && (
        <Field>
          <FieldLabel htmlFor="dns-user">WAPI user</FieldLabel>
          <Input id="dns-user" value={user} autoComplete="off" onChange={(e) => onUser(e.target.value)} required />
        </Field>
      )}
      <Field>
        <FieldLabel htmlFor="dns-secret">{SECRET_LABEL[type]}</FieldLabel>
        <Input id="dns-secret" type="password" value={secret} autoComplete="off" onChange={(e) => onSecret(e.target.value)} required />
        {type === "rfc2136" && <FieldDescription>As written in the server's configuration: base64.</FieldDescription>}
      </Field>
    </>
  );
}

/** The button for a new DNS Provider, and the dialog it opens. */
export function AddDnsProviderDialog({ orgId, relay }: { orgId: string; relay: Relay | null }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          Add a DNS Provider
        </Button>
      </DialogTrigger>
      <WizardDialogContent title="Add a DNS Provider" description="The secret is stored encrypted and is never shown again.">
        <ProviderWizard orgId={orgId} relay={relay} onDone={() => setOpen(false)} />
      </WizardDialogContent>
    </Dialog>
  );
}

/** Changes a provider's name, settings and relaying Agents; its type and secret stay (the secret has a dialog of its own). */
export function EditDnsProviderDialog({ orgId, provider, relay }: { orgId: string; provider: DnsProvider; relay: Relay | null }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" aria-label={`Edit ${provider.name}`}>
          Edit
        </Button>
      </DialogTrigger>
      <WizardDialogContent title={`Edit ${provider.name}`} description="The secret stays as it is; replace it on its own.">
        <ProviderWizard orgId={orgId} provider={provider} relay={relay} onDone={() => setOpen(false)} />
      </WizardDialogContent>
    </Dialog>
  );
}

// The steps' own page, as the new Managed Certificate dialog has it.
function WizardDialogContent({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return (
    <DialogContent className="gap-0 overflow-hidden p-0 sm:max-w-[calc(100%-2rem)] md:max-w-[760px] lg:max-w-[860px]">
      <DialogTitle className="sr-only">{title}</DialogTitle>
      <DialogDescription className="sr-only">{description}</DialogDescription>
      {children}
    </DialogContent>
  );
}

// Only mounted while the dialog is open, so the form starts clean each time and no secret outlives it. Every step's
// state lives here, so moving between steps never loses what was entered.
function ProviderWizard({ orgId, provider, relay, onDone }: { orgId: string; provider?: DnsProvider; relay: Relay | null; onDone: () => void }) {
  const editing = provider !== undefined;
  const [fields, setFields] = useState(() => fieldsOf(provider));
  const [secret, setSecret] = useState("");
  const [user, setUser] = useState("");
  const set = (change: Partial<Fields>) => setFields((f) => ({ ...f, ...change }));

  // The type is chosen once; only an RFC 2136 provider has settings of its own to authenticate with, the other's login being its secret.
  const steps = STEP_ORDER.filter((id) =>
    id === "type" ? !editing : id === "authentication" ? !editing || fields.type === "rfc2136" : id === "relay" ? relay !== null : true,
  );
  const [step, setStep] = useState<StepId>(steps[0]!);
  const index = Math.max(0, steps.indexOf(step));
  const last = index === steps.length - 1;

  const secretGiven = secret !== "" && (fields.type !== "infoblox" || user.trim() !== "");
  const complete: Record<StepId, boolean> = {
    type: true,
    connection: fields.name.trim() !== "" && fields.zone.trim() !== "" && (fields.type === "rfc2136" ? fields.server.trim() !== "" && fields.port !== "" : fields.url.trim() !== "" && fields.view.trim() !== ""),
    authentication: (fields.type !== "rfc2136" || fields.keyName.trim() !== "") && (editing || secretGiven),
    relay: true,
    review: true,
  };
  // A step may be opened once every step before it is complete.
  const reachable = (i: number) => steps.slice(0, i).every((id) => complete[id]);
  const goTo = (i: number) => {
    const target = steps[i];
    if (target && reachable(i)) setStep(target);
  };

  const relayChanged = editing && relay !== null && (fields.relayAgentIds.length !== provider.relayAgentIds.length || fields.relayAgentIds.some((id) => !provider.relayAgentIds.includes(id)));
  const save = useAction(
    async () => {
      if (!editing) {
        await api.createDnsProvider(orgId, { name: fields.name.trim(), type: fields.type, settings: settingsOf(fields), secret: secretOf(fields.type, user, secret), relayAgentIds: fields.relayAgentIds });
        return;
      }
      await api.changeDnsProvider(orgId, provider.id, { name: fields.name.trim(), settings: settingsOf(fields) });
      if (relayChanged) await api.setDnsProviderRelay(orgId, provider.id, fields.relayAgentIds);
    },
    ["dns-providers"],
    onDone,
  );
  const heading = editing ? `Edit ${provider.name}` : "Add a DNS Provider";

  return (
    <SidebarProvider className="h-[min(600px,85vh)] min-h-0 items-stretch">
      <Sidebar collapsible="none" className="hidden border-r md:flex">
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupContent>
              <SidebarMenu>
                {steps.map((id, i) => {
                  const Icon = STEPS[id].icon;
                  return (
                    <SidebarMenuItem key={id}>
                      <SidebarMenuButton isActive={id === step} disabled={!reachable(i)} onClick={() => goTo(i)}>
                        {i < index && complete[id] ? <CheckIcon className="text-primary" /> : <Icon />}
                        <span>{STEPS[id].title}</span>
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
          else if (steps.every((id) => complete[id])) save.mutate(undefined);
        }}
      >
        <header className="flex h-14 shrink-0 items-center justify-between gap-2 px-4 pr-12">
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem className="hidden md:block">{heading}</BreadcrumbItem>
              <BreadcrumbSeparator className="hidden md:block" />
              <BreadcrumbItem>
                <BreadcrumbPage>{STEPS[steps[index]!].title}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
          <span className="text-xs text-muted-foreground">
            Step {index + 1} of {steps.length}
          </span>
        </header>
        <div className="flex flex-1 flex-col gap-4 overflow-y-auto p-4 pt-0">
          {step === "type" && (
            <FieldSet>
              <FieldLegend>What kind of DNS does it connect to?</FieldLegend>
              <FieldDescription>It cannot be changed afterwards.</FieldDescription>
              <RadioGroup value={fields.type} onValueChange={(type) => set({ type: type as DnsProviderType })}>
                {TYPES.map((t) => (
                  <FieldLabel key={t.value} htmlFor={`dns-type-${t.value}`}>
                    <Field orientation="horizontal">
                      <FieldContent>
                        <FieldTitle>{t.title}</FieldTitle>
                        <FieldDescription>{t.description}</FieldDescription>
                      </FieldContent>
                      <RadioGroupItem value={t.value} id={`dns-type-${t.value}`} />
                    </Field>
                  </FieldLabel>
                ))}
              </RadioGroup>
            </FieldSet>
          )}

          {step === "connection" && (
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="dns-name">Name</FieldLabel>
                <Input id="dns-name" autoFocus value={fields.name} maxLength={100} onChange={(e) => set({ name: e.target.value })} required />
                <FieldDescription>What you call it here, to tell providers apart.</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="dns-zone">Zone</FieldLabel>
                <Input id="dns-zone" value={fields.zone} placeholder="example.com" onChange={(e) => set({ zone: e.target.value })} required />
                <FieldDescription>The zone the records are published in, and only there.</FieldDescription>
              </Field>
              {fields.type === "rfc2136" ? (
                <div className="grid grid-cols-[1fr_6rem] gap-4">
                  <Field>
                    <FieldLabel htmlFor="dns-server">Server</FieldLabel>
                    <Input id="dns-server" value={fields.server} placeholder="ns1.example.com" onChange={(e) => set({ server: e.target.value })} required />
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="dns-port">Port</FieldLabel>
                    <Input id="dns-port" type="number" min={1} max={65535} value={fields.port} onChange={(e) => set({ port: e.target.value })} required />
                  </Field>
                </div>
              ) : (
                <>
                  <Field>
                    <FieldLabel htmlFor="dns-url">WAPI URL</FieldLabel>
                    <Input id="dns-url" value={fields.url} placeholder="https://gm.example.com/wapi/v2.12" onChange={(e) => set({ url: e.target.value })} required />
                    <FieldDescription>With the WAPI version in it.</FieldDescription>
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="dns-view">DNS view</FieldLabel>
                    <Input id="dns-view" value={fields.view} onChange={(e) => set({ view: e.target.value })} required />
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="dns-ca">Grid certificate authority (optional)</FieldLabel>
                    <Textarea id="dns-ca" className="font-mono text-xs" rows={4} value={fields.caCertificate} onChange={(e) => set({ caCertificate: e.target.value })} />
                    <FieldDescription>PEM. Only for a grid whose certificate is not signed by a publicly trusted authority.</FieldDescription>
                  </Field>
                </>
              )}
            </FieldGroup>
          )}

          {step === "authentication" && (
            <FieldGroup>
              {fields.type === "rfc2136" && (
                <div className="grid grid-cols-2 gap-4">
                  <Field>
                    <FieldLabel htmlFor="dns-key-name">TSIG key name</FieldLabel>
                    <Input id="dns-key-name" autoFocus value={fields.keyName} onChange={(e) => set({ keyName: e.target.value })} required />
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="dns-algorithm">TSIG algorithm</FieldLabel>
                    <Select value={fields.algorithm} onValueChange={(algorithm) => set({ algorithm: algorithm as Fields["algorithm"] })}>
                      <SelectTrigger id="dns-algorithm" className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {TSIG_ALGORITHMS.map((a) => (
                          <SelectItem key={a} value={a}>
                            {a}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </Field>
                </div>
              )}
              {!editing && (
                <FieldSet>
                  <FieldLegend>Secret</FieldLegend>
                  <FieldDescription>Stored encrypted. It can be replaced or tested later, but it is never shown again.</FieldDescription>
                  <SecretFields type={fields.type} secret={secret} user={user} onSecret={setSecret} onUser={setUser} />
                </FieldSet>
              )}
            </FieldGroup>
          )}

          {step === "relay" && relay && (
            <FieldSet>
              <FieldLegend>Where should its operations run?</FieldLegend>
              <FieldDescription>
                By default the platform talks to the DNS server itself. Choose Agents to reach DNS inside your network instead: any chosen Agent that is online carries out the operation.
              </FieldDescription>
              <div className="flex max-h-72 flex-col gap-3 overflow-y-auto rounded-md border p-3">
                {(() => {
                  const choices = relay.agents.filter((a) => a.status !== "revoked" || fields.relayAgentIds.includes(a.id));
                  return choices.length === 0 ? (
                    <span className="text-sm text-muted-foreground">No Agent is registered, so the platform runs the operations itself.</span>
                  ) : (
                    choices.map((a) => (
                      <Field key={a.id} orientation="horizontal">
                        <Checkbox
                          id={`dns-relay-${a.id}`}
                          checked={fields.relayAgentIds.includes(a.id)}
                          onCheckedChange={(on) => set({ relayAgentIds: on === true ? [...fields.relayAgentIds, a.id] : fields.relayAgentIds.filter((id) => id !== a.id) })}
                        />
                        <FieldLabel htmlFor={`dns-relay-${a.id}`} className="font-normal">
                          {a.hostName} <span className="text-muted-foreground">({a.status})</span>
                        </FieldLabel>
                      </Field>
                    ))
                  );
                })()}
              </div>
            </FieldSet>
          )}

          {step === "review" && (
            <FieldGroup>
              <FieldSet>
                <FieldLegend>Review</FieldLegend>
                <FieldDescription>{editing ? "Saving changes it at once." : "Test the connection from the list once it is added."} Use Back to change anything.</FieldDescription>
                <Summary fields={fields} editing={editing} agents={relay?.agents ?? []} />
              </FieldSet>
              {save.error && <FieldError>{save.error.message}</FieldError>}
            </FieldGroup>
          )}
        </div>
        <footer className="flex shrink-0 items-center justify-between gap-2 border-t bg-muted/50 p-4">
          <Button type="button" variant="outline" disabled={index === 0} onClick={() => goTo(index - 1)}>
            Back
          </Button>
          {last ? (
            <Button key="save" type="submit" disabled={save.isPending}>
              {editing ? "Save" : "Add"}
            </Button>
          ) : (
            <Button key="next" type="button" disabled={!complete[steps[index]!]} onClick={() => goTo(index + 1)}>
              Next
            </Button>
          )}
        </footer>
      </form>
    </SidebarProvider>
  );
}

function Summary({ fields, editing, agents }: { fields: Fields; editing: boolean; agents: Agent[] }) {
  const rfc = fields.type === "rfc2136";
  const rows: { label: string; value: ReactNode }[] = [
    { label: "Type", value: TYPE_LABEL[fields.type] },
    { label: "Name", value: fields.name.trim() },
    { label: "Zone", value: <span className="font-mono text-xs">{fields.zone.trim()}</span> },
    rfc
      ? { label: "Server", value: <span className="font-mono text-xs">{`${fields.server.trim()}:${fields.port}`}</span> }
      : { label: "WAPI URL", value: <span className="break-all font-mono text-xs">{fields.url.trim()}</span> },
    ...(rfc
      ? [{ label: "TSIG key", value: `${fields.keyName.trim()} (${fields.algorithm})` }]
      : [
          { label: "DNS view", value: fields.view.trim() },
          { label: "Grid authority", value: fields.caCertificate.trim() ? "Provided" : <span className="text-muted-foreground">The system's trusted authorities</span> },
        ]),
    { label: "Secret", value: editing ? <span className="text-muted-foreground">Unchanged</span> : "Provided; stored encrypted and never shown" },
    {
      label: "Runs through",
      value:
        fields.relayAgentIds.length === 0 ? (
          <span className="text-muted-foreground">The platform</span>
        ) : (
          fields.relayAgentIds.map((id) => agents.find((a) => a.id === id)?.hostName ?? "An Agent").join(", ")
        ),
    },
  ];
  return (
    <div className="rounded-md border p-4">
      <dl className="grid grid-cols-[8rem_1fr] gap-x-4 gap-y-3 text-sm">
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

/** Replaces a provider's secret without showing the one it has: write-only, so there is nothing to fill in. */
export function ReplaceSecretDialog({ orgId, provider }: { orgId: string; provider: DnsProvider }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" aria-label={`Replace the secret of ${provider.name}`}>
          Replace secret
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Replace the secret of {provider.name}</DialogTitle>
          <DialogDescription>The stored secret is never shown, so there is nothing to edit: enter the new one. Test the connection afterwards.</DialogDescription>
        </DialogHeader>
        {open && <ReplaceSecretForm orgId={orgId} provider={provider} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function ReplaceSecretForm({ orgId, provider, onDone }: { orgId: string; provider: DnsProvider; onDone: () => void }) {
  const [secret, setSecret] = useState("");
  const [user, setUser] = useState("");
  const replace = useAction(() => api.replaceDnsProviderSecret(orgId, provider.id, secretOf(provider.type, user, secret)), ["dns-providers"], onDone);
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        replace.mutate(undefined);
      }}
    >
      <SecretFields type={provider.type} secret={secret} user={user} onSecret={setSecret} onUser={setUser} />
      {replace.error && <p className="text-sm text-destructive">{replace.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={secret === "" || (provider.type === "infoblox" && user.trim() === "") || replace.isPending}>
          Replace
        </Button>
      </DialogFooter>
    </form>
  );
}
