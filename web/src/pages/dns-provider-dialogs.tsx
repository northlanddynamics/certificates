import { useState, type FormEvent } from "react";
import { PlusIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { TSIG_ALGORITHMS, api, type Agent, type DnsProvider, type DnsProviderSettings, type DnsProviderType } from "@/lib/api";
import { useAction } from "@/lib/use-action";

export const TYPE_LABEL: Record<DnsProviderType, string> = { rfc2136: "RFC 2136", infoblox: "Infoblox" };
const SECRET_LABEL: Record<DnsProviderType, string> = { rfc2136: "TSIG key secret", infoblox: "WAPI password" };

/** The Agents the Organization may choose to relay a provider: those not revoked, and any still chosen, so that they can be taken off. */
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

const complete = (f: Fields) =>
  f.name.trim() !== "" && f.zone.trim() !== "" && (f.type === "rfc2136" ? f.server.trim() !== "" && f.port !== "" && f.keyName.trim() !== "" : f.url.trim() !== "" && f.view.trim() !== "");

/** What a provider is connected with that is not secret, for the Add and Edit dialogs alike. */
function SettingsFields({ fields, set, typeFixed }: { fields: Fields; set: (change: Partial<Fields>) => void; typeFixed: boolean }) {
  return (
    <>
      <div className="flex flex-col gap-2">
        <Label htmlFor="dns-name">Name</Label>
        <Input id="dns-name" value={fields.name} maxLength={100} onChange={(e) => set({ name: e.target.value })} required />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="dns-type">Type</Label>
        <Select value={fields.type} disabled={typeFixed} onValueChange={(type) => set({ type: type as DnsProviderType })}>
          <SelectTrigger id="dns-type">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="rfc2136">RFC 2136: dynamic updates signed with a TSIG key (BIND and others)</SelectItem>
            <SelectItem value="infoblox">Infoblox: the NIOS WAPI</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="dns-zone">Zone</Label>
        <Input id="dns-zone" value={fields.zone} placeholder="example.com" onChange={(e) => set({ zone: e.target.value })} required />
      </div>
      {fields.type === "rfc2136" ? (
        <>
          <div className="grid grid-cols-[1fr_6rem] gap-4">
            <div className="flex flex-col gap-2">
              <Label htmlFor="dns-server">Server</Label>
              <Input id="dns-server" value={fields.server} placeholder="ns1.example.com" onChange={(e) => set({ server: e.target.value })} required />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="dns-port">Port</Label>
              <Input id="dns-port" type="number" min={1} max={65535} value={fields.port} onChange={(e) => set({ port: e.target.value })} required />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="flex flex-col gap-2">
              <Label htmlFor="dns-key-name">TSIG key name</Label>
              <Input id="dns-key-name" value={fields.keyName} onChange={(e) => set({ keyName: e.target.value })} required />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="dns-algorithm">TSIG algorithm</Label>
              <Select value={fields.algorithm} onValueChange={(algorithm) => set({ algorithm: algorithm as Fields["algorithm"] })}>
                <SelectTrigger id="dns-algorithm">
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
            </div>
          </div>
        </>
      ) : (
        <>
          <div className="flex flex-col gap-2">
            <Label htmlFor="dns-url">WAPI URL</Label>
            <Input id="dns-url" value={fields.url} placeholder="https://gm.example.com/wapi/v2.12" onChange={(e) => set({ url: e.target.value })} required />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="dns-view">DNS view</Label>
            <Input id="dns-view" value={fields.view} onChange={(e) => set({ view: e.target.value })} required />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="dns-ca">Grid certificate authority (PEM, optional)</Label>
            <Textarea id="dns-ca" className="font-mono text-xs" rows={4} value={fields.caCertificate} onChange={(e) => set({ caCertificate: e.target.value })} />
            <p className="text-xs text-muted-foreground">Only for a grid whose certificate is not signed by a publicly trusted authority.</p>
          </div>
        </>
      )}
    </>
  );
}

/** The Agents that may relay a provider's operations, to reach DNS the platform cannot. Hidden to someone who may not see Agents. */
function RelayFields({ agents, chosen, onChange }: { agents: Agent[]; chosen: string[]; onChange: (ids: string[]) => void }) {
  const choices = agents.filter((a) => a.status !== "revoked" || chosen.includes(a.id));
  return (
    <fieldset className="flex flex-col gap-2">
      <legend className="text-sm font-medium">Run through Agents (optional)</legend>
      <p className="text-xs text-muted-foreground">
        Without one the platform talks to the DNS server itself. Choose Agents to reach DNS inside your network: any chosen Agent that is online carries out the operation.
      </p>
      {choices.length === 0 && <p className="text-sm text-muted-foreground">No Agent is registered.</p>}
      {choices.map((a) => (
        <div key={a.id} className="flex items-center gap-2">
          <Checkbox
            id={`dns-relay-${a.id}`}
            checked={chosen.includes(a.id)}
            onCheckedChange={(on) => onChange(on === true ? [...chosen, a.id] : chosen.filter((id) => id !== a.id))}
          />
          <Label htmlFor={`dns-relay-${a.id}`} className="font-normal">
            {a.hostName} <span className="text-muted-foreground">({a.status})</span>
          </Label>
        </div>
      ))}
    </fieldset>
  );
}

const SCROLLING = "sm:max-w-lg max-h-[90vh] overflow-y-auto";

/** Adds a provider: its settings and its secret, which is written once and never shown again. */
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
      <DialogContent className={SCROLLING}>
        <DialogHeader>
          <DialogTitle>Add a DNS Provider</DialogTitle>
          <DialogDescription>The platform publishes the records that prove control of a domain through it. Its secret is stored encrypted and is never shown.</DialogDescription>
        </DialogHeader>
        {/* Only mounted while open, so each opening starts from a clean form and no secret outlives it. */}
        {open && <AddForm orgId={orgId} relay={relay} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

/** The secret of a provider as one string: a TSIG key's secret, or the WAPI's `user:password`. */
function SecretFields({ type, secret, user, onSecret, onUser }: { type: DnsProviderType; secret: string; user: string; onSecret: (s: string) => void; onUser: (u: string) => void }) {
  return (
    <>
      {type === "infoblox" && (
        <div className="flex flex-col gap-2">
          <Label htmlFor="dns-user">WAPI user</Label>
          <Input id="dns-user" value={user} autoComplete="off" onChange={(e) => onUser(e.target.value)} required />
        </div>
      )}
      <div className="flex flex-col gap-2">
        <Label htmlFor="dns-secret">{SECRET_LABEL[type]}</Label>
        <Input id="dns-secret" type="password" value={secret} autoComplete="off" onChange={(e) => onSecret(e.target.value)} required />
        {type === "rfc2136" && <p className="text-xs text-muted-foreground">As written in the server's configuration: base64.</p>}
      </div>
    </>
  );
}

const secretOf = (type: DnsProviderType, user: string, secret: string) => (type === "infoblox" ? `${user.trim()}:${secret}` : secret.trim());

function AddForm({ orgId, relay, onDone }: { orgId: string; relay: Relay | null; onDone: () => void }) {
  const [fields, setFields] = useState(() => fieldsOf());
  const [secret, setSecret] = useState("");
  const [user, setUser] = useState("");
  const set = (change: Partial<Fields>) => setFields((f) => ({ ...f, ...change }));
  const add = useAction(
    () => api.createDnsProvider(orgId, { name: fields.name.trim(), type: fields.type, settings: settingsOf(fields), secret: secretOf(fields.type, user, secret), relayAgentIds: fields.relayAgentIds }),
    ["dns-providers"],
    onDone,
  );
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        add.mutate(undefined);
      }}
    >
      <SettingsFields fields={fields} set={set} typeFixed={false} />
      <SecretFields type={fields.type} secret={secret} user={user} onSecret={setSecret} onUser={setUser} />
      {relay && <RelayFields agents={relay.agents} chosen={fields.relayAgentIds} onChange={(relayAgentIds) => set({ relayAgentIds })} />}
      {add.error && <p className="text-sm text-destructive">{add.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={!complete(fields) || secret === "" || (fields.type === "infoblox" && user.trim() === "") || add.isPending}>
          Add
        </Button>
      </DialogFooter>
    </form>
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
      <DialogContent className={SCROLLING}>
        <DialogHeader>
          <DialogTitle>Edit {provider.name}</DialogTitle>
          <DialogDescription>The secret stays as it is; replace it on its own.</DialogDescription>
        </DialogHeader>
        {open && <EditForm orgId={orgId} provider={provider} relay={relay} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function EditForm({ orgId, provider, relay, onDone }: { orgId: string; provider: DnsProvider; relay: Relay | null; onDone: () => void }) {
  const [fields, setFields] = useState(() => fieldsOf(provider));
  const set = (change: Partial<Fields>) => setFields((f) => ({ ...f, ...change }));
  const relayChanged =
    relay !== null && (fields.relayAgentIds.length !== provider.relayAgentIds.length || fields.relayAgentIds.some((id) => !provider.relayAgentIds.includes(id)));
  const save = useAction(
    async () => {
      await api.changeDnsProvider(orgId, provider.id, { name: fields.name.trim(), settings: settingsOf(fields) });
      if (relayChanged) await api.setDnsProviderRelay(orgId, provider.id, fields.relayAgentIds);
    },
    ["dns-providers"],
    onDone,
  );
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        save.mutate(undefined);
      }}
    >
      <SettingsFields fields={fields} set={set} typeFixed />
      {relay && <RelayFields agents={relay.agents} chosen={fields.relayAgentIds} onChange={(relayAgentIds) => set({ relayAgentIds })} />}
      {save.error && <p className="text-sm text-destructive">{save.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={!complete(fields) || save.isPending}>
          Save
        </Button>
      </DialogFooter>
    </form>
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
