import { useMutation, useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { createColumnHelper, tableFeatures, useTable } from "@tanstack/react-table";
import { PlusIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { DataTable } from "@/components/data-table/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { api, can, type SsoConnection, type SsoConnectionChange } from "@/lib/api";
import { useAction } from "@/lib/use-action";

const ROUTE = "/app/organizations/$orgId/sso-connections";
const TYPE_LABEL: Record<SsoConnection["type"], string> = { oidc: "OIDC", saml: "SAML" };

// The server lists every connection, so there is nothing to page.
const features = tableFeatures({});
const columnHelper = createColumnHelper<typeof features, SsoConnection>();
const noRows: SsoConnection[] = [];

/**
 * The Organization's SSO connections: the SAML (Ping, for example) or OIDC identity providers its users sign in through,
 * each for one email domain, which a TXT record must prove before it signs anyone in. Someone signing in through one becomes a Member. Only Organization
 * Administrators see or configure them, and every change is audited. Requiring SSO is on the Login policy page.
 */
export function SsoConnectionsPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.organizations.find((o) => o.id === orgId) }).data;
  const allowed = org ? can(org, "ssoConnection", "read") : false;
  const may = {
    test: org ? can(org, "ssoConnection", "test") : false,
    change: org ? can(org, "ssoConnection", "update") : false,
    delete: org ? can(org, "ssoConnection", "delete") : false,
  };
  const connections = useQuery({ queryKey: ["sso-connections", orgId], queryFn: () => api.ssoConnections(orgId), enabled: allowed });
  const columns = columnHelper.columns([
    columnHelper.accessor("name", { header: "Name", cell: ({ cell }) => <span className="font-medium">{cell.getValue()}</span> }),
    columnHelper.accessor("type", { header: "Type", cell: ({ cell }) => <Badge variant="secondary">{TYPE_LABEL[cell.getValue()]}</Badge> }),
    columnHelper.accessor("domain", {
      header: "Domain",
      cell: ({ row }) => (
        <span className="flex items-center gap-2">
          {row.original.domain}
          {!row.original.domainVerified && <Badge variant="outline">Not proven</Badge>}
        </span>
      ),
    }),
    columnHelper.display({
      id: "idp",
      header: "Identity provider",
      cell: ({ row }) => <span className="break-all">{row.original.oidc?.issuer ?? row.original.saml?.entityId}</span>,
    }),
    columnHelper.display({
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      cell: ({ row }) => <ConnectionActions orgId={orgId} connection={row.original} may={may} />,
    }),
  ]);
  const table = useTable({ features, columns, data: connections.data?.items ?? noRows, getRowId: (c) => c.id });

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">SSO connections</h1>
        {org && can(org, "ssoConnection", "create") && <AddConnectionDialog orgId={orgId} />}
      </div>
      <p className="text-sm text-muted-foreground">
        Users whose email is in a connection's domain sign in through its identity provider, and become Members the first time they do. A member who already has an account
        keeps it, and their role. A connection signs nobody in until a TXT record proves the Organization holds its domain.
      </p>
      <DataTable table={table} empty={connections.isPending ? "Loading…" : "No SSO connection is configured yet."} />
      {connections.error && <p className="text-sm text-destructive">{connections.error.message}</p>}
    </div>
  );
}

/** What may be done with a connection; how a test went is said under the buttons, where a long reason has room to wrap. */
function ConnectionActions({ orgId, connection, may }: { orgId: string; connection: SsoConnection; may: { test: boolean; change: boolean; delete: boolean } }) {
  // A success is a toast; a failure stays by the buttons, where its reason can be read while the settings are corrected.
  const test = useMutation({
    mutationFn: () => api.testSsoConnection(orgId, connection.id),
    onSuccess: (result) => {
      if (result.ok) toast.success(`${connection.name}: the connection checks out`);
    },
  });
  return (
    <div className="flex flex-col items-end gap-2">
      <div className="flex flex-wrap items-center justify-end gap-1">
        {may.change && !connection.domainVerified && <ProveDomainDialog orgId={orgId} connection={connection} />}
        {may.test && (
          <Button variant="ghost" size="sm" disabled={test.isPending} aria-label={`Test ${connection.name}`} onClick={() => test.mutate()}>
            {test.isPending ? "Testing…" : "Test"}
          </Button>
        )}
        <EditConnectionDialog orgId={orgId} connection={connection} mayChange={may.change} />
        {may.delete && <DeleteConnection orgId={orgId} connection={connection} />}
      </div>
      {test.data && !test.data.ok && <span role="alert" className="max-w-72 whitespace-normal break-words text-right text-sm text-destructive">{test.data.error}</span>}
      {test.error && <span role="alert" className="max-w-72 whitespace-normal break-words text-right text-sm text-destructive">{test.error.message}</span>}
    </div>
  );
}

/** Proving the domain: the TXT record to publish, and a button to have the platform look for it. */
function ProveDomainDialog({ orgId, connection }: { orgId: string; connection: SsoConnection }) {
  const [open, setOpen] = useState(false);
  const verify = useAction(() => api.verifySsoConnectionDomain(orgId, connection.id), ["sso-connections", "audit-events"], () => {
    setOpen(false);
    toast.success(`${connection.domain} is proven: ${connection.name} now signs users in`);
  });
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          Prove domain
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Prove {connection.domain}</DialogTitle>
          <DialogDescription>
            The connection signs nobody in until this TXT record is published in the domain's DNS. It shows the Organization holds the domain, since the connection speaks for
            every address in it.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-2 rounded-md border p-3 text-sm">
          <span className="font-medium">Name</span>
          <code className="break-all text-xs">{connection.domainVerification.name}</code>
          <span className="font-medium">Value</span>
          <code className="break-all text-xs">{connection.domainVerification.value}</code>
        </div>
        {verify.error && <p className="text-sm text-destructive">{verify.error.message}</p>}
        <Button onClick={() => verify.mutate(undefined)} disabled={verify.isPending}>
          {verify.isPending ? "Looking…" : "Look for the record"}
        </Button>
      </DialogContent>
    </Dialog>
  );
}

function DeleteConnection({ orgId, connection }: { orgId: string; connection: SsoConnection }) {
  const [open, setOpen] = useState(false);
  const remove = useAction(() => api.deleteSsoConnection(orgId, connection.id), ["sso-connections", "audit-events"], () => setOpen(false));
  return (
    <>
      <Button variant="ghost" size="sm" aria-label={`Delete ${connection.name}`} onClick={() => setOpen(true)}>
        Delete
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title={`Delete ${connection.name}?`}
        description="Users can no longer sign in through it. Their accounts and memberships stay."
        confirmLabel="Delete"
        pending={remove.isPending}
        error={remove.error}
        onConfirm={() => remove.mutate(undefined)}
      />
    </>
  );
}

/** What the identity provider needs to know about the platform, to set up its side of the connection. */
function ServiceProviderDetails({ connection }: { connection: SsoConnection }) {
  const sp = connection.serviceProvider;
  const rows: [string, string | undefined][] =
    connection.type === "oidc"
      ? [["Redirect URI", sp.redirectUri]]
      : [
          ["Entity ID (audience)", sp.entityId],
          ["ACS URL (HTTP-POST)", sp.acsUrl],
          ["Metadata", sp.metadataUrl],
        ];
  return (
    <div className="flex flex-col gap-2 rounded-md border p-3 text-sm">
      <p className="text-muted-foreground">Give the identity provider:</p>
      {rows.map(([label, value]) => (
        <div key={label} className="flex flex-col">
          <span className="font-medium">{label}</span>
          <code className="break-all text-xs">{value}</code>
        </div>
      ))}
    </div>
  );
}

function AddConnectionDialog({ orgId }: { orgId: string }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          Add a connection
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add an SSO connection</DialogTitle>
          <DialogDescription>An OIDC provider is checked against its discovery document when it is added. A client secret cannot be read back.</DialogDescription>
        </DialogHeader>
        {/* Only mounted while open, so each opening starts from a clean form. */}
        {open && <ConnectionForm orgId={orgId} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function EditConnectionDialog({ orgId, connection, mayChange }: { orgId: string; connection: SsoConnection; mayChange: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="sm">
          {mayChange ? "Edit" : "Details"}
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{connection.name}</DialogTitle>
          <DialogDescription>
            {mayChange
              ? "Leave the client secret or certificate empty to keep it. Once someone has signed in through it, it cannot be pointed at another identity provider. A new domain must be proven again."
              : null}
          </DialogDescription>
        </DialogHeader>
        <ServiceProviderDetails connection={connection} />
        {open && mayChange && <ConnectionForm orgId={orgId} existing={connection} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

/** Adds a connection, or, given `existing`, changes it, sending only what was changed. */
function ConnectionForm({ orgId, existing, onDone }: { orgId: string; existing?: SsoConnection; onDone: () => void }) {
  const [type, setType] = useState<SsoConnection["type"]>(existing?.type ?? "saml");
  const [name, setName] = useState(existing?.name ?? "");
  const [domain, setDomain] = useState(existing?.domain ?? "");
  const [issuer, setIssuer] = useState(existing?.oidc?.issuer ?? "");
  const [clientId, setClientId] = useState(existing?.oidc?.clientId ?? "");
  const [clientSecret, setClientSecret] = useState("");
  const [entityId, setEntityId] = useState(existing?.saml?.entityId ?? "");
  const [ssoUrl, setSsoUrl] = useState(existing?.saml?.ssoUrl ?? "");
  const [certificate, setCertificate] = useState("");
  const save = useAction(
    () => {
      if (!existing) {
        const base = { name: name.trim(), domain: domain.trim() };
        return api.addSsoConnection(
          orgId,
          type === "oidc" ? { ...base, oidc: { issuer: issuer.trim(), clientId: clientId.trim(), clientSecret } } : { ...base, saml: { entityId: entityId.trim(), ssoUrl: ssoUrl.trim(), certificate } },
        );
      }
      const changed = <T,>(next: T, before: T) => (next !== before ? next : undefined);
      const body: SsoConnectionChange = { name: changed(name.trim(), existing.name), domain: changed(domain.trim(), existing.domain) };
      if (existing.oidc) body.oidc = { issuer: changed(issuer.trim(), existing.oidc.issuer), clientId: changed(clientId.trim(), existing.oidc.clientId), clientSecret: clientSecret || undefined };
      if (existing.saml) body.saml = { entityId: changed(entityId.trim(), existing.saml.entityId), ssoUrl: changed(ssoUrl.trim(), existing.saml.ssoUrl), certificate: certificate || undefined };
      return api.changeSsoConnection(orgId, existing.id, body);
    },
    ["sso-connections", "audit-events"],
    onDone,
  );
  const field = (id: string, label: string, value: string, set: (v: string) => void, props: Record<string, unknown> = {}) => (
    <div className="flex flex-col gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Input id={id} value={value} onChange={(e) => set(e.target.value)} {...props} />
    </div>
  );
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        save.mutate(undefined);
      }}
    >
      {!existing && (
        <div className="flex flex-col gap-2">
          <Label htmlFor="sso-type">Type</Label>
          <Select value={type} onValueChange={(value) => setType(value as SsoConnection["type"])}>
            <SelectTrigger id="sso-type" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="saml">SAML (Ping, for example)</SelectItem>
              <SelectItem value="oidc">OIDC</SelectItem>
            </SelectContent>
          </Select>
        </div>
      )}
      {field("sso-name", "Name", name, setName, { maxLength: 100, required: true })}
      {field("sso-domain", "Email domain", domain, setDomain, { placeholder: "example.com", required: true })}
      {type === "oidc" ? (
        <>
          {field("sso-issuer", "Issuer", issuer, setIssuer, { placeholder: "https://login.example.com", required: true })}
          {field("sso-client-id", "Client ID", clientId, setClientId, { required: true })}
          {field("sso-client-secret", "Client secret", clientSecret, setClientSecret, { type: "password", autoComplete: "off", required: !existing })}
        </>
      ) : (
        <>
          {field("sso-entity-id", "Identity provider entity ID", entityId, setEntityId, { required: true })}
          {field("sso-url", "Single sign-on URL", ssoUrl, setSsoUrl, { placeholder: "https://idp.example.com/idp/SSO.saml2", required: true })}
          <div className="flex flex-col gap-2">
            <Label htmlFor="sso-certificate">Signing certificate (PEM)</Label>
            <Textarea
              id="sso-certificate"
              className="font-mono text-xs"
              rows={5}
              value={certificate}
              onChange={(e) => setCertificate(e.target.value)}
              placeholder={existing?.saml ? `${existing.saml.certificate.subject}, valid until ${new Date(existing.saml.certificate.notAfter).toLocaleDateString()}` : "-----BEGIN CERTIFICATE-----"}
              required={!existing}
            />
          </div>
        </>
      )}
      {save.error && <p className="text-sm text-destructive">{save.error.message}</p>}
      <Button type="submit" disabled={save.isPending}>
        {existing ? "Save" : "Add"}
      </Button>
    </form>
  );
}
