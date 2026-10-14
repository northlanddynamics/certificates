import { useQuery } from "@tanstack/react-query";
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
import { Textarea } from "@/components/ui/textarea";
import { api, can, type SsoConnection, type SsoConnectionChange } from "@/lib/api";
import { useAction } from "@/lib/use-action";

const ROUTE = "/app/organizations/$orgId/sso-connections";
const TYPE_LABEL: Record<SsoConnection["type"], string> = { oidc: "OIDC", saml: "SAML" };

// The server lists every connection, so there is nothing to page.
const features = tableFeatures({});
const columnHelper = createColumnHelper<typeof features, SsoConnection>();
const columns = columnHelper.columns([
  columnHelper.accessor("name", { header: "Name", cell: ({ cell }) => <span className="font-medium">{cell.getValue()}</span> }),
  columnHelper.accessor("type", { header: "Type", cell: ({ cell }) => <Badge variant="secondary">{TYPE_LABEL[cell.getValue()]}</Badge> }),
  columnHelper.accessor("domain", { header: "Domain" }),
  columnHelper.display({
    id: "idp",
    header: "Identity provider",
    cell: ({ row }) => <span className="break-all">{row.original.oidc?.issuer ?? row.original.saml?.entityId}</span>,
  }),
  columnHelper.display({ id: "actions", header: () => <span className="sr-only">Actions</span>, cell: ({ row }) => <ConnectionActions connection={row.original} /> }),
]);
const noRows: SsoConnection[] = [];

/**
 * The Organization's SSO connections: the SAML (Ping, for example) or OIDC identity providers its users sign in through,
 * each for one email domain. Someone signing in through one for the first time becomes a Member. Only Organization
 * Administrators see or configure them, and every change is audited. Requiring SSO is on the Login policy page.
 */
export function SsoConnectionsPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.organizations.find((o) => o.id === orgId) }).data;
  const allowed = org ? can(org, "ssoConnection", "read") : false;
  const connections = useQuery({ queryKey: ["sso-connections", orgId], queryFn: () => api.ssoConnections(orgId), enabled: allowed });
  const table = useTable({ features, columns, data: connections.data?.items ?? noRows, getRowId: (c) => c.id });

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">SSO connections</h1>
        {org && can(org, "ssoConnection", "create") && <AddConnectionDialog orgId={orgId} />}
      </div>
      <p className="text-sm text-muted-foreground">
        Users whose email is in a connection's domain sign in through its identity provider, and become Members the first time they do. A member who already has an account
        keeps it, and their role.
      </p>
      <DataTable table={table} empty={connections.isPending ? "Loading…" : "No SSO connection is configured yet."} />
      {connections.error && <p className="text-sm text-destructive">{connections.error.message}</p>}
    </div>
  );
}

function ConnectionActions({ connection }: { connection: SsoConnection }) {
  const { orgId } = useParams({ from: ROUTE });
  const org = useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.organizations.find((o) => o.id === orgId) }).data;
  // A success is a toast; a failure stays by the buttons, where its reason can be read while the settings are corrected.
  const [failure, setFailure] = useState<string | null>(null);
  const test = useAction(() => api.testSsoConnection(orgId, connection.id), ["audit-events"]);
  if (!org) return null;
  return (
    <div className="flex flex-col items-end gap-1">
      <div className="flex justify-end gap-1">
        {can(org, "ssoConnection", "test") && (
          <Button
            variant="ghost"
            size="sm"
            disabled={test.isPending}
            onClick={() =>
              test.mutate(undefined, {
                onSuccess: (result) => {
                  const { ok, error } = result as { ok: boolean; error?: string };
                  setFailure(ok ? null : (error ?? "the test failed"));
                  if (ok) toast.success(`${connection.name}: the connection checks out`);
                },
              })
            }
          >
            Test
          </Button>
        )}
        <EditConnectionDialog orgId={orgId} connection={connection} mayChange={can(org, "ssoConnection", "update")} />
        {can(org, "ssoConnection", "delete") && <DeleteConnection orgId={orgId} connection={connection} />}
      </div>
      {(failure ?? test.error?.message) && <p className="max-w-sm text-right text-sm text-destructive">{failure ?? test.error?.message}</p>}
    </div>
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
            {mayChange ? "Leave the client secret or certificate empty to keep it. Once someone has signed in through it, it cannot be pointed at another identity provider." : null}
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
          <select id="sso-type" className="h-9 rounded-md border bg-transparent px-3 text-sm" value={type} onChange={(e) => setType(e.target.value as SsoConnection["type"])}>
            <option value="saml">SAML (Ping, for example)</option>
            <option value="oidc">OIDC</option>
          </select>
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
