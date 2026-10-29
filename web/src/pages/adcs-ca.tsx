import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, Outlet, useLocation, useNavigate, useParams } from "@tanstack/react-router";
import { DownloadIcon, MoreHorizontalIcon, RotateCwIcon } from "lucide-react";
import { useState } from "react";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { LoadError } from "@/components/load-error";
import { usePageCrumbs } from "@/components/page-crumbs";
import { SummaryRows } from "@/components/summary-rows";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { api, can, type AdcsCa, type Me } from "@/lib/api";
import { permittedNamesLabel } from "@/lib/private-ca";
import { adcsAttention, healthOf } from "@/lib/private-ca-list";
import { useAction } from "@/lib/use-action";
import { useOrg } from "@/lib/use-org";
import { EditAdcsCaDialog, NoPermittedNames, TemplateTable, useAdcsAgents, type AdcsWizardStep } from "./adcs-ca-controls";
import { NotFound } from "./platform-ca";
import { caDate } from "./private-ca-controls";
import { HealthBadge, KindBadge } from "./private-cas";

const ROUTE = "/app/organizations/$orgId/private-cas/adcs/$caId";

const TABS = [
  { to: "/organizations/$orgId/private-cas/adcs/$caId", label: "Overview", exact: true },
  { to: "/organizations/$orgId/private-cas/adcs/$caId/templates", label: "Templates", exact: false },
] as const;

/** The ADCS CA of the page, from the Organization's list of them, with what the caller may do to it. */
function useAdcsCa() {
  const { orgId, caId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const cas = useQuery({ queryKey: ["adcs-cas", orgId], queryFn: () => api.adcsCas(orgId), enabled: org ? can(org, "adcsCa", "read") : false });
  return { orgId, org, cas, ca: cas.data?.items.find((c) => c.id === caId) };
}

/**
 * One ADCS CA's page: its header and what needs doing always in view, and under them the open tab, its overview or its
 * Certificate Templates. The platform reaches it only through the Agents assigned to it.
 */
export function AdcsCaPage() {
  const { orgId, org, cas, ca } = useAdcsCa();
  const { pathname } = useLocation();
  const tab = TABS.find((t) => !t.exact && pathname.endsWith(t.to.slice(t.to.lastIndexOf("/"))));
  usePageCrumbs(ca ? [{ label: ca.name, url: `/organizations/${orgId}/private-cas/adcs/${ca.id}` }, ...(tab ? [{ label: tab.label }] : [])] : []);
  const [editing, setEditing] = useState<AdcsWizardStep | null>(null);

  if (cas.error) return <LoadError title="Can't load this ADCS CA" description={cas.error.message} onRetry={() => cas.refetch()} retrying={cas.isFetching} />;
  if (!cas.data || !org) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (!ca) return <NotFound orgId={orgId} />;

  const mayManage = can(org, "adcsCa", "update");
  return (
    <div className="flex flex-col gap-6">
      <AdcsCaHeader orgId={orgId} org={org} ca={ca} onEdit={() => setEditing("ca")} />
      {ca.discoveryFailure && (
        <Alert variant="destructive">
          <AlertTitle>The last discovery failed, {new Date(ca.discoveryFailure.at).toLocaleString()}</AlertTitle>
          <AlertDescription>{ca.discoveryFailure.error} The chain and templates are from the last discovery that worked.</AlertDescription>
        </Alert>
      )}
      {!ca.permittedNames && (
        <NoPermittedNames
          action={
            mayManage && (
              <Button variant="outline" size="sm" onClick={() => setEditing("names")}>
                Add Permitted Name Rules
              </Button>
            )
          }
        />
      )}
      <nav aria-label="ADCS CA" className="flex gap-1 overflow-x-auto border-b">
        {TABS.map((t) => (
          <Link
            key={t.to}
            to={t.to}
            params={{ orgId, caId: ca.id }}
            activeOptions={{ exact: t.exact }}
            className="-mb-px border-b-2 border-transparent px-3 py-2 text-sm font-medium whitespace-nowrap text-muted-foreground hover:text-foreground data-[status=active]:border-foreground data-[status=active]:text-foreground"
            activeProps={{ "aria-current": "page" }}
          >
            {t.label}
            {t.label === "Templates" && (
              <Badge variant="secondary" className="ml-2">
                {ca.templates.length}
              </Badge>
            )}
          </Link>
        ))}
      </nav>
      <Outlet />
      {mayManage && <EditAdcsCaDialog orgId={orgId} ca={ca} open={editing !== null} onOpenChange={(open) => setEditing(open ? "ca" : null)} step={editing ?? "ca"} />}
    </div>
  );
}

function AdcsCaHeader({ orgId, org, ca, onEdit }: { orgId: string; org: Me["organizations"][number]; ca: AdcsCa; onEdit: () => void }) {
  const mayManage = can(org, "adcsCa", "update");
  const mayDelete = can(org, "adcsCa", "delete");
  const navigate = useNavigate();
  const [removing, setRemoving] = useState(false);
  const remove = useAction(() => api.deleteAdcsCa(orgId, ca.id), ["adcs-cas"], () => {
    setRemoving(false);
    void navigate({ to: "/organizations/$orgId/private-cas", params: { orgId } });
  });
  const queryClient = useQueryClient();
  // A failed discovery is recorded on the CA too, so the CA is fetched again either way.
  const refresh = useMutation({ mutationFn: () => api.refreshAdcsCa(orgId, ca.id), onSettled: () => queryClient.invalidateQueries({ queryKey: ["adcs-cas"] }) });
  return (
    <header className="flex flex-col gap-2">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex min-w-0 flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-xl font-semibold">{ca.name}</h1>
            <KindBadge kind="adcs" />
            <HealthBadge health={healthOf(adcsAttention(ca))} />
          </div>
          <p className="break-all font-mono text-xs text-muted-foreground">{ca.configString}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" asChild>
            <a href={api.adcsCaChainUrl(orgId, ca.id)} download aria-label={`Download the chain of ${ca.name}`}>
              <DownloadIcon />
              Chain
            </a>
          </Button>
          {mayManage && (
            <Button variant="outline" onClick={() => refresh.mutate()} disabled={refresh.isPending} aria-label={`Refresh the templates of ${ca.name}`}>
              <RotateCwIcon className={refresh.isPending ? "animate-spin" : undefined} />
              Refresh
            </Button>
          )}
          {mayManage && (
            <Button variant="outline" onClick={onEdit} aria-label={`Edit ${ca.name}`}>
              Edit
            </Button>
          )}
          {mayDelete && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="icon" aria-label={`More actions for ${ca.name}`}>
                  <MoreHorizontalIcon />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem variant="destructive" onSelect={() => setRemoving(true)}>
                  Remove…
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
      </div>
      {refresh.error && <p className="text-sm text-destructive">{refresh.error.message}</p>}
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
    </header>
  );
}

const AGENT_STATUS_VARIANT = { online: "success", offline: "destructive", revoked: "neutral" } as const;

/** An ADCS CA's overview: the names it may be asked for, what it is offered for, its Agents, its discovery, and its chain. */
export function AdcsCaOverview() {
  const { orgId, org, ca } = useAdcsCa();
  const agents = useAdcsAgents(orgId);
  if (!ca || !org) return null;
  const offered = (ids: string[]) =>
    ids.length === 0 ? (
      <span className="text-muted-foreground">No template</span>
    ) : (
      ca.templates
        .filter((t) => ids.includes(t.id))
        .map((t) => t.displayName || t.name)
        .join(", ")
    );
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Permitted names</CardTitle>
          <CardDescription>The platform refuses any other name before anything reaches ADCS, at proposal, Name Change and Issuance.</CardDescription>
        </CardHeader>
        <CardContent className="text-sm">{ca.permittedNames ? permittedNamesLabel(ca.permittedNames) : <span className="text-muted-foreground">None: Approval alone decides</span>}</CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>What it is offered for</CardTitle>
          <CardAction>
            <Button variant="ghost" size="sm" asChild>
              <Link to="/organizations/$orgId/private-cas/adcs/$caId/templates" params={{ orgId, caId: ca.id }}>
                Templates
              </Link>
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent>
          <SummaryRows
            rows={[
              { label: "TLS", value: offered(ca.offered.tls) },
              { label: "Devices", value: offered(ca.offered.devices) },
            ]}
          />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Runs through</CardTitle>
          <CardDescription>Any of its Agents that is online carries out each operation, as its own account.</CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="divide-y rounded-md border">
            {ca.agentIds.map((id) => {
              const agent = agents.find((a) => a.id === id);
              return (
                <li key={id} className="flex flex-wrap items-center justify-between gap-2 p-3 text-sm">
                  <span className="min-w-0 break-all">
                    {agent?.hostName ?? "An Agent"}
                    {agent && <span className="block text-xs text-muted-foreground">Version {agent.version}{agent.outdated ? ", outdated" : ""} · last seen {new Date(agent.lastContactAt).toLocaleString()}</span>}
                  </span>
                  {agent && <Badge variant={AGENT_STATUS_VARIANT[agent.status]}>{agent.status === "online" ? "Online" : agent.status === "offline" ? "Offline" : "Revoked"}</Badge>}
                </li>
              );
            })}
          </ul>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Discovery</CardTitle>
          <CardDescription>Its chain and templates are fetched through an Agent once a day, and on Refresh.</CardDescription>
        </CardHeader>
        <CardContent>
          <SummaryRows
            rows={[
              { label: "Last succeeded", value: new Date(ca.discoveredAt).toLocaleString() },
              ...(ca.discoveryFailure ? [{ label: "Last failed", value: <span className="text-destructive">{new Date(ca.discoveryFailure.at).toLocaleString()}</span> }] : []),
            ]}
          />
        </CardContent>
      </Card>
      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle>Chain and revocation</CardTitle>
          <CardDescription>ADCS publishes its own CRL; the platform serves none for it.</CardDescription>
        </CardHeader>
        <CardContent>
          <SummaryRows
            rows={[
              {
                label: "Chain",
                value: (
                  <ol className="flex flex-col gap-1">
                    {ca.chain.map((c) => (
                      <li key={c.fingerprint} className="break-all">
                        {c.subject} <span className="text-muted-foreground">(until {caDate(c.notAfter)})</span>
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
            ]}
          />
        </CardContent>
      </Card>
    </div>
  );
}

/** An ADCS CA's Certificate Templates, grouped as the platform can use them. */
export function AdcsCaTemplates() {
  const { orgId, org, ca } = useAdcsCa();
  if (!ca || !org) return null;
  return (
    <div className="flex flex-col gap-4">
      <p className="max-w-3xl text-sm text-muted-foreground">
        ADCS's Certificate Templates decide validity, key usage and EKUs. The platform offers one only while it is published, enrollable by the Agents' account, and takes the subject from the
        request: for TLS with Server Authentication, for devices with Client Authentication.
      </p>
      <div className="rounded-lg border">
        <TemplateTable orgId={orgId} ca={ca} mayManage={can(org, "adcsCa", "update")} />
      </div>
    </div>
  );
}
