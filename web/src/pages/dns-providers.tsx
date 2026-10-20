import { useMutation, useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { createColumnHelper, tableFeatures, useTable } from "@tanstack/react-table";
import { toast } from "sonner";
import { DataTable } from "@/components/data-table/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api, can, type Agent, type DnsProvider } from "@/lib/api";
import { useOrg } from "@/lib/use-org";
import { AddDnsProviderDialog, EditDnsProviderDialog, ReplaceSecretDialog, TYPE_LABEL } from "./dns-provider-dialogs";

const ROUTE = "/app/organizations/$orgId/dns-providers";

// The server lists every provider, so there is nothing to page.
const features = tableFeatures({});
const columnHelper = createColumnHelper<typeof features, DnsProvider>();
const noRows: DnsProvider[] = [];
const noAgents: Agent[] = [];

/** What the provider talks to: a server and port, or the WAPI's URL. */
const endpointOf = (p: DnsProvider) => (p.type === "rfc2136" ? `${p.settings.server}:${p.settings.port}` : p.settings.url);

/**
 * The Organization's connections to its DNS, which Domain Control Validation publishes its records through. The secret of
 * each (a TSIG key, a WAPI password) is written once and never shown: it can be replaced or tested, and that is all.
 */
export function DnsProvidersPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const allowed = org ? can(org, "dnsProvider", "read") : false;
  const mayRelay = org ? can(org, "agent", "read") : false;
  const providers = useQuery({ queryKey: ["dns-providers", orgId], queryFn: () => api.dnsProviders(orgId), enabled: allowed });
  // The same query as the Deployment dialog's choice of Agent, so the two share what was fetched.
  const agents = useQuery({
    queryKey: ["agents", orgId, "choices"],
    queryFn: () => api.agents(orgId, { status: [], os: [], outdated: false }, { page: 1, pageSize: 100 }),
    enabled: allowed && mayRelay,
  });
  const agentList = agents.data?.items ?? noAgents;
  const relay = mayRelay && agents.data ? { agents: agentList } : null;
  const mayChange = org ? can(org, "dnsProvider", "update") : false;
  const mayTest = org ? can(org, "dnsProvider", "test") : false;

  const columns = columnHelper.columns([
    columnHelper.accessor("name", { header: "Name", cell: ({ cell }) => <span className="font-medium">{cell.getValue()}</span> }),
    columnHelper.accessor("type", { header: "Type", cell: ({ cell }) => <Badge variant="secondary">{TYPE_LABEL[cell.getValue()]}</Badge> }),
    columnHelper.accessor((p) => p.settings.zone, { id: "zone", header: "Zone", cell: ({ cell }) => <span className="font-mono text-xs">{cell.getValue()}</span> }),
    columnHelper.accessor(endpointOf, { id: "endpoint", header: "Server", cell: ({ cell }) => <span className="break-all font-mono text-xs">{cell.getValue()}</span> }),
    columnHelper.accessor((p) => p.relayAgentIds, {
      id: "runsThrough",
      header: "Runs through",
      cell: ({ cell }) =>
        cell.getValue().length === 0 ? (
          <span className="text-muted-foreground">The platform</span>
        ) : (
          cell.getValue().map((id) => agentList.find((a) => a.id === id)?.hostName ?? "An Agent").join(", ")
        ),
    }),
    columnHelper.display({
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      cell: ({ row }) => <ProviderActions orgId={orgId} provider={row.original} relay={relay} mayTest={mayTest} mayChange={mayChange} />,
    }),
  ]);
  const table = useTable({ features, columns, data: providers.data?.items ?? noRows, getRowId: (p) => p.id });

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">DNS Providers</h1>
        {org && can(org, "dnsProvider", "create") && <AddDnsProviderDialog orgId={orgId} relay={relay} />}
      </div>
      <p className="text-sm text-muted-foreground">
        A DNS Provider is the Organization's way into its own DNS: the platform publishes the records that prove control of a domain through it, and removes them again. Each
        provider's secret is stored encrypted and never shown; it can be replaced or tested.
      </p>
      {org && !allowed ? (
        <p className="text-sm text-muted-foreground">Only Organization Administrators see the DNS Providers.</p>
      ) : (
        <div className="flex flex-col gap-4">
          <DataTable table={table} empty={providers.isPending ? "Loading…" : "No DNS Provider is connected yet."} />
          {providers.error && <p className="text-sm text-destructive">{providers.error.message}</p>}
        </div>
      )}
    </div>
  );
}

/** What may be done with a provider; how a test went is said under the buttons, where a long reason has room to wrap. */
function ProviderActions({
  orgId,
  provider,
  relay,
  mayTest,
  mayChange,
}: {
  orgId: string;
  provider: DnsProvider;
  relay: { agents: Agent[] } | null;
  mayTest: boolean;
  mayChange: boolean;
}) {
  // A test publishes a throwaway record through the provider and removes it again.
  // A success is a toast; a failure stays by the buttons, where its reason can be read while the settings are corrected.
  const test = useMutation({
    mutationFn: () => api.testDnsProvider(orgId, provider.id),
    onSuccess: (result) => {
      if (result.ok) toast.success(`${provider.name}: the connection works`);
    },
  });
  return (
    <div className="flex flex-col items-end gap-2">
      <div className="flex flex-wrap items-center justify-end gap-2">
        {mayTest && (
          <Button variant="outline" size="sm" disabled={test.isPending} aria-label={`Test ${provider.name}`} onClick={() => test.mutate()}>
            {test.isPending ? "Testing…" : "Test"}
          </Button>
        )}
        {mayChange && <EditDnsProviderDialog orgId={orgId} provider={provider} relay={relay} />}
        {mayChange && <ReplaceSecretDialog orgId={orgId} provider={provider} />}
      </div>
      {test.data && !test.data.ok && <span role="alert" className="max-w-72 whitespace-normal break-words text-right text-sm text-destructive">{test.data.error}</span>}
      {test.error && <span role="alert" className="max-w-72 whitespace-normal break-words text-right text-sm text-destructive">{test.error.message}</span>}
    </div>
  );
}
