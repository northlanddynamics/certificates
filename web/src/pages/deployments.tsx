import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { createColumnHelper, rowPaginationFeature, tableFeatures, useTable, type PaginationState } from "@tanstack/react-table";
import { useMemo, useState } from "react";
import { DataTable } from "@/components/data-table/data-table";
import { DataTablePagination } from "@/components/data-table/data-table-pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { api, can, type Deployment, type DeploymentRun, type DeploymentState } from "@/lib/api";
import { useAction } from "@/lib/use-action";
import { NewDeploymentDialog } from "./new-deployment-dialog";

const ROUTE = "/app/organizations/$orgId/deployments";

const STATE: Record<DeploymentState, { label: string; hint: string; variant: "default" | "secondary" | "destructive" | "outline" }> = {
  awaiting_key: { label: "Awaiting key", hint: "Waiting for the Agent to make the key and send a CSR", variant: "outline" },
  key_failed: { label: "Key failed", hint: "The Agent could not make the key, or its CSR was refused", variant: "destructive" },
  issuing: { label: "Issuing…", hint: "The Certificate is being issued", variant: "secondary" },
  issuance_failed: { label: "Issuance failed", hint: "See the Managed Certificate for why, and try issuing it again", variant: "destructive" },
  awaiting_deployment: { label: "Awaiting deployment", hint: "Waiting for the Agent to run the script for the Certificate", variant: "outline" },
  deployed: { label: "Deployed", hint: "The script succeeded for the current Certificate", variant: "default" },
  deployment_failed: { label: "Deployment failed", hint: "The script did not succeed for the current Certificate", variant: "destructive" },
};
/** The states that move on without anyone: worth looking at again soon. */
const MOVING: DeploymentState[] = ["awaiting_key", "issuing", "awaiting_deployment"];

const shortHash = (hash: string) => hash.slice(0, 12);

// Paging is the server's (Page<Deployment>); the table lays out the page it was given.
const features = tableFeatures({ rowPaginationFeature });
const columnHelper = createColumnHelper<typeof features, Deployment>();
const noRows: Deployment[] = [];

/** How a run ended, in a word: its exit code, or that the script was not started. */
function RunResult({ run }: { run: DeploymentRun }) {
  return (
    <Badge variant={run.status === "succeeded" ? "default" : "destructive"}>
      {run.exitCode === null ? "Not run" : run.status === "succeeded" ? "Succeeded" : `Exit ${run.exitCode}`}
    </Badge>
  );
}

/**
 * The Organization's Deployments: an Agent makes the key for a Managed Certificate, and runs a Deployment Script each time a
 * Certificate is issued for it. Only Organization Administrators set one up, see them or run one again.
 */
export function DeploymentsPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.organizations.find((o) => o.id === orgId) }).data;
  const allowed = org ? can(org, "deployment", "read") : false;
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 25 });
  const deployments = useQuery({
    queryKey: ["deployments", orgId, pagination],
    queryFn: () => api.deployments(orgId, { page: pagination.pageIndex + 1, pageSize: pagination.pageSize }),
    enabled: allowed,
    placeholderData: keepPreviousData,
    // The Agent does its part when it next polls: look again until nothing is waiting on it.
    refetchInterval: (query) => (query.state.data?.items.some((d) => MOVING.includes(d.state) || d.runPending) ? 3000 : 30_000),
  });
  const columns = useMemo(
    () =>
      columnHelper.columns([
        columnHelper.accessor("names", {
          header: "Names",
          cell: ({ row }) => (
            <div className="flex flex-col gap-0.5">
              <Link to="/organizations/$orgId/certificates/$id" params={{ orgId, id: row.original.managedCertificateId }} className="font-mono text-xs font-medium underline-offset-4 hover:underline">
                {row.original.names[0]}
              </Link>
              {row.original.names.length > 1 && <span className="text-xs text-muted-foreground">and {row.original.names.length - 1} more</span>}
            </div>
          ),
        }),
        columnHelper.accessor((d) => d.agent.hostName, { id: "agent", header: "Agent" }),
        columnHelper.accessor((d) => d.script.name, {
          id: "script",
          header: "Script",
          cell: ({ row }) => (
            <span className="flex items-center gap-2">
              {row.original.script.name}
              <span className="text-xs text-muted-foreground">v{row.original.script.version}</span>
            </span>
          ),
        }),
        columnHelper.accessor("state", {
          header: "State",
          cell: ({ row }) => (
            <div className="flex flex-col gap-1">
              <Badge variant={STATE[row.original.state].variant} title={STATE[row.original.state].hint}>
                {STATE[row.original.state].label}
              </Badge>
              {row.original.keyFailure && <span className="text-xs text-destructive">{row.original.keyFailure}</span>}
              {row.original.runPending && <span className="text-xs text-muted-foreground">Script run requested</span>}
            </div>
          ),
        }),
        columnHelper.accessor((d) => d.lastRun?.finishedAt ?? "", {
          id: "lastRun",
          header: "Last run",
          cell: ({ row }) =>
            row.original.lastRun ? (
              <span className="flex items-center gap-2">
                <time dateTime={row.original.lastRun.finishedAt}>{new Date(row.original.lastRun.finishedAt).toLocaleString()}</time>
                <RunResult run={row.original.lastRun} />
              </span>
            ) : (
              <span className="text-muted-foreground">Not yet</span>
            ),
        }),
        columnHelper.display({ id: "actions", header: () => <span className="sr-only">Actions</span>, cell: ({ row }) => <DeploymentActions deployment={row.original} /> }),
      ]),
    [orgId],
  );
  const table = useTable({
    features,
    columns,
    data: deployments.data?.items ?? noRows,
    rowCount: deployments.data?.total,
    manualPagination: true,
    state: { pagination },
    onPaginationChange: setPagination,
    getRowId: (d) => d.id,
  });

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">Deployments</h1>
        {org && can(org, "deployment", "create") && <NewDeploymentDialog orgId={orgId} />}
      </div>
      <p className="text-sm text-muted-foreground">
        A Deployment has one Agent make the private key for a Managed Certificate on its own host, so the key never reaches the platform, and run a Deployment Script with the
        Certificate and the key's location each time a Certificate is issued for it. The Agent does its part when it next polls.
      </p>
      {org && !allowed ? (
        <p className="text-sm text-muted-foreground">Only Organization Administrators see the Deployments.</p>
      ) : (
        <div className="flex flex-col gap-4">
          <DataTable table={table} empty={deployments.isPending ? "Loading…" : "No Deployment is set up yet."} />
          <DataTablePagination
            pageIndex={pagination.pageIndex}
            pageSize={pagination.pageSize}
            rowCount={deployments.data?.total ?? 0}
            onPageIndexChange={(pageIndex) => setPagination({ ...pagination, pageIndex })}
            onPageSizeChange={(pageSize) => setPagination({ pageIndex: 0, pageSize })}
          />
          {deployments.error && <p className="text-sm text-destructive">{deployments.error.message}</p>}
        </div>
      )}
    </div>
  );
}

function DeploymentActions({ deployment }: { deployment: Deployment }) {
  const { orgId } = useParams({ from: ROUTE });
  const org = useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.organizations.find((o) => o.id === orgId) }).data;
  const runAgain = useAction(() => api.runDeploymentAgain(orgId, deployment.id), ["deployments"]);
  // There is a Certificate to run it for once it has been issued, which a run (successful or not) or the Agent's waiting shows.
  const hasCertificate = deployment.state === "awaiting_deployment" || deployment.state === "deployed" || deployment.state === "deployment_failed";
  // When the Agent could not make the key, the same request asks it again.
  const keyFailed = deployment.state === "key_failed";
  return (
    <div className="flex flex-col items-end gap-1">
      <div className="flex items-center justify-end gap-2">
        <RunsDialog orgId={orgId} deployment={deployment} />
        {org && can(org, "deployment", "run") && (
          <Button
            variant="outline"
            size="sm"
            aria-label={`${keyFailed ? "Ask for the key of" : "Run"} ${deployment.names[0]} again`}
            disabled={!(hasCertificate || keyFailed) || deployment.runPending || runAgain.isPending}
            onClick={() => runAgain.mutate(undefined)}
          >
            {keyFailed ? "Ask for the key again" : "Run again"}
          </Button>
        )}
      </div>
      {runAgain.error && <span className="text-xs text-destructive">{runAgain.error.message}</span>}
    </div>
  );
}

/** A Deployment's runs, newest first, each with what the script wrote. */
function RunsDialog({ orgId, deployment }: { orgId: string; deployment: Deployment }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" aria-label={`Runs of ${deployment.names[0]}`}>
          Runs
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>Runs of {deployment.names[0]}</DialogTitle>
          <DialogDescription>
            On {deployment.agent.hostName}, with {deployment.script.name} v{deployment.script.version}. Output is kept up to 32 KiB.
          </DialogDescription>
        </DialogHeader>
        {open && <Runs orgId={orgId} deployment={deployment} />}
      </DialogContent>
    </Dialog>
  );
}

function Runs({ orgId, deployment }: { orgId: string; deployment: Deployment }) {
  const runs = useQuery({
    queryKey: ["deployments", orgId, deployment.id, "runs"],
    queryFn: () => api.deploymentRuns(orgId, deployment.id, { page: 1, pageSize: 25 }),
    refetchInterval: deployment.runPending ? 3000 : false,
  });
  if (runs.isPending) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (runs.error) return <p className="text-sm text-destructive">{runs.error.message}</p>;
  if (runs.data.items.length === 0) return <p className="text-sm text-muted-foreground">The script has not run yet.</p>;
  return (
    <div className="flex max-h-[70vh] flex-col gap-4 overflow-y-auto">
      {runs.data.items.map((run) => (
        <section key={run.id} aria-label={`Run at ${run.startedAt}`} className="flex flex-col gap-2 rounded-md border p-3 text-sm">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <RunResult run={run} />
            <time dateTime={run.startedAt}>{new Date(run.startedAt).toLocaleString()}</time>
            <span className="text-muted-foreground">{run.trigger === "issuance" ? "Certificate issued" : "Run again"}</span>
            <span className="text-muted-foreground">
              Certificate <span className="font-mono text-xs">{shortHash(run.certificate.fingerprint)}</span>
            </span>
            <span className="text-muted-foreground">
              Script v{run.script.version} <span className="font-mono text-xs">{shortHash(run.script.hash)}</span>
            </span>
          </div>
          {run.output && (
            <pre aria-label="Output" className="max-h-60 overflow-auto rounded-md border bg-muted p-3 font-mono text-xs whitespace-pre-wrap">
              {run.output}
            </pre>
          )}
          {run.outputTruncated && <span className="text-xs text-muted-foreground">The output was cut short.</span>}
        </section>
      ))}
    </div>
  );
}
