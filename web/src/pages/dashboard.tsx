import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { BotIcon, CircleCheckIcon, FileKey2Icon, ScrollTextIcon } from "lucide-react";
import type { ReactNode } from "react";
import { AcmeCaTagBadge } from "@/components/acme-ca-tag";
import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { api, can, type Dashboard, type ManagedCertificate, type Me } from "@/lib/api";
import { acmeCaName, useAcmeCas } from "@/lib/acme-cas";
import { targetTypeLabel } from "@/lib/audit-search";
import { primaryName, status } from "@/lib/managed-certificate";
import { useOrg } from "@/lib/use-org";
import { NewManagedCertificateDialog } from "./new-managed-certificate-dialog";

type Org = Me["organizations"][number];

const day = (iso: string) => new Date(iso).toLocaleDateString();
const when = (iso: string) => new Date(iso).toLocaleString();

/**
 * What needs doing across the Managed Certificates the caller sees: the inventory's counts, those needing someone now,
 * when Certificates end in the weeks ahead and which CAs they come from, and, for those who may see them, what waits
 * for Approval, the Agents and the latest of the audit log. Each panel is shown only to whoever may use it.
 */
export function DashboardPage() {
  const { orgId } = useParams({ from: "/app/organizations/$orgId/dashboard" });
  const org = useOrg(orgId);
  const navigate = useNavigate();
  const board = useQuery({ queryKey: ["dashboard", orgId], queryFn: () => api.dashboard(orgId), enabled: !!org });
  if (!org) return <p className="text-muted-foreground">You do not belong to this Organization.</p>;
  const seesAll = can(org, "managedCertificate", "read");
  const data = board.data;
  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Dashboard"
        description={seesAll ? "What needs doing across this Organization's Managed Certificates." : "The Managed Certificates you own or proposed, and what needs doing."}
        action={<NewManagedCertificateDialog org={org} onCreated={(m) => void navigate({ to: "/organizations/$orgId/certificates/$id", params: { orgId: org.id, id: m.id } })} />}
      />
      {board.error && <p className="text-sm text-destructive">{board.error.message}</p>}
      <Summary org={org} data={data} />
      {data && data.counts.managed === 0 ? (
        <GettingStarted org={org} />
      ) : (
        <>
          <div className="grid gap-4 lg:grid-cols-3">
            <NeedsAttention org={org} data={data} className={can(org, "approval", "read") ? "lg:col-span-2" : "lg:col-span-3"} />
            {can(org, "approval", "read") && <Approvals org={org} />}
          </div>
          <div className="grid gap-4 lg:grid-cols-3">
            <ExpiryOutlook data={data} className="lg:col-span-2" />
            <Issuers org={org} data={data} />
          </div>
        </>
      )}
      {(can(org, "agent", "read") || can(org, "audit", "read")) && (
        <div className="grid items-start gap-4 lg:grid-cols-2">
          {can(org, "agent", "read") && <Agents org={org} />}
          {can(org, "audit", "read") && <RecentActivity org={org} />}
        </div>
      )}
    </div>
  );
}

/** One count, a link to the inventory narrowed to it where there is one. */
function Tile({ label, value, note, link }: { label: string; value: number | undefined; note: ReactNode; link: (children: ReactNode) => ReactNode }) {
  const body = (
    <Card size="sm" className="h-full transition-colors hover:bg-muted/50">
      <CardHeader>
        <CardDescription>{label}</CardDescription>
        <span className="text-3xl font-semibold tabular-nums">{value ?? <Skeleton className="h-9 w-12" />}</span>
      </CardHeader>
      <CardContent className="text-xs text-muted-foreground">{note}</CardContent>
    </Card>
  );
  return link(body);
}

function Summary({ org, data }: { org: Org; data: Dashboard | undefined }) {
  const counts = data?.counts;
  const inventory = (search: { status?: string; tab?: "approval" }) => (children: ReactNode) => (
    <Link to="/organizations/$orgId/certificates" params={{ orgId: org.id }} search={search} className="rounded-xl focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none">
      {children}
    </Link>
  );
  return (
    <section aria-label="Summary" className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      <Tile label="Managed Certificates" value={counts?.managed} note="Archived ones are not counted." link={inventory({})} />
      <Tile label="Expiring within 30 days" value={counts?.expiringSoon} note="Or already ended." link={inventory({ status: "expiringSoon" })} />
      <Tile
        label="Needs attention"
        value={data?.attention.total}
        note={counts ? `${counts.renewalFailing} with Renewal failing · ${counts.agentOffline} with Agent offline` : " "}
        link={(children) => (
          <a href="#needs-attention" className="rounded-xl focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none">
            {children}
          </a>
        )}
      />
      <Tile
        label="Awaiting Approval"
        value={counts?.pendingApproval}
        note="Proposals, not Name Changes."
        link={inventory(can(org, "approval", "read") ? { tab: "approval" } : { status: "pendingApproval" })}
      />
    </section>
  );
}

/** Why a Managed Certificate needs someone now, in one sentence. */
function reasonOf(m: ManagedCertificate, now: Date): string {
  if (m.renewal.failing) return `Renewal failed ${m.renewal.failing.failures === 1 ? "once" : `${m.renewal.failing.failures} times`}: ${m.renewal.failing.lastFailure.message}`;
  if (m.agent?.status === "offline") return `The Agent ${m.agent.hostName}, which holds its key, is offline.`;
  if (!m.currentCertificate) return `Its first Issuance failed${m.issuance?.failure ? `: ${m.issuance.failure.message}` : "."}`;
  const ends = m.currentCertificate.notAfter;
  if (new Date(ends) <= now) return `Its Certificate ended on ${day(ends)}.`;
  return `Its Certificate ends on ${day(ends)}, and its Renewal is manual: it is due now.`;
}

function NeedsAttention({ org, data, className }: { org: Org; data: Dashboard | undefined; className?: string }) {
  const now = new Date();
  const attention = data?.attention;
  return (
    <Card className={className} id="needs-attention">
      <CardHeader>
        <CardTitle>Needs attention</CardTitle>
        <CardDescription>A Renewal failing, an Agent offline, a first Issuance that failed, a manual Renewal that is due, or a Certificate that has ended.</CardDescription>
      </CardHeader>
      <CardContent>
        {!attention ? (
          <Skeleton className="h-24" />
        ) : attention.items.length === 0 ? (
          <p className="flex items-center gap-2 text-muted-foreground">
            <CircleCheckIcon className="size-4 text-success" aria-hidden />
            Nothing needs attention.
          </p>
        ) : (
          <ul className="flex flex-col divide-y">
            {attention.items.map((m) => (
              <li key={m.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-3 first:pt-0 last:pb-0">
                <div className="flex min-w-0 flex-1 basis-64 flex-col gap-0.5">
                  <Link to="/organizations/$orgId/certificates/$id" params={{ orgId: org.id, id: m.id }} className="truncate font-medium underline-offset-4 hover:underline">
                    {primaryName(m)}
                    {m.names.length > 1 && <span className="text-muted-foreground"> +{m.names.length - 1}</span>}
                  </Link>
                  <span className="text-xs break-words text-muted-foreground">{reasonOf(m, now)}</span>
                </div>
                <Badge variant={status(m, now).variant}>{status(m, now).label}</Badge>
              </li>
            ))}
          </ul>
        )}
        {attention && attention.total > attention.items.length && (
          <p className="mt-3 text-xs text-muted-foreground">
            Showing {attention.items.length} of {attention.total}.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

const QUEUE_SHOWN = 5;

/** What waits for the caller's decision; the decisions themselves are made in the queue. */
function Approvals({ org }: { org: Org }) {
  const queue = useQuery({ queryKey: ["approvals", org.id], queryFn: () => api.approvalQueue(org.id) });
  const waiting = [
    ...(queue.data?.items ?? []).map((m) => ({ id: m.id, kind: "Proposal", names: m.names, by: m.approval.proposedBy?.email })),
    ...(queue.data?.nameChanges ?? []).map((c) => ({ id: c.managedCertificateId, kind: "Name Change", names: c.names, by: c.proposedBy.email })),
  ];
  return (
    <Card>
      <CardHeader>
        <CardTitle>Awaiting your Approval</CardTitle>
        <CardDescription>Nobody decides what they proposed.</CardDescription>
        {waiting.length > 0 && (
          <CardAction>
            <Badge variant="secondary">{waiting.length}</Badge>
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {queue.isPending ? (
          <Skeleton className="h-24" />
        ) : waiting.length === 0 ? (
          <p className="text-muted-foreground">Nothing is waiting.</p>
        ) : (
          <ul className="flex flex-col divide-y">
            {waiting.slice(0, QUEUE_SHOWN).map((w) => (
              <li key={`${w.kind}:${w.id}`} className="flex flex-col gap-0.5 py-3 first:pt-0 last:pb-0">
                <span className="text-xs font-medium text-muted-foreground">{w.kind}</span>
                <Link to="/organizations/$orgId/certificates/$id" params={{ orgId: org.id, id: w.id }} className="truncate font-mono text-xs underline-offset-4 hover:underline">
                  {w.names[0]}
                  {w.names.length > 1 && ` +${w.names.length - 1}`}
                </Link>
                {w.by && <span className="truncate text-xs text-muted-foreground">Proposed by {w.by}</span>}
              </li>
            ))}
          </ul>
        )}
        {waiting.length > 0 && (
          <Button variant="outline" size="sm" className="self-start" asChild>
            <Link to="/organizations/$orgId/certificates" params={{ orgId: org.id }} search={{ tab: "approval" }}>
              Review {waiting.length > QUEUE_SHOWN ? `all ${waiting.length}` : "them"}
            </Link>
          </Button>
        )}
        {queue.error && <p className="text-sm text-destructive">{queue.error.message}</p>}
      </CardContent>
    </Card>
  );
}

// The two series of the outlook: the one a person must act on is the darker, in each theme.
const MANUAL_FILL = "bg-foreground/80";
const AUTOMATIC_FILL = "bg-chart-2";

/** How many Certificates end in each week ahead, stacked by Renewal Policy, with the same numbers as a table for assistive technology. */
function ExpiryOutlook({ data, className }: { data: Dashboard | undefined; className?: string }) {
  const weeks = data?.expiry;
  const most = Math.max(1, ...(weeks ?? []).map((w) => w.automatic + w.manual));
  const total = (weeks ?? []).reduce((n, w) => n + w.automatic + w.manual, 0);
  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle>Ending in the next {weeks?.length ?? 13} weeks</CardTitle>
        <CardDescription>{weeks ? `${total} current Certificate${total === 1 ? "" : "s"}, by week and Renewal Policy.` : " "}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {!weeks ? (
          <Skeleton className="h-44" />
        ) : (
          <>
            <div aria-hidden className="flex h-40 items-end gap-1 border-b border-border sm:gap-2">
              {weeks.map((w) => (
                <Tooltip key={w.start}>
                  <TooltipTrigger asChild>
                    {/* The whole column is the hover target, not only its bar. */}
                    <div className="flex h-full flex-1 flex-col justify-end gap-0.5 rounded-t-sm hover:bg-muted/60">
                      {w.manual > 0 && <div className={`${MANUAL_FILL} rounded-t-[4px]`} style={{ height: `${(w.manual / most) * 100}%` }} />}
                      {w.automatic > 0 && <div className={`${AUTOMATIC_FILL} ${w.manual > 0 ? "" : "rounded-t-[4px]"}`} style={{ height: `${(w.automatic / most) * 100}%` }} />}
                    </div>
                  </TooltipTrigger>
                  <TooltipContent>
                    <p className="font-medium">Week of {day(w.start)}</p>
                    <p>
                      {w.manual} manual · {w.automatic} automatic
                    </p>
                  </TooltipContent>
                </Tooltip>
              ))}
            </div>
            <div aria-hidden className="flex justify-between text-xs text-muted-foreground">
              {weeks
                .filter((_, i) => i % 4 === 0)
                .map((w) => (
                  <span key={w.start}>{day(w.start)}</span>
                ))}
            </div>
            <div aria-hidden className="flex flex-wrap gap-4 text-xs text-muted-foreground">
              <span className="flex items-center gap-1.5">
                <span className={`size-2.5 rounded-sm ${MANUAL_FILL}`} />
                Manual Renewal
              </span>
              <span className="flex items-center gap-1.5">
                <span className={`size-2.5 rounded-sm ${AUTOMATIC_FILL}`} />
                Automatic Renewal
              </span>
            </div>
            <table className="sr-only">
              <caption>Certificates ending each week, by Renewal Policy</caption>
              <thead>
                <tr>
                  <th scope="col">Week of</th>
                  <th scope="col">Manual Renewal</th>
                  <th scope="col">Automatic Renewal</th>
                </tr>
              </thead>
              <tbody>
                {weeks.map((w) => (
                  <tr key={w.start}>
                    <th scope="row">{day(w.start)}</th>
                    <td>{w.manual}</td>
                    <td>{w.automatic}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function Issuers({ org, data }: { org: Org; data: Dashboard | undefined }) {
  const acmeCas = useAcmeCas(org.id).data?.items;
  const issuers = data?.issuers;
  const most = Math.max(1, ...(issuers ?? []).map((i) => i.count));
  return (
    <Card>
      <CardHeader>
        <CardTitle>By Certificate Authority</CardTitle>
      </CardHeader>
      <CardContent>
        {!issuers ? (
          <Skeleton className="h-24" />
        ) : (
          <ul className="flex flex-col gap-3">
            {issuers.map((i) => (
              <li key={`${i.kind}:${i.id}`} className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="flex min-w-0 items-center gap-2">
                    <span className="truncate">{i.kind === "acme" ? acmeCaName(acmeCas, i.id) : i.name}</span>
                    {i.kind === "acme" ? <AcmeCaTagBadge tag={acmeCas?.find((ca) => ca.id === i.id)?.tag ?? null} /> : <Badge variant="outline">{i.kind === "adcs" ? "ADCS" : "Private"}</Badge>}
                  </span>
                  <span className="tabular-nums">{i.count}</span>
                </div>
                <div aria-hidden className="h-2 rounded-full bg-muted">
                  <div className="h-2 rounded-full bg-chart-2" style={{ width: `${(i.count / most) * 100}%` }} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

const AGENTS_SHOWN = 5;

function Agents({ org }: { org: Org }) {
  const offline = useQuery({ queryKey: ["agents", org.id, "dashboard", "offline"], queryFn: () => api.agents(org.id, { status: ["offline"], os: [], outdated: false }, { page: 1, pageSize: AGENTS_SHOWN }) });
  const online = useQuery({ queryKey: ["agents", org.id, "dashboard", "online"], queryFn: () => api.agents(org.id, { status: ["online"], os: [], outdated: false }, { page: 1, pageSize: 1 }) });
  return (
    <Card>
      <CardHeader>
        <CardTitle>Agents</CardTitle>
        <CardDescription>{offline.data && online.data ? `${online.data.total} online · ${offline.data.total} offline` : " "}</CardDescription>
        <CardAction>
          <Button variant="ghost" size="sm" asChild>
            <Link to="/organizations/$orgId/agents" params={{ orgId: org.id }}>
              <BotIcon />
              All Agents
            </Link>
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent>
        {!offline.data ? (
          <Skeleton className="h-16" />
        ) : offline.data.items.length === 0 ? (
          <p className="text-muted-foreground">{online.data?.total ? "Every Agent is online." : "No Agents are registered."}</p>
        ) : (
          <ul className="flex flex-col divide-y">
            {offline.data.items.map((a) => (
              <li key={a.id} className="flex items-center justify-between gap-3 py-2 first:pt-0 last:pb-0">
                <span className="truncate">{a.hostName}</span>
                <span className="shrink-0 text-xs text-muted-foreground">Last seen {when(a.lastContactAt)}</span>
              </li>
            ))}
          </ul>
        )}
        {(offline.error ?? online.error) && <p className="text-sm text-destructive">{(offline.error ?? online.error)!.message}</p>}
      </CardContent>
    </Card>
  );
}

const EVENTS_SHOWN = 6;

function RecentActivity({ org }: { org: Org }) {
  const events = useQuery({ queryKey: ["audit", org.id, "dashboard"], queryFn: () => api.auditEvents(org.id, {}, undefined, EVENTS_SHOWN) });
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent activity</CardTitle>
        <CardAction>
          <Button variant="ghost" size="sm" asChild>
            <Link to="/organizations/$orgId/audit-log" params={{ orgId: org.id }}>
              <ScrollTextIcon />
              Audit log
            </Link>
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent>
        {!events.data ? (
          <Skeleton className="h-24" />
        ) : events.data.items.length === 0 ? (
          <p className="text-muted-foreground">Nothing has happened yet.</p>
        ) : (
          <ul className="flex flex-col divide-y">
            {events.data.items.map((e) => (
              <li key={e.id} className="flex flex-col gap-0.5 py-2 first:pt-0 last:pb-0">
                <span className="flex flex-wrap items-center gap-2">
                  <Badge variant="secondary">{e.action}</Badge>
                  <span className="text-xs text-muted-foreground">{targetTypeLabel(e.target.type)}</span>
                </span>
                <span className="truncate text-xs text-muted-foreground">
                  {e.actor.email ?? "The platform"} · {when(e.occurredAt)}
                </span>
              </li>
            ))}
          </ul>
        )}
        {events.error && <p className="text-sm text-destructive">{events.error.message}</p>}
      </CardContent>
    </Card>
  );
}

/** For an Organization with nothing managed yet: the pages that set it up, each for whoever may use it. */
function GettingStarted({ org }: { org: Org }) {
  const base = `/organizations/${org.id}`;
  const steps = [
    ...(can(org, "invitation", "create") ? [{ title: "Invite members", detail: "And put them in Teams, which can own Managed Certificates.", to: `${base}/members`, action: "Members" }] : []),
    ...(can(org, "acmeAccount", "read") ? [{ title: "Register with an ACME CA", detail: "Let's Encrypt is built in; register the Organization's ACME Account with it.", to: `${base}/acme-accounts`, action: "ACME accounts" }] : []),
    ...(can(org, "privateCa", "create") ? [{ title: "Or make a Private CA", detail: "For internal TLS, issued with no DCV.", to: `${base}/private-cas`, action: "Private CAs" }] : []),
    ...(can(org, "dnsProvider", "read") ? [{ title: "Connect a DNS Provider", detail: "So DCV can publish the records an ACME CA asks for.", to: `${base}/dns-providers`, action: "DNS Providers" }] : []),
    ...(can(org, "agent", "register") ? [{ title: "Register an Agent", detail: "For Deployments, ADCS, or DNS the platform cannot reach. Optional.", to: `${base}/agents`, action: "Agents" }] : []),
  ];
  return (
    <Card>
      <CardHeader>
        <CardTitle>{can(org, "managedCertificate", "read") ? "Nothing is managed yet" : "You do not own any Managed Certificates yet"}</CardTitle>
        <CardDescription>Request one with the button above; once there is one, this page shows what it needs.</CardDescription>
      </CardHeader>
      <CardContent>
        <ol className="flex flex-col divide-y">
          {steps.map((s, i) => (
            <li key={s.to} className="flex flex-wrap items-center gap-x-4 gap-y-2 py-3 first:pt-0">
              <span aria-hidden className="flex size-7 shrink-0 items-center justify-center rounded-full border text-xs font-medium">
                {i + 1}
              </span>
              <div className="flex min-w-0 flex-1 basis-60 flex-col gap-0.5">
                <span className="font-medium">{s.title}</span>
                <span className="text-xs text-muted-foreground">{s.detail}</span>
              </div>
              <Button variant="outline" size="sm" asChild>
                <Link to={s.to}>{s.action}</Link>
              </Button>
            </li>
          ))}
          <li className="flex flex-wrap items-center gap-x-4 gap-y-2 py-3 last:pb-0">
            <span aria-hidden className="flex size-7 shrink-0 items-center justify-center rounded-full border text-xs font-medium">
              {steps.length + 1}
            </span>
            <div className="flex min-w-0 flex-1 basis-60 flex-col gap-0.5">
              <span className="font-medium">Make a key and CSR</span>
              <span className="text-xs text-muted-foreground">In your browser, for a Managed Certificate whose key you keep.</span>
            </div>
            <Button variant="outline" size="sm" asChild>
              <Link to="/organizations/$orgId/tools/csr" params={{ orgId: org.id }}>
                <FileKey2Icon />
                CSR Generator
              </Link>
            </Button>
          </li>
        </ol>
      </CardContent>
    </Card>
  );
}
