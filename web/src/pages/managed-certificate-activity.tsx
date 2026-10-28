import { useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { ArchiveIcon, BanIcon, CheckIcon, CircleAlertIcon, ClockIcon, FileCheckIcon, LoaderIcon, PencilIcon, PlusIcon, XIcon } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { api, type HistoryEntry, type Issuance } from "@/lib/api";
import { ISSUANCE_KIND_WORDS } from "@/lib/managed-certificate";
import { managedCertificateKey, useManagedCertificatePage } from "@/lib/use-managed-certificate";
import { cn } from "@/lib/utils";

type Category = "issuance" | "approvals" | "revocations" | "other";
const FILTERS: { value: Category | "all"; label: string }[] = [
  { value: "all", label: "All" },
  { value: "issuance", label: "Issuance" },
  { value: "approvals", label: "Approvals and names" },
  { value: "revocations", label: "Revocations" },
];

type HistoryKind = Exclude<HistoryEntry["kind"], "certificate_issued">;
const HISTORY: Record<HistoryKind, { words: string; category: Category; icon: ReactNode }> = {
  created: { words: "Created", category: "other", icon: <PlusIcon /> },
  proposed: { words: "Proposed", category: "approvals", icon: <ClockIcon /> },
  approved: { words: "Approved", category: "approvals", icon: <CheckIcon /> },
  rejected: { words: "Rejected", category: "approvals", icon: <XIcon /> },
  names_change_proposed: { words: "Name change proposed", category: "approvals", icon: <PencilIcon /> },
  names_change_approved: { words: "Name change approved", category: "approvals", icon: <CheckIcon /> },
  names_change_rejected: { words: "Name change rejected", category: "approvals", icon: <XIcon /> },
  names_change_withdrawn: { words: "Name change withdrawn", category: "approvals", icon: <XIcon /> },
  names_change_discarded: { words: "Name change discarded", category: "approvals", icon: <XIcon /> },
  names_changed: { words: "Names changed", category: "approvals", icon: <PencilIcon /> },
  archived: { words: "Archived", category: "other", icon: <ArchiveIcon /> },
  certificate_revoked: { words: "Certificate revoked", category: "revocations", icon: <BanIcon /> },
};

const ATTEMPT_WORDS = { running: "running", succeeded: "succeeded", failed: "failed" } as const;

/** One event of Activity: a history entry or an Issuance attempt, at the moment it happened (an attempt's, when it ended). */
type Event = {
  key: string;
  at: string;
  category: Category;
  icon: ReactNode;
  title: string;
  /** Who did it, or what it was for, after the title. */
  by: string | null;
  failed: boolean;
  /** More of it, shown under the title. */
  body?: ReactNode;
  /** Its full record, for a failed attempt, shown on request. */
  details?: [string, ReactNode][];
};

const time = (iso: string) => new Date(iso).toLocaleTimeString(undefined, { timeStyle: "short" });
const when = (iso: string) => new Date(iso).toLocaleString();

function historyEvent(e: HistoryEntry, i: number): Event {
  if (e.kind === "certificate_issued") {
    return {
      key: `history-${i}`,
      at: e.at,
      category: "issuance",
      icon: <FileCheckIcon />,
      title: "Certificate issued",
      by: null,
      failed: false,
      body: (
        <span className="text-muted-foreground">
          Valid until {new Date(e.certificate.notAfter).toLocaleDateString()} · <span className="font-mono text-xs">{e.certificate.fingerprint.slice(0, 16)}…</span>
          {e.certificate.revocation && ", since revoked"}
        </span>
      ),
    };
  }
  const { words, category, icon } = HISTORY[e.kind];
  return {
    key: `history-${i}`,
    at: e.at,
    category,
    icon,
    title: words,
    by: e.actor ? `by ${e.actor.email}` : null,
    failed: false,
    body: (e.names || e.reason) && (
      <>
        {e.names && <NamesChange from={e.names.from} to={e.names.to} />}
        {e.reason && <span className="text-muted-foreground">{e.reason}</span>}
      </>
    ),
  };
}

function attemptEvent(a: Issuance): Event {
  const waiting = a.status === "running" && a.awaitingKey;
  const failed = a.status === "failed";
  // An ADCS CA's request, while it runs: waiting for one of the CA's Agents to be online, or with the one that submits it.
  const adcs = a.status === "running" ? a.adcs : null;
  const state = waiting
    ? "waiting for the Agent's new key"
    : adcs?.status === "waiting"
      ? "waiting for an Agent of the ADCS CA to be online"
      : adcs?.status === "submitted" && adcs.agent
        ? `submitted to ADCS through the Agent on ${adcs.agent.hostName}`
        : ATTEMPT_WORDS[a.status];
  return {
    key: a.id,
    at: a.finishedAt ?? a.startedAt,
    category: "issuance",
    icon: failed ? <CircleAlertIcon /> : a.status === "running" ? <LoaderIcon /> : <CheckIcon />,
    title: `${ISSUANCE_KIND_WORDS[a.kind]} ${state}`,
    by: a.requestedBy ? `asked for by ${a.requestedBy.email}` : "by the Renewal scheduler",
    failed,
    body: a.failure && (
      <span>
        {a.failure.message} <span className="font-mono text-xs">({a.failure.code})</span>
      </span>
    ),
    details: failed
      ? [
          ["Started", when(a.startedAt)],
          ["Ended", a.finishedAt ? when(a.finishedAt) : "—"],
          ["Asked for by", a.requestedBy?.email ?? "The Renewal scheduler"],
          ...(a.adcs?.requestId ? [["ADCS request", a.adcs.requestId] as [string, string]] : []),
        ]
      : undefined,
  };
}

/** The names a name change added and removed. */
function NamesChange({ from, to }: { from: string[]; to: string[] }) {
  const added = to.filter((name) => !from.includes(name));
  const removed = from.filter((name) => !to.includes(name));
  return (
    <span className="flex flex-wrap gap-x-3 font-mono text-xs">
      {added.map((name) => (
        <span key={`+${name}`} className="text-success">
          + {name}
        </span>
      ))}
      {removed.map((name) => (
        <span key={`-${name}`} className="text-destructive line-through">
          − {name}
        </span>
      ))}
    </span>
  );
}

/** A day as a heading: "Today", "Yesterday", or its date. */
function dayLabel(iso: string, now = new Date()) {
  const day = new Date(iso).toDateString();
  if (day === now.toDateString()) return "Today";
  if (day === new Date(now.getTime() - 24 * 60 * 60 * 1000).toDateString()) return "Yesterday";
  return new Date(iso).toLocaleDateString(undefined, { dateStyle: "medium" });
}

/**
 * How a Managed Certificate got to where it is, the newest first and by day: its history and every Issuance attempt, so
 * that a failure a later attempt cleared can still be explained. It can be narrowed to one kind of event, or to failures.
 */
export function ActivityTab() {
  const { orgId, id } = useParams({ from: "/app/organizations/$orgId/certificates/$id/activity" });
  const { certificate } = useManagedCertificatePage(orgId, id);
  const latest = certificate.data?.issuance;
  // Under the page's key, so its refresh covers them; and asked again whenever its latest attempt moves on, which the page polls for.
  const key = [...managedCertificateKey(orgId, id), "activity", latest?.id, latest?.status];
  const history = useQuery({ queryKey: [...key, "history"], queryFn: () => api.history(orgId, id) });
  const attempts = useQuery({ queryKey: [...key, "issuances"], queryFn: () => api.issuances(orgId, id) });
  const [filter, setFilter] = useState<Category | "all">("all");
  const [failuresOnly, setFailuresOnly] = useState(false);
  const [open, setOpen] = useState<Set<string>>(new Set());

  const error = history.error ?? attempts.error;
  if (error) return <p className="text-sm text-destructive">{error.message}</p>;
  if (!history.data || !attempts.data) return <ActivitySkeleton />;

  const events = [...history.data.items.map(historyEvent), ...attempts.data.items.map(attemptEvent)]
    .filter((e) => (filter === "all" || e.category === filter) && (!failuresOnly || e.failed))
    .sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
  const days: { label: string; events: Event[] }[] = [];
  for (const e of events) {
    const label = dayLabel(e.at);
    if (days.at(-1)?.label === label) days.at(-1)!.events.push(e);
    else days.push({ label, events: [e] });
  }
  const toggle = (key: string) =>
    setOpen((now) => {
      const next = new Set(now);
      if (!next.delete(key)) next.add(key);
      return next;
    });

  return (
    <div className="flex flex-col gap-4 text-sm">
      {attempts.data.items.length === 0 && <p className="rounded-lg border border-dashed p-6 text-center text-muted-foreground">No Issuance has been attempted for it yet.</p>}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div role="group" aria-label="Show" className="flex flex-wrap gap-2">
          {FILTERS.map((f) => (
            <Button key={f.value} size="sm" variant={filter === f.value ? "default" : "outline"} className="rounded-full" aria-pressed={filter === f.value} onClick={() => setFilter(f.value)}>
              {f.label}
            </Button>
          ))}
        </div>
        <Label className="gap-2 font-normal">
          <Checkbox checked={failuresOnly} onCheckedChange={(checked) => setFailuresOnly(checked === true)} />
          Failures only
        </Label>
      </div>
      {days.length === 0 ? (
        <p className="py-6 text-center text-muted-foreground">Nothing to show for this choice.</p>
      ) : (
        days.map((day) => (
          <section key={day.label} aria-label={day.label} className="flex flex-col gap-2">
            <h3 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">{day.label}</h3>
            <ol className="flex flex-col gap-2">
              {day.events.map((e) => (
                <li key={e.key} className={cn("grid grid-cols-[4.5rem_auto_minmax(0,1fr)_auto] items-start gap-3 rounded-lg border bg-card px-4 py-3", e.failed && "border-destructive/40")}>
                  <time dateTime={e.at} className="leading-7 text-muted-foreground">
                    {time(e.at)}
                  </time>
                  <span
                    aria-hidden
                    className={cn("flex size-7 items-center justify-center rounded-full bg-muted [&_svg]:size-4", e.failed && "bg-destructive/10 text-destructive")}
                  >
                    {e.icon}
                  </span>
                  <div className="flex min-w-0 flex-col gap-1 pt-1">
                    <p>
                      <span className={cn("font-medium", e.failed && "text-destructive")}>{e.title}</span>
                      {e.by && <span className="text-muted-foreground"> · {e.by}</span>}
                    </p>
                    {e.body}
                    {e.details && open.has(e.key) && (
                      <dl className="mt-1 grid grid-cols-[8rem_minmax(0,1fr)] gap-x-3 gap-y-1 rounded-md border bg-muted/40 p-3">
                        {e.details.map(([label, value]) => (
                          <div key={label} className="contents">
                            <dt className="text-muted-foreground">{label}</dt>
                            <dd className="min-w-0 break-words">{value}</dd>
                          </div>
                        ))}
                      </dl>
                    )}
                  </div>
                  {e.details ? (
                    <Button size="sm" variant="ghost" aria-expanded={open.has(e.key)} onClick={() => toggle(e.key)}>
                      {open.has(e.key) ? "Hide" : "Details"}
                    </Button>
                  ) : (
                    <span />
                  )}
                </li>
              ))}
            </ol>
          </section>
        ))
      )}
    </div>
  );
}

function ActivitySkeleton() {
  return (
    <div className="flex flex-col gap-2" role="status" aria-label="Loading">
      {[0, 1, 2, 3].map((i) => (
        <Skeleton key={i} className="h-12 w-full" />
      ))}
    </div>
  );
}
