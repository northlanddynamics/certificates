import { CheckIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { ManagedCertificate } from "@/lib/api";
import { ISSUANCE_KIND_WORDS, lifeOf } from "@/lib/managed-certificate";
import { expiryTone } from "@/lib/renewal-urgency";
import { cn, date } from "@/lib/utils";
import { nextRenewal } from "./renewal-controls";

/**
 * Where a Managed Certificate is in its life, always in view above its tabs: for one with a Certificate, a bar from that
 * Certificate's start to its end with today and the Renewal on it, and how long is left, when it renews and how its latest
 * Issuance went; for a Proposal, the steps to its first Certificate. Nothing for one approved but not yet issued.
 */
export function Lifecycle({ m }: { m: ManagedCertificate }) {
  if (m.approval.status === "pending" || m.approval.status === "rejected") return <ProposalPath m={m} />;
  const current = m.currentCertificate;
  if (!current) return null;

  const now = Date.now();
  const { total, left } = lifeOf(current, now);
  const next = nextRenewal(m);
  return (
    <Card className="gap-4">
      <CardHeader>
        <CardTitle>Lifecycle</CardTitle>
        <CardDescription>
          Current Certificate valid {date(current.notBefore)} – {date(current.notAfter)} ({total} days)
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4 text-sm">
        <ValidityBar m={m} now={now} />
        <div className="grid gap-3 sm:grid-cols-3">
          <Tile label="Remaining" value={current.revocation ? "Revoked" : left === null ? "Expired" : `${left} of ${total} days`} tone={expiryTone(m, new Date(now))}>
            Until {new Date(current.notAfter).toLocaleString()}
          </Tile>
          <Tile label="Next Renewal" value={next.headline} tone={next.problem ? "danger" : null}>
            {next.detail}
          </Tile>
          <LastIssuance m={m} />
        </div>
      </CardContent>
    </Card>
  );
}

function Tile({ label, value, tone = null, children }: { label: string; value: string; tone?: "warning" | "danger" | null; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5 rounded-md border px-3 py-2.5">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      <span className={cn("text-base font-semibold", tone === "warning" && "text-warning", tone === "danger" && "text-destructive")}>{value}</span>
      <span className="text-muted-foreground">{children}</span>
    </div>
  );
}

const ISSUANCE_STATUS_WORDS = { running: "running", succeeded: "succeeded", failed: "failed" } as const;

function LastIssuance({ m }: { m: ManagedCertificate }) {
  const latest = m.issuance;
  if (!latest) return <Tile label="Last Issuance" value="None recorded">No Issuance attempt is on record</Tile>;
  const by = latest.requestedBy ? `asked for by ${latest.requestedBy.email}` : "by the Renewal scheduler";
  return (
    <Tile label="Last Issuance" value={`${ISSUANCE_KIND_WORDS[latest.kind]} ${ISSUANCE_STATUS_WORDS[latest.status]}`} tone={latest.status === "failed" ? "danger" : null}>
      {date(latest.finishedAt ?? latest.startedAt)}, {by}
    </Tile>
  );
}

/**
 * The current Certificate's validity as a bar: the part already gone, today, when the Renewal is due and the CA's
 * suggested window. A Renewal that is overdue (failing or blocked) is hatched from when it was due until today.
 */
function ValidityBar({ m, now }: { m: ManagedCertificate; now: number }) {
  const current = m.currentCertificate!;
  const start = Date.parse(current.notBefore);
  const end = Date.parse(current.notAfter);
  const progress = (t: number) => Math.min(Math.max((t - start) / (end - start), 0), 1);
  const at = (t: number) => `${(progress(t) * 100).toFixed(2)}%`;
  const { dueAt, failing, blocked, ari } = m.renewal;
  const due = dueAt && !m.archivedAt ? Date.parse(dueAt) : null;
  // A failing Renewal was due before its first failure; a blocked one, since the scheduler found it due.
  const overdueSince = blocked ? Date.parse(blocked.since) : failing && due !== null ? Math.min(due, Date.parse(failing.lastFailure.at)) : null;
  const window = ari?.window && !m.archivedAt ? { from: Date.parse(ari.window.start), to: Date.parse(ari.window.end) } : null;

  const description = [
    `Issued ${date(current.notBefore)}`,
    `today ${date(new Date(now).toISOString())}`,
    due !== null && `Renewal due ${date(dueAt!)}`,
    `expires ${date(current.notAfter)}`,
  ]
    .filter(Boolean)
    .join(", ");
  return (
    <div className="flex flex-col gap-1.5">
      <div role="img" aria-label={description} className="relative h-8">
        {/* Kept inside the bar at its ends: centred on today, unless that would run past either. */}
        <span
          className={cn("absolute top-0 text-xs font-medium", progress(now) < 0.05 ? "" : progress(now) > 0.95 ? "-translate-x-full" : "-translate-x-1/2")}
          style={{ left: at(now) }}
        >
          Today
        </span>
        <div className="absolute inset-x-0 top-5 h-2.5 rounded-full bg-muted" />
        <div className="absolute top-5 left-0 h-2.5 rounded-l-full bg-muted-foreground/70" style={{ width: at(now) }} />
        {window && (
          <div
            className="absolute top-4 h-4.5 rounded-sm bg-[repeating-linear-gradient(45deg,var(--color-sky-500)_0_2px,transparent_2px_5px)] opacity-70"
            style={{ left: at(window.from), width: `calc(${at(window.to)} - ${at(window.from)})`, minWidth: "4px" }}
          />
        )}
        {overdueSince !== null && overdueSince < now && (
          <div
            className="absolute top-5 h-2.5 bg-[repeating-linear-gradient(45deg,var(--color-destructive)_0_3px,transparent_3px_6px)]"
            style={{ left: at(overdueSince), width: `calc(${at(now)} - ${at(overdueSince)})` }}
          />
        )}
        {due !== null && <div className={cn("absolute top-3.5 h-5.5 w-0.5", overdueSince !== null ? "bg-destructive" : "bg-sky-600 dark:bg-sky-400")} style={{ left: at(due) }} />}
        <div className="absolute top-3.5 h-5.5 w-0.5 bg-foreground" style={{ left: at(now) }} />
      </div>
      <div className="flex flex-wrap justify-between gap-x-4 text-xs text-muted-foreground">
        <span>Issued {date(current.notBefore)}</span>
        {due !== null && (
          <span className={cn("font-medium", overdueSince !== null ? "text-destructive" : "text-sky-700 dark:text-sky-400")}>
            {blocked ? `Renewal blocked since ${date(blocked.since)}` : failing ? "Renewal failing" : `Renews from ${date(dueAt!)}`}
          </span>
        )}
        <span>Expires {date(current.notAfter)}</span>
      </div>
    </div>
  );
}

/** A Proposal's way to its first Certificate: proposed, decided by an Approver, issued; and where it stopped, if rejected. */
function ProposalPath({ m }: { m: ManagedCertificate }) {
  const rejected = m.approval.status === "rejected";
  const steps: { title: string; detail: ReactNode; state: "done" | "now" | "failed" | "later" }[] = [
    { title: "Proposed", detail: m.approval.proposedBy ? `By ${m.approval.proposedBy.email}` : null, state: "done" },
    rejected
      ? { title: "Rejected", detail: `By ${m.approval.decidedBy?.email}: ${m.approval.reason}`, state: "failed" }
      : { title: "Approval", detail: "Waiting for an Approver", state: "now" },
    { title: "Issuance", detail: rejected ? "Not started" : "Starts once approved", state: "later" },
    { title: "Issued", detail: "Then renews by its Renewal Policy", state: "later" },
  ];
  return (
    <Card>
      <CardContent>
        <ol aria-label="Path to its first Certificate" className="grid gap-4 text-sm sm:grid-cols-4">
          {steps.map((step, i) => (
            <li key={step.title} className="flex flex-col gap-1" aria-current={step.state === "now" ? "step" : undefined}>
              <div className="flex items-center gap-2">
                <span
                  className={cn(
                    "flex size-6 shrink-0 items-center justify-center rounded-full text-xs font-semibold",
                    step.state === "done" && "bg-primary text-primary-foreground",
                    step.state === "now" && "border-2 border-primary",
                    step.state === "failed" && "bg-destructive text-white",
                    step.state === "later" && "bg-muted text-muted-foreground",
                  )}
                >
                  {step.state === "done" ? <CheckIcon className="size-3.5" aria-hidden /> : i + 1}
                </span>
                <span className={cn("font-medium", step.state === "later" && "text-muted-foreground", step.state === "failed" && "text-destructive")}>{step.title}</span>
                {i < steps.length - 1 && <span className={cn("hidden h-0.5 flex-1 sm:block", step.state === "done" ? "bg-primary" : "bg-border")} />}
              </div>
              {step.detail && <span className={cn("pl-8", step.state === "failed" ? "text-destructive" : "text-muted-foreground")}>{step.detail}</span>}
            </li>
          ))}
        </ol>
      </CardContent>
    </Card>
  );
}
