import { useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { CircleAlertIcon } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { api, type HistoryEntry, type Issuance } from "@/lib/api";
import { ISSUANCE_KIND_WORDS } from "@/lib/managed-certificate";
import { managedCertificateKey, useManagedCertificatePage } from "@/lib/use-managed-certificate";

const HISTORY_WORDS = {
  created: "Created",
  proposed: "Proposed",
  approved: "Approved",
  rejected: "Rejected",
  names_change_proposed: "Name change proposed",
  names_change_approved: "Name change approved",
  names_change_rejected: "Name change rejected",
  names_change_withdrawn: "Name change withdrawn",
  names_change_discarded: "Name change discarded",
  names_changed: "Names changed",
  archived: "Archived",
  certificate_revoked: "Certificate revoked",
} as const;
const historyLine = (e: HistoryEntry) =>
  e.kind === "certificate_issued"
    ? `Certificate issued, valid until ${new Date(e.certificate.notAfter).toLocaleDateString()} (${e.certificate.fingerprint.slice(0, 16)}…)${e.certificate.revocation ? ", since revoked" : ""}`
    : `${HISTORY_WORDS[e.kind]}${e.actor ? ` by ${e.actor.email}` : ""}${e.names ? ` (${e.names.from.join(", ")} to ${e.names.to.join(", ")})` : ""}${e.reason ? `: ${e.reason}` : ""}`;

const attemptLine = (a: Issuance) =>
  `${ISSUANCE_KIND_WORDS[a.kind]} ${a.status === "running" && a.awaitingKey ? "waiting for the Agent's new key" : a.status}` +
  `${a.requestedBy ? `, asked for by ${a.requestedBy.email}` : ", by the Renewal scheduler"}` +
  `${a.failure ? `: ${a.failure.message} (${a.failure.code})` : ""}`;

/** One line of Activity: a history entry or an Issuance attempt, at the moment it happened (an attempt's, when it ended). */
type Line = { at: string; text: string; failed: boolean; key: string };

/**
 * How a Managed Certificate got to where it is, the newest first: its history and every Issuance attempt, so that a
 * failure a later attempt cleared can still be explained.
 */
export function ActivityTab() {
  const { orgId, id } = useParams({ from: "/app/organizations/$orgId/certificates/$id/activity" });
  const { certificate } = useManagedCertificatePage(orgId, id);
  const latest = certificate.data?.issuance;
  // Under the page's key, so its refresh covers them; and asked again whenever its latest attempt moves on, which the page polls for.
  const key = [...managedCertificateKey(orgId, id), "activity", latest?.id, latest?.status];
  const history = useQuery({ queryKey: [...key, "history"], queryFn: () => api.history(orgId, id) });
  const attempts = useQuery({ queryKey: [...key, "issuances"], queryFn: () => api.issuances(orgId, id) });

  const error = history.error ?? attempts.error;
  if (error) return <p className="text-sm text-destructive">{error.message}</p>;
  if (!history.data || !attempts.data) return <ActivitySkeleton />;

  const lines: Line[] = [
    ...history.data.items.map((e, i) => ({ at: e.at, text: historyLine(e), failed: false, key: `history-${i}` })),
    ...attempts.data.items.map((a) => ({ at: a.finishedAt ?? a.startedAt, text: attemptLine(a), failed: a.status === "failed", key: a.id })),
  ].sort((a, b) => Date.parse(b.at) - Date.parse(a.at));

  return (
    <div className="flex flex-col gap-4 text-sm">
      {attempts.data.items.length === 0 && <p className="rounded-lg border border-dashed p-6 text-center text-muted-foreground">No Issuance has been attempted for it yet.</p>}
      <ol className="flex flex-col gap-2">
        {lines.map((line) => (
          <li key={line.key} className={line.failed ? "flex gap-2 text-destructive" : "flex gap-2"}>
            {line.failed && <CircleAlertIcon className="mt-0.5 size-4 shrink-0" aria-label="Failed" />}
            <span>
              <time dateTime={line.at} className={line.failed ? undefined : "text-muted-foreground"}>
                {new Date(line.at).toLocaleString()}
              </time>{" "}
              {line.text}
            </span>
          </li>
        ))}
      </ol>
    </div>
  );
}

function ActivitySkeleton() {
  return (
    <div className="flex flex-col gap-2" role="status" aria-label="Loading">
      {[0, 1, 2, 3].map((i) => (
        <Skeleton key={i} className="h-5 w-full max-w-xl" />
      ))}
    </div>
  );
}
