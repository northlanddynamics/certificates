import { Link, Outlet, useParams } from "@tanstack/react-router";
import { ArrowLeftIcon, ArchiveIcon } from "lucide-react";
import type { ReactNode } from "react";
import { DownloadDialog } from "@/components/download-dialog";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError, can, type ManagedCertificate } from "@/lib/api";
import { useAcmeCas } from "@/lib/acme-cas";
import { expiryPhrase, issuerLabel, keyAlgorithmLabel, primaryName, profileLabel, status } from "@/lib/managed-certificate";
import { useManagedCertificatePage } from "@/lib/use-managed-certificate";
import { AlertStrip } from "./certificate-alerts";
import { Lifecycle } from "./certificate-lifecycle";
import { ManageMenu } from "./manage-menu";
import { RenewNowButton } from "./renewal-controls";

const ROUTE = "/app/organizations/$orgId/certificates/$id";

const TABS = [
  { to: "/organizations/$orgId/certificates/$id", label: "Overview", exact: true },
  { to: "/organizations/$orgId/certificates/$id/issued", label: "Certificates", exact: false },
  { to: "/organizations/$orgId/certificates/$id/activity", label: "Activity", exact: false },
  { to: "/organizations/$orgId/certificates/$id/notifications", label: "Notifications", exact: false },
] as const;

/** One Managed Certificate's page: its header, what needs attention and where it is in its life always in view, and under them the tab that is open. */
export function ManagedCertificateDetailsPage() {
  const { orgId, id } = useParams({ from: ROUTE });
  const { org, userId, me, certificate, refresh } = useManagedCertificatePage(orgId, id);
  const acmeCas = useAcmeCas(orgId).data?.items;
  const m = certificate.data;

  if (me.isPending || (certificate.isPending && org)) return <DetailsSkeleton />;
  // The same answer whether it is missing, is not the caller's to see, or is in an Organization the caller is not in.
  if (!org || (certificate.error instanceof ApiError && (certificate.error.status === 404 || certificate.error.status === 403))) {
    return <NotFound />;
  }
  if (!m) return <p className="text-destructive">{certificate.error?.message ?? "Something went wrong."}</p>;

  const state = status(m);
  const expiry = expiryPhrase(m.currentCertificate);
  return (
    <div className="flex flex-col gap-4">
      <BackLink />
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex min-w-0 flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-2xl font-semibold break-all">{primaryName(m)}</h1>
            <OtherNames m={m} />
          </div>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
            <Badge variant={state.variant}>{expiry && !m.archivedAt && m.approval.status !== "pending" ? `${state.label} · ${expiry}` : state.label}</Badge>
            <span className="text-muted-foreground">
              {[issuerLabel(m.issuer, acmeCas), keyAlgorithmLabel(m.keyAlgorithm), m.keyCustody === "owner" ? "Key held by its Owners" : "Key held by an Agent", m.profile && `Profile ${profileLabel(m.profile)}`]
                .filter(Boolean)
                .join(" · ")}
            </span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <RenewNowButton org={org} m={m} userId={userId} onChanged={refresh} />
          {m.currentCertificate && can(org, "managedCertificate", "download") && <DownloadDialog orgId={org.id} id={m.id} />}
          <ManageMenu org={org} m={m} userId={userId} onChanged={refresh} />
        </div>
      </header>
      {m.archivedAt && (
        <Alert>
          <ArchiveIcon />
          <AlertTitle>Archived {new Date(m.archivedAt).toLocaleString()}</AlertTitle>
          <AlertDescription>It no longer issues, renews or deploys, and its Certificates stay valid until they end or are revoked. This page is read-only.</AlertDescription>
        </Alert>
      )}
      <AlertStrip org={org} m={m} userId={userId} onChanged={refresh} />
      <Lifecycle m={m} />
      <nav aria-label="Managed Certificate" className="flex gap-1 overflow-x-auto border-b">
        {TABS.map((tab) => (
          <Link
            key={tab.to}
            to={tab.to}
            params={{ orgId, id }}
            activeOptions={{ exact: tab.exact }}
            className="-mb-px border-b-2 border-transparent px-3 py-2 text-sm font-medium whitespace-nowrap text-muted-foreground hover:text-foreground data-[status=active]:border-foreground data-[status=active]:text-foreground"
            activeProps={{ "aria-current": "page" }}
          >
            {tab.label}
          </Link>
        ))}
      </nav>
      <Outlet />
    </div>
  );
}

/** The names other than the one in the title, behind a "+N names" chip; nothing for one with a single name. */
function OtherNames({ m }: { m: ManagedCertificate }) {
  const others = m.names.filter((name) => name !== primaryName(m));
  if (others.length === 0) return null;
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="h-6 rounded-full px-2.5 text-xs">
          +{others.length} name{others.length === 1 ? "" : "s"}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-auto max-w-sm">
        <p className="mb-2 text-sm font-medium">All {m.names.length} names</p>
        <ul className="flex flex-col gap-0.5 font-mono text-xs break-all">
          {m.names.map((name) => (
            <li key={name}>{name}</li>
          ))}
        </ul>
      </PopoverContent>
    </Popover>
  );
}

function BackLink(): ReactNode {
  const { orgId } = useParams({ from: ROUTE });
  return (
    <Link to="/organizations/$orgId/certificates" params={{ orgId }} className="flex w-fit items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
      <ArrowLeftIcon className="size-4" />
      Managed Certificates
    </Link>
  );
}

function NotFound() {
  return (
    <div className="flex flex-col gap-4">
      <BackLink />
      <div className="flex flex-col gap-1 rounded-lg border border-dashed p-10 text-center">
        <h1 className="text-base font-medium">Managed Certificate not found</h1>
        <p className="text-sm text-muted-foreground">It does not exist, or you may not see it.</p>
      </div>
    </div>
  );
}

/** The page's shape while it loads: header, lifecycle, tabs and two columns. */
function DetailsSkeleton() {
  return (
    <div className="flex flex-col gap-4" role="status" aria-label="Loading">
      <Skeleton className="h-4 w-36" />
      <div className="flex justify-between gap-4">
        <div className="flex flex-col gap-2">
          <Skeleton className="h-7 w-72" />
          <div className="flex gap-2">
            <Skeleton className="h-5 w-16" />
            <Skeleton className="h-5 w-20" />
            <Skeleton className="h-5 w-24" />
          </div>
        </div>
        <div className="flex gap-2">
          <Skeleton className="h-9 w-28" />
          <Skeleton className="h-9 w-28" />
        </div>
      </div>
      <Skeleton className="h-44 w-full" />
      <Skeleton className="h-9 w-full" />
      <div className="grid gap-4 lg:grid-cols-3">
        <Skeleton className="h-64 lg:col-span-2" />
        <Skeleton className="h-64" />
      </div>
    </div>
  );
}
