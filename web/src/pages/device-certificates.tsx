import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { createColumnHelper, rowExpandingFeature, rowPaginationFeature, tableFeatures, useTable, type PaginationState } from "@tanstack/react-table";
import { ChevronLeftIcon, DownloadIcon, SearchIcon, XIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { DataTable } from "@/components/data-table/data-table";
import { DataTablePagination } from "@/components/data-table/data-table-pagination";
import { ExpandButton } from "@/components/data-table/expand-button";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { DEVICE_CERTIFICATE_STATUSES, api, can, revocationReasonLabel, type DeviceCertificate, type DeviceCertificateStatus } from "@/lib/api";

const ROUTE = "/app/organizations/$orgId/enrollment-profiles/$id/device-certificates";

/** How long typing pauses before the search is sent. */
const SEARCH_DELAY_MS = 300;

const STATUS_LABEL: Record<DeviceCertificateStatus, string> = { active: "Active", expired: "Expired", revoked: "Revoked" };
const STATUS_VARIANT: Record<DeviceCertificateStatus, "default" | "secondary" | "destructive"> = { active: "default", expired: "secondary", revoked: "destructive" };
const ANY_STATUS = "any";

// Paging, searching and ordering are the server's (Page<DeviceCertificate>): a profile can have thousands. A row opens to its details.
const features = tableFeatures({ rowPaginationFeature, rowExpandingFeature });
const columnHelper = createColumnHelper<typeof features, DeviceCertificate>();
const columns = columnHelper.columns([
  columnHelper.display({
    id: "expand",
    header: () => <span className="sr-only">Details</span>,
    cell: ({ row }) => <ExpandButton open={row.getIsExpanded()} what={row.original.subject} onToggle={() => row.toggleExpanded()} />,
  }),
  columnHelper.accessor("subject", { header: "Subject", cell: ({ cell }) => <span className="font-medium">{cell.getValue()}</span> }),
  columnHelper.accessor((c) => c.deviceId ?? "—", { id: "deviceId", header: "Device ID", cell: ({ cell }) => <span className="font-mono text-xs">{cell.getValue()}</span> }),
  columnHelper.accessor("serial", { header: "Serial", cell: ({ cell }) => <span className="block max-w-40 truncate font-mono text-xs" title={cell.getValue()}>{cell.getValue()}</span> }),
  columnHelper.accessor("status", { header: "Status", cell: ({ cell }) => <Badge variant={STATUS_VARIANT[cell.getValue()]}>{STATUS_LABEL[cell.getValue()]}</Badge> }),
  columnHelper.accessor((c) => new Date(c.notAfter).toLocaleDateString(), { id: "validUntil", header: "Valid until" }),
]);
const noRows: DeviceCertificate[] = [];

/** `value`, once it has stopped changing for `ms`. */
function useSettled<T>(value: T, ms: number): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setSettled(value), ms);
    return () => clearTimeout(timer);
  }, [value, ms]);
  return settled;
}

/**
 * The Device Certificates an Enrollment Profile issued, newest first, searched by subject, subject alternative name,
 * serial or device ID, and narrowed by status. Each opens to its details and can be downloaded.
 */
export function DeviceCertificatesPage() {
  const { orgId, id } = useParams({ from: ROUTE });
  const org = useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.organizations.find((o) => o.id === orgId) }).data;
  const allowed = org ? can(org, "deviceCertificate", "read") : false;
  const profile = useQuery({ queryKey: ["enrollment-profile", orgId, id], queryFn: () => api.enrollmentProfile(orgId, id), enabled: org ? can(org, "enrollmentProfile", "read") : false });
  const [typed, setTyped] = useState("");
  const q = useSettled(typed.trim(), SEARCH_DELAY_MS);
  const [status, setStatus] = useState<DeviceCertificateStatus | undefined>();
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 25 });
  // A new search starts again from the first page.
  useEffect(() => setPagination((p) => ({ ...p, pageIndex: 0 })), [q, status]);
  const certificates = useQuery({
    queryKey: ["device-certificates", orgId, id, q, status, pagination],
    queryFn: () => api.deviceCertificates(orgId, id, { q, status }, { page: pagination.pageIndex + 1, pageSize: pagination.pageSize }),
    placeholderData: keepPreviousData,
    enabled: allowed,
  });
  const table = useTable({
    features,
    columns,
    data: certificates.data?.items ?? noRows,
    rowCount: certificates.data?.total,
    manualPagination: true,
    state: { pagination },
    onPaginationChange: setPagination,
    getRowId: (c) => c.id,
    getRowCanExpand: () => true,
  });
  const narrowed = q !== "" || status !== undefined;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-2">
        <Button variant="ghost" size="sm" className="self-start" asChild>
          <Link to="/organizations/$orgId/enrollment-profiles" params={{ orgId }}>
            <ChevronLeftIcon />
            Enrollment Profiles
          </Link>
        </Button>
        <h1 className="text-xl font-semibold">{profile.data ? `${profile.data.name}: Device Certificates` : "Device Certificates"}</h1>
      </div>
      {org && !allowed ? (
        <p className="text-sm text-muted-foreground">Only Organization Administrators see Device Certificates.</p>
      ) : (
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center gap-2">
            <InputGroup className="w-full sm:w-96">
              <InputGroupAddon>
                <SearchIcon />
              </InputGroupAddon>
              <InputGroupInput aria-label="Search Device Certificates" placeholder="Subject, name, serial or device ID" value={typed} onChange={(e) => setTyped(e.target.value)} />
            </InputGroup>
            <Select value={status ?? ANY_STATUS} onValueChange={(v) => setStatus(v === ANY_STATUS ? undefined : (v as DeviceCertificateStatus))}>
              <SelectTrigger className="w-36" aria-label="Status">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ANY_STATUS}>Any status</SelectItem>
                {DEVICE_CERTIFICATE_STATUSES.map((value) => (
                  <SelectItem key={value} value={value}>
                    {STATUS_LABEL[value]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {narrowed && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setTyped("");
                  setStatus(undefined);
                }}
              >
                Reset
                <XIcon />
              </Button>
            )}
          </div>
          <DataTable
            table={table}
            empty={certificates.isPending ? "Loading…" : narrowed ? "No Device Certificates match." : "No device has enrolled under this profile yet."}
            details={(certificate) => <CertificateDetails orgId={orgId} certificate={certificate} />}
          />
          <DataTablePagination
            pageIndex={pagination.pageIndex}
            pageSize={pagination.pageSize}
            rowCount={certificates.data?.total ?? 0}
            onPageIndexChange={(pageIndex) => setPagination({ ...pagination, pageIndex })}
            onPageSizeChange={(pageSize) => setPagination({ pageIndex: 0, pageSize })}
          />
          {certificates.error && <p className="text-sm text-destructive">{certificates.error.message}</p>}
        </div>
      )}
    </div>
  );
}

function CertificateDetails({ orgId, certificate }: { orgId: string; certificate: DeviceCertificate }) {
  const facts: [string, React.ReactNode][] = [
    ["Subject", certificate.subject],
    ["Subject alternative names", certificate.subjectAltNames.length === 0 ? "None" : certificate.subjectAltNames.map((n) => `${n.type.toUpperCase()}: ${n.value}`).join(", ")],
    ["Device ID", certificate.deviceId ?? "None"],
    ["Serial", <span className="break-all font-mono text-xs">{certificate.serial}</span>],
    ["Issuer", certificate.issuer],
    ["Valid", `${new Date(certificate.notBefore).toLocaleString()} – ${new Date(certificate.notAfter).toLocaleString()}`],
    ["Enrolled", new Date(certificate.createdAt).toLocaleString()],
    ...(certificate.revocation ? ([["Revoked", `${new Date(certificate.revocation.revokedAt).toLocaleString()}: ${revocationReasonLabel(certificate.revocation.reason)}`]] as [string, string][]) : []),
  ];
  return (
    <div className="flex flex-col gap-4">
      <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[max-content_1fr]">
        {facts.map(([label, value]) => (
          <div key={label} className="contents">
            <dt className="text-muted-foreground">{label}</dt>
            <dd className="break-words">{value}</dd>
          </div>
        ))}
      </dl>
      <Button variant="outline" size="sm" className="self-start" asChild>
        <a href={api.deviceCertificateUrl(orgId, certificate.enrollmentProfileId, certificate.id)} download>
          <DownloadIcon />
          Download certificate
        </a>
      </Button>
    </div>
  );
}
