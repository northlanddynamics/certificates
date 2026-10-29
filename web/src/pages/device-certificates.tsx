import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { createColumnHelper, rowExpandingFeature, rowPaginationFeature, tableFeatures, useTable, type PaginationState } from "@tanstack/react-table";
import { BanIcon, DownloadIcon, SearchIcon, XIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { usePageCrumbs } from "@/components/page-crumbs";
import { DataTable } from "@/components/data-table/data-table";
import { DataTablePagination } from "@/components/data-table/data-table-pagination";
import { ExpandButton } from "@/components/data-table/expand-button";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { Field, FieldLabel } from "@/components/ui/field";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/page-header";
import { DEVICE_KEY_TYPE_LABELS, WEAK_DEVICE_KEY_TYPE } from "../../../server/src/enrollment/enrollment-profile-kinds";
import { awaitsCa, requestedLine } from "./revocation-controls";
import { DEVICE_CERTIFICATE_STATUSES, api, can, revocationReasonLabel, revocationReasonsOf, type DeviceCertificate, type DeviceCertificateStatus, type EnrollmentProfile, type Me } from "@/lib/api";
import { useOrg } from "@/lib/use-org";

const ROUTE = "/app/organizations/$orgId/enrollment-profiles/$id/device-certificates";

/** How long typing pauses before the search is sent. */
const SEARCH_DELAY_MS = 300;

const STATUS_LABEL: Record<DeviceCertificateStatus, string> = { active: "Active", expired: "Expired", revoked: "Revoked" };
const STATUS_VARIANT: Record<DeviceCertificateStatus, "success" | "neutral" | "destructive"> = { active: "success", expired: "neutral", revoked: "destructive" };
const ANY_STATUS = "any";
const isWeak = (c: DeviceCertificate) => c.keyType === WEAK_DEVICE_KEY_TYPE;
/** Marks a Device Certificate whose key can be broken, to be found and replaced. */
const WeakKeyBadge = () => (
  <Badge variant="destructive" title="A 1024-bit RSA key, which can be broken">
    Weak key
  </Badge>
);

// Paging, searching and ordering are the server's (Page<DeviceCertificate>): a profile can have thousands. A row opens to its details.
const features = tableFeatures({ rowPaginationFeature, rowExpandingFeature });
const columnHelper = createColumnHelper<typeof features, DeviceCertificate>();
const columns = columnHelper.columns([
  columnHelper.display({
    id: "expand",
    header: () => <span className="sr-only">Details</span>,
    cell: ({ row }) => <ExpandButton open={row.getIsExpanded()} what={row.original.subject} onToggle={() => row.toggleExpanded()} />,
  }),
  columnHelper.accessor("subject", {
    header: "Subject",
    cell: ({ row, cell }) => (
      <span className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{cell.getValue()}</span>
        {isWeak(row.original) && <WeakKeyBadge />}
      </span>
    ),
  }),
  columnHelper.accessor((c) => c.deviceId ?? "—", { id: "deviceId", header: "Device ID", cell: ({ cell }) => <span className="font-mono text-xs">{cell.getValue()}</span> }),
  columnHelper.accessor("serial", { header: "Serial", cell: ({ cell }) => <span className="block max-w-40 truncate font-mono text-xs" title={cell.getValue()}>{cell.getValue()}</span> }),
  columnHelper.accessor("status", { header: "Status", cell: ({ cell }) => <Badge variant={STATUS_VARIANT[cell.getValue()]}>{STATUS_LABEL[cell.getValue()]}</Badge> }),
  columnHelper.accessor((c) => new Date(c.notAfter).toLocaleDateString(), { id: "validUntil", header: "Valid until" }),
]);
const noRows: DeviceCertificate[] = [];

/**
 * The Device Certificates an Enrollment Profile issued, newest first, searched by subject, subject alternative name,
 * serial or device ID, and narrowed by status. Each opens to its details and can be downloaded, and revoked by those who may.
 */
export function DeviceCertificatesPage() {
  const { orgId, id } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const allowed = org ? can(org, "deviceCertificate", "read") : false;
  const profile = useQuery({ queryKey: ["enrollment-profile", orgId, id], queryFn: () => api.enrollmentProfile(orgId, id), enabled: org ? can(org, "enrollmentProfile", "read") : false });
  const [typed, setTyped] = useState("");
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<DeviceCertificateStatus | undefined>();
  const [weakKey, setWeakKey] = useState(false);
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 25 });
  // A new search starts again from the first page, sent once typing pauses.
  useEffect(() => {
    const settled = typed.trim();
    if (settled === q) return;
    const timer = setTimeout(() => {
      setQ(settled);
      setPagination((p) => ({ ...p, pageIndex: 0 }));
    }, SEARCH_DELAY_MS);
    return () => clearTimeout(timer);
  }, [typed, q]);
  // A narrower list starts again from the first page.
  const narrowing =
    <T,>(set: (next: T) => void) =>
    (next: T) => {
      set(next);
      setPagination({ ...pagination, pageIndex: 0 });
    };
  const narrowStatus = narrowing(setStatus);
  const narrowWeakKey = narrowing(setWeakKey);
  const certificates = useQuery({
    queryKey: ["device-certificates", orgId, id, q, status, weakKey, pagination],
    queryFn: () => api.deviceCertificates(orgId, id, { q, status, weakKey }, { page: pagination.pageIndex + 1, pageSize: pagination.pageSize }),
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
  const narrowed = q !== "" || status !== undefined || weakKey;
  // After Enrollment Profiles in the breadcrumb.
  usePageCrumbs([...(profile.data ? [{ label: profile.data.name }] : []), { label: "Device Certificates" }]);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title={profile.data ? `${profile.data.name}: Device Certificates` : "Device Certificates"} />
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
            <Select value={status ?? ANY_STATUS} onValueChange={(v) => narrowStatus(v === ANY_STATUS ? undefined : (v as DeviceCertificateStatus))}>
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
            <Field orientation="horizontal" className="w-auto">
              <Checkbox id="device-certificates-weak-key" checked={weakKey} onCheckedChange={(on) => narrowWeakKey(on === true)} />
              <FieldLabel htmlFor="device-certificates-weak-key" className="font-normal">
                Weak keys only
              </FieldLabel>
            </Field>
            {narrowed && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setTyped("");
                  setQ("");
                  setWeakKey(false);
                  narrowStatus(undefined);
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
            details={(certificate) => <CertificateDetails org={org!} certificate={certificate} profile={profile.data} />}
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

/**
 * Which of its profile's Shared Challenges a Device Certificate was issued under: the current one, the previous one
 * (still valid or not), or one retired before that; none for a renewal. Nothing when its profile uses none.
 */
function sharedChallengeFact(certificate: DeviceCertificate, profile: EnrollmentProfile | undefined): [string, string][] {
  if (!profile?.sharedChallenge) return [];
  const id = certificate.sharedChallenge?.id;
  if (!id) return [["Shared Challenge", "None: renewed with its previous certificate"]];
  if (id === profile.sharedChallenge.id) return [["Shared Challenge", "Current"]];
  if (id === profile.previousSharedChallenge?.id) return [["Shared Challenge", `Previous, which works until ${new Date(profile.previousSharedChallenge.expiresAt).toLocaleString()}`]];
  return [["Shared Challenge", "An earlier one, no longer valid"]];
}

function CertificateDetails({ org, certificate, profile }: { org: Me["organizations"][number]; certificate: DeviceCertificate; profile: EnrollmentProfile | undefined }) {
  const facts: [string, React.ReactNode][] = [
    ["Subject", certificate.subject],
    ["Subject alternative names", certificate.subjectAltNames.length === 0 ? "None" : certificate.subjectAltNames.map((n) => `${n.type.toUpperCase()}: ${n.value}`).join(", ")],
    ["Device ID", certificate.deviceId ?? "None"],
    [
      "Key",
      <span className="flex flex-wrap items-center gap-2">
        {DEVICE_KEY_TYPE_LABELS[certificate.keyType]}
        {isWeak(certificate) && <WeakKeyBadge />}
      </span>,
    ],
    ...sharedChallengeFact(certificate, profile),
    ["Serial", <span className="break-all font-mono text-xs">{certificate.serial}</span>],
    ["Issuer", certificate.issuer],
    ["Valid", `${new Date(certificate.notBefore).toLocaleString()} – ${new Date(certificate.notAfter).toLocaleString()}`],
    ["Enrolled", new Date(certificate.createdAt).toLocaleString()],
    ...(certificate.revocation ? ([["Revoked", `${new Date(certificate.revocation.revokedAt).toLocaleString()}: ${revocationReasonLabel(certificate.revocation.reason)}`]] as [string, string][]) : []),
    ...(certificate.revocationRequest ? ([["Revocation", requestedLine(certificate.revocationRequest)]] as [string, string][]) : []),
    ...(certificate.crlDistributionPoints.length > 0
      ? ([
          [
            "CRL Distribution Points",
            <ul className="flex flex-col gap-0.5 font-mono text-xs break-all">
              {certificate.crlDistributionPoints.map((url) => (
                <li key={url}>{url}</li>
              ))}
            </ul>,
          ],
        ] as [string, React.ReactNode][])
      : []),
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
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" size="sm" asChild>
          <a href={api.deviceCertificateUrl(org.id, certificate.enrollmentProfileId, certificate.id)} download>
            <DownloadIcon />
            Download certificate
          </a>
        </Button>
        <RevokeDialog org={org} certificate={certificate} />
      </div>
    </div>
  );
}

/** Revokes a Device Certificate with an RFC 5280 reason, for those who may: on its Issuing CA's CRL once this succeeds, or once its ADCS CA confirms. */
function RevokeDialog({ org, certificate }: { org: Me["organizations"][number]; certificate: DeviceCertificate }) {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const revoke = useMutation({
    mutationFn: () => api.revokeDeviceCertificate(org.id, certificate.enrollmentProfileId, certificate.id, reason),
    onSuccess: async (revoked) => {
      setOpen(false);
      toast.success(`The Device Certificate for ${certificate.subject} was ${revoked.revocation ? "revoked" : "asked to be revoked; its CA confirms it later"}`);
      await queryClient.invalidateQueries({ queryKey: ["device-certificates", org.id, certificate.enrollmentProfileId] });
    },
  });
  const selectId = `revocation-reason-${certificate.id}`;

  if (certificate.revocation || awaitsCa(certificate) || !can(org, "deviceCertificate", "revoke")) return null;
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (next) {
          setReason("");
          revoke.reset();
        }
      }}
    >
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          <BanIcon />
          Revoke
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Revoke this Device Certificate?</DialogTitle>
          <DialogDescription>
            {certificate.subject}, serial <span className="break-all font-mono">{certificate.serial}</span>. {certificate.issuerKind === "adcs" ? "An Agent asks its ADCS CA to revoke it, which publishes its own CRL" : "It is on its Issuing CA's CRL at once"}; a revocation cannot be undone.
          </DialogDescription>
        </DialogHeader>
        <Field>
          <FieldLabel htmlFor={selectId}>Reason</FieldLabel>
          <Select value={reason} onValueChange={setReason}>
            <SelectTrigger id={selectId} className="w-full">
              <SelectValue placeholder="Choose a reason (RFC 5280)" />
            </SelectTrigger>
            <SelectContent>
              {revocationReasonsOf(certificate.issuerKind).map(([value, text]) => (
                <SelectItem key={value} value={value}>
                  {text}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
        {revoke.error && <p className="text-sm text-destructive">{revoke.error.message}</p>}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button variant="destructive" disabled={!reason || revoke.isPending} onClick={() => revoke.mutate()}>
            Revoke
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
