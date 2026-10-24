import { useParams } from "@tanstack/react-router";
import { DownloadIcon } from "lucide-react";
import { useState, type ReactNode } from "react";
import { CopyButton } from "@/components/copy-button";
import { DownloadDialog } from "@/components/download-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, can, type Certificate, type ManagedCertificate, type Me } from "@/lib/api";
import { acmeCaName, useAcmeCas } from "@/lib/acme-cas";
import { caLabel } from "@/lib/managed-certificate";
import { useCertificateFacts, useCertificates, useManagedCertificatePage } from "@/lib/use-managed-certificate";
import { date } from "@/lib/utils";
import { RevokeDialog, revokedLine } from "./revocation-controls";

type CertificateState = { label: "Current" | "Superseded" | "Expired" | "Revoked"; variant: "default" | "secondary" | "destructive" | "outline" };

/** Where a Certificate stands: revoked or ended whatever else, otherwise the Managed Certificate's current one or superseded. */
function stateOf(c: Certificate, isCurrent: boolean): CertificateState {
  if (c.revocation) return { label: "Revoked", variant: "destructive" };
  if (Date.parse(c.notAfter) <= Date.now()) return { label: "Expired", variant: "outline" };
  return isCurrent ? { label: "Current", variant: "default" } : { label: "Superseded", variant: "secondary" };
}

/** Every Certificate the Managed Certificate has had, newest first; one opens in a side sheet with its full facts. */
export function IssuedCertificatesTab() {
  const { orgId, id } = useParams({ from: "/app/organizations/$orgId/certificates/$id/issued" });
  const { org, userId, certificate, refresh } = useManagedCertificatePage(orgId, id);
  const m = certificate.data;
  const currentId = m?.currentCertificate?.id;
  const certificates = useCertificates(orgId, id, currentId);
  const [selected, setSelected] = useState<string>();
  if (!org || !m) return null;

  if (certificates.isPending) {
    return (
      <div className="flex flex-col gap-2" role="status" aria-label="Loading">
        <Skeleton className="h-9 w-full" />
        <Skeleton className="h-12 w-full" />
        <Skeleton className="h-12 w-full" />
      </div>
    );
  }
  if (certificates.error) return <p className="text-sm text-destructive">{certificates.error.message}</p>;
  const items = certificates.data.items;
  if (items.length === 0) {
    return (
      <div className="flex flex-col gap-1 rounded-lg border border-dashed p-10 text-center">
        <p className="text-base font-medium">No Certificates yet</p>
        <p className="text-sm text-muted-foreground">Each Certificate issued for it, and each Renewal, will be listed here.</p>
      </div>
    );
  }

  const mayDownload = can(org, "managedCertificate", "download");
  return (
    <>
      <div className="rounded-lg border bg-card">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>State</TableHead>
              <TableHead>Issued</TableHead>
              <TableHead>Valid from</TableHead>
              <TableHead>Valid until</TableHead>
              <TableHead>Fingerprint</TableHead>
              <TableHead>Serial</TableHead>
              <TableHead className="text-right">
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((c) => {
              const state = stateOf(c, c.id === currentId);
              return (
                <TableRow key={c.id} className="cursor-pointer" data-state={selected === c.id ? "selected" : undefined} onClick={() => setSelected(c.id)}>
                  <TableCell>
                    <Badge variant={state.variant}>{state.label}</Badge>
                  </TableCell>
                  <TableCell>{date(c.issuedAt)}</TableCell>
                  <TableCell>{date(c.notBefore)}</TableCell>
                  <TableCell>{date(c.notAfter)}</TableCell>
                  <TableCell>
                    <span className="flex items-center gap-1">
                      <button type="button" className="font-mono text-xs hover:underline" title={c.fingerprint} onClick={() => setSelected(c.id)}>
                        {c.fingerprint.slice(0, 16)}…
                      </button>
                      <CopyButton text={c.fingerprint} label={`Copy the fingerprint of the Certificate issued ${date(c.issuedAt)}`} />
                    </span>
                  </TableCell>
                  <TableCell className="max-w-48 truncate font-mono text-xs" title={c.serial}>
                    {c.serial}
                  </TableCell>
                  <TableCell>
                    {/* Actions open their own dialogs, not the side sheet. */}
                    <div className="flex justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                      {mayDownload && c.hasCsr && (
                        <Button asChild variant="outline" size="sm">
                          <a href={api.certificateCsrUrl(org.id, m.id, c.id)} download>
                            <DownloadIcon />
                            CSR
                          </a>
                        </Button>
                      )}
                      {mayDownload && <DownloadDialog orgId={org.id} id={m.id} certificateId={c.id} trigger={downloadButton} />}
                      <RevokeDialog org={org} m={m} certificate={c} userId={userId} onChanged={refresh} />
                    </div>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
      <CertificateSheet org={org} m={m} certificateId={selected} isCurrent={selected === currentId} onClose={() => setSelected(undefined)} />
    </>
  );
}

// An element, not a component: the dialog's trigger hands it the props that open the dialog.
const downloadButton = (
  <Button variant="outline" size="sm">
    <DownloadIcon />
    Download
  </Button>
);

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}

/** One Certificate's full facts: what it is, who issued it and how, its chain, and its revocation if any. */
function CertificateSheet({ org, m, certificateId, isCurrent, onClose }: { org: Me["organizations"][number]; m: ManagedCertificate; certificateId?: string; isCurrent: boolean; onClose: () => void }) {
  const facts = useCertificateFacts(org.id, m.id, certificateId);
  const acmeCas = useAcmeCas(org.id).data?.items;
  const c = facts.data;
  return (
    <Sheet open={Boolean(certificateId)} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <SheetTitle>{c ? stateOf(c, isCurrent).label : "Certificate"}</SheetTitle>
          <SheetDescription>{c ? `Issued ${new Date(c.issuedAt).toLocaleString()}` : "Loading…"}</SheetDescription>
        </SheetHeader>
        <div className="px-4 pb-4 text-sm">
          {facts.error && <p className="text-destructive">{facts.error.message}</p>}
          {facts.isPending && certificateId && (
            <div className="flex flex-col gap-3" role="status" aria-label="Loading">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          )}
          {c && (
            <dl className="flex flex-col gap-4">
              {c.revocation && (
                <Fact label="Revocation">
                  <span className="text-destructive">{revokedLine(c.revocation)}</span>
                </Fact>
              )}
              <Fact label="Subject names">
                <ul className="flex flex-col gap-0.5 font-mono text-xs">
                  {c.names.map((name) => (
                    <li key={name}>{name}</li>
                  ))}
                </ul>
              </Fact>
              {c.subject && <Fact label="Subject">{c.subject}</Fact>}
              <Fact label="Issuer">{c.issuer}</Fact>
              <Fact label="Valid">
                {new Date(c.notBefore).toLocaleString()} to {new Date(c.notAfter).toLocaleString()}
              </Fact>
              <Fact label="Serial">
                <span className="font-mono text-xs break-all">{c.serial}</span>
              </Fact>
              <Fact label="Fingerprint (SHA-256)">
                <span className="flex items-start gap-1">
                  <span className="font-mono text-xs break-all">{c.fingerprint}</span>
                  <CopyButton text={c.fingerprint} label="Copy the fingerprint" />
                </span>
              </Fact>
              <Fact label="Key algorithm">{c.keyAlgorithm}</Fact>
              <Fact label="Signature algorithm">{c.signatureAlgorithm}</Fact>
              <Fact label="CA">{caLabel(c.ca)}</Fact>
              {c.acmeAccount && (
                <Fact label="ACME Account">
                  {acmeCaName(acmeCas, c.acmeAccount.acmeCaId)} <span className="font-mono text-xs text-muted-foreground">{c.acmeAccount.id}</span>
                </Fact>
              )}
              <Fact label="Chain">
                <ol className="flex flex-col gap-2">
                  {c.chain.map((cert, i) => (
                    <li key={cert.fingerprint} className="rounded-md border p-2">
                      <p className="font-medium">{i === 0 ? "Leaf" : cert.subject}</p>
                      <p className="text-muted-foreground">Issued by {cert.issuer}</p>
                      <p className="text-muted-foreground">Valid until {new Date(cert.notAfter).toLocaleDateString()}</p>
                      <p className="font-mono text-xs break-all text-muted-foreground">{cert.fingerprint}</p>
                    </li>
                  ))}
                </ol>
              </Fact>
            </dl>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
