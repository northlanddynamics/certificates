import { useParams } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { Certificate, ManagedCertificate } from "@/lib/api";
import { keyAlgorithmLabel } from "@/lib/managed-certificate";
import { useManagedCertificatePage } from "@/lib/use-managed-certificate";
import { NameChange } from "./name-change-controls";
import { Owners } from "./owner-controls";
import { Renewal } from "./renewal-controls";
import { Revoke, revokedLine } from "./revocation-controls";

const KEY_CUSTODY_LABELS = { owner: "Owner" } as const;

const DAY = 24 * 60 * 60 * 1000;
const date = (iso: string) => new Date(iso).toLocaleDateString();

/** How much of a Certificate's life is left, in days: "N of M days left", or that it has ended. */
function daysLeft({ notBefore, notAfter }: Certificate, now = Date.now()) {
  const total = Math.round((Date.parse(notAfter) - Date.parse(notBefore)) / DAY);
  const left = Math.ceil((Date.parse(notAfter) - now) / DAY);
  return left <= 0 ? "Expired" : `${left} of ${total} days left`;
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid gap-1 sm:grid-cols-[9rem_1fr] sm:gap-4">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}

/** What a Managed Certificate is, who owns it and how it renews: all that the inventory's row used to open to. */
export function ManagedCertificateOverview() {
  const { orgId, id } = useParams({ from: "/app/organizations/$orgId/certificates/$id/" });
  const { org, userId, certificate, refresh } = useManagedCertificatePage(orgId, id);
  const m = certificate.data;
  if (!org || !m) return null;

  const current = m.currentCertificate;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Identity</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4 text-sm">
          <dl className="flex flex-col gap-3">
            <Fact label="Names">
              <ul className="flex flex-col gap-0.5 font-mono text-xs">
                {m.names.map((name) => (
                  <li key={name}>{name}</li>
                ))}
              </ul>
            </Fact>
            <Fact label="Environment">
              <span className="capitalize">{m.environment}</span>
            </Fact>
            <Fact label="Key algorithm">{keyAlgorithmLabel(m.keyAlgorithm)}</Fact>
            <Fact label="Key Custody">{KEY_CUSTODY_LABELS[m.keyCustody]}</Fact>
            <ProposalStatus m={m} />
          </dl>
          {!m.archivedAt && <NameChange org={org} m={m} userId={userId} onChanged={refresh} />}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Current Certificate</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4 text-sm">
          {current ? (
            <dl className="flex flex-col gap-3">
              <Fact label="Fingerprint">
                <span className="font-mono text-xs break-all">{current.fingerprint}</span>
              </Fact>
              <Fact label="Valid">
                {date(current.notBefore)} to {date(current.notAfter)} ({daysLeft(current)})
              </Fact>
              {current.revocation && (
                <Fact label="Revoked">
                  <span className="text-destructive">{revokedLine(current.revocation)}</span>
                </Fact>
              )}
            </dl>
          ) : (
            <p className="text-muted-foreground">No Certificate yet.</p>
          )}
          {/* Revoke stays here until the Issued certificates tab holds it; an archived page offers only Download. */}
          {!m.archivedAt && <Revoke org={org} m={m} userId={userId} onChanged={refresh} />}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Owners</CardTitle>
        </CardHeader>
        <CardContent>
          <Owners org={org} m={m} userId={userId} onChanged={refresh} />
        </CardContent>
      </Card>

      {!m.archivedAt && m.approval.status !== "pending" && m.approval.status !== "rejected" && (
        <Card>
          <CardHeader>
            <CardTitle>Renewal</CardTitle>
          </CardHeader>
          <CardContent className="text-sm">
            <Renewal org={org} m={m} userId={userId} onChanged={refresh} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}

/** Where a Proposal stands, for one that is waiting or was rejected; nothing for one that was never one. */
function ProposalStatus({ m }: { m: ManagedCertificate }) {
  if (m.approval.status === "pending") return <Fact label="Proposal">Proposed by {m.approval.proposedBy?.email}; waiting for Approval of these names.</Fact>;
  if (m.approval.status === "rejected") {
    return (
      <Fact label="Rejected">
        <span className="text-destructive">
          By {m.approval.decidedBy?.email}: {m.approval.reason}
        </span>
      </Fact>
    );
  }
  return null;
}
