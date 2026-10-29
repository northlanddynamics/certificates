import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { PlusIcon, ShieldCheckIcon } from "lucide-react";
import { useState } from "react";
import { LoadError } from "@/components/load-error";
import { usePageCrumbs } from "@/components/page-crumbs";
import { PublicationSummary } from "@/components/pki-publication";
import { SummaryRows } from "@/components/summary-rows";
import { TrustRootDialog } from "@/components/trust-root-dialog";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api, can, type IssuingCa, type PrivateCa } from "@/lib/api";
import { KEY_ALGORITHM_LABELS } from "@/lib/csr-generator";
import { keyAlgorithmLabel } from "@/lib/managed-certificate";
import { commonNameOf, permittedNamesLabel, validityLabel } from "@/lib/private-ca";
import { healthOf, platformAttention } from "@/lib/private-ca-list";
import { useOrg } from "@/lib/use-org";
import { AddIssuingCaDialog, IssuingCaActions, RolloverDue, RootNameConstraints, StatusBadge, caDate } from "./private-ca-controls";
import { HealthBadge, KindBadge } from "./private-cas";

const ROUTE = "/app/organizations/$orgId/private-cas/platform/$caId";

/** One Private CA the platform runs: what needs doing, its root and the Issuing CAs under it, what it is offered for, and where it publishes. */
export function PlatformCaPage() {
  const { orgId, caId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const cas = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId), enabled: org ? can(org, "privateCa", "read") : false });
  const ca = cas.data?.items.find((c) => c.id === caId);
  usePageCrumbs(ca ? [{ label: ca.name }] : []);
  const [adding, setAdding] = useState(false);
  const [trusting, setTrusting] = useState(false);

  if (cas.error) return <LoadError title="Can't load this Private CA" description={cas.error.message} onRetry={() => cas.refetch()} retrying={cas.isFetching} />;
  if (!cas.data || !org) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (!ca) return <NotFound orgId={orgId} />;

  // Under an active root only: the platform's signs the new one at once, the Organization's own signs its CSR later.
  const mayAdd = can(org, "privateCa", "update") && ca.status === "active";
  const attention = platformAttention(ca, new Date());
  return (
    <div className="flex flex-col gap-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex min-w-0 flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-xl font-semibold">{ca.name}</h1>
            <KindBadge kind="platform" />
            <HealthBadge health={healthOf(attention, ca.status === "revoked")} />
          </div>
          <p className="text-sm text-muted-foreground">
            {ca.kind === "platform_root" ? "Root made by the platform" : "The Organization's own root"} · {keyAlgorithmLabel(ca.keyAlgorithm)} · keys in the KMS
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {ca.root && (
            <Button variant="outline" onClick={() => setTrusting(true)}>
              <ShieldCheckIcon />
              Trust this root
            </Button>
          )}
          {mayAdd && (
            <Button onClick={() => setAdding(true)}>
              <PlusIcon />
              Add Issuing CA
            </Button>
          )}
        </div>
      </header>

      {ca.status === "revoked" && (
        <Alert variant="destructive">
          <AlertTitle>Its root is revoked</AlertTitle>
          <AlertDescription>Its Issuing CAs issue nothing more, for good.</AlertDescription>
        </Alert>
      )}
      {can(org, "privateCa", "update") &&
        attention.map((a) => (
          <Alert key={`${a.title}-${a.detail}`} variant={a.tone === "bad" ? "destructive" : "default"} className={a.tone === "warn" ? "border-warning/50 bg-warning/5" : undefined}>
            <AlertTitle>{a.title}</AlertTitle>
            <AlertDescription>{a.detail}</AlertDescription>
          </Alert>
        ))}

      <Card>
        <CardHeader>
          <CardTitle>Hierarchy</CardTitle>
          <CardDescription>Whatever trusts the root trusts every Issuing CA under it.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <div className="flex flex-wrap items-start justify-between gap-3 rounded-lg border bg-muted/30 p-4">
            <div className="min-w-0">
              <div className="text-xs text-muted-foreground">Root CA</div>
              <div className="break-all font-medium">{ca.root?.subject ?? "The Organization's own, not uploaded yet"}</div>
              {ca.root && <div className="text-sm text-muted-foreground">Until {caDate(ca.root.notAfter)}</div>}
            </div>
            <Badge variant={ca.status === "active" ? "success" : "destructive"}>{ca.status === "active" ? "Active" : "Revoked"}</Badge>
          </div>
          <ul className="ml-4 grid gap-3 border-l-2 pl-4 lg:grid-cols-2">
            {ca.issuingCas.map((issuing) => (
              <li key={issuing.id}>
                <IssuingCaCard orgId={orgId} ca={ca} issuing={issuing} />
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>What it is offered for</CardTitle>
          </CardHeader>
          <CardContent>
            <SummaryRows
              rows={[
                { label: "TLS", value: `Its active Issuing CAs, for ${ca.certificateKeyAlgorithms.map((alg) => KEY_ALGORITHM_LABELS[alg]).join(", ")} keys` },
                { label: "Devices", value: ca.enrollmentProfileRefusal ?? "Its active Issuing CAs, through Enrollment Profiles" },
              ]}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Revocation and publication</CardTitle>
            <CardDescription>The platform serves each Issuing CA's CRL, and the root's, at the PKI base URL.</CardDescription>
          </CardHeader>
          <CardContent>
            <PublicationSummary publication={cas.data.publication} orgId={orgId} />
          </CardContent>
        </Card>
      </div>

      {mayAdd && <AddIssuingCaDialog orgId={orgId} ca={ca} open={adding} onOpenChange={setAdding} />}
      {ca.root && <TrustRootDialog orgId={orgId} ca={ca} publication={cas.data.publication} open={trusting} onOpenChange={setTrusting} />}
    </div>
  );
}

function IssuingCaCard({ orgId, ca, issuing }: { orgId: string; ca: PrivateCa; issuing: IssuingCa }) {
  return (
    <Card size="sm" className="h-full">
      <CardHeader>
        <CardDescription>Issuing CA</CardDescription>
        <CardTitle className="break-all">{commonNameOf(issuing.subject)}</CardTitle>
        <CardAction className="flex items-center gap-2">
          <StatusBadge status={issuing.status} />
          <RolloverDue issuing={issuing} />
          <IssuingCaActions orgId={orgId} ca={ca} issuing={issuing} />
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        <SummaryRows
          rows={[
            { label: "Subject", value: <span className="break-all font-mono text-xs">{issuing.subject}</span> },
            { label: "Permitted names", value: permittedNamesLabel(issuing.permittedNames) },
            { label: "Validity", value: validityLabel(issuing.validity) },
            { label: "Ends", value: issuing.notAfter ? caDate(issuing.notAfter) : <span className="text-muted-foreground">Not signed yet</span> },
          ]}
        />
        {ca.kind === "organization_root" && issuing.status !== "awaiting_signature" && <RootNameConstraints constraints={issuing.nameConstraints} />}
      </CardContent>
    </Card>
  );
}

export function NotFound({ orgId }: { orgId: string }) {
  return (
    <div className="flex flex-col items-start gap-3">
      <h1 className="text-xl font-semibold">No such Private CA</h1>
      <p className="text-sm text-muted-foreground">It may have been removed, or you may not see it.</p>
      <Button variant="outline" asChild>
        <Link to="/organizations/$orgId/private-cas" params={{ orgId }}>
          Back to Private CAs
        </Link>
      </Button>
    </div>
  );
}
