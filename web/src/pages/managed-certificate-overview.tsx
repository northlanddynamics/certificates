import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { PencilIcon } from "lucide-react";
import { useState, type ReactNode } from "react";
import { CopyButton } from "@/components/copy-button";
import { DcvByName } from "@/components/dcv-plan";
import { IssuerName } from "@/components/issuer-name";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api, can, type AcmeCa, type Certificate, type ManagedCertificate, type Me } from "@/lib/api";
import { acmeCaName, useAcmeCas } from "@/lib/acme-cas";
import { caLabel, keyAlgorithmLabel, profileLabel } from "@/lib/managed-certificate";
import { chosenValidityLabel } from "@/lib/private-ca";
import { useCertificateFacts, useManagedCertificatePage } from "@/lib/use-managed-certificate";
import { date } from "@/lib/utils";
import { IssuingCaStopped, mayRepoint, RepointDialog } from "./issuer-controls";
import { KeyChangeSheet, keyChanges, type KeyChange } from "./key-change-sheet";
import { Owners } from "./owner-controls";
import { Renewal } from "./renewal-controls";
import { RevokeDialog, requestedLine, revokedLine } from "./revocation-controls";

type Org = Me["organizations"][number];

function Fact({ label, children, action }: { label: string; children: ReactNode; action?: ReactNode }) {
  return (
    <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-1 sm:grid-cols-[8rem_minmax(0,1fr)_auto]">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="col-start-1 min-w-0 break-words sm:col-start-2">{children}</dd>
      {action && <div className="col-start-2 row-span-2 row-start-1 sm:col-start-3 sm:row-span-1">{action}</div>}
    </div>
  );
}

/**
 * What a Managed Certificate is, on the left (its names and its current Certificate), and how it is run, on the right
 * (Renewal, Owners, key, issuer and who is told of it), each with the change it allows beside it.
 */
export function ManagedCertificateOverview() {
  const { orgId, id } = useParams({ from: "/app/organizations/$orgId/certificates/$id/" });
  const { org, userId, certificate, refresh } = useManagedCertificatePage(orgId, id);
  const m = certificate.data;
  // The key sheet, opened from the names or the key; the same one the "⋯" menu opens.
  const [change, setChange] = useState<KeyChange | null>(null);
  if (!org || !m) return null;

  return (
    <div className="grid items-start gap-4 lg:grid-cols-3">
      <div className="flex min-w-0 flex-col gap-4 lg:col-span-2">
        <NamesCard org={org} m={m} userId={userId} onChange={setChange} />
        <CurrentCertificateCard org={org} m={m} userId={userId} onChanged={refresh} />
        {/* An ACME CA asks for DCV of each name: shown to those who may see how it is done, so CNAMEs are made before they are needed. */}
        {!m.archivedAt && m.issuer.kind === "acme" && can(org, "dcvRule", "read") && (
          <Card id="dcv" className="scroll-mt-4">
            <CardHeader>
              <CardTitle>How each name is validated</CardTitle>
            </CardHeader>
            <CardContent className="text-sm">
              <DcvByName orgId={orgId} names={[...new Set([...m.names, ...(m.pendingNameChange?.names ?? [])])]} />
            </CardContent>
          </Card>
        )}
      </div>
      <Card className="gap-0 py-2">
        <CardContent className="flex flex-col divide-y text-sm [&>*]:py-4">
          {!m.archivedAt && <Renewal org={org} m={m} userId={userId} onChanged={refresh} />}
          <RunSection title="Owners">
            <Owners org={org} m={m} userId={userId} onChanged={refresh} />
          </RunSection>
          <KeySection org={org} m={m} userId={userId} onChange={setChange} />
          <IssuerSection org={org} m={m} onChanged={refresh} />
          <NotificationsSection orgId={orgId} id={id} />
        </CardContent>
      </Card>
      <KeyChangeSheet org={org} m={m} userId={userId} change={change} onClose={() => setChange(null)} onChanged={refresh} />
    </div>
  );
}

/** One part of how a Managed Certificate is run: a heading, with the change it allows beside it, over what it is now. */
function RunSection({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-1">
      <div className="flex min-h-8 items-center justify-between gap-2">
        <h3 className="font-medium">{title}</h3>
        {action}
      </div>
      {children}
    </section>
  );
}

/** Its names, the common name marked, with the means to change them (or propose to) for those who may. */
function NamesCard({ org, m, userId, onChange }: { org: Org; m: ManagedCertificate; userId?: string; onChange: (change: KeyChange) => void }) {
  const { mayChangeNames, direct } = keyChanges(org, m, userId);
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Names <span className="font-normal text-muted-foreground">{m.names.length}</span>
        </CardTitle>
        {mayChangeNames && (
          <CardAction>
            <Button variant="outline" size="sm" onClick={() => onChange("names")}>
              <PencilIcon />
              {direct ? "Change names" : "Propose a name change"}
            </Button>
          </CardAction>
        )}
      </CardHeader>
      <CardContent>
        <ul className="grid gap-x-6 gap-y-1 font-mono text-xs sm:grid-cols-2">
          {m.names.map((name) => (
            <li key={name} className="flex min-w-0 items-center gap-2 break-all">
              {name}
              {name === m.commonName && <span className="font-sans text-muted-foreground">common name</span>}
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

/**
 * Who issued `certificate`, named as the Managed Certificate's issuer is when it is that one; one issued before the
 * issuer was changed goes by its CA's name.
 */
function CertificateIssuer({ org, m, certificate, acmeCas }: { org: Org; m: ManagedCertificate; certificate: Certificate; acmeCas: AcmeCa[] | undefined }) {
  const { issuer } = m;
  const same = issuer.kind === "acme" ? certificate.acmeCaId === issuer.acmeCaId : certificate.issuingCaId === issuer.issuingCa.id;
  if (same) return <IssuerName org={org} issuer={issuer} acmeCas={acmeCas} />;
  return <>{certificate.acmeCaId ? acmeCaName(acmeCas, certificate.acmeCaId) : caLabel(certificate.ca)}</>;
}

/** A fingerprint shortened to its ends, which is enough to tell one from another, with the whole of it on request. */
function Fingerprint({ value }: { value: string }) {
  const [whole, setWhole] = useState(false);
  return (
    <span className="font-mono text-xs break-all">
      {whole ? value : `${value.slice(0, 16)}…${value.slice(-8)}`}{" "}
      <Button variant="link" size="sm" className="h-auto p-0 font-sans" onClick={() => setWhole(!whole)}>
        {whole ? "Show less" : "Show all"}
      </Button>
    </span>
  );
}

/** The current Certificate: who issued it, when it is valid, and how to tell it apart; with Revoke, and the way to every other. */
function CurrentCertificateCard({ org, m, userId, onChanged }: { org: Org; m: ManagedCertificate; userId?: string; onChanged: () => void }) {
  // What the current Certificate says about itself (its issuer); the rest is on the Managed Certificate already.
  const facts = useCertificateFacts(org.id, m.id, m.currentCertificate?.id);
  const acmeCas = useAcmeCas(org.id).data?.items;
  const current = m.currentCertificate;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Current Certificate</CardTitle>
        <CardAction className="flex flex-wrap gap-2">
          {current && <RevokeDialog org={org} m={m} certificate={current} userId={userId} onChanged={onChanged} />}
          <Button variant="outline" size="sm" asChild>
            <Link to="/organizations/$orgId/certificates/$id/issued" params={{ orgId: org.id, id: m.id }}>
              View history
            </Link>
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent className="text-sm">
        {current ? (
          <dl className="flex flex-col gap-3">
            <Fact label="Issued by">
              <span className="flex flex-col gap-0.5">
                <span>
                  <CertificateIssuer org={org} m={m} certificate={current} acmeCas={acmeCas} />
                </span>
                {facts.data ? (
                  <span className="font-mono text-xs break-all text-muted-foreground">{facts.data.issuer}</span>
                ) : (
                  facts.error && <span className="text-xs text-destructive">{facts.error.message}</span>
                )}
              </span>
            </Fact>
            <Fact label="Valid">
              {date(current.notBefore)} – {date(current.notAfter)}
            </Fact>
            <Fact label="Serial" action={<CopyButton text={current.serial} label="Copy the serial" />}>
              <span className="font-mono text-xs break-all">{current.serial}</span>
            </Fact>
            <Fact label="SHA-256" action={<CopyButton text={current.fingerprint} label="Copy the fingerprint" />}>
              <Fingerprint value={current.fingerprint} />
            </Fact>
            {current.acmeCaId && (
              <Fact label="ACME Account">
                <span className="font-mono text-xs text-muted-foreground">{current.acmeAccountId}</span>
              </Fact>
            )}
            {current.revocation && (
              <Fact label="Revoked">
                <span className="text-destructive">{revokedLine(current.revocation)}</span>
              </Fact>
            )}
            {current.revocationRequest && (
              <Fact label="Revocation">
                <span className={current.revocationRequest.status === "failed" ? "text-destructive" : undefined}>{requestedLine(current.revocationRequest)}</span>
              </Fact>
            )}
          </dl>
        ) : (
          <p className="text-muted-foreground">No Certificate yet.</p>
        )}
      </CardContent>
    </Card>
  );
}

const AGENT_STATUS_WORDS = { online: "online", offline: "offline", revoked: "revoked" } as const;

/** Who holds the key and what that means for Renewal, with Replace for those who may. */
function KeySection({ org, m, userId, onChange }: { org: Org; m: ManagedCertificate; userId?: string; onChange: (change: KeyChange) => void }) {
  const { mayReplace } = keyChanges(org, m, userId);
  const algorithm = keyAlgorithmLabel(m.keyAlgorithm);
  return (
    <RunSection
      title="Key"
      action={
        mayReplace && (
          <Button variant="ghost" size="sm" onClick={() => onChange("replace")}>
            Replace
          </Button>
        )
      }
    >
      {m.keyCustody === "owner" ? (
        <>
          <span>{algorithm}, held by its Owners</span>
          <span className="text-muted-foreground">The platform has only the CSR; every Renewal reuses it until it is replaced.</span>
        </>
      ) : (
        <>
          <span>
            {algorithm}, held by {m.agent ? `the Agent on ${m.agent.hostName}` : "an Agent"}
          </span>
          {m.agent && (
            <span className={m.agent.status === "online" ? "text-muted-foreground" : "text-destructive"}>
              The Agent is {AGENT_STATUS_WORDS[m.agent.status]}; it makes a new key for each Renewal.
            </span>
          )}
        </>
      )}
    </RunSection>
  );
}

/** Where its Certificates come from, and the Certificate Profile it was made through; with Change Issuing CA for those who may. */
function IssuerSection({ org, m, onChanged }: { org: Org; m: ManagedCertificate; onChanged: () => void }) {
  const acmeCas = useAcmeCas(org.id).data?.items;
  const [repointing, setRepointing] = useState(false);
  const repoint = mayRepoint(org, m);
  return (
    <RunSection
      title="Issuer"
      action={
        repoint && (
          <Button variant="ghost" size="sm" onClick={() => setRepointing(true)}>
            Change
          </Button>
        )
      }
    >
      <span>
        <IssuerName org={org} issuer={m.issuer} acmeCas={acmeCas} />
      </span>
      {m.issuer.kind === "private_ca" && <span className="text-muted-foreground">Validity: {chosenValidityLabel(m.validityDays)}</span>}
      {m.profile && <span className="text-muted-foreground">From the Certificate Profile {profileLabel(m.profile)}</span>}
      <IssuingCaStopped org={org} m={m} />
      {repoint && <RepointDialog org={org} m={m} open={repointing} onOpenChange={setRepointing} onChanged={onChanged} />}
    </RunSection>
  );
}

/** How many are told of its events, and the way to the tab that changes that. */
function NotificationsSection({ orgId, id }: { orgId: string; id: string }) {
  // The Notifications tab reads the same, under the same key.
  const subscribers = useQuery({ queryKey: ["managed-certificate", orgId, id, "subscribers"], queryFn: () => api.subscribers(orgId, id) });
  const count = subscribers.data?.items.length;
  return (
    <RunSection
      title="Notifications"
      action={
        <Button variant="ghost" size="sm" asChild>
          <Link to="/organizations/$orgId/certificates/$id/notifications" params={{ orgId, id }}>
            Manage
          </Link>
        </Button>
      }
    >
      <span className="text-muted-foreground">
        {count === undefined ? "…" : count === 0 ? "No Subscribers: nobody is told of its events" : `${count} Subscriber${count === 1 ? "" : "s"}`}
      </span>
    </RunSection>
  );
}
