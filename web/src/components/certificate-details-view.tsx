import { CircleAlertIcon, CircleCheckIcon, ChevronDownIcon, DownloadIcon, TriangleAlertIcon } from "lucide-react";
import { CopyButton } from "@/components/copy-button";
import { downloadPem } from "@/components/csr-key-source";
import { ExtensionRows, Mono, Row, Rows, SubjectRows } from "@/components/details-parts";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { type CertificateDetails } from "@/lib/certificate-details";
import { fileBaseOf } from "@/lib/pki-convert";
import { cn } from "@/lib/utils";

const when = (iso: string) => `${new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(new Date(iso))} UTC`;
const days = (count: number) => `${count} ${count === 1 ? "day" : "days"}`;

/** Whether the certificate is valid now, and until when, with what else is worth knowing of it. */
function Verdict({ details }: { details: CertificateDetails }) {
  const { status, days: count, notBefore, notAfter, lifetimeDays } = details.validity;
  const ok = status === "valid";
  return (
    <Alert variant={ok ? "default" : "destructive"}>
      {ok ? <CircleCheckIcon className="text-emerald-600" /> : <CircleAlertIcon />}
      <AlertTitle>
        {status === "valid" && (count === 0 ? "Valid, and expires within a day" : `Valid for ${days(count)} more`)}
        {status === "expired" && (count === 0 ? "Expired today" : `Expired ${days(count)} ago`)}
        {status === "not-yet-valid" && `Not valid for another ${days(count)}`}
      </AlertTitle>
      <AlertDescription>
        <p className="text-foreground">
          {when(notBefore)} to {when(notAfter)} ({days(lifetimeDays)}).
        </p>
        {(details.isCa || details.selfIssued) && (
          <p className="mt-2 flex flex-wrap gap-2">
            {details.isCa && <Badge variant="secondary">CA certificate</Badge>}
            {details.selfIssued && <Badge variant="secondary">self-issued</Badge>}
          </p>
        )}
        {details.warnings.map((warning) => (
          <p key={warning} role="note" className="mt-2 flex items-start gap-2 text-amber-700 dark:text-amber-400">
            <TriangleAlertIcon className="mt-0.5 size-4 shrink-0" />
            {warning}
          </p>
        ))}
      </AlertDescription>
    </Alert>
  );
}

/** What a certificate says of its signature: a self-issued one is checked against its own key, and any other was signed by an issuer this page does not have. */
function signatureNote(details: CertificateDetails): string {
  switch (details.signature.check) {
    case "valid":
      return "verifies against its own key";
    case "invalid":
      return "does not verify against its own key";
    case "unchecked":
      return details.selfIssued ? "could not be checked in this browser" : "made by its issuer, whose certificate is needed to check it";
  }
}

export function CertificateDetailsView({ details }: { details: CertificateDetails }) {
  const fileBase = fileBaseOf(details.names.find((name) => name.type === "DNS")?.value ?? details.subject.find((field) => field.type === "CN")?.value ?? null, "certificate");
  return (
    <div className="flex flex-col gap-6">
      <Verdict details={details} />

      <Card>
        <CardHeader>
          <CardTitle>Issued to</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <SubjectRows fields={details.subject} />
          <h3 className="text-sm font-medium">Names</h3>
          {details.names.length === 0 ? (
            <p className="-mt-2 text-sm text-muted-foreground">None.</p>
          ) : (
            <ul className="-mt-2 flex flex-col gap-1.5 text-sm">
              {details.names.map((name, i) => (
                <li key={`${name.value}-${i}`} className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs break-all">{name.value}</span>
                  <Badge variant="secondary">{name.type}</Badge>
                  {name.wildcard && <Badge variant="outline">wildcard</Badge>}
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Issued by</CardTitle>
        </CardHeader>
        <CardContent>
          <SubjectRows fields={details.issuer} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Key and signature</CardTitle>
        </CardHeader>
        <CardContent>
          <Rows>
            <Row label="Public key">{details.key.label}</Row>
            <Row label="Key SHA-256">
              <Mono text={details.key.sha256} label="key SHA-256" />
            </Row>
            <Row label="Signature">
              {details.signature.algorithm}, <span className={cn(details.signature.check === "invalid" && "text-destructive")}>{signatureNote(details)}</span>
            </Row>
          </Rows>
        </CardContent>
      </Card>

      {details.extensions.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Extensions</CardTitle>
          </CardHeader>
          <CardContent>
            <Rows>
              <ExtensionRows extensions={details.extensions} />
            </Rows>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>The certificate itself</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <Rows>
            <Row label="Serial number">
              <Mono text={details.serialNumber} label="serial number" />
            </Row>
            <Row label="SHA-256">
              <Mono text={details.fingerprint} label="certificate SHA-256" />
            </Row>
            <Row label="SHA-1">
              <Mono text={details.sha1} label="certificate SHA-1" />
            </Row>
            <Row label="Size">{details.derLength.toLocaleString("en-US")} bytes (DER)</Row>
          </Rows>
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" size="sm" onClick={() => downloadPem(`${fileBase}.crt.pem`, `${details.pem}\n`)}>
              <DownloadIcon />
              Download as PEM
            </Button>
          </div>
          <Collapsible className="group/raw">
            <CollapsibleTrigger asChild>
              <Button type="button" variant="ghost" size="sm" className="-ml-2">
                <ChevronDownIcon className="transition-transform group-data-[state=closed]/raw:-rotate-90" />
                Clean PEM and public key
              </Button>
            </CollapsibleTrigger>
            <CollapsibleContent className="flex flex-col gap-3 pt-2">
              {(
                [
                  ["Certificate", details.pem],
                  ["Public key", details.key.publicKeyPem],
                ] as const
              ).map(([title, pem]) => (
                <div key={title} className="relative">
                  <pre aria-label={title} className="overflow-x-auto rounded-md bg-muted p-3 pr-12 font-mono text-xs">
                    {pem}
                  </pre>
                  <span className="absolute top-1 right-1">
                    <CopyButton text={pem} label={`Copy the ${title.toLowerCase()}`} />
                  </span>
                </div>
              ))}
            </CollapsibleContent>
          </Collapsible>
        </CardContent>
      </Card>
    </div>
  );
}
