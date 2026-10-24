import { CheckIcon, ChevronDownIcon, CircleAlertIcon, CircleCheckIcon, DownloadIcon, MinusIcon, TriangleAlertIcon, XIcon } from "lucide-react";
import { CopyButton } from "@/components/copy-button";
import { downloadPem } from "@/components/csr-key-source";
import { ExtensionRows, Mono, Row, Rows, SubjectRows } from "@/components/details-parts";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import type { CsrDetails, CsrFitCheck, SignatureCheck } from "@/lib/csr-details";
import { fileBaseOf } from "@/lib/pki-convert";
import { cn } from "@/lib/utils";

function Fit({ check }: { check: CsrFitCheck }) {
  const Icon = check.ok === true ? CheckIcon : check.ok === false ? XIcon : MinusIcon;
  return (
    <li className="flex items-start gap-2">
      <Icon className={cn("mt-0.5 size-4 shrink-0", check.ok === true && "text-emerald-600 dark:text-emerald-400", check.ok === false && "text-destructive", check.ok === null && "text-muted-foreground")} />
      <span>{check.text}</span>
    </li>
  );
}

/** Whether the platform would take the CSR, and each thing it checks, so a refusal is never a mystery. */
function Verdict({ details }: { details: CsrDetails }) {
  return (
    <Alert variant={details.acceptable ? "default" : "destructive"}>
      {details.acceptable ? <CircleCheckIcon className="text-emerald-600 dark:text-emerald-400" /> : <CircleAlertIcon />}
      <AlertTitle>{details.acceptable ? "The platform would take this CSR" : "The platform would refuse this CSR"}</AlertTitle>
      <AlertDescription>
        <ul className="mt-1 flex flex-col gap-1 text-foreground">
          {details.fit.map((check) => (
            <Fit key={check.id} check={check} />
          ))}
        </ul>
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

const SIGNATURE_NOTES: Record<SignatureCheck, string> = {
  valid: "verifies against the CSR's own key",
  invalid: "does not verify",
  unchecked: "could not be checked in this browser",
};

export function CsrDetailsView({ details }: { details: CsrDetails }) {
  const fileBase = fileBaseOf(details.distinctNames[0] ?? null, "csr");
  return (
    <div className="flex flex-col gap-6">
      <Verdict details={details} />

      <Card>
        <CardHeader>
          <CardTitle>Names</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {details.names.length === 0 ? (
            <p className="text-sm text-muted-foreground">It asks for no names.</p>
          ) : (
            <ul className="flex flex-col gap-1.5 text-sm">
              {details.names.map((name, i) => (
                <li key={`${name.source}-${i}`} className="flex flex-wrap items-center gap-2">
                  <span className={cn("font-mono text-xs break-all", name.problem && "text-destructive")}>{name.value}</span>
                  <Badge variant={name.problem ? "destructive" : "secondary"}>{name.type}</Badge>
                  {name.wildcard && <Badge variant="outline">wildcard</Badge>}
                  {name.source === "cn" && <Badge variant="outline">{name.repeat ? "common name, also above" : "common name"}</Badge>}
                  {name.problem && <span className="text-xs text-destructive">{name.problem}</span>}
                </li>
              ))}
            </ul>
          )}
          <h3 className="text-sm font-medium">Subject</h3>
          <SubjectRows fields={details.subject} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Key and signature</CardTitle>
        </CardHeader>
        <CardContent>
          <Rows>
            <Row label="Public key">
              {details.key.label}
              {details.key.algorithm === null && <Badge variant="destructive" className="ml-2">not taken</Badge>}
            </Row>
            <Row label="Key SHA-256">
              <Mono text={details.key.sha256} label="key SHA-256" />
            </Row>
            <Row label="Signature">
              {details.signature.algorithm}, <span className={cn(details.signature.check === "invalid" && "text-destructive")}>{SIGNATURE_NOTES[details.signature.check]}</span>
            </Row>
          </Rows>
        </CardContent>
      </Card>

      {(details.extensions.length > 0 || details.attributes.length > 0) && (
        <Card>
          <CardHeader>
            <CardTitle>What else it asks for</CardTitle>
          </CardHeader>
          <CardContent>
            <Rows>
              <ExtensionRows extensions={details.extensions} />
              {details.attributes.map((attribute) => (
                <Row key={attribute.oid} label={attribute.label}>
                  {attribute.summary}
                </Row>
              ))}
            </Rows>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>The CSR itself</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <Rows>
            <Row label="SHA-256">
              <Mono text={details.fingerprint} label="CSR SHA-256" />
            </Row>
            <Row label="Size">{details.derLength.toLocaleString("en-US")} bytes (DER)</Row>
          </Rows>
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" size="sm" onClick={() => downloadPem(`${fileBase}.csr.pem`, `${details.pem}\n`)}>
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
                  ["CSR", details.pem],
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
