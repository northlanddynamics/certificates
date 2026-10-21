import { CircleCheckIcon, CircleHelpIcon, TriangleAlertIcon } from "lucide-react";
import { GuideLink } from "@/components/guide";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import type { PkiPublication } from "@/lib/api";
import { publicationProblems, publicationUrls } from "@/lib/pki-publication";

/** The PKI base URL as it is set, with what the platform can tell of it: plain HTTP, and whether the operator set it. */
export function PublicationSummary({ publication, orgId }: { publication: PkiPublication; orgId?: string }) {
  const problems = publicationProblems(publication);
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm text-muted-foreground">PKI base URL</span>
        <code className="text-sm">{publication.baseUrl}</code>
        {problems.length === 0 && (
          <Badge variant="outline">
            <CircleCheckIcon />
            Plain HTTP, set by the operator
          </Badge>
        )}
        {orgId && (
          <GuideLink orgId={orgId} guide="private-cas" section="url" className="text-sm font-medium underline underline-offset-4 hover:text-primary">
            What this is
          </GuideLink>
        )}
      </div>
      {problems.map((p) => (
        <Alert key={p.title}>
          <TriangleAlertIcon />
          <AlertTitle>{p.title}</AlertTitle>
          <AlertDescription>{p.detail}</AlertDescription>
        </Alert>
      ))}
    </div>
  );
}

/**
 * Before the first Private CA: the addresses every Certificate it signs will carry, what the platform can check of them,
 * and the one thing only the administrator can (that relying parties reach them), which `acknowledged` records.
 */
export function PublicationCheck({
  orgId,
  publication,
  acknowledged,
  onAcknowledge,
}: {
  orgId: string;
  publication: PkiPublication;
  acknowledged: boolean;
  onAcknowledge: (value: boolean) => void;
}) {
  const urls = publicationUrls(publication.baseUrl, { signer: "issuing", id: "<id>" });
  const problems = publicationProblems(publication);
  return (
    <section aria-label="Where its Certificates send relying parties" className="flex flex-col gap-3 rounded-lg border p-4 text-sm">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="font-medium">Before you start: where its Certificates send relying parties</h3>
        <GuideLink orgId={orgId} guide="private-cas" className="text-xs font-medium underline underline-offset-4 hover:text-primary">
          Publishing guide
        </GuideLink>
      </div>
      <p className="text-muted-foreground">Every Certificate it signs will name these addresses, which relying parties fetch to check revocation. They cannot change afterwards.</p>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1">
        <dt className="text-muted-foreground">CRL Distribution Point</dt>
        <dd className="break-all font-mono text-xs">{urls.crl}</dd>
        <dt className="text-muted-foreground">AIA caIssuers</dt>
        <dd className="break-all font-mono text-xs">{urls.certificate}</dd>
      </dl>
      {problems.length > 0 ? (
        problems.map((p) => (
          <Alert key={p.title}>
            <TriangleAlertIcon />
            <AlertTitle>{p.title}</AlertTitle>
            <AlertDescription>{p.detail}</AlertDescription>
          </Alert>
        ))
      ) : (
        <span className="flex items-center gap-2">
          <CircleCheckIcon className="size-4 text-primary" />
          Plain HTTP, and set by the platform's operator.
        </span>
      )}
      <span className="flex items-start gap-2 text-muted-foreground">
        <CircleHelpIcon className="mt-0.5 size-4 shrink-0" />
        Whether your relying parties can reach them is for you to check from their network: the platform cannot see it.
      </span>
      <div className="flex items-start gap-2 rounded-md border p-3">
        <Checkbox id="publication-acknowledged" checked={acknowledged} onCheckedChange={(v) => onAcknowledge(v === true)} />
        <Label htmlFor="publication-acknowledged" className="font-normal leading-snug">
          Relying parties can fetch these addresses over plain HTTP, without signing in or a VPN.
        </Label>
      </div>
    </section>
  );
}
