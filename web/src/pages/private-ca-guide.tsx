import { useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { ShieldAlertIcon } from "lucide-react";
import { GuidePage, GuideSection } from "@/components/guide";
import { PublicationSummary } from "@/components/pki-publication";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, can } from "@/lib/api";
import { publicationUrls } from "@/lib/pki-publication";
import { TRUST_STORES } from "@/lib/trust-stores";
import { useOrg } from "@/lib/use-org";

const ROUTE = "/app/organizations/$orgId/private-cas/guide";

const CHECK_STEPS = [
  { title: "Relying party", body: "A server, load balancer, RADIUS server or browser is shown a Certificate." },
  { title: "Reads the addresses", body: "Its CRL Distribution Point and AIA caIssuers, both under the PKI base URL." },
  { title: "Fetches over HTTP", body: "With no credentials and no TLS: checking TLS would need a revocation check of its own." },
  { title: "Decides", body: "A CRL it cannot fetch, or an expired one, can mean it refuses the Certificate." },
];

const REACHABLE: [string, string][] = [
  ["Public", "Reachable by every relying party: no sign-in, no VPN, no IP allowlist. With the SCEP routes, these are the platform's only unauthenticated routes outside sign-in."],
  ["Plain HTTP", "An http:// PKI base URL. The routes answer over HTTPS too, but relying parties must not need it."],
  ["No redirect, no HSTS", "A TLS terminator or load balancer in front passes /pki/* through over HTTP, with no redirect to HTTPS and no HSTS on that host."],
  ["Platform serves TLS", "When the platform terminates TLS itself, the operator sets PKI_HTTP_PORT (such as 80) so it also listens over plain HTTP, answering only /pki/*."],
];

/**
 * How to publish a Private CA: what relying parties fetch to check revocation, the PKI base URL every Certificate names
 * (this platform's, as it is set), making it reachable, when CRLs change, trusting the root and rolling over.
 */
export function PrivateCaGuidePage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const allowed = org ? can(org, "privateCa", "read") : false;
  const cas = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId), enabled: allowed });
  const publication = cas.data?.publication;
  const example = publicationUrls(publication?.baseUrl ?? "http://pki.example.com", { signer: "issuing", id: "<issuing CA id>" }).crl;
  return (
    <GuidePage
      guide="private-cas"
      title="Publishing a Private CA"
      back={{ to: "/organizations/$orgId/private-cas", label: "Private CAs", orgId }}
      lede="Every Certificate a Private CA signs tells relying parties where to fetch its CRL and its Issuing CA's certificate. The platform serves both. Your part is to make that address reachable, and to settle it before anything is issued."
    >
      <Alert variant="destructive">
        <ShieldAlertIcon />
        <AlertTitle>Settle this first</AlertTitle>
        <AlertDescription>The PKI base URL is written into every Certificate when it is signed. Changing it later leaves every Certificate already issued pointing at the old address.</AlertDescription>
      </Alert>

      <GuideSection guide="private-cas" id="how">
        <ol className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {CHECK_STEPS.map((s, i) => (
            <li key={s.title} className="flex flex-col gap-1 rounded-lg border p-3">
              <span className="text-xs font-semibold text-primary">
                {i + 1} · {s.title}
              </span>
              <span>{s.body}</span>
            </li>
          ))}
        </ol>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Served at</TableHead>
                <TableHead>What</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {[
                ["/pki/issuing-cas/{id}/ca.crl", "The Issuing CA's CRL (DER)"],
                ["/pki/issuing-cas/{id}/ca.crt", "The Issuing CA's certificate (DER)"],
                ["/pki/roots/{id}/ca.crl", "A platform-made root's CRL, listing its revoked Issuing CAs"],
                ["/pki/roots/{id}/ca.crt", "A platform-made root's certificate"],
              ].map(([path, what]) => (
                <TableRow key={path}>
                  <TableCell className="font-mono text-xs">{path}</TableCell>
                  <TableCell className="whitespace-normal">{what}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </GuideSection>

      <GuideSection guide="private-cas" id="url">
        {publication ? <PublicationSummary publication={publication} /> : <p className="text-muted-foreground">{cas.isPending && allowed ? "Loading…" : "Not available to you."}</p>}
        <p className="text-muted-foreground">
          The platform's operator sets it with <code>PKI_BASE_URL</code>; without it, the address the platform is served at is used. Organization Administrators see it here but
          cannot change it.
        </p>
      </GuideSection>

      <GuideSection guide="private-cas" id="reach">
        <ul className="flex flex-col gap-2">
          {REACHABLE.map(([title, body]) => (
            <li key={title} className="grid gap-1 rounded-md border p-3 sm:grid-cols-[10rem_1fr] sm:gap-3">
              <span className="font-medium">{title}</span>
              <span>{body}</span>
            </li>
          ))}
        </ul>
        <span className="font-medium">Check it from a relying party's network</span>
        <pre className="overflow-x-auto rounded-md border bg-muted p-3 font-mono text-xs leading-relaxed">{`curl -sI ${example}\n# Expect: HTTP 200, and no Location header`}</pre>
      </GuideSection>

      <GuideSection guide="private-cas" id="crl">
        <ul className="grid gap-2 sm:grid-cols-2">
          <li className="rounded-md border p-3">
            <strong>On every revocation.</strong> The Issuing CA's CRL is reissued in the same change.
          </li>
          <li className="rounded-md border p-3">
            <strong>Valid for 7 days.</strong> Each CRL's next update is 7 days after it was issued.
          </li>
          <li className="rounded-md border p-3">
            <strong>Reissued early.</strong> At least 3 days before that, so a relying party is never left with an expired one.
          </li>
          <li className="rounded-md border p-3">
            <strong>Cached elsewhere.</strong> A relying party may keep a CRL until its next update, so a revocation can take up to 7 days to reach it.
          </li>
        </ul>
      </GuideSection>

      <GuideSection guide="private-cas" id="trust">
        <p>
          Install the root once on everything that must trust the Private CA's Certificates; it covers every Issuing CA under it, now and later. Use the Private CA's “Trust this
          root” action to download it, and compare the SHA-256 fingerprint shown there after installing.
        </p>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Where</TableHead>
                <TableHead>How</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {TRUST_STORES.map((t) => (
                <TableRow key={t.id}>
                  <TableCell className="align-top font-medium">{t.label}</TableCell>
                  <TableCell className="flex flex-col gap-2 whitespace-normal">
                    <span>{t.how}</span>
                    <code className="whitespace-pre-wrap">{t.command({ pem: "root.pem", der: "root.crt" })}</code>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </GuideSection>

      <GuideSection guide="private-cas" id="rollover">
        <p>
          When an Issuing CA nears its end (the list marks it “Roll over”), add another under the same root, repoint its Managed Certificates, then retire it. Nothing that trusts
          the root needs anything new, and the retired one keeps publishing its CRL until the last Certificate it issued expires.
        </p>
      </GuideSection>
    </GuidePage>
  );
}
