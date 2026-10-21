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
  { title: "Reads the addresses", body: "The Certificate names where its CA's revocation list (CRL) and certificate can be fetched." },
  { title: "Fetches them", body: "Over plain HTTP, without signing in: checking HTTPS would need a revocation check of its own." },
  { title: "Decides", body: "A CRL it cannot fetch, or an expired one, can mean it refuses the Certificate." },
];

/** What a relying party must see when it fetches a CRL, each a sign of something only whoever runs the platform can fix. */
const REACHABLE: [string, string][] = [
  ["The file itself", "An answer of 200 with the CRL, not a sign-in page or an error."],
  ["No redirect", "Not sent on to an https:// address: a relying party checking revocation will not follow it."],
  ["From everywhere it is needed", "From every network your relying parties are on, including ones outside your VPN."],
];

/**
 * Publishing a Private CA, for the Organization Administrator: what relying parties fetch to check revocation, the
 * address every Certificate names (as it is set), checking relying parties reach it, when CRLs change, trusting the root
 * and rolling over. How the platform itself is served is not theirs to change, so it is not here.
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
      lede="Every Certificate a Private CA signs tells relying parties where to fetch its CA's revocation list and certificate. The platform publishes both. Your part is to check that your relying parties can reach them, and to make them trust the root."
    >
      <Alert variant="destructive">
        <ShieldAlertIcon />
        <AlertTitle>Check this before you issue</AlertTitle>
        <AlertDescription>The address is written into every Certificate when it is signed, and stays there. If it changes later, Certificates already issued still point at the old one.</AlertDescription>
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
      </GuideSection>

      <GuideSection guide="private-cas" id="url">
        {publication ? <PublicationSummary publication={publication} /> : <p className="text-muted-foreground">{cas.isPending && allowed ? "Loading…" : "Not available to you."}</p>}
        <p className="text-muted-foreground">
          It is the same for every Private CA on the platform, and is set by whoever runs the platform, not here. If the Private CAs page warns about it, ask them before you
          issue anything. The exact addresses of each CA are in its “Trust this root” action.
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
        <p>From a machine on a relying party's network, fetch one of the CRL addresses (copy it from “Trust this root”):</p>
        <pre className="overflow-x-auto rounded-md border bg-muted p-3 font-mono text-xs leading-relaxed">{`curl -sI ${example}\n# Expect: HTTP 200, and no Location header`}</pre>
        <p className="text-muted-foreground">If it fails, tell whoever runs the platform what you saw and from where: the address is theirs to make reachable.</p>
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
