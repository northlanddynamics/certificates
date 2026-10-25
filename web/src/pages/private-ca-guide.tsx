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

const CHECK_STEPS = [
  { title: "A Certificate is shown", body: "A server, app, Wi-Fi network or browser is given one of your Certificates." },
  { title: "It finds the address", body: "The Certificate includes the web address of its revocation list (CRL): the list of Certificates that were cancelled." },
  { title: "It downloads the list", body: "Over plain HTTP, without signing in." },
  { title: "It decides", body: "If it can't download the list, or the list is out of date, it may reject the Certificate." },
];

/** What a relying party must see when it fetches a CRL, each a sign of something only whoever runs the platform can fix. */
const REACHABLE: [string, string][] = [
  ["The list itself", "The address returns the file, not a sign-in page or an error."],
  ["No redirects", "It isn't sent on to an https:// address. Most apps won't follow that when checking revocation."],
  ["Reachable everywhere", "Every network your apps and devices use can reach it, including outside your VPN."],
];

/**
 * Publishing a Private CA, for the Organization Administrator: what relying parties fetch to check revocation, the
 * address every Certificate names (as it is set), checking relying parties reach it, when CRLs change, trusting the root
 * and rolling over. How the platform itself is served is not theirs to change, so it is not here.
 */
export function PrivateCaGuidePage() {
  // Shown as a page or in the help panel over any of the Organization's pages.
  const orgId = useParams({ strict: false }).orgId ?? "";
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
      lede="Apps and devices that use your Private CA's Certificates need two things: to trust your root certificate, and to be able to check whether a Certificate was revoked. The platform publishes what they need. Your part is to check they can reach it, and to install the root."
    >
      <Alert variant="destructive">
        <ShieldAlertIcon />
        <AlertTitle>Check this before you issue</AlertTitle>
        <AlertDescription>Every Certificate includes the address where its revocation can be checked, and it can't be changed later. Make sure the address works before you issue.</AlertDescription>
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
          It is the same for every Private CA, and whoever runs the platform sets it. If the Private CAs page shows a warning about it, talk to them before you issue anything.
          Each CA's exact addresses are under its “Trust this root” action.
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
        <p>To test it, run this on a machine on that network, with a CRL address copied from “Trust this root”:</p>
        <pre className="overflow-x-auto rounded-md border bg-muted p-3 font-mono text-xs leading-relaxed">{`curl -sI ${example}\n# You want: HTTP 200, and no Location line`}</pre>
        <p className="text-muted-foreground">If it doesn't work, tell whoever runs the platform what you saw and where you ran it from.</p>
      </GuideSection>

      <GuideSection guide="private-cas" id="crl">
        <ul className="grid gap-2 sm:grid-cols-2">
          <li className="rounded-md border p-3">
            <strong>The list updates at once.</strong> Revoking a Certificate updates its CA's list straight away.
          </li>
          <li className="rounded-md border p-3">
            <strong>Apps may wait.</strong> An app can keep a downloaded list for up to 7 days, so a revocation can take that long to reach it.
          </li>
        </ul>
      </GuideSection>

      <GuideSection guide="private-cas" id="trust">
        <p>
          Install the root certificate once on every device and app that needs to trust your Certificates. It covers every Issuing CA under it, including ones you add later.
          Download it with the Private CA's “Trust this root” action, and after installing, check its fingerprint matches the one shown there.
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
          When an Issuing CA is near its end, the list marks it “Roll over”. Add a new Issuing CA under the same root, move its Managed Certificates to the new one, then
          retire the old one. Devices that trust the root need no changes.
        </p>
      </GuideSection>
    </GuidePage>
  );
}
