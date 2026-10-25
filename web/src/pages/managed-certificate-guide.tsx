import { useParams } from "@tanstack/react-router";
import { TriangleAlertIcon } from "lucide-react";
import { GuideLink, GuidePage, GuideSection, Steps } from "@/components/guide";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { can } from "@/lib/api";
import { useOrg } from "@/lib/use-org";

const WAYS: { title: string; who: string; body: string; when: string }[] = [
  {
    title: "New Managed Certificate",
    who: "You keep the key",
    body: "You make the key yourself, here in your browser or on your own server. The platform issues and renews the Certificate, and you install it where it is needed.",
    when: "Use it for one-off servers and appliances, or anywhere an Agent can't run.",
  },
  {
    title: "New Deployment",
    who: "An Agent keeps the key",
    body: "An Agent on your server makes the key, gets the Certificate and runs a Deployment Script to install it. It does the same on every renewal, with nothing for you to do.",
    when: "Use it when you want renewals installed for you. Only Organization Administrators set these up.",
  },
];

const KEY_OPTIONS: [string, string, string][] = [
  ["Generate here", "Your browser makes the key and the CSR. You download the key and keep it safe.", "The quickest way, if you can copy the key to your server."],
  ["Run a command", "You run an OpenSSL command on your server. It writes the key and the CSR there, and you paste the CSR back.", "When the key should never leave the server it is used on."],
  ["Paste a CSR", "You make the CSR with your own tools, and paste it in.", "When your server or appliance makes its own CSR."],
];

const STATUSES: [string, string][] = [
  ["Awaiting Approval", "It is a Proposal. An Approver has to approve it before anything is issued."],
  ["Rejected", "An Approver turned it down. Its page says why."],
  ["Issuing…", "The CA is checking the names and issuing the Certificate. This usually takes under a minute."],
  ["Issued", "It is ready to download. It turns amber when renewal is coming up."],
  ["Issuance failed", "The first Certificate couldn't be issued. Its Activity tab says why."],
  ["Renewal failing", "A renewal didn't work. The current Certificate still works until it expires, so fix the cause soon."],
  ["Renewal blocked", "Its Certificate Profile is disabled, so it can't renew. An Organization Administrator can enable the profile or detach the certificate."],
  ["Expired / Revoked", "The current Certificate no longer works. Renew it, or request a new one."],
];

/**
 * How to request a Managed Certificate, for anyone who may: the two ways to get one, the New Managed Certificate steps,
 * choosing how to make the key, what happens afterwards and what each status means.
 */
export function ManagedCertificateGuidePage() {
  // Shown as a page or in the help panel over any of the Organization's pages.
  const orgId = useParams({ strict: false }).orgId ?? "";
  const org = useOrg(orgId);
  if (org && !can(org, "managedCertificate", "create") && !can(org, "managedCertificate", "propose"))
    return <p className="text-sm text-muted-foreground">Your role can't request Managed Certificates.</p>;
  const mayDeploy = org ? can(org, "deployment", "create") : false;
  return (
    <GuidePage
      guide="managed-certificates"
      title="Requesting a certificate"
      back={{ to: "/organizations/$orgId/certificates", label: "Managed Certificates", orgId }}
      lede="A Managed Certificate is a certificate the platform looks after for you: it gets it issued for the names you ask for, keeps track of when it expires, and renews it in time. This guide walks you through requesting one."
    >
      <GuideSection guide="managed-certificates" id="ways">
        <div className="grid gap-3 md:grid-cols-2">
          {WAYS.map((w) => (
            <div key={w.title} className="flex flex-col gap-2 rounded-lg border p-4">
              <span className="text-base font-semibold">{w.title}</span>
              <span className="text-xs font-medium text-primary">{w.who}</span>
              <span>{w.body}</span>
              <span className="text-muted-foreground">{w.when}</span>
            </div>
          ))}
        </div>
        {mayDeploy && (
          <p className="text-muted-foreground">
            A Deployment needs an Agent on the server first: see <GuideLink guide="agents">Setting up an Agent</GuideLink>.
          </p>
        )}
      </GuideSection>

      <GuideSection guide="managed-certificates" id="steps">
        <p className="text-muted-foreground">Choose “New Managed Certificate” on the Managed Certificates page. Some steps only appear when they apply.</p>
        <Steps>
          {[
            <>
              <strong>Choose a profile.</strong> A Certificate Profile makes most choices for you, such as the CA and the key type. Pick the one that fits, or Custom if it is
              offered and none does.
            </>,
            <>
              <strong>Certificate Authority.</strong> Choose an ACME CA, such as Let's Encrypt, for names the public can reach. Choose a Private CA for internal names that
              only your own devices need to trust.
            </>,
            <>
              <strong>Domain names.</strong> One per line, such as <code>www.example.com</code>. A wildcard, <code>*.example.com</code>, covers every name one level below
              it, but not <code>example.com</code> itself.
            </>,
            <>
              <strong>Key and CSR.</strong> Choose how the key is made (see <GuideLink guide="managed-certificates" section="key">below</GuideLink>) and its type. Leave the type as
              ECDSA P-256 unless your server needs something else.
            </>,
            <>
              <strong>Save your key.</strong> Only if the key was made in your browser. Download or copy it now: it exists nowhere else, and the platform never sees it.
            </>,
            <>
              <strong>Ownership.</strong> Owners look after the certificate and can renew, replace or revoke it. Add a Team as well as yourself, so someone still can when you
              are away.
            </>,
            <>
              <strong>Review.</strong> Check everything, then create it. Use Back to change anything.
            </>,
          ]}
        </Steps>
      </GuideSection>

      <GuideSection guide="managed-certificates" id="key">
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Option</TableHead>
                <TableHead>What happens</TableHead>
                <TableHead>Best when</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {KEY_OPTIONS.map(([option, what, when]) => (
                <TableRow key={option}>
                  <TableCell className="font-medium whitespace-nowrap!">{option}</TableCell>
                  <TableCell className="whitespace-normal">{what}</TableCell>
                  <TableCell className="whitespace-normal">{when}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        <Alert>
          <TriangleAlertIcon />
          <AlertTitle>Keep the key safe</AlertTitle>
          <AlertDescription>
            The platform only ever gets the CSR, never the key. If you lose the key, the Certificate is no use: replace the key from the certificate's page and install the new
            Certificate.
          </AlertDescription>
        </Alert>
      </GuideSection>

      <GuideSection guide="managed-certificates" id="after">
        <ul className="flex flex-col gap-2">
          <li className="rounded-md border p-3">
            <strong>If you aren't an Organization Administrator</strong>, it becomes a Proposal. An Approver decides on it, and nothing is issued until they approve it.
          </li>
          <li className="rounded-md border p-3">
            <strong>From an ACME CA</strong>, the CA first checks that you control each name. The platform does this for you through your DNS, which an Organization
            Administrator sets up (see <GuideLink guide="dcv">Choosing how names are validated</GuideLink>).
          </li>
          <li className="rounded-md border p-3">
            <strong>From a Private CA</strong>, it is issued straight away.
          </li>
          <li className="rounded-md border p-3">
            <strong>Then install it.</strong> Open the certificate and choose “Download”. Put it on your server with the key you kept.
          </li>
        </ul>
        <span className="font-medium">Renewals</span>
        <p>
          By default it renews automatically 30 days before it expires, using the same key. Each time, you need to download the new Certificate and install it again. To hear
          when that happens, add yourself or your Team under Subscribers on the certificate's Notifications tab: nobody is told by default.
        </p>
      </GuideSection>

      <GuideSection guide="managed-certificates" id="status">
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Status</TableHead>
                <TableHead>What it means</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {STATUSES.map(([status, meaning]) => (
                <TableRow key={status}>
                  <TableCell className="font-medium whitespace-nowrap!">{status}</TableCell>
                  <TableCell className="whitespace-normal">{meaning}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        <p className="text-muted-foreground">Certificates kept by an Agent can also show “Agent offline”: the Agent must be back before it can renew.</p>
      </GuideSection>
    </GuidePage>
  );
}
