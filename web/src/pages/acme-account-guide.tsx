import { useParams } from "@tanstack/react-router";
import { AcmeCaTagBadge } from "@/components/acme-ca-tag";
import { GuideLink, GuidePage, GuideSection, Steps } from "@/components/guide";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { can } from "@/lib/api";
import { useAcmeCas } from "@/lib/acme-cas";
import { useOrg } from "@/lib/use-org";

const CUSTOM_FIELDS: [string, string][] = [
  ["Name", "What you call it here. It must be different from the other ACME CAs' names."],
  ["Directory URL", "The CA's ACME address, from its documentation. It starts with https://."],
  ["Tag", "Optional: Staging or Production, to show what it is for."],
  ["External Account Binding", "Only if the CA asks for it (see below)."],
  ["Contact email", "Optional: where the CA can contact you about the account."],
];

const MANAGE: [string, string][] = [
  ["Test", "Checks that the CA still accepts the account. Use it if certificates from that CA start failing."],
  ["Edit", "Changes a custom ACME CA's name, tag and contact email. Its directory URL and External Account Binding can't be changed: delete it and add it again instead."],
  ["Delete", "Removes a custom ACME CA and its account. You can't delete one that has issued anything, so its certificates keep working. Rename or retag it instead."],
];

/** How to set up ACME accounts: what one is, starting with Let's Encrypt, adding a custom ACME CA with or without External Account Binding, tags, and managing them. */
export function AcmeAccountGuidePage() {
  // Shown as a page or in the help panel over any of the Organization's pages.
  const orgId = useParams({ strict: false }).orgId ?? "";
  const org = useOrg(orgId);
  const allowed = org ? can(org, "acmeAccount", "read") : false;
  // The built-in ones as the platform has them, so the table can't fall out of step.
  const builtIn = useAcmeCas(orgId).data?.items.filter((ca) => ca.builtIn) ?? [];
  if (org && !allowed) return <p className="text-sm text-muted-foreground">Only Organization Administrators see the ACME accounts.</p>;
  return (
    <GuidePage
      guide="acme-accounts"
      title="Setting up ACME accounts"
      back={{ to: "/organizations/$orgId/acme-accounts", label: "ACME accounts", orgId }}
      lede="An ACME CA, such as Let's Encrypt, issues certificates for names on the internet. Before it will issue any, your Organization needs an account with it. The platform makes and looks after the account for you: you only choose the CA."
    >
      <GuideSection guide="acme-accounts" id="what">
        <ul className="flex list-disc flex-col gap-1.5 pl-5">
          <li>Each ACME CA needs its own account, and your Organization has one account per CA.</li>
          <li>Every Managed Certificate from that CA is issued under the account.</li>
          <li>The platform makes the account's key and keeps it safe. Nobody, including you, ever sees it.</li>
          <li>Without an account, certificates from that CA can't be issued. The ACME accounts page says which CAs have none yet.</li>
        </ul>
      </GuideSection>

      <GuideSection guide="acme-accounts" id="letsencrypt">
        <p>Let's Encrypt is built in, in two forms:</p>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ACME CA</TableHead>
                <TableHead>Directory URL</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {builtIn.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={2} className="text-muted-foreground">
                    Loading…
                  </TableCell>
                </TableRow>
              ) : (
                builtIn.map((ca) => (
                  <TableRow key={ca.id}>
                    <TableCell className="font-medium">
                      <span className="flex flex-wrap items-center gap-2">
                        {ca.name}
                        {ca.tag && <AcmeCaTagBadge tag={ca.tag} />}
                      </span>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{ca.directoryUrl}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
        <Steps>
          {[
            <>
              <strong>Register with Let's Encrypt Staging first.</strong> On the ACME accounts page, choose Register an account, pick it, and agree to its terms. Its
              certificates aren't trusted by browsers, but it lets you check everything works without hitting Let's Encrypt's limits.
            </>,
            <>
              <strong>Try a certificate.</strong> New Managed Certificates use Staging unless you choose otherwise. When one is issued, your DNS set-up works (see{" "}
              <GuideLink guide="dcv">Choosing how names are validated</GuideLink>).
            </>,
            <>
              <strong>Then register with Let's Encrypt Production</strong>, and choose it for real certificates.
            </>,
          ]}
        </Steps>
      </GuideSection>

      <GuideSection guide="acme-accounts" id="custom">
        <p>
          To use another ACME CA, such as a commercial CA or one your company runs, choose Register an account, then <strong>A custom ACME CA…</strong>, and fill in:
        </p>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Field</TableHead>
                <TableHead>What to enter</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {CUSTOM_FIELDS.map(([field, what]) => (
                <TableRow key={field}>
                  <TableCell className="font-medium [overflow-wrap:normal]!">{field}</TableCell>
                  <TableCell className="whitespace-normal">{what}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        <p>
          The account is registered as soon as you add the CA. If the CA turns it down, or can't be reached, you see why and nothing is saved, so you can correct it and try
          again.
        </p>
        <p className="text-muted-foreground">
          If the CA is only reachable inside your network, ask whoever runs the platform whether the platform can reach it. Names are validated the same way as for Let's
          Encrypt, through your DNS.
        </p>
      </GuideSection>

      <GuideSection guide="acme-accounts" id="eab">
        <p>
          Some CAs, mostly commercial ones, only accept accounts linked to an account you already have with them. They call this External Account Binding (EAB), and give you
          two values in their portal: a <strong>key id</strong> and an <strong>HMAC key</strong>.
        </p>
        <ul className="flex list-disc flex-col gap-1.5 pl-5">
          <li>Enter both, exactly as the CA shows them, in the External Account Binding step.</li>
          <li>The HMAC key is stored securely and never shown again.</li>
          <li>Some CAs let you use a pair only once. If registering fails, you may need a new pair from the CA.</li>
          <li>If the CA doesn't mention EAB, leave both blank.</li>
        </ul>
      </GuideSection>

      <GuideSection guide="acme-accounts" id="tags">
        <p>
          A tag, Staging or Production, says what an ACME CA is for. It is shown next to the CA's name, and you can filter Managed Certificates by it. It doesn't change how the CA
          issues: it is there so everyone can tell test certificates from real ones at a glance.
        </p>
      </GuideSection>

      <GuideSection guide="acme-accounts" id="manage">
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Action</TableHead>
                <TableHead>What it does</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {MANAGE.map(([action, what]) => (
                <TableRow key={action}>
                  <TableCell className="font-medium whitespace-nowrap!">{action}</TableCell>
                  <TableCell className="whitespace-normal">{what}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        <p className="text-muted-foreground">The built-in Let's Encrypt CAs can't be edited or deleted.</p>
      </GuideSection>
    </GuidePage>
  );
}
