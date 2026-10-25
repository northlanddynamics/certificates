import { useParams } from "@tanstack/react-router";
import { GuidePage, GuideSection, Steps } from "@/components/guide";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { can } from "@/lib/api";
import { useOrg } from "@/lib/use-org";

/** The guide's worked example: three rules, and what each of six names gets under them. */
const EXAMPLE_RULES: [string, string, string][] = [
  ["Zone example.com", "Direct", "DNS Provider “public-dns”"],
  ["Zone corp.example.com", "Delegated", "Validation Zone acme.example.net"],
  ["Name legacy.corp.example.com", "Direct", "DNS Provider “infoblox-internal”"],
];
const EXAMPLE_NAMES: [string, string, string][] = [
  ["www.example.com", "Zone example.com · Direct", "The only zone that contains it"],
  ["app.corp.example.com", "Zone corp.example.com · Delegated", "corp.example.com is closer to the name than example.com"],
  ["legacy.corp.example.com", "Name legacy.corp.example.com · Direct", "A name's own rule beats any zone"],
  ["*.legacy.corp.example.com", "Name legacy.corp.example.com · Direct", "A name's rule also covers its wildcard"],
  ["api.legacy.corp.example.com", "Zone corp.example.com · Delegated", "A name's rule doesn't cover names under it"],
  ["shop.example.org", "No rule · Direct", "Uses the DNS Provider that has example.org, if there is one"],
];

const FAILURES: [string, string][] = [
  ["No DNS Provider can add the record", "None of your DNS Providers has the name's domain, or the rule points to one that doesn't. Add a DNS Provider, or a rule."],
  ["The CNAME is missing or wrong (Delegated)", "Add the CNAME exactly as the platform shows it, in your domain's DNS. The Managed Certificate's overview shows each name's record and whether it is in place."],
  ["The record was added but couldn't be seen", "The DNS Provider may be internal DNS that the internet can't see, or DNS was slow. Relay the DNS Provider through an Agent, or use Delegated."],
  ["The DNS Provider refused the change, or couldn't be reached", "Use Test on the DNS Providers page to check its login details and that it can be reached."],
  ["A rule can't be saved", "Rules can't use a wildcard: use the base name instead. Or there is already a rule for that name or zone."],
];

/** How names are validated for an ACME CA: Direct or Delegated, which rule applies to a name, setting up delegation, and failures. */
export function DcvGuidePage() {
  // Shown as a page or in the help panel over any of the Organization's pages.
  const orgId = useParams({ strict: false }).orgId ?? "";
  const org = useOrg(orgId);
  if (org && !can(org, "dcvRule", "read")) return <p className="text-sm text-muted-foreground">Only Organization Administrators see how DCV is done.</p>;
  return (
    <GuidePage
      guide="dcv"
      title="Choosing how names are validated"
      back={{ to: "/organizations/$orgId/dcv", label: "Domain Control Validation", orgId }}
      lede="Before an ACME CA, such as Let's Encrypt, issues a Certificate, it checks that you control each name on it. The platform proves this for you by adding a short-lived DNS record. There are two ways it can do that, and DCV Rules choose which one each name uses. Private CAs don't need any of this."
    >
      <GuideSection guide="dcv" id="methods">
        <div className="grid gap-3 md:grid-cols-2">
          <div className="flex flex-col gap-2 rounded-lg border p-4">
            <span className="text-base font-semibold">Direct</span>
            <span className="rounded-md border bg-muted/50 p-2">The platform, through your DNS Provider</span>
            <span aria-hidden="true" className="text-center text-muted-foreground">↓ adds a TXT record</span>
            <span className="rounded-md border bg-muted/50 p-2">
              <code>_acme-challenge.www.example.com</code> in your domain's DNS
            </span>
            <span>
              <strong>Use it when</strong> the platform is allowed to change your domain's DNS. There is nothing else to set up.
            </span>
          </div>
          <div className="flex flex-col gap-2 rounded-lg border p-4">
            <span className="text-base font-semibold">Delegated</span>
            <span className="rounded-md border bg-muted/50 p-2">
              <code>_acme-challenge.app.corp.example.com</code>, a CNAME you add once
            </span>
            <span aria-hidden="true" className="text-center text-muted-foreground">↓ points to</span>
            <span className="rounded-md border bg-muted/50 p-2">
              <code>app.corp.example.com.acme.example.net</code> in a Validation Zone, where the platform adds the TXT record
            </span>
            <span>
              <strong>Use it when</strong> the platform must not change your domain's DNS. You add one CNAME record per name, once.
            </span>
          </div>
        </div>
      </GuideSection>

      <GuideSection guide="dcv" id="rules">
        <p>
          A rule is for one <strong>name</strong> (and its wildcard), or for a <strong>zone</strong>: a domain and everything under it. For each name, the platform uses:
        </p>
        <Steps>
          {[
            <>the name's own rule, if it has one;</>,
            <>
              otherwise, the rule for the zone <strong>closest</strong> to the name;
            </>,
            <>otherwise, Direct, through whichever DNS Provider has the name. If none does, validation fails.</>,
          ]}
        </Steps>
        <span className="font-medium">With these rules</span>
        <ExampleTable head={["Rule", "Method", "Through"]} rows={EXAMPLE_RULES} />
        <span className="font-medium">These names get</span>
        <ExampleTable head={["Name", "Decided by", "Why"]} rows={EXAMPLE_NAMES} mono />
        <p className="text-muted-foreground">Not sure? Type a name into “Which rule applies?” on the Domain Control Validation page.</p>
      </GuideSection>

      <GuideSection guide="dcv" id="delegate">
        <Steps>
          {[
            <>
              <strong>Add a Validation Zone</strong>: a zone on one of your DNS Providers that the platform may change, such as <code>acme.example.net</code>. Only this
              Organization uses it.
            </>,
            <>
              <strong>Add a rule</strong> for the names or zone you want to delegate, and choose that Validation Zone.
            </>,
            <>
              <strong>Add each CNAME</strong> to your domain's DNS, exactly as the platform shows it. A wildcard uses the same record as its base name.
            </>,
            <>
              <strong>Check it</strong>: the Managed Certificate's overview shows whether each CNAME is in place. Or check it yourself:
            </>,
          ]}
        </Steps>
        <pre className="overflow-x-auto rounded-md border bg-muted p-3 font-mono text-xs leading-relaxed">{"dig +short CNAME _acme-challenge.app.corp.example.com\n# app.corp.example.com.acme.example.net."}</pre>
      </GuideSection>

      <GuideSection guide="dcv" id="fails">
        <ExampleTable head={["Symptom", "Likely cause and fix"]} rows={FAILURES} />
      </GuideSection>
    </GuidePage>
  );
}

function ExampleTable({ head, rows, mono = false }: { head: string[]; rows: string[][]; mono?: boolean }) {
  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            {head.map((h) => (
              <TableHead key={h}>{h}</TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => (
            <TableRow key={row[0]}>
              {row.map((cell, i) => (
                <TableCell key={i} className={i === 0 && mono ? "font-mono text-xs" : "whitespace-normal"}>
                  {cell}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
