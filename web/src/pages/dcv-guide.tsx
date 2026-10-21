import { useParams } from "@tanstack/react-router";
import { GuidePage, GuideSection, Steps } from "@/components/guide";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { can } from "@/lib/api";
import { useOrg } from "@/lib/use-org";

const ROUTE = "/app/organizations/$orgId/dcv/guide";

/** The guide's worked example: three rules, and what each of six names gets under them. */
const EXAMPLE_RULES: [string, string, string][] = [
  ["Zone example.com", "Direct", "DNS Provider “public-dns”"],
  ["Zone corp.example.com", "Delegated", "Validation Zone acme.example.net"],
  ["Name legacy.corp.example.com", "Direct", "DNS Provider “infoblox-internal”"],
];
const EXAMPLE_NAMES: [string, string, string][] = [
  ["www.example.com", "Zone example.com · Direct", "The only zone that contains it"],
  ["app.corp.example.com", "Zone corp.example.com · Delegated", "corp.example.com is longer than example.com"],
  ["legacy.corp.example.com", "Name legacy.corp.example.com · Direct", "A name's own rule beats any zone"],
  ["*.legacy.corp.example.com", "Name legacy.corp.example.com · Direct", "A name's rule covers its wildcard"],
  ["api.legacy.corp.example.com", "Zone corp.example.com · Delegated", "A name's rule does not cover names beneath it"],
  ["shop.example.org", "No rule · Direct", "Whichever DNS Provider publishes example.org, if any"],
];

const FAILURES: [string, string][] = [
  ["No DNS Provider can publish the name", "No rule applies and none of your DNS Providers holds its zone, or the rule names one that does not. Add a DNS Provider, or a rule."],
  ["The CNAME is missing, or points elsewhere (Delegated)", "Create the CNAME exactly as the platform shows it, in the DNS of the name's own domain. The Managed Certificate's overview shows each name's record and whether DNS has it."],
  ["The record was published but did not show in DNS", "The DNS Provider writes to a zone the internet does not see, such as internal DNS, or DNS was slow to answer. Relay the provider through an Agent, or delegate the names."],
  ["The DNS Provider refused the update, or could not be reached", "Test the DNS Provider under DNS Providers: its credentials, and whether the platform (or its relay Agent) can reach it."],
  ["A rule cannot be saved", "Its domain is a wildcard (give the base name instead), or there is a rule for that name or zone already."],
];

/** How names are validated for an ACME CA: Direct or Delegated, which rule applies to a name, setting up delegation, and failures. */
export function DcvGuidePage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  if (org && !can(org, "dcvRule", "read")) return <p className="text-sm text-muted-foreground">Only Organization Administrators see how DCV is done.</p>;
  return (
    <GuidePage
      guide="dcv"
      title="Choosing how names are validated"
      back={{ to: "/organizations/$orgId/dcv", label: "Domain Control Validation", orgId }}
      lede="Before an ACME CA issues a Certificate, it asks for proof that you control each name: a TXT record at _acme-challenge.<name>. The platform publishes that record for you, in one of two ways, and DCV Rules choose which for each name. Private CAs need none of this."
    >
      <GuideSection guide="dcv" id="methods">
        <div className="grid gap-3 md:grid-cols-2">
          <div className="flex flex-col gap-2 rounded-lg border p-4">
            <span className="text-base font-semibold">Direct</span>
            <span className="rounded-md border bg-muted/50 p-2">Platform, through a DNS Provider</span>
            <span aria-hidden="true" className="text-center text-muted-foreground">↓ writes TXT</span>
            <span className="rounded-md border bg-muted/50 p-2">
              <code>_acme-challenge.www.example.com</code> in the domain's own zone
            </span>
            <span>
              <strong>Use when</strong> the platform may write to the domain's zone. Nothing to set up per name.
            </span>
          </div>
          <div className="flex flex-col gap-2 rounded-lg border p-4">
            <span className="text-base font-semibold">Delegated</span>
            <span className="rounded-md border bg-muted/50 p-2">
              <code>_acme-challenge.app.corp.example.com</code> CNAME, made once by you
            </span>
            <span aria-hidden="true" className="text-center text-muted-foreground">↓ points to</span>
            <span className="rounded-md border bg-muted/50 p-2">
              <code>app.corp.example.com.acme.example.net</code> in a Validation Zone, where the platform writes the TXT
            </span>
            <span>
              <strong>Use when</strong> the platform must not write to the domain's zone. One CNAME per name, then nothing more.
            </span>
          </div>
        </div>
      </GuideSection>

      <GuideSection guide="dcv" id="rules">
        <p>
          A rule is for one <strong>name</strong> (and its wildcard) or for a <strong>zone</strong> (the name and everything beneath it). For each name, the platform takes:
        </p>
        <Steps>
          {[
            <>the name's own rule, if it has one;</>,
            <>
              else the rule of the <strong>longest</strong> zone that contains it;
            </>,
            <>else no rule: Direct, through whichever DNS Provider publishes the name. If none does, DCV fails.</>,
          ]}
        </Steps>
        <span className="font-medium">With these rules</span>
        <ExampleTable head={["Rule", "Method", "Through"]} rows={EXAMPLE_RULES} />
        <span className="font-medium">These names get</span>
        <ExampleTable head={["Name", "Decided by", "Why"]} rows={EXAMPLE_NAMES} mono />
        <p className="text-muted-foreground">Not sure? Type any name into “Which rule applies?” on the Domain Control Validation page.</p>
      </GuideSection>

      <GuideSection guide="dcv" id="delegate">
        <Steps>
          {[
            <>
              <strong>Add a Validation Zone</strong>: a zone the platform may write to, on one of your DNS Providers, such as <code>acme.example.net</code>. It belongs to this
              Organization alone.
            </>,
            <>
              <strong>Add a rule</strong> for the names or zone to delegate, choosing that Validation Zone.
            </>,
            <>
              <strong>Create each CNAME</strong> in the name's own DNS, exactly as the platform shows it. A wildcard uses its base name's record.
            </>,
            <>
              <strong>Check it</strong>: the Managed Certificate's overview says whether DNS has each CNAME, or from anywhere on the internet:
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
