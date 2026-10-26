import { useParams } from "@tanstack/react-router";
import { CommandBlock } from "@/components/command-block";
import { GuideLink, GuidePage, GuideSection, Steps } from "@/components/guide";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { can } from "@/lib/api";
import { useOrg } from "@/lib/use-org";

const KINDS: [string, string, string][] = [
  ["RFC 2136", "BIND, PowerDNS, Knot, and other DNS servers and appliances that accept dynamic updates signed with a key.", "A TSIG key"],
  ["Infoblox", "An Infoblox grid, through its REST API (WAPI).", "A user name and password"],
];

const BIND_KEY = `tsig-keygen -a hmac-sha256 certificates`;

const BIND_ZONE = `zone "example.com" {
    // ... your existing settings ...
    update-policy {
        grant certificates subdomain example.com. TXT;
    };
};`;

const RFC2136_FIELDS: [string, string][] = [
  ["Server", "Your DNS server's name or address, such as ns1.example.com."],
  ["Port", "53, unless your server listens elsewhere. The platform connects over TCP."],
  ["Zone", "The zone it may change, such as example.com. One DNS Provider covers one zone."],
  ["TSIG key name", "The key's name in the server's settings: certificates, above."],
  ["TSIG algorithm", "The one the key was made with: hmac-sha256, above."],
  ["TSIG key secret", "The secret part of the key, exactly as the server's settings show it."],
];

const INFOBLOX_FIELDS: [string, string][] = [
  ["WAPI URL", "Your grid's API address, with the version, such as https://gm.example.com/wapi/v2.12."],
  ["Zone", "The zone it may change, such as example.com."],
  ["DNS view", "The view the zone is in. Usually default."],
  ["Grid certificate authority", "Only if the grid's HTTPS certificate isn't from a public CA: its root certificate (PEM)."],
  ["WAPI user and password", "The user you made for the platform."],
];

const FAILURES: [string, string][] = [
  ["It can't be reached", "The platform can't connect to the server. Check the address and port, and that your firewall allows it. If the server is only inside your network, relay it through an Agent."],
  ["It was refused", "The server turned the change down. Check the key name, algorithm and secret (or user and password), and that they may change TXT records in this zone."],
  ["A name isn't inside the zone", "The record belongs to another zone. Add a DNS Provider for that zone."],
  ["The test record wasn't removed", "The message names the TXT record left behind. Delete it by hand, then fix what stopped it being removed."],
];

/** How to connect a DNS Provider: what it is for, setting up RFC 2136 and Infoblox, relaying through Agents and testing. */
export function DnsProviderGuidePage() {
  // Shown as a page or in the help panel over any of the Organization's pages.
  const orgId = useParams({ strict: false }).orgId ?? "";
  const org = useOrg(orgId);
  if (org && !can(org, "dnsProvider", "read")) return <p className="text-sm text-muted-foreground">Only Organization Administrators see the DNS Providers.</p>;
  return (
    <GuidePage
      guide="dns-providers"
      title="Connecting a DNS Provider"
      back={{ to: "/organizations/$orgId/dns-providers", label: "DNS Providers", orgId }}
      lede="A DNS Provider lets the platform make small, short-lived changes to your DNS. ACME CAs such as Let's Encrypt need these to check that you control a name before they issue a Certificate for it."
    >
      <GuideSection guide="dns-providers" id="what">
        <p>
          Before each Certificate, the platform adds a TXT record named <code>_acme-challenge.</code> plus the name, waits for the CA to check it, then removes it. Nothing else in
          your DNS is touched. Private CAs don't need any of this.
        </p>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Kind</TableHead>
                <TableHead>For</TableHead>
                <TableHead>Signs in with</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {KINDS.map(([kind, what, auth]) => (
                <TableRow key={kind}>
                  <TableCell className="font-medium whitespace-nowrap!">{kind}</TableCell>
                  <TableCell className="whitespace-normal">{what}</TableCell>
                  <TableCell className="whitespace-normal">{auth}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        <p className="text-muted-foreground">
          The kind can't be changed later. If the platform mustn't change your domain's DNS at all, use Delegated validation instead (see{" "}
          <GuideLink guide="dcv" section="methods">
            Choosing how names are validated
          </GuideLink>
          ).
        </p>
      </GuideSection>

      <GuideSection guide="dns-providers" id="rfc2136">
        <span className="font-medium">On your DNS server (BIND shown)</span>
        <Steps>
          {[
            <>Make a key for the platform. This prints a key block: add it to your server's settings, and keep the secret for later.</>,
            <>Let that key change TXT records in the zone, and nothing else. Then reload the server.</>,
          ]}
        </Steps>
        <CommandBlock code={BIND_KEY} shell="bash" label="Make a TSIG key" />
        <CommandBlock code={BIND_ZONE} shell="bash" label="Allow the key to change TXT records" />
        <span className="font-medium">Here</span>
        <p>Add a DNS Provider, choose RFC 2136, and fill in:</p>
        <FieldTable rows={RFC2136_FIELDS} />
      </GuideSection>

      <GuideSection guide="dns-providers" id="infoblox">
        <span className="font-medium">In Infoblox</span>
        <Steps>
          {[
            <>
              Create an admin group for the platform that may use the <strong>API</strong>, with read and write permission on <strong>TXT records</strong> in the zone.
            </>,
            <>Create a user in that group, with a strong password.</>,
          ]}
        </Steps>
        <span className="font-medium">Here</span>
        <p>Add a DNS Provider, choose Infoblox, and fill in:</p>
        <FieldTable rows={INFOBLOX_FIELDS} />
        <p className="text-muted-foreground">The password, like an RFC 2136 secret, is stored encrypted and never shown again. You can replace it at any time.</p>
      </GuideSection>

      <GuideSection guide="dns-providers" id="relay">
        <p>
          The platform connects to your DNS server from the internet. If the server is only reachable inside your network, choose one or more{" "}
          <GuideLink guide="agents">Agents</GuideLink> in the “Where should its operations run?” step. An Agent that is online then makes the changes for the platform.
        </p>
        <ul className="flex list-disc flex-col gap-1.5 pl-5">
          <li>Choose two Agents on different servers, so changes still work when one is offline.</li>
          <li>Each chosen Agent must be able to reach the DNS server.</li>
          <li>The Agent is given the secret only for each change, and keeps nothing.</li>
        </ul>
        <p className="text-muted-foreground">
          If the DNS server can be changed but isn't what the internet sees, such as internal-only DNS, the CA can't see the record. Use Delegated validation for those names.
        </p>
      </GuideSection>

      <GuideSection guide="dns-providers" id="test">
        <p>
          Choose <strong>Test</strong> on the DNS Provider's row. It adds a test TXT record at <code>_acme-challenge.</code> plus the zone, then removes it. If that works,
          Certificates can be validated through it.
        </p>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>If the test fails because</TableHead>
                <TableHead>Do this</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {FAILURES.map(([says, fix]) => (
                <TableRow key={says}>
                  <TableCell className="whitespace-normal">{says}</TableCell>
                  <TableCell className="whitespace-normal">{fix}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </GuideSection>
    </GuidePage>
  );
}

function FieldTable({ rows }: { rows: [string, string][] }) {
  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Field</TableHead>
            <TableHead>What to enter</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map(([field, what]) => (
            <TableRow key={field}>
              <TableCell className="font-medium [overflow-wrap:normal]!">{field}</TableCell>
              <TableCell className="whitespace-normal">{what}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
