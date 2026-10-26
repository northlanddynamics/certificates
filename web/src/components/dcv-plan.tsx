import { useQueries } from "@tanstack/react-query";
import { CopyButton } from "@/components/copy-button";
import { GuideLink } from "@/components/guide";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, type DcvPreview } from "@/lib/api";

/** A CNAME record as a zone file writes it. */
export const cnameLine = (cname: NonNullable<DcvPreview["cname"]>) => `${cname.name}. CNAME ${cname.value}.`;

/** Which rule decided, in words. */
const decidedBy = (plan: DcvPreview) => (plan.rule ? `${plan.rule.scope === "name" ? "Name" : "Zone"} ${plan.rule.domain}` : "No rule applies");

/** Whether DNS has the CNAME a Delegated name needs, as the platform's resolvers last saw it. */
function DnsStatus({ dns }: { dns: DcvPreview["dns"] }) {
  if (dns === undefined || dns === null) return <span className="text-muted-foreground">—</span>;
  if (dns.matches) return <Badge variant="outline">Found</Badge>;
  return (
    <span className="flex flex-col gap-0.5">
      <Badge variant="destructive">{dns.pointsTo.length > 0 ? "Points elsewhere" : "Not found"}</Badge>
      {dns.pointsTo.length > 0 && <span className="break-all font-mono text-xs text-muted-foreground">{dns.pointsTo.join(", ")}</span>}
    </span>
  );
}

/** What DCV will do for one name: the method, the rule that decides, where the record is written, and any CNAME to create. */
export function DcvPlanSummary({ orgId, plan }: { orgId: string; plan: DcvPreview }) {
  const through = plan.validationZone
    ? `Validation Zone ${plan.validationZone.name}`
    : plan.dnsProvider
      ? `DNS Provider ${plan.dnsProvider.name}`
      : "No DNS Provider can publish it, so DCV would fail";
  return (
    <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 rounded-md border bg-background p-3 text-sm">
      <dt className="text-muted-foreground">Method</dt>
      <dd className="font-medium">{plan.method === "delegated" ? "Delegated" : "Direct"}</dd>
      <dt className="text-muted-foreground">Decided by</dt>
      <dd>{decidedBy(plan)}</dd>
      <dt className="text-muted-foreground">Written through</dt>
      <dd className={plan.dnsProvider ? undefined : "text-destructive"}>{through}</dd>
      <dt className="text-muted-foreground">Challenge at</dt>
      <dd className="break-all font-mono text-xs">{plan.challengeName}</dd>
      {plan.cname && (
        <>
          <dt className="text-muted-foreground">Create this CNAME</dt>
          <dd className="flex items-center gap-1">
            <code className="break-all text-xs">{cnameLine(plan.cname)}</code>
            <CopyButton text={cnameLine(plan.cname)} label="Copy the CNAME record" />
          </dd>
          <dt className="text-muted-foreground">In DNS now</dt>
          <dd>
            <DnsStatus dns={plan.dns} />
          </dd>
        </>
      )}
      {!plan.dnsProvider && (
        <dd className="col-span-2">
          <GuideLink orgId={orgId} guide="dcv" section="fails">
            When validation fails
          </GuideLink>
        </dd>
      )}
    </dl>
  );
}

/**
 * How each of a Managed Certificate's names is validated, with the CNAMEs to create for the Delegated ones and whether
 * DNS has them yet, so they can be made before an Issuance needs them. A wildcard shares its base name's record.
 */
export function DcvByName({ orgId, names }: { orgId: string; names: string[] }) {
  const plans = useQueries({
    queries: names.map((name) => ({ queryKey: ["dcv-preview", orgId, name], queryFn: () => api.dcvPreview(orgId, name, { lookup: true }) })),
  });
  const loaded = plans.flatMap((p) => (p.data ? [p.data] : []));
  const cnames = [...new Map(loaded.flatMap((p) => (p.cname ? [[p.cname.name, p.cname] as const] : []))).values()];
  const lines = cnames.map(cnameLine).join("\n");
  return (
    <div className="flex flex-col gap-3">
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Method</TableHead>
              <TableHead>Decided by</TableHead>
              <TableHead>Record you create</TableHead>
              <TableHead>In DNS</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {names.map((name, i) => {
              const plan = plans[i]?.data;
              return (
                <TableRow key={name}>
                  <TableCell className="font-mono text-xs">{name}</TableCell>
                  {plan ? (
                    <>
                      <TableCell>{plan.method === "delegated" ? "Delegated" : "Direct"}</TableCell>
                      <TableCell className="whitespace-normal">{decidedBy(plan)}</TableCell>
                      <TableCell className="whitespace-normal">
                        {plan.cname ? (
                          <code className="break-all text-xs">{cnameLine(plan.cname)}</code>
                        ) : plan.dnsProvider ? (
                          <span className="text-muted-foreground">None: written through {plan.dnsProvider.name}</span>
                        ) : (
                          <span className="text-destructive">No DNS Provider can publish it</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <DnsStatus dns={plan.dns} />
                      </TableCell>
                    </>
                  ) : (
                    <TableCell colSpan={4} className="text-muted-foreground">
                      {plans[i]?.error ? plans[i].error.message : "Loading…"}
                    </TableCell>
                  )}
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {cnames.length > 0 && (
          <Button type="button" variant="outline" size="sm" onClick={() => void navigator.clipboard.writeText(lines)}>
            Copy {cnames.length === 1 ? "the CNAME" : `all ${cnames.length} CNAMEs`} as zone-file lines
          </Button>
        )}
        <Button type="button" variant="outline" size="sm" disabled={plans.some((p) => p.isFetching)} onClick={() => plans.forEach((p) => void p.refetch())}>
          Check DNS again
        </Button>
        <GuideLink orgId={orgId} guide="dcv" section="delegate" className="text-sm font-medium underline underline-offset-4 hover:text-primary">
          Setting up delegation
        </GuideLink>
      </div>
    </div>
  );
}
