import { useMutation, useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { BookOpenIcon, PlusIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { DcvPlanSummary } from "@/components/dcv-plan";
import { GuideLink } from "@/components/guide";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldSet, FieldLegend, FieldTitle } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, can, type DcvRule, type DnsProvider, type ValidationZone } from "@/lib/api";
import { useAction } from "@/lib/use-action";
import { useOrg } from "@/lib/use-org";
import { WRAPPING_TABLE } from "@/lib/utils";

const ROUTE = "/app/organizations/$orgId/dcv";
const ANY_PROVIDER = "any";

/** The rules in the order they win: names' own, then zones from the longest. */
export const byPrecedence = (rules: DcvRule[]) =>
  [...rules].sort((a, b) => (a.scope === b.scope ? b.domain.length - a.domain.length || a.domain.localeCompare(b.domain) : a.scope === "name" ? -1 : 1));

/**
 * How the Organization proves control of names to an ACME CA: its DCV Rules, which choose Direct or Delegated DCV for a
 * name or a zone, the Validation Zones Delegated names point into, and a check of what applies to any name. Only those
 * who may read DCV Rules see it.
 */
export function DcvPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const allowed = org ? can(org, "dcvRule", "read") : false;
  const rules = useQuery({ queryKey: ["dcv-rules", orgId], queryFn: () => api.dcvRules(orgId), enabled: allowed });
  const zones = useQuery({ queryKey: ["validation-zones", orgId], queryFn: () => api.validationZones(orgId), enabled: allowed });
  const providers = useQuery({ queryKey: ["dns-providers", orgId], queryFn: () => api.dnsProviders(orgId), enabled: allowed && can(org!, "dnsProvider", "read") });
  const providerName = (id: string | null) => (id === null ? null : (providers.data?.items.find((p) => p.id === id)?.name ?? "A DNS Provider"));
  const zoneName = (id: string | null) => zones.data?.items.find((z) => z.id === id)?.name ?? "A Validation Zone";

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">Domain Control Validation</h1>
        <Button variant="outline" asChild>
          <GuideLink orgId={orgId} guide="dcv" className="">
            <BookOpenIcon />
            How DCV is chosen
          </GuideLink>
        </Button>
      </div>
      <p className="text-sm text-muted-foreground">
        How the platform proves control of each name to an ACME CA: by writing the challenge record in the name's own zone (Direct), or in a Validation Zone that the name's{" "}
        <code>_acme-challenge</code> CNAME points into (Delegated). A name's own rule wins, then the longest zone; with none, DCV is Direct through whichever DNS Provider
        publishes the name. Private CAs need none of this.
      </p>
      {org && !allowed ? (
        <p className="text-sm text-muted-foreground">Only Organization Administrators see how DCV is done.</p>
      ) : (
        <>
          <RuleCheck orgId={orgId} />

          <section aria-labelledby="dcv-rules" className="flex flex-col gap-3">
            <div className="flex items-center justify-between gap-2">
              <h2 id="dcv-rules" className="text-base font-semibold">
                DCV Rules
              </h2>
              {org && can(org, "dcvRule", "create") && <NewRuleDialog orgId={orgId} zones={zones.data?.items ?? []} providers={providers.data?.items ?? []} />}
            </div>
            <div className={`rounded-md border ${WRAPPING_TABLE}`}>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Applies to</TableHead>
                    <TableHead>Method</TableHead>
                    <TableHead>Through</TableHead>
                    <TableHead>
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rules.data && rules.data.items.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={4} className="whitespace-normal text-muted-foreground">
                        No rule yet: every name is validated Direct, through whichever DNS Provider publishes it.
                      </TableCell>
                    </TableRow>
                  )}
                  {byPrecedence(rules.data?.items ?? []).map((rule) => (
                    <TableRow key={rule.id}>
                      <TableCell className="whitespace-normal">
                        {rule.scope === "name" ? "Name" : "Zone"} <code>{rule.domain}</code>{" "}
                        <span className="text-muted-foreground">{rule.scope === "name" ? "and its wildcard" : "and everything beneath it"}</span>
                      </TableCell>
                      <TableCell>{rule.method === "delegated" ? "Delegated" : "Direct"}</TableCell>
                      <TableCell>
                        {rule.method === "delegated" ? (
                          <code>{zoneName(rule.validationZoneId)}</code>
                        ) : (
                          (providerName(rule.dnsProviderId) ?? <span className="text-muted-foreground">Whichever publishes the name</span>)
                        )}
                      </TableCell>
                      <TableCell className="text-right">{org && can(org, "dcvRule", "delete") && <RemoveRule orgId={orgId} rule={rule} />}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            {rules.error && <p className="text-sm text-destructive">{rules.error.message}</p>}
          </section>

          <section aria-labelledby="validation-zones" className="flex flex-col gap-3">
            <div className="flex items-center justify-between gap-2">
              <h2 id="validation-zones" className="text-base font-semibold">
                Validation Zones
              </h2>
              {org && can(org, "validationZone", "create") && <NewZoneDialog orgId={orgId} providers={providers.data?.items ?? []} />}
            </div>
            <div className={`rounded-md border ${WRAPPING_TABLE}`}>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Zone</TableHead>
                    <TableHead>On DNS Provider</TableHead>
                    <TableHead>Used by</TableHead>
                    <TableHead>
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {zones.data && zones.data.items.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={4} className="whitespace-normal text-muted-foreground">
                        None yet. Add one to delegate names: a zone the platform may write to, on one of your DNS Providers.
                      </TableCell>
                    </TableRow>
                  )}
                  {zones.data?.items.map((zone) => {
                    const using = rules.data?.items.filter((r) => r.validationZoneId === zone.id).length ?? 0;
                    return (
                      <TableRow key={zone.id}>
                        <TableCell>
                          <code>{zone.name}</code>
                        </TableCell>
                        <TableCell>{providerName(zone.dnsProviderId)}</TableCell>
                        <TableCell>{using === 0 ? <span className="text-muted-foreground">No rule</span> : using === 1 ? "1 rule" : `${using} rules`}</TableCell>
                        <TableCell className="text-right">{org && can(org, "validationZone", "delete") && <RemoveZone orgId={orgId} zone={zone} inUse={using > 0} />}</TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
            {zones.error && <p className="text-sm text-destructive">{zones.error.message}</p>}
          </section>
        </>
      )}
    </div>
  );
}

/** “Which rule applies?”: what DCV will do for any name, the record a Delegated one needs, and whether DNS has it yet. */
function RuleCheck({ orgId }: { orgId: string }) {
  const [name, setName] = useState("");
  const check = useMutation({ mutationFn: (asked: string) => api.dcvPreview(orgId, asked, { lookup: true }) });
  return (
    <section aria-labelledby="rule-check" className="flex flex-col gap-3 rounded-lg border bg-muted/40 p-4">
      <h2 id="rule-check" className="text-base font-semibold">
        Which rule applies?
      </h2>
      <form
        className="flex flex-wrap gap-2"
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          if (name.trim()) check.mutate(name.trim());
        }}
      >
        <label htmlFor="dcv-check-name" className="sr-only">
          Name to check
        </label>
        <Input id="dcv-check-name" className="max-w-md flex-1 font-mono" placeholder="app.example.com or *.example.com" value={name} onChange={(e) => setName(e.target.value)} />
        <Button type="submit" disabled={!name.trim() || check.isPending}>
          Check
        </Button>
      </form>
      {check.error && <p className="text-sm text-destructive">{check.error.message}</p>}
      {check.data && <DcvPlanSummary orgId={orgId} plan={check.data} />}
    </section>
  );
}

function NewRuleDialog({ orgId, zones, providers }: { orgId: string; zones: ValidationZone[]; providers: DnsProvider[] }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <PlusIcon />
          Add rule
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Add a DCV Rule</DialogTitle>
          <DialogDescription>A name's own rule beats any zone's, and the longest zone beats the others.</DialogDescription>
        </DialogHeader>
        {open && <NewRuleForm orgId={orgId} zones={zones} providers={providers} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function NewRuleForm({ orgId, zones, providers, onDone }: { orgId: string; zones: ValidationZone[]; providers: DnsProvider[]; onDone: () => void }) {
  const [scope, setScope] = useState<DcvRule["scope"]>("zone");
  const [domain, setDomain] = useState("");
  const [method, setMethod] = useState<DcvRule["method"]>("delegated");
  const [providerId, setProviderId] = useState(ANY_PROVIDER);
  const [zoneId, setZoneId] = useState(zones[0]?.id ?? "");
  const create = useAction(
    () =>
      api.createDcvRule(orgId, {
        scope,
        domain: domain.trim(),
        method,
        dnsProviderId: method === "direct" && providerId !== ANY_PROVIDER ? providerId : null,
        validationZoneId: method === "delegated" ? zoneId : null,
      }),
    ["dcv-rules"],
    onDone,
  );
  const wildcard = domain.trim().startsWith("*");
  const ready = domain.trim() !== "" && !wildcard && (method === "direct" || zoneId !== "");
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        if (ready) create.mutate(undefined);
      }}
    >
      <FieldGroup>
        <Choice<DcvRule["scope"]>
          legend="Applies to"
          id="rule-scope"
          value={scope}
          onChange={setScope}
          options={[
            ["zone", "A zone", "The name and everything beneath it."],
            ["name", "One name", "That name and its wildcard only, not names beneath it."],
          ]}
        />
        <Field data-invalid={wildcard}>
          <FieldLabel htmlFor="rule-domain">{scope === "zone" ? "Zone" : "Name"}</FieldLabel>
          <Input id="rule-domain" className="font-mono" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder={scope === "zone" ? "corp.example.com" : "legacy.corp.example.com"} />
          {wildcard && <FieldError>Give the base name: a rule for a name covers its wildcard too.</FieldError>}
        </Field>
        <Choice<DcvRule["method"]>
          legend="Method"
          id="rule-method"
          value={method}
          onChange={setMethod}
          options={[
            ["delegated", "Delegated", "Through a Validation Zone. You create one CNAME per name, once."],
            ["direct", "Direct", "In the name's own zone, through a DNS Provider."],
          ]}
        />
        {method === "delegated" ? (
          <Field>
            <FieldLabel htmlFor="rule-zone">Validation Zone</FieldLabel>
            <Select value={zoneId} onValueChange={setZoneId}>
              <SelectTrigger id="rule-zone" className="w-full">
                <SelectValue placeholder="No Validation Zone yet" />
              </SelectTrigger>
              <SelectContent>
                {zones.map((z) => (
                  <SelectItem key={z.id} value={z.id}>
                    {z.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {zones.length === 0 && <FieldError>Add a Validation Zone first.</FieldError>}
          </Field>
        ) : (
          <Field>
            <FieldLabel htmlFor="rule-provider">DNS Provider</FieldLabel>
            <Select value={providerId} onValueChange={setProviderId}>
              <SelectTrigger id="rule-provider" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ANY_PROVIDER}>Whichever publishes the name</SelectItem>
                {providers.map((p) => (
                  <SelectItem key={p.id} value={p.id}>
                    {p.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FieldDescription>Name one to write through it even where another also holds the zone.</FieldDescription>
          </Field>
        )}
      </FieldGroup>
      {create.error && <p className="text-sm text-destructive">{create.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={!ready || create.isPending}>
          Add rule
        </Button>
      </DialogFooter>
    </form>
  );
}

/** One of a few options, each a title and a line on what it means. */
function Choice<T extends string>({ legend, id, value, onChange, options }: { legend: string; id: string; value: T; onChange: (value: T) => void; options: [T, string, string][] }) {
  return (
    <FieldSet>
      <FieldLegend variant="label">{legend}</FieldLegend>
      <RadioGroup value={value} onValueChange={(v) => onChange(v as T)} className="grid gap-2 sm:grid-cols-2">
        {options.map(([option, title, description]) => (
          <FieldLabel key={option} htmlFor={`${id}-${option}`}>
            <Field orientation="horizontal">
              <FieldContent>
                <FieldTitle>{title}</FieldTitle>
                <FieldDescription>{description}</FieldDescription>
              </FieldContent>
              <RadioGroupItem value={option} id={`${id}-${option}`} />
            </Field>
          </FieldLabel>
        ))}
      </RadioGroup>
    </FieldSet>
  );
}

function RemoveRule({ orgId, rule }: { orgId: string; rule: DcvRule }) {
  const [open, setOpen] = useState(false);
  const remove = useAction(() => api.deleteDcvRule(orgId, rule.id), ["dcv-rules"], () => setOpen(false));
  return (
    <>
      <Button variant="ghost" size="sm" aria-label={`Remove the rule for ${rule.domain}`} onClick={() => setOpen(true)}>
        Remove
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title={`Remove the rule for ${rule.domain}?`}
        description="Its names follow the next rule that covers them from the next Issuance on, or Direct DCV through whichever DNS Provider publishes them. Issuances under way keep the rule they began with."
        confirmLabel="Remove rule"
        pending={remove.isPending}
        error={remove.error}
        onConfirm={() => remove.mutate(undefined)}
      />
    </>
  );
}

function RemoveZone({ orgId, zone, inUse }: { orgId: string; zone: ValidationZone; inUse: boolean }) {
  const [open, setOpen] = useState(false);
  const remove = useAction(() => api.deleteValidationZone(orgId, zone.id), ["validation-zones"], () => setOpen(false));
  return (
    <>
      <Button variant="ghost" size="sm" disabled={inUse} title={inUse ? "A rule delegates through it: remove or change that rule first" : undefined} aria-label={`Remove ${zone.name}`} onClick={() => setOpen(true)}>
        Remove
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title={`Remove ${zone.name}?`}
        description="The platform stops using it. The records in it, and the CNAMEs pointing into it, are not touched."
        confirmLabel="Remove zone"
        pending={remove.isPending}
        error={remove.error}
        onConfirm={() => remove.mutate(undefined)}
      />
    </>
  );
}

function NewZoneDialog({ orgId, providers }: { orgId: string; providers: DnsProvider[] }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [providerId, setProviderId] = useState("");
  const create = useAction(
    () => api.createValidationZone(orgId, { name: name.trim(), dnsProviderId: providerId }),
    ["validation-zones"],
    () => {
      setOpen(false);
      setName("");
    },
  );
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline">
          <PlusIcon />
          Add zone
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Add a Validation Zone</DialogTitle>
          <DialogDescription>A zone the platform may write challenge records to, on one of your DNS Providers. It belongs to this Organization alone.</DialogDescription>
        </DialogHeader>
        <form
          className="flex flex-col gap-4"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            if (name.trim() && providerId) create.mutate(undefined);
          }}
        >
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="zone-name">Zone</FieldLabel>
              <Input id="zone-name" className="font-mono" value={name} onChange={(e) => setName(e.target.value)} placeholder="acme.example.net" />
            </Field>
            <Field>
              <FieldLabel htmlFor="zone-provider">DNS Provider</FieldLabel>
              <Select value={providerId} onValueChange={setProviderId}>
                <SelectTrigger id="zone-provider" className="w-full">
                  <SelectValue placeholder="Choose the DNS Provider that holds it" />
                </SelectTrigger>
                <SelectContent>
                  {providers.map((p) => (
                    <SelectItem key={p.id} value={p.id}>
                      {p.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {providers.length === 0 && <FieldError>Add a DNS Provider first, under DNS Providers.</FieldError>}
            </Field>
          </FieldGroup>
          {create.error && <p className="text-sm text-destructive">{create.error.message}</p>}
          <DialogFooter>
            <DialogClose asChild>
              <Button type="button" variant="outline">
                Cancel
              </Button>
            </DialogClose>
            <Button type="submit" disabled={!name.trim() || !providerId || create.isPending}>
              Add zone
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

