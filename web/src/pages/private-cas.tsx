import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { BookOpenIcon, ChevronRightIcon, PlusIcon } from "lucide-react";
import { useState } from "react";
import { GuideLink } from "@/components/guide";
import { ActionLabel, PageHeader } from "@/components/page-header";
import { STEPPED_DIALOG } from "@/components/stepped-form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api, can } from "@/lib/api";
import { CA_KIND_LABELS, allAttention, caRows, type Attention, type CaKind, type CaRow, type Health } from "@/lib/private-ca-list";
import { useOrg } from "@/lib/use-org";
import { ADD_ADCS_CA_DESCRIPTION, AdcsCaWizard, useAdcsAgents } from "./adcs-ca-controls";
import { CREATE_DESCRIPTION, CreatePrivateCaForm, caDate } from "./private-ca-controls";

const ROUTE = "/app/organizations/$orgId/private-cas";

/** The page of one CA, by its kind. */
export const caUrl = (orgId: string, kind: CaKind, id: string) => `/organizations/${orgId}/private-cas/${kind}/${id}`;

export const KindBadge = ({ kind }: { kind: CaKind }) => <Badge variant="outline">{CA_KIND_LABELS[kind]}</Badge>;

const HEALTH_VARIANT = { ok: "success", warn: "warning", bad: "destructive", neutral: "neutral" } as const;
export const HealthBadge = ({ health }: { health: Health }) => <Badge variant={HEALTH_VARIANT[health.tone]}>{health.label}</Badge>;

/**
 * The Organization's Private CAs, of both kinds: those the platform runs, whose keys it holds only in a KMS, and its
 * Active Directory Certificate Services CAs, which it reaches only through Windows Agents. What needs an Organization
 * Administrator comes first; each CA opens on a page of its own.
 */
export function PrivateCasPage() {
  const { orgId } = useParams({ from: ROUTE });
  const { kind } = useSearch({ from: ROUTE });
  const navigate = useNavigate({ from: "/organizations/$orgId/private-cas" });
  const org = useOrg(orgId);
  const may = (resource: string, action: string) => (org ? can(org, resource, action) : false);
  const seePlatform = may("privateCa", "read");
  const seeAdcs = may("adcsCa", "read");
  const platform = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId), enabled: seePlatform });
  const adcs = useQuery({ queryKey: ["adcs-cas", orgId], queryFn: () => api.adcsCas(orgId), enabled: seeAdcs });
  const platformCas = platform.data?.items ?? [];
  const adcsCas = adcs.data?.items ?? [];
  const now = new Date();
  const rows = caRows(platformCas, adcsCas, now);
  const shown = rows.filter((r) => !kind || r.kind === kind);
  // What needs doing is for those who may do it.
  const attention = allAttention(may("privateCa", "update") ? platformCas : [], may("adcsCa", "update") ? adcsCas : [], now);
  const pending = (seePlatform && platform.isPending) || (seeAdcs && adcs.isPending);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Private CAs"
        guide="private-cas"
        action={
          <>
            {seePlatform && (
              <Button variant="outline" asChild>
                <GuideLink orgId={orgId} guide="private-cas" className="">
                  <BookOpenIcon />
                  <ActionLabel>Publishing guide</ActionLabel>
                </GuideLink>
              </Button>
            )}
            <AddPrivateCaDialog orgId={orgId} platform={may("privateCa", "create")} adcs={may("adcsCa", "create")} />
          </>
        }
        description="The Organization's own CAs, for internal names a public CA will not validate: those the platform runs, with their keys in its KMS, and the Active Directory Certificate Services CAs it reaches through Windows Agents."
        howItWorks={
          <>
            <p>
              A CA the platform runs is a root and one or more Issuing CAs under it, each with its own key in the KMS, which never leaves it. Add an Issuing CA under the same root, for other names or
              to roll over, and nothing that trusts the root needs anything new.
            </p>
            <p>
              An ADCS CA keeps its own key, Certificate Templates and CRL. Each Agent assigned to it reaches ADCS as its own account (a gMSA), so ADCS's template permissions decide what can be issued;
              the platform holds no AD credential.
            </p>
            <p>Either kind issues a Managed Certificate with no DCV, and can back a Certificate Profile or an Enrollment Profile.</p>
          </>
        }
      />
      {org && !seePlatform && !seeAdcs ? (
        <p className="text-sm text-muted-foreground">You may not see the Private CAs.</p>
      ) : (
        <>
          {attention.length > 0 && <NeedsAttention orgId={orgId} items={attention} />}
          {seePlatform && seeAdcs && rows.length > 0 && (
            <Tabs value={kind ?? "all"} onValueChange={(value) => void navigate({ search: value === "all" ? {} : { kind: value as CaKind }, replace: true })}>
              <TabsList aria-label="Kind of CA">
                <TabsTrigger value="all">All {rows.length}</TabsTrigger>
                <TabsTrigger value="platform">Platform {rows.filter((r) => r.kind === "platform").length}</TabsTrigger>
                <TabsTrigger value="adcs">AD CS {rows.filter((r) => r.kind === "adcs").length}</TabsTrigger>
              </TabsList>
            </Tabs>
          )}
          <CaTable orgId={orgId} rows={shown} empty={pending ? "Loading…" : rows.length === 0 ? "No Private CA yet." : "None of this kind."} />
          {platform.error && <p className="text-sm text-destructive">{platform.error.message}</p>}
          {adcs.error && <p className="text-sm text-destructive">{adcs.error.message}</p>}
        </>
      )}
    </div>
  );
}

function NeedsAttention({ orgId, items }: { orgId: string; items: Attention[] }) {
  return (
    <section aria-labelledby="needs-attention" className="rounded-lg border">
      <h2 id="needs-attention" className="border-b px-4 py-3 text-sm font-medium">
        Needs attention · {items.length}
      </h2>
      <ul className="divide-y">
        {items.map((item) => (
          <li key={`${item.caId}-${item.title}-${item.detail}`} className="flex flex-wrap items-center gap-3 px-4 py-3 text-sm">
            <Badge variant={item.tone === "bad" ? "destructive" : "warning"}>{item.title}</Badge>
            <span className="min-w-0 flex-1 basis-80">
              <span className="font-medium">{item.caName}</span> · {item.detail}
            </span>
            <Button variant="outline" size="sm" asChild>
              <Link to={caUrl(orgId, item.kind, item.caId)}>Open</Link>
            </Button>
          </li>
        ))}
      </ul>
    </section>
  );
}

function CaTable({ orgId, rows, empty }: { orgId: string; rows: CaRow[]; empty: string }) {
  if (rows.length === 0) return <p className="text-sm text-muted-foreground">{empty}</p>;
  return (
    <div className="rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Kind</TableHead>
            <TableHead>Issues through</TableHead>
            <TableHead>Permitted names</TableHead>
            <TableHead>Health</TableHead>
            <TableHead>CA expires</TableHead>
            <TableHead className="sr-only">Open</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => (
            <TableRow key={`${row.kind}-${row.id}`}>
              <TableCell className="min-w-56 max-w-72 whitespace-normal">
                <Link to={caUrl(orgId, row.kind, row.id)} className="font-medium hover:underline">
                  {row.name}
                </Link>
                <div className="break-all font-mono text-xs text-muted-foreground">{row.identity}</div>
              </TableCell>
              <TableCell>
                <KindBadge kind={row.kind} />
              </TableCell>
              <TableCell>
                {row.issuesThrough}
                <div className="text-xs text-muted-foreground">{row.issuesThroughDetail}</div>
              </TableCell>
              <TableCell className="min-w-56 max-w-72 whitespace-normal">{row.permittedNames}</TableCell>
              <TableCell>
                <HealthBadge health={row.health} />
              </TableCell>
              <TableCell>{row.expires ? caDate(row.expires) : <span className="text-muted-foreground">Not yet</span>}</TableCell>
              <TableCell className="text-right">
                <Button variant="ghost" size="icon-sm" asChild>
                  <Link to={caUrl(orgId, row.kind, row.id)} aria-label={`Open ${row.name}`}>
                    <ChevronRightIcon />
                  </Link>
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

const KINDS: { value: CaKind; title: string; description: string }[] = [
  {
    value: "platform",
    title: "Run it on the platform",
    description: "The platform makes the keys in its KMS: a root of its own with an Issuing CA under it, or an Issuing CA for your Organization's own root to sign. It serves the CRL.",
  },
  {
    value: "adcs",
    title: "Connect Active Directory Certificate Services",
    description:
      "An existing ADCS CA, reached only through your domain-joined Windows Agents, each as its own account. ADCS keeps its key, decides validity and EKUs by Certificate Template, and publishes its own CRL.",
  },
];

/** Adds a Private CA: first which kind, when the caller may add both, then that kind's own wizard. */
function AddPrivateCaDialog({ orgId, platform, adcs }: { orgId: string; platform: boolean; adcs: boolean }) {
  const only: CaKind | null = platform && !adcs ? "platform" : adcs && !platform ? "adcs" : null;
  const [open, setOpen] = useState(false);
  const [choice, setChoice] = useState<CaKind>("platform");
  const [chosen, setChosen] = useState<CaKind | null>(only);
  const agents = useAdcsAgents(orgId);
  if (!platform && !adcs) return null;
  const onOpenChange = (next: boolean) => {
    setOpen(next);
    // Each opening starts from the choice again.
    if (next) setChosen(only);
  };
  const done = () => setOpen(false);
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          <ActionLabel>Add a Private CA</ActionLabel>
        </Button>
      </DialogTrigger>
      {chosen === null ? (
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>Add a Private CA</DialogTitle>
            <DialogDescription>Where does its key live? Either kind issues Managed Certificates with no DCV.</DialogDescription>
          </DialogHeader>
          <RadioGroup value={choice} onValueChange={(value) => setChoice(value as CaKind)} aria-label="Kind of Private CA">
            {KINDS.map((k) => (
              <Label key={k.value} htmlFor={`private-ca-add-${k.value}`} className="flex items-start gap-3 rounded-md border p-4 font-normal has-data-[state=checked]:border-foreground">
                <RadioGroupItem value={k.value} id={`private-ca-add-${k.value}`} className="mt-0.5" />
                <span className="flex flex-col gap-1">
                  <span className="font-medium">{k.title}</span>
                  <span className="text-sm text-muted-foreground">{k.description}</span>
                </span>
              </Label>
            ))}
          </RadioGroup>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline">Cancel</Button>
            </DialogClose>
            <Button onClick={() => setChosen(choice)}>Continue</Button>
          </DialogFooter>
        </DialogContent>
      ) : (
        <DialogContent className={STEPPED_DIALOG}>
          <DialogTitle className="sr-only">{chosen === "platform" ? "New Private CA" : "Add an ADCS CA"}</DialogTitle>
          <DialogDescription className="sr-only">{chosen === "platform" ? CREATE_DESCRIPTION : ADD_ADCS_CA_DESCRIPTION}</DialogDescription>
          {/* Only mounted while open, so each opening starts from a clean form. */}
          {open && chosen === "platform" && <CreatePrivateCaForm orgId={orgId} onDone={done} />}
          {open && chosen === "adcs" && <AdcsCaWizard orgId={orgId} agents={agents} title="Add an ADCS CA" onDone={done} />}
        </DialogContent>
      )}
    </Dialog>
  );
}
