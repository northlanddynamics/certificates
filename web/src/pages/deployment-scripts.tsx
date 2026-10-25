import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { createColumnHelper, rowPaginationFeature, tableFeatures, useTable, type PaginationState } from "@tanstack/react-table";
import { BookOpenIcon, CircleCheckIcon, InfoIcon, PlusIcon, TriangleAlertIcon, XIcon } from "lucide-react";
import { Suspense, lazy, useState, type FormEvent, type ReactNode } from "react";
import { DataTable } from "@/components/data-table/data-table";
import { DataTableFacetedFilter } from "@/components/data-table/data-table-faceted-filter";
import { DataTablePagination } from "@/components/data-table/data-table-pagination";
import { ScriptCode } from "@/components/script-code";
import { ScriptEnvironment } from "@/components/script-environment";
import { GuideLink } from "@/components/guide";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ActionLabel, PageHeader } from "@/components/page-header";
import { api, can, type DeploymentScript, type ScriptParameter } from "@/lib/api";
import { EXAMPLE_SCRIPTS, exampleById, exampleContent, type ExampleScript } from "@/lib/deployment-script-examples";
import { ENV_PREFIX, readDeclaration } from "@/lib/script-parameters";
import { useOrg } from "@/lib/use-org";
import { WRAPPING_TABLE } from "@/lib/utils";
import { useAction } from "@/lib/use-action";

const ROUTE = "/app/organizations/$orgId/deployment-scripts";
const INTERPRETERS: DeploymentScript["interpreter"][] = ["bash", "powershell"];
const INTERPRETER_LABEL: Record<DeploymentScript["interpreter"], string> = { bash: "Bash", powershell: "PowerShell" };
const INTERPRETER_FACETS = INTERPRETERS.map((value) => ({ value, label: INTERPRETER_LABEL[value] }));
const shortHash = (hash: string) => hash.slice(0, 12);

// Paging and narrowing are the server's (Page<DeploymentScript>); the table lays out the page it was given.
const features = tableFeatures({ rowPaginationFeature });
const columnHelper = createColumnHelper<typeof features, DeploymentScript>();
const columns = columnHelper.columns([
  columnHelper.accessor("name", { header: "Name", cell: ({ cell }) => <span className="font-medium">{cell.getValue()}</span> }),
  columnHelper.accessor("interpreter", { header: "Interpreter", cell: ({ cell }) => <Badge variant="secondary">{INTERPRETER_LABEL[cell.getValue()]}</Badge> }),
  columnHelper.accessor((s) => s.latestVersion.version, {
    id: "latestVersion",
    header: "Latest version",
    cell: ({ row }) => (
      <span className="flex items-center gap-2">
        {row.original.latestVersion.version}
        <span className="font-mono text-xs text-muted-foreground">{shortHash(row.original.latestVersion.hash)}</span>
      </span>
    ),
  }),
  columnHelper.accessor((s) => s.latestVersion.parameters.length, {
    id: "parameters",
    header: "Parameters",
    cell: ({ row }) => <ParameterCount parameters={row.original.latestVersion.parameters} />,
  }),
  columnHelper.accessor((s) => s.latestVersion.uploadedAt, {
    id: "uploaded",
    header: "Uploaded",
    cell: ({ row }) => (
      <span>
        {row.original.latestVersion.uploadedBy}, <time dateTime={row.original.latestVersion.uploadedAt}>{new Date(row.original.latestVersion.uploadedAt).toLocaleString()}</time>
      </span>
    ),
  }),
  columnHelper.display({ id: "actions", header: () => <span className="sr-only">Actions</span>, cell: ({ row }) => <ScriptActions script={row.original} /> }),
]);
const noRows: DeploymentScript[] = [];

/**
 * The Organization's Deployment Scripts: what an Agent runs to put a Certificate to use. Agents run them on their hosts, so
 * only Organization Administrators see or change the library. A change is a new version, and no version is ever altered:
 * each is identified by the hash of its content.
 */
export function DeploymentScriptsPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const allowed = org ? can(org, "deploymentScript", "read") : false;
  const [interpreter, setInterpreter] = useState<string[]>([]);
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 25 });
  const scripts = useQuery({
    queryKey: ["deployment-scripts", orgId, { interpreter }, pagination],
    queryFn: () => api.deploymentScripts(orgId, { page: pagination.pageIndex + 1, pageSize: pagination.pageSize }, { interpreter }),
    enabled: allowed,
    placeholderData: keepPreviousData,
  });
  const table = useTable({
    features,
    columns,
    data: scripts.data?.items ?? noRows,
    rowCount: scripts.data?.total,
    manualPagination: true,
    state: { pagination },
    onPaginationChange: setPagination,
    getRowId: (s) => s.id,
  });
  const mayUpload = org ? can(org, "deploymentScript", "upload") : false;
  const narrowed = interpreter.length > 0;
  // A new narrowing starts again from the first page.
  const narrow = (values: string[]) => {
    setInterpreter(values);
    setPagination({ ...pagination, pageIndex: 0 });
  };

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Deployment Scripts"
        guide="deployment-scripts"
        action={
          <>
            {allowed && (
              <Button variant="outline" asChild>
                <GuideLink orgId={orgId} guide="deployment-scripts" className="">
                  <BookOpenIcon />
                  <ActionLabel>How to write a script</ActionLabel>
                </GuideLink>
              </Button>
            )}
            {mayUpload && <UploadDialog orgId={orgId} />}
          </>
        }
        description="The Bash or PowerShell that an Agent runs to place a new key and Certificate where they are needed."
        howItWorks={
          <p>
            A script runs with the Agent's rights on the Agent's host, so only Organization Administrators can upload one. Uploading a change adds a version; earlier versions
            stay as they were.
          </p>
        }
      />
      {org && !allowed ? (
        <p className="text-sm text-muted-foreground">Only Organization Administrators see the Deployment Scripts.</p>
      ) : (
        <div className="flex flex-col gap-4">
          <ParametersBanner orgId={orgId} />
          <div className="flex flex-wrap items-center gap-2">
            <DataTableFacetedFilter title="Interpreter" options={INTERPRETER_FACETS} value={interpreter} onChange={narrow} />
            {narrowed && (
              <Button variant="ghost" size="sm" onClick={() => narrow([])}>
                Reset
                <XIcon />
              </Button>
            )}
          </div>
          <DataTable table={table} empty={scripts.isPending ? "Loading…" : narrowed ? "No Deployment Scripts match." : <NoScripts orgId={orgId} mayUpload={mayUpload} />} />
          <DataTablePagination
            pageIndex={pagination.pageIndex}
            pageSize={pagination.pageSize}
            rowCount={scripts.data?.total ?? 0}
            onPageIndexChange={(pageIndex) => setPagination({ ...pagination, pageIndex })}
            onPageSizeChange={(pageSize) => setPagination({ pageIndex: 0, pageSize })}
          />
          {scripts.error && <p className="text-sm text-destructive">{scripts.error.message}</p>}
        </div>
      )}
    </div>
  );
}

function ScriptActions({ script }: { script: DeploymentScript }) {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  return (
    <div className="flex items-center justify-end gap-2">
      <VersionsDialog orgId={orgId} script={script} />
      {org && can(org, "deploymentScript", "upload") && <NewVersionDialog orgId={orgId} script={script} />}
    </div>
  );
}

/** Every version of a script, newest first; picking one shows its content as it was uploaded. */
function VersionsDialog({ orgId, script }: { orgId: string; script: DeploymentScript }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" aria-label={`Versions of ${script.name}`}>
          Versions
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{script.name}</DialogTitle>
          <DialogDescription>Each version is identified by the SHA-256 of its content, which an Agent checks before it runs the script.</DialogDescription>
        </DialogHeader>
        {open && <Versions orgId={orgId} script={script} />}
      </DialogContent>
    </Dialog>
  );
}

function Versions({ orgId, script }: { orgId: string; script: DeploymentScript }) {
  const detail = useQuery({ queryKey: ["deployment-scripts", orgId, script.id], queryFn: () => api.deploymentScript(orgId, script.id) });
  const [shown, setShown] = useState<string | null>(null);
  const hash = shown ?? detail.data?.versions[0]?.hash;
  const content = useQuery({
    queryKey: ["deployment-scripts", orgId, script.id, hash],
    queryFn: () => api.deploymentScriptVersion(orgId, script.id, hash!),
    enabled: !!hash,
  });
  return (
    <div className="flex min-w-0 flex-col gap-4">
      <div className={`rounded-md border ${WRAPPING_TABLE}`}>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Version</TableHead>
              <TableHead>Hash</TableHead>
              <TableHead>Uploaded</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {detail.data?.versions.map((v) => (
              <TableRow key={v.hash} data-state={v.hash === hash ? "selected" : undefined}>
                <TableCell>{v.version}</TableCell>
                <TableCell className="break-all font-mono text-xs">{v.hash}</TableCell>
                <TableCell className="text-sm">
                  {v.uploadedBy}, {new Date(v.uploadedAt).toLocaleString()}
                </TableCell>
                <TableCell className="text-right">
                  <Button variant="ghost" size="sm" aria-label={`View version ${v.version}`} aria-pressed={v.hash === hash} onClick={() => setShown(v.hash)}>
                    View
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {detail.error && <p className="text-sm text-destructive">{detail.error.message}</p>}
      {content.data && (
        <Tabs key={content.data.hash} defaultValue="content" className="min-w-0">
          <TabsList aria-label={`Version ${content.data.version}`}>
            <TabsTrigger value="content">Content</TabsTrigger>
            <TabsTrigger value="parameters">Parameters ({content.data.parameters.length})</TabsTrigger>
            <TabsTrigger value="environment">Environment</TabsTrigger>
          </TabsList>
          <TabsContent value="content">
            <ScriptCode code={content.data.content} interpreter={script.interpreter} label={`Content of version ${content.data.version}`} lineNumbers className="max-h-80" />
          </TabsContent>
          <TabsContent value="parameters" className="flex flex-col gap-3">
            <p className="text-sm text-muted-foreground">
              A Deployment of this version asks for these values. They are fixed with the version: to change them, upload a new one.{" "}
              <GuideLink orgId={orgId} guide="deployment-scripts" section="declare">
                How parameters are declared
              </GuideLink>
            </p>
            <ParameterTable parameters={content.data.parameters} />
          </TabsContent>
          <TabsContent value="environment" className="flex flex-col gap-3">
            <p className="text-sm text-muted-foreground">
              What a run of this version is given.{" "}
              <GuideLink orgId={orgId} guide="deployment-scripts" section="receives">
                Every variable, explained
              </GuideLink>
            </p>
            <ScriptEnvironment declared={content.data.parameters} />
          </TabsContent>
        </Tabs>
      )}
      {content.error && <p className="text-sm text-destructive">{content.error.message}</p>}
    </div>
  );
}

/** The button that uploads a new script, and its dialog; `start` fills it with the guide's example in that interpreter. */
export function UploadDialog({ orgId, start, trigger }: { orgId: string; start?: ExampleScript["id"]; trigger?: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {trigger ?? (
          <Button>
            <PlusIcon />
            <ActionLabel>Upload a script</ActionLabel>
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className="sm:max-w-5xl">
        <DialogHeader>
          <DialogTitle>Upload a Deployment Script</DialogTitle>
          <DialogDescription>It becomes version 1. Agents run it with their own rights on their hosts, so review it as you would code you deploy.</DialogDescription>
        </DialogHeader>
        {/* Only mounted while open, so each opening starts from a clean form. */}
        {open && <UploadForm orgId={orgId} start={start} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function UploadForm({ orgId, start, onDone }: { orgId: string; start?: ExampleScript["id"]; onDone: () => void }) {
  const started = start ? exampleById(start) : undefined;
  const [name, setName] = useState(started?.name ?? "");
  const [interpreter, setInterpreter] = useState<DeploymentScript["interpreter"]>(started?.interpreter ?? "bash");
  const [content, setContent] = useState(started ? exampleContent(started) : "");
  // Starting from an example takes its interpreter, and its name unless one is typed.
  const startFrom = (example: ExampleScript) => {
    setInterpreter(example.interpreter);
    setContent(exampleContent(example));
    if (!name.trim()) setName(example.name);
  };
  const upload = useAction(() => api.uploadDeploymentScript(orgId, { name: name.trim(), interpreter, content }), ["deployment-scripts"], onDone);
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        upload.mutate(undefined);
      }}
    >
      <div className="flex flex-col gap-2">
        <Label htmlFor="script-name">Name</Label>
        <Input id="script-name" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="script-interpreter">Interpreter</Label>
        <select id="script-interpreter" className="h-9 rounded-md border bg-transparent px-3 text-sm" value={interpreter} onChange={(e) => setInterpreter(e.target.value as DeploymentScript["interpreter"])}>
          {INTERPRETERS.map((i) => (
            <option key={i} value={i}>
              {INTERPRETER_LABEL[i]}
            </option>
          ))}
        </select>
      </div>
      {!content.trim() && (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-muted-foreground">Start from an example:</span>
          {EXAMPLE_SCRIPTS.map((example) => (
            <Button key={example.id} type="button" variant="outline" size="sm" onClick={() => startFrom(example)}>
              {example.title} ({INTERPRETER_LABEL[example.interpreter]})
            </Button>
          ))}
        </div>
      )}
      <ContentWithDeclaration orgId={orgId} id="script-content" interpreter={interpreter} value={content} onChange={setContent} />
      {upload.error && <p className="text-sm text-destructive">{upload.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={!name.trim() || !content.trim() || upload.isPending}>
          Upload
        </Button>
      </DialogFooter>
    </form>
  );
}

/** A change to a script is a new version, which starts from the latest one's content. */
function NewVersionDialog({ orgId, script }: { orgId: string; script: DeploymentScript }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" aria-label={`Upload a new version of ${script.name}`}>
          New version
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-5xl">
        <DialogHeader>
          <DialogTitle>New version of {script.name}</DialogTitle>
          <DialogDescription>
            It becomes version {script.latestVersion.version + 1}; version {script.latestVersion.version} stays as it is.
          </DialogDescription>
        </DialogHeader>
        {open && <NewVersionForm orgId={orgId} script={script} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function NewVersionForm({ orgId, script, onDone }: { orgId: string; script: DeploymentScript; onDone: () => void }) {
  const latest = useQuery({ queryKey: ["deployment-scripts", orgId, script.id, script.latestVersion.hash], queryFn: () => api.deploymentScriptVersion(orgId, script.id, script.latestVersion.hash) });
  const [edited, setEdited] = useState<string | null>(null);
  const content = edited ?? latest.data?.content ?? "";
  const upload = useAction(() => api.uploadDeploymentScriptVersion(orgId, script.id, content), ["deployment-scripts"], onDone);
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        upload.mutate(undefined);
      }}
    >
      <ContentWithDeclaration orgId={orgId} id="version-content" interpreter={script.interpreter} value={content} onChange={setEdited} />
      {latest.error && <p className="text-sm text-destructive">{latest.error.message}</p>}
      {upload.error && <p className="text-sm text-destructive">{upload.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={!content.trim() || content === latest.data?.content || upload.isPending}>
          Upload
        </Button>
      </DialogFooter>
    </form>
  );
}

/** The editor, coloured for the interpreter: loaded only once a dialog that edits a script opens. */
const ScriptEditor = lazy(() => import("@/components/script-editor"));

/** The script's content, beside what its parameter section declares as it is typed, read as the upload will read it. */
function ContentWithDeclaration({
  orgId,
  id,
  interpreter,
  value,
  onChange,
}: {
  orgId: string;
  id: string;
  interpreter: DeploymentScript["interpreter"];
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_18rem]">
      <div className="flex min-w-0 flex-col gap-2">
        <div className="flex items-baseline justify-between gap-2">
          <Label id={`${id}-label`}>Script</Label>
          <GuideLink orgId={orgId} guide="deployment-scripts" section="declare" className="text-xs font-medium text-primary underline-offset-4 hover:underline">
            How to ask for parameters
          </GuideLink>
        </div>
        <Suspense fallback={<div className="h-96 rounded-md border bg-muted/30" aria-busy="true" />}>
          <ScriptEditor
            value={value}
            onChange={onChange}
            interpreter={interpreter}
            labelledBy={`${id}-label`}
            className="h-96 min-w-0 overflow-hidden rounded-md border focus-within:border-ring focus-within:ring-[3px] focus-within:ring-ring/50"
          />
        </Suspense>
      </div>
      <DeclarationPanel orgId={orgId} content={value} />
    </div>
  );
}

/** What `content` declares, or why the upload would be refused. Only a preview: the server reads the section again and decides. */
function DeclarationPanel({ orgId, content }: { orgId: string; content: string }) {
  const declaration = readDeclaration(content);
  return (
    <section aria-label="Parameters this version declares" aria-live="polite" className="flex flex-col gap-3 rounded-md border bg-muted/40 p-3 text-sm">
      <h3 className="font-medium">Parameters this version declares</h3>
      {declaration.problem !== undefined ? (
        <Alert variant="destructive">
          <TriangleAlertIcon />
          <AlertTitle>The upload would be refused</AlertTitle>
          <AlertDescription>
            <p>{declaration.problem}</p>
            <GuideLink orgId={orgId} guide="deployment-scripts" section="refused">
              How to fix it
            </GuideLink>
          </AlertDescription>
        </Alert>
      ) : declaration.parameters.length === 0 ? (
        <p className="text-muted-foreground">
          None. A Deployment of this version is asked for nothing; to take values, add a <code># deploy-params:begin</code> section.
        </p>
      ) : (
        <>
          <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <CircleCheckIcon className="size-3.5" />
            {declaration.parameters.length} found: what the Deployment form will ask for
          </span>
          <ul className="flex flex-col gap-2">
            {declaration.parameters.map((p) => (
              <li key={p.name} className="flex flex-col gap-1 rounded-md border bg-background p-2">
                <span className="flex items-baseline justify-between gap-2">
                  <span className="font-medium">{p.label}</span>
                  <span className="text-xs text-muted-foreground">{parameterRule(p)}</span>
                </span>
                <code className="text-xs break-all">
                  ${ENV_PREFIX}
                  {p.name}
                </code>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

/** Whether a parameter must be given, and what a blank does. */
const parameterRule = (p: ScriptParameter) => (p.required ? "Required" : p.default?.trim() ? `Default ${p.default}` : "Optional");

function ParameterTable({ parameters }: { parameters: ScriptParameter[] }) {
  if (parameters.length === 0) return <p className="text-sm text-muted-foreground">This version declares no parameters.</p>;
  return (
    <div className={`rounded-md border ${WRAPPING_TABLE}`}>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Label</TableHead>
            <TableHead>Variable</TableHead>
            <TableHead>Required</TableHead>
            <TableHead>Default</TableHead>
            <TableHead>Description</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {parameters.map((p) => (
            <TableRow key={p.name}>
              <TableCell>{p.label}</TableCell>
              <TableCell className="font-mono text-xs">
                {ENV_PREFIX}
                {p.name}
              </TableCell>
              <TableCell>{p.required ? "Yes" : "No"}</TableCell>
              <TableCell className="font-mono text-xs">{p.default ?? <span className="font-sans text-muted-foreground">None</span>}</TableCell>
              <TableCell className="whitespace-normal">{p.description || <span className="text-muted-foreground">None</span>}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function ParameterCount({ parameters }: { parameters: ScriptParameter[] }) {
  if (parameters.length === 0) return <span className="text-muted-foreground">None</span>;
  const required = parameters.filter((p) => p.required).length;
  return (
    <Badge variant="outline">
      {parameters.length}
      {required > 0 && <> · {required} required</>}
    </Badge>
  );
}

const BANNER_DISMISSED = "deployment-scripts:parameters-banner-dismissed";

/** Introduces script parameters until it is dismissed, which this browser remembers; storage that cannot be used shows it again. */
function ParametersBanner({ orgId }: { orgId: string }) {
  const [dismissed, setDismissed] = useState(() => {
    try {
      return localStorage.getItem(BANNER_DISMISSED) === "1";
    } catch {
      return false;
    }
  });
  if (dismissed) return null;
  return (
    <Alert>
      <InfoIcon />
      <AlertTitle>One script, many targets</AlertTitle>
      <AlertDescription>
        <p>A script can ask for values, called Deployment Parameters, such as a site name or a port. Each Deployment fills in its own.</p>
        <span className="flex flex-wrap gap-4">
          <GuideLink orgId={orgId} guide="deployment-scripts" section="declare">
            How to ask for parameters
          </GuideLink>
          <GuideLink orgId={orgId} guide="deployment-scripts" section="example">
            See an example script
          </GuideLink>
        </span>
      </AlertDescription>
      <Button
        variant="ghost"
        size="icon"
        className="absolute top-1.5 right-1.5 size-7"
        aria-label="Dismiss"
        onClick={() => {
          setDismissed(true);
          try {
            localStorage.setItem(BANNER_DISMISSED, "1");
          } catch {
            // Not remembered: it shows again next time.
          }
        }}
      >
        <XIcon />
      </Button>
    </Alert>
  );
}

/** The library while it is empty: the way in is the guide, or an example to start from. */
function NoScripts({ orgId, mayUpload }: { orgId: string; mayUpload: boolean }) {
  return (
    <div className="flex flex-col items-center gap-3 py-6 text-center whitespace-normal">
      <p className="font-medium">No Deployment Script is uploaded yet.</p>
      <p className="max-w-md text-muted-foreground">
        Start from a working example, which takes Deployment Parameters, picks up the Certificate and key, and marks where your own deployment goes.
      </p>
      {mayUpload && (
        <div className="flex flex-wrap justify-center gap-2">
          {EXAMPLE_SCRIPTS.map((example) => (
            <UploadDialog
              key={example.id}
              orgId={orgId}
              start={example.id}
              trigger={
                <Button variant="outline">
                  {example.title} ({INTERPRETER_LABEL[example.interpreter]})
                </Button>
              }
            />
          ))}
        </div>
      )}
      <GuideLink orgId={orgId} guide="deployment-scripts">Read the guide</GuideLink>
    </div>
  );
}
