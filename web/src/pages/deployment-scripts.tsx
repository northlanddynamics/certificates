import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { createColumnHelper, rowPaginationFeature, tableFeatures, useTable, type PaginationState } from "@tanstack/react-table";
import { PlusIcon, XIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { DataTable } from "@/components/data-table/data-table";
import { DataTableFacetedFilter } from "@/components/data-table/data-table-faceted-filter";
import { DataTablePagination } from "@/components/data-table/data-table-pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { ActionLabel, PageHeader } from "@/components/page-header";
import { api, can, type DeploymentScript } from "@/lib/api";
import { useOrg } from "@/lib/use-org";
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
        action={mayUpload && <UploadDialog orgId={orgId} />}
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
          <div className="flex flex-wrap items-center gap-2">
            <DataTableFacetedFilter title="Interpreter" options={INTERPRETER_FACETS} value={interpreter} onChange={narrow} />
            {narrowed && (
              <Button variant="ghost" size="sm" onClick={() => narrow([])}>
                Reset
                <XIcon />
              </Button>
            )}
          </div>
          <DataTable table={table} empty={scripts.isPending ? "Loading…" : narrowed ? "No Deployment Scripts match." : "No Deployment Script is uploaded yet."} />
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
    <div className="flex flex-col gap-4">
      <div className="rounded-md border">
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
        <pre aria-label={`Content of version ${content.data.version}`} className="max-h-80 overflow-auto rounded-md border bg-muted p-3 font-mono text-xs">
          {content.data.content}
        </pre>
      )}
      {content.error && <p className="text-sm text-destructive">{content.error.message}</p>}
    </div>
  );
}

function UploadDialog({ orgId }: { orgId: string }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          <ActionLabel>Upload a script</ActionLabel>
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Upload a Deployment Script</DialogTitle>
          <DialogDescription>It becomes version 1. Agents run it with their own rights on their hosts, so review it as you would code you deploy.</DialogDescription>
        </DialogHeader>
        {/* Only mounted while open, so each opening starts from a clean form. */}
        {open && <UploadForm orgId={orgId} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function UploadForm({ orgId, onDone }: { orgId: string; onDone: () => void }) {
  const [name, setName] = useState("");
  const [interpreter, setInterpreter] = useState<DeploymentScript["interpreter"]>("bash");
  const [content, setContent] = useState("");
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
      <ContentField id="script-content" value={content} onChange={setContent} />
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
      <DialogContent className="sm:max-w-2xl">
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
      <ContentField id="version-content" value={content} onChange={setEdited} />
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

function ContentField({ id, value, onChange }: { id: string; value: string; onChange: (value: string) => void }) {
  return (
    <div className="flex flex-col gap-2">
      <Label htmlFor={id}>Script</Label>
      <Textarea id={id} className="max-h-96 min-h-48 font-mono text-xs" spellCheck={false} value={value} onChange={(e) => onChange(e.target.value)} />
    </div>
  );
}
