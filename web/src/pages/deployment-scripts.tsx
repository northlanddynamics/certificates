import { useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { PlusIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api, can, type DeploymentScript } from "@/lib/api";
import { useAction } from "@/lib/use-action";

const ROUTE = "/app/organizations/$orgId/deployment-scripts";
const INTERPRETERS: DeploymentScript["interpreter"][] = ["bash", "powershell"];
const INTERPRETER_LABEL: Record<DeploymentScript["interpreter"], string> = { bash: "Bash", powershell: "PowerShell" };
const shortHash = (hash: string) => hash.slice(0, 12);

/**
 * The Organization's Deployment Scripts: what an Agent runs to put a Certificate to use. Agents run them on their hosts, so
 * only Organization Administrators see or change the library. A change is a new version, and no version is ever altered:
 * each is identified by the hash of its content.
 */
export function DeploymentScriptsPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.organizations.find((o) => o.id === orgId) }).data;
  const allowed = org ? can(org, "deploymentScript", "read") : false;
  const scripts = useQuery({ queryKey: ["deployment-scripts", orgId], queryFn: () => api.deploymentScripts(orgId), enabled: allowed });
  const items = scripts.data?.items ?? [];
  const mayUpload = org ? can(org, "deploymentScript", "upload") : false;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">Deployment Scripts</h1>
        {mayUpload && <UploadDialog orgId={orgId} />}
      </div>
      <p className="text-sm text-muted-foreground">
        A Deployment Script is the Bash or PowerShell that an Agent runs to place a new key and Certificate where they are needed. It runs with the Agent's rights on the Agent's
        host, so only Organization Administrators can upload one. Uploading a change adds a version; earlier versions stay as they were.
      </p>
      {org && !allowed ? (
        <p className="text-sm text-muted-foreground">Only Organization Administrators see the Deployment Scripts.</p>
      ) : (
        <div className="flex flex-col gap-4">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Interpreter</TableHead>
                <TableHead>Latest version</TableHead>
                <TableHead>Uploaded</TableHead>
                <TableHead>
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((script) => (
                <TableRow key={script.id}>
                  <TableCell className="font-medium">{script.name}</TableCell>
                  <TableCell>
                    <Badge variant="secondary">{INTERPRETER_LABEL[script.interpreter]}</Badge>
                  </TableCell>
                  <TableCell>
                    <span>{script.latestVersion.version}</span> <span className="font-mono text-xs text-muted-foreground">{shortHash(script.latestVersion.hash)}</span>
                  </TableCell>
                  <TableCell className="text-sm">
                    {script.latestVersion.uploadedBy}, {new Date(script.latestVersion.uploadedAt).toLocaleString()}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-2">
                      <VersionsDialog orgId={orgId} script={script} />
                      {mayUpload && <NewVersionDialog orgId={orgId} script={script} />}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {items.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-muted-foreground">
                    {scripts.isPending ? "Loading…" : "No Deployment Script is uploaded yet."}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
          {scripts.error && <p className="text-sm text-destructive">{scripts.error.message}</p>}
        </div>
      )}
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
          Upload a script
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
