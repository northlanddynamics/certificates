import { useParams } from "@tanstack/react-router";
import { ShieldAlertIcon, TriangleAlertIcon } from "lucide-react";
import type { ReactNode } from "react";
import { toast } from "sonner";
import { CopyButton } from "@/components/copy-button";
import { ScriptCode } from "@/components/script-code";
import { GuideLink, GuidePage, GuideSection } from "@/components/guide";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { can, type DeploymentScript } from "@/lib/api";
import { CERT_VARIABLES, EXAMPLE_SCRIPTS, exampleContent } from "@/lib/deployment-script-examples";
import { ENV_PREFIX, MAX_PARAMETERS } from "@/lib/script-parameters";
import { useOrg } from "@/lib/use-org";
import { UploadDialog } from "./deployment-scripts";


const RUN_STEPS: { title: string; body: ReactNode }[] = [
  { title: "Upload", body: "Each upload is a version, named by the SHA-256 of its content. Its parameter section is read now." },
  { title: "Deployment", body: "Pins one version for life and stores its parameter values." },
  { title: "Agent checks", body: "The hash, that the Certificate is the one named, and that its key is on the host." },
  {
    title: "Script runs",
    body: (
      <>
        With <code>CERT_*</code> and <code>{ENV_PREFIX}*</code> set. Stopped after ten minutes.
      </>
    ),
  },
  { title: "Run recorded", body: "The exit code and up to 32 KiB of output, kept on the platform." },
];

const REFUSALS: { says: string; fix: ReactNode }[] = [
  {
    says: 'line 12 is inside the parameter section but is not a comment: start it with "# "',
    fix: (
      <>
        Start every line between the markers with <code># </code>.
      </>
    ),
  },
  {
    says: "the parameter section is not JSON: …",
    fix: (
      <>
        Look for a trailing comma or an unquoted name. The whole block is one array, <code>[ … ]</code>.
      </>
    ),
  },
  {
    says: "the parameter section must be a JSON array of parameters: …",
    fix: "Each entry is an object with a string name, and only the five fields below.",
  },
  {
    says: 'the parameter name "site-id" must be upper-case letters, digits and _, starting with a letter',
    fix: (
      <>
        Rename it, as <code>SITE_ID</code>.
      </>
    ),
  },
  { says: `the parameter name "${ENV_PREFIX}SITE" must not start with ${ENV_PREFIX}`, fix: "Drop the prefix: the Agent adds it." },
  { says: 'the parameter "PORT" is declared more than once', fix: "Keep one entry for each name." },
  { says: `a script declares at most ${MAX_PARAMETERS} parameters`, fix: "Split the script, or work values out inside it." },
  { says: 'the default of the parameter "PORT" contains a newline', fix: "A default obeys the rules for values: one line, at most 1 KiB, no NUL." },
  { says: 'the parameter section needs exactly one "# deploy-params:end" line after its "# deploy-params:begin" line', fix: "One begin line, then one end line after it." },
];

const DECLARATION = `# deploy-params:begin
# [
#   { "name": "SITE_ID", "label": "Site id", "required": true,
#     "description": "The site's id in the load balancer's console." },
#   { "name": "PORT", "default": "443" },
#   { "name": "POOL", "description": "Leave blank to use the site's default pool." }
# ]
# deploy-params:end`;

/**
 * How to write a Deployment Script: what the Agent gives it, how it declares parameters and how their values reach it,
 * a worked example in each interpreter, and what is unsafe. The rest of the app links into its sections by anchor.
 */
export function DeploymentScriptGuidePage() {
  // Shown as a page or in the help panel over any of the Organization's pages.
  const orgId = useParams({ strict: false }).orgId ?? "";
  const org = useOrg(orgId);
  if (org && !can(org, "deploymentScript", "read")) return <p className="text-sm text-muted-foreground">Only Organization Administrators see the Deployment Scripts.</p>;
  const mayUpload = org ? can(org, "deploymentScript", "upload") : false;
  return (
    <GuidePage
      guide="deployment-scripts"
      title="Writing Deployment Scripts"
      back={{ to: "/organizations/$orgId/deployment-scripts", label: "Deployment Scripts", orgId }}
      lede="A Deployment Script is the Bash or PowerShell an Agent runs, on its own host and with its own rights, to put a new key and Certificate where they are needed. One script can serve many targets: it declares its Deployment Parameters, and each Deployment gives its own values."
    >

        <GuideSection guide="deployment-scripts" id="how">
          <ol className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            {RUN_STEPS.map((s, i) => (
              <li key={s.title} className="flex flex-col gap-1 rounded-lg border p-3">
                <span className="text-xs font-semibold text-primary">
                  {i + 1} · {s.title}
                </span>
                <span>{s.body}</span>
              </li>
            ))}
          </ol>
          <p className="text-muted-foreground">
            The same happens on every Renewal and every “Run again”, with the values stored on the Deployment. Exit 0 for success; any other exit code marks the Deployment Run
            failed and tells the Managed Certificate's Subscribers.
          </p>
        </GuideSection>

        <GuideSection guide="deployment-scripts" id="receives">
          <p className="text-muted-foreground">Set by the Agent for every run, whether or not the script declares parameters.</p>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Variable</TableHead>
                  <TableHead>What it holds</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {CERT_VARIABLES.map((v) => (
                  <TableRow key={v.name}>
                    <TableCell className="font-mono text-xs">{v.name}</TableCell>
                    <TableCell className="whitespace-normal">{v.meaning}</TableCell>
                  </TableRow>
                ))}
                <TableRow>
                  <TableCell className="font-mono text-xs">{ENV_PREFIX}&lt;NAME&gt;</TableCell>
                  <TableCell className="whitespace-normal">
                    One for each parameter that has a value (<GuideLink guide="deployment-scripts" section="values">below</GuideLink>)
                  </TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </div>
        </GuideSection>

        <GuideSection guide="deployment-scripts" id="declare">
          <p>
            Put one comment block anywhere in the script. Between the two marker lines every line is a comment; with each line's leading <code># </code> removed, the block is a
            JSON array. <code>#</code> starts a comment in Bash and PowerShell alike, so the format is the same for both.
          </p>
          <Code text={DECLARATION} label="Copy the example section" />
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Field</TableHead>
                  <TableHead>Needed</TableHead>
                  <TableHead>Meaning</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <FieldRow field="name" needed>
                  Upper-case letters, digits and <code>_</code>, starting with a letter. The script reads it as <code>{ENV_PREFIX}</code> and the name.
                </FieldRow>
                <FieldRow field="label">What the Deployment form shows. The name when left out.</FieldRow>
                <FieldRow field="description">Help shown under the input.</FieldRow>
                <FieldRow field="required">
                  <code>true</code> or <code>false</code> (the default). A Deployment cannot be set up or saved without a value.
                </FieldRow>
                <FieldRow field="default">Filled in on the form, and used when the value is left blank.</FieldRow>
              </TableBody>
            </Table>
          </div>
          <ul className="grid gap-2 sm:grid-cols-2">
            <li className="rounded-md border p-3">At most {MAX_PARAMETERS} parameters, each name once.</li>
            <li className="rounded-md border p-3">
              A name does not itself start with <code>{ENV_PREFIX}</code>.
            </li>
            <li className="rounded-md border p-3">Only the five fields above: any other refuses the upload.</li>
            <li className="rounded-md border p-3">The section is part of the content, so it is inside the hash: to change it, upload a new version.</li>
          </ul>
        </GuideSection>

        <GuideSection guide="deployment-scripts" id="values">
          <p className="text-muted-foreground">For the section above, a Deployment set up with these entries gives the script this environment:</p>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Parameter</TableHead>
                  <TableHead>Entered</TableHead>
                  <TableHead>The script sees</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow>
                  <TableCell>SITE_ID (required)</TableCell>
                  <TableCell className="font-mono text-xs">site-7f3a9c</TableCell>
                  <TableCell className="font-mono text-xs">{ENV_PREFIX}SITE_ID=site-7f3a9c</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell>PORT (default 443)</TableCell>
                  <TableCell className="text-muted-foreground">blank</TableCell>
                  <TableCell className="font-mono text-xs">{ENV_PREFIX}PORT=443</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell>POOL</TableCell>
                  <TableCell className="text-muted-foreground">blank</TableCell>
                  <TableCell className="text-muted-foreground">nothing: the variable is absent</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </div>
          <ul className="flex list-disc flex-col gap-1.5 pl-5">
            <li>A value is text of at most 1 KiB, with no newline and no NUL character.</li>
            <li>A blank value counts as not given: the default applies, and with none the variable is left out, so test for “unset”, not for an empty string.</li>
            <li>A value the Deployment gives wins over a variable of the same name in the Agent's own environment.</li>
            <li>Editing a Deployment's values takes effect from the next delivery to the Agent; a run already delivered keeps what it was given.</li>
          </ul>
        </GuideSection>

        <GuideSection guide="deployment-scripts" id="example">
          <p className="text-muted-foreground">
            Takes a required, a defaulted and an optional parameter, picks up the Certificate and key, and leaves one marked place for your own deployment.
          </p>
          <Tabs defaultValue="bash">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <TabsList>
                <TabsTrigger value="bash">Bash</TabsTrigger>
                <TabsTrigger value="powershell">PowerShell</TabsTrigger>
              </TabsList>
            </div>
            {(["bash", "powershell"] as const).map((interpreter) => (
              <TabsContent key={interpreter} value={interpreter} className="mt-4">
                <Example interpreter={interpreter} mayUpload={mayUpload} orgId={orgId} />
              </TabsContent>
            ))}
          </Tabs>
        </GuideSection>

        <GuideSection guide="deployment-scripts" id="safety">
          <div className="grid gap-3 md:grid-cols-2">
            <Alert variant="destructive">
              <ShieldAlertIcon />
              <AlertTitle>Parameters are not for secrets</AlertTitle>
              <AlertDescription>
                Values are stored as plain text on the Deployment, and every Organization Administrator can read them. Set passwords and keys in the Agent service's environment
                on its host instead, under a name that does not start with <code>{ENV_PREFIX}</code>: the Agent drops those, so that a parameter left unset stays unset.
              </AlertDescription>
            </Alert>
            <Alert>
              <TriangleAlertIcon />
              <AlertTitle>Output is kept on the platform</AlertTitle>
              <AlertDescription>
                Up to 32 KiB of what the script prints is stored with each Deployment Run. Never print parameter values, secrets or the key, and leave <code>set -x</code> off.
              </AlertDescription>
            </Alert>
            <Alert>
              <AlertTitle>Guard required parameters</AlertTitle>
              <AlertDescription>
                The platform refuses a Deployment without them, but an Agent that predates script parameters ignores them altogether. Step 2 of the example makes that fail
                rather than half-deploy; the Agents page shows which Agents are outdated.
              </AlertDescription>
            </Alert>
            <Alert>
              <AlertTitle>It runs as the Agent</AlertTitle>
              <AlertDescription>With the Agent's rights, on the Agent's host. Review a script as you would code you deploy, and quote every variable you use.</AlertDescription>
            </Alert>
          </div>
        </GuideSection>

        <GuideSection guide="deployment-scripts" id="refused">
          <p className="text-muted-foreground">The platform reads the parameter section at upload and refuses a version it cannot use, saying why.</p>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>The message says</TableHead>
                  <TableHead>What to do</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {REFUSALS.map((r) => (
                  <TableRow key={r.says}>
                    <TableCell className="whitespace-normal">{r.says}</TableCell>
                    <TableCell className="whitespace-normal">{r.fix}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </GuideSection>
    </GuidePage>
  );
}

function FieldRow({ field, needed = false, children }: { field: string; needed?: boolean; children: ReactNode }) {
  return (
    <TableRow>
      <TableCell className="font-mono text-xs">{field}</TableCell>
      <TableCell>{needed ? "Yes" : "No"}</TableCell>
      <TableCell className="whitespace-normal">{children}</TableCell>
    </TableRow>
  );
}

/** A block of code with a button that copies it. */
function Code({ text, label }: { text: string; label: string }) {
  return (
    <div className="relative">
      <ScriptCode code={text} interpreter="bash" label="An example parameter section" className="pr-8" />
      <div className="absolute top-1.5 right-1.5">
        <CopyButton text={text} label={label} />
      </div>
    </div>
  );
}

/** One example, a step at a time, with the place for the author's own deployment marked. */
function Example({ interpreter, mayUpload, orgId }: { interpreter: DeploymentScript["interpreter"]; mayUpload: boolean; orgId: string }) {
  const example = EXAMPLE_SCRIPTS[interpreter];
  const content = exampleContent(example);
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-end gap-2">
        <Button variant="outline" size="sm" onClick={() => navigator.clipboard.writeText(content).then(() => toast.success("Copied the script"), () => toast.error("Could not copy the script"))}>
          Copy the whole script
        </Button>
        {mayUpload && <UploadDialog orgId={orgId} start={interpreter} trigger={<Button size="sm">Use as a new script</Button>} />}
      </div>
      <ol className="flex flex-col gap-4">
        {example.steps.map((step, i) => (
          <li key={step.title} className="flex gap-3">
            <span aria-hidden="true" className="flex size-6 shrink-0 items-center justify-center rounded-full bg-primary text-xs font-semibold text-primary-foreground">
              {i + 1}
            </span>
            <div className={step.yours ? "flex min-w-0 flex-1 flex-col gap-2 rounded-lg border-2 border-dashed border-primary/60 bg-primary/5 p-3" : "flex min-w-0 flex-1 flex-col gap-2"}>
              <span className="flex items-center gap-2 font-medium">
                {step.title}
                {step.yours && <Badge>Your code</Badge>}
              </span>
              {step.note && <p className="text-muted-foreground">{step.note}</p>}
              <ScriptCode code={step.code} interpreter={interpreter} label={`Step ${i + 1}: ${step.title}`} />
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}
