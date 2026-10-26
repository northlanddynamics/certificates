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
import { CERT_VARIABLES, EXAMPLE_SCRIPTS, exampleContent, type ExampleScript } from "@/lib/deployment-script-examples";
import { ENV_PREFIX, MAX_PARAMETERS } from "@/lib/script-parameters";
import { useOrg } from "@/lib/use-org";
import { UploadDialog } from "./deployment-scripts";


const RUN_STEPS: { title: string; body: ReactNode }[] = [
  { title: "You upload it", body: "Each upload is saved as a new version. Earlier versions stay as they were." },
  { title: "You set up a Deployment", body: "It picks a version of the script and fills in its parameters." },
  { title: "The Agent checks", body: "That the script is unchanged, and that the Certificate and key are the right ones." },
  {
    title: "The script runs",
    body: (
      <>
        With the files and parameters in <code>CERT_*</code> and <code>{ENV_PREFIX}*</code> variables. It is stopped after 10 minutes.
      </>
    ),
  },
  { title: "The result is saved", body: "Whether it worked, and the first 32 KiB of what it printed." },
];

const REFUSALS: { says: string; fix: ReactNode }[] = [
  {
    says: 'line 12 is inside the parameter section but is not a comment: start it with "# "',
    fix: (
      <>
        Start every line between the begin and end lines with <code># </code>.
      </>
    ),
  },
  {
    says: "the parameter section is not JSON: …",
    fix: (
      <>
        Look for a comma after the last item, or a missing quote. The whole block is one list: <code>[ … ]</code>.
      </>
    ),
  },
  {
    says: "the parameter section must be a JSON array of parameters: …",
    fix: "Give each entry a name, and use only the five fields above.",
  },
  {
    says: 'the parameter name "site-id" must be upper-case letters, digits and _, starting with a letter',
    fix: (
      <>
        Rename it, for example to <code>SITE_ID</code>.
      </>
    ),
  },
  { says: `the parameter name "${ENV_PREFIX}SITE" must not start with ${ENV_PREFIX}`, fix: `Remove ${ENV_PREFIX} from the name. The Agent adds it for you.` },
  { says: 'the parameter "PORT" is declared more than once', fix: "Keep one entry for each name." },
  { says: `a script declares at most ${MAX_PARAMETERS} parameters`, fix: "Use fewer parameters, or work some values out in the script." },
  { says: 'the default of the parameter "PORT" contains a newline', fix: "Keep the default to one line, up to 1 KiB." },
  { says: 'the parameter section needs exactly one "# deploy-params:end" line after its "# deploy-params:begin" line', fix: "Have one begin line, then one end line after it." },
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
      lede="A Deployment Script is a Bash or PowerShell script that an Agent runs on its server whenever a Certificate is issued or renewed. Its job is to put the new Certificate and key where your software uses them. One script can serve many servers: it asks for a few values, called Deployment Parameters, and each Deployment fills them in."
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
            This happens again on every renewal, and whenever you choose “Run again”. Exit with 0 when it worked. Any other exit code marks the run as failed and tells the
            Managed Certificate's Subscribers.
          </p>
        </GuideSection>

        <GuideSection guide="deployment-scripts" id="receives">
          <p className="text-muted-foreground">The Agent sets these environment variables for every run.</p>
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
                    One for each parameter that has a value (see <GuideLink guide="deployment-scripts" section="values">below</GuideLink>)
                  </TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </div>
        </GuideSection>

        <GuideSection guide="deployment-scripts" id="declare">
          <p>
            To ask for values, add a comment block like this anywhere in your script. Between the begin and end lines, each line starts with <code># </code> and the rest is a
            list in JSON. It is the same in Bash and PowerShell.
          </p>
          <Code text={DECLARATION} label="Copy the example section" />
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Field</TableHead>
                  <TableHead>Needed</TableHead>
                  <TableHead>What it does</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <FieldRow field="name" needed>
                  Capital letters, digits and <code>_</code>, starting with a letter. Your script reads it as <code>{ENV_PREFIX}</code> plus the name.
                </FieldRow>
                <FieldRow field="label">The name shown on the Deployment form. Uses the name if left out.</FieldRow>
                <FieldRow field="description">Help text shown under the field.</FieldRow>
                <FieldRow field="required">
                  <code>true</code> if every Deployment must give a value. Leave it out otherwise.
                </FieldRow>
                <FieldRow field="default">Used when the field is left blank.</FieldRow>
              </TableBody>
            </Table>
          </div>
          <ul className="grid gap-2 sm:grid-cols-2">
            <li className="rounded-md border p-3">Up to {MAX_PARAMETERS} parameters, each with its own name.</li>
            <li className="rounded-md border p-3">
              Don't start a name with <code>{ENV_PREFIX}</code>. The Agent adds it.
            </li>
            <li className="rounded-md border p-3">Use only the five fields above.</li>
            <li className="rounded-md border p-3">To change the block, upload a new version of the script.</li>
          </ul>
        </GuideSection>

        <GuideSection guide="deployment-scripts" id="values">
          <p className="text-muted-foreground">With the block above, a Deployment filled in like this gives your script these variables:</p>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Parameter</TableHead>
                  <TableHead>You entered</TableHead>
                  <TableHead>Your script gets</TableHead>
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
                  <TableCell className="text-muted-foreground">nothing: the variable is not set</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </div>
          <ul className="flex list-disc flex-col gap-1.5 pl-5">
            <li>A value is one line of text, up to 1 KiB.</li>
            <li>A blank value means “not given”: the default is used, and if there is none the variable is not set at all. So check whether it is set, not whether it is empty.</li>
            <li>If the Agent's own environment has a variable with the same name, the Deployment's value wins.</li>
            <li>When you change a Deployment's values, its next run uses them.</li>
          </ul>
        </GuideSection>

        <GuideSection guide="deployment-scripts" id="example">
          <p className="text-muted-foreground">
            Three scripts to start from. Each one picks up the Certificate and key, reads its parameters, and marks the part you change for your own server.
          </p>
          <Tabs defaultValue={EXAMPLE_SCRIPTS[0]!.id} className="min-w-0">
            <TabsList className="h-auto flex-wrap">
              {EXAMPLE_SCRIPTS.map((example) => (
                <TabsTrigger key={example.id} value={example.id}>
                  {example.title} <span className="text-muted-foreground">· {example.interpreter === "bash" ? "Bash" : "PowerShell"}</span>
                </TabsTrigger>
              ))}
            </TabsList>
            {EXAMPLE_SCRIPTS.map((example) => (
              <TabsContent key={example.id} value={example.id} className="mt-4">
                <Example example={example} mayUpload={mayUpload} orgId={orgId} />
              </TabsContent>
            ))}
          </Tabs>
        </GuideSection>

        <GuideSection guide="deployment-scripts" id="safety">
          <div className="grid gap-3 md:grid-cols-2">
            <Alert variant="destructive">
              <ShieldAlertIcon />
              <AlertTitle>Don't put secrets in parameters</AlertTitle>
              <AlertDescription>
                Parameters are saved as plain text, and every Organization Administrator can read them. Keep passwords and keys in the Agent's own environment on its server,
                under a name that doesn't start with <code>{ENV_PREFIX}</code>.
              </AlertDescription>
            </Alert>
            <Alert>
              <TriangleAlertIcon />
              <AlertTitle>What your script prints is saved</AlertTitle>
              <AlertDescription>
                The first 32 KiB of output is kept with each run. Never print parameter values, secrets or the key, and leave <code>set -x</code> off.
              </AlertDescription>
            </Alert>
            <Alert>
              <AlertTitle>Check required parameters</AlertTitle>
              <AlertDescription>
                Older Agents run scripts without any parameters. Step 2 of each example stops the script when a required one is missing, so nothing is half-installed. The
                Agents page shows which Agents need updating.
              </AlertDescription>
            </Alert>
            <Alert>
              <AlertTitle>It runs with the Agent's access</AlertTitle>
              <AlertDescription>Review a script as you would any code you put on a server, and put quotes around every variable you use.</AlertDescription>
            </Alert>
          </div>
        </GuideSection>

        <GuideSection guide="deployment-scripts" id="refused">
          <p className="text-muted-foreground">When you upload a script, the platform checks its parameter block. If something is wrong, it refuses the upload and tells you why.</p>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>If the message says</TableHead>
                  <TableHead>Do this</TableHead>
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
function Example({ example, mayUpload, orgId }: { example: ExampleScript; mayUpload: boolean; orgId: string }) {
  const { interpreter } = example;
  const content = exampleContent(example);
  return (
    <div className="flex flex-col gap-4">
      <p className="text-muted-foreground">{example.summary}</p>
      <div className="flex flex-wrap items-center justify-end gap-2">
        <Button variant="outline" size="sm" onClick={() => navigator.clipboard.writeText(content).then(() => toast.success("Copied the script"), () => toast.error("Could not copy the script"))}>
          Copy the whole script
        </Button>
        {mayUpload && <UploadDialog orgId={orgId} start={example.id} trigger={<Button size="sm">Use as a new script</Button>} />}
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
