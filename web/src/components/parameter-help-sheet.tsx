import { CircleHelpIcon } from "lucide-react";
import { GuideLink } from "@/components/guide";
import { ScriptEnvironment } from "@/components/script-environment";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import type { ScriptParameter } from "@/lib/api";

const RULES: [string, string][] = [
  ["Blank", "Takes the default; with none, the variable is left out."],
  ["Limits", "One line, at most 1 KiB."],
  ["Renewals", "Every Renewal and “Run again” reuses these values."],
  ["Changing", "Edit them later from the Deployment: the next delivery to the Agent has the new ones."],
  ["Secrets", "Not here: they are kept in plain text. Set them in the Agent's own environment on its host."],
];

/**
 * How the values a Deployment form holds reach its script, in a side sheet so the form stays in view: the environment the
 * script will see with them, the rules, and the way into the guide. `script` names the version, as "nginx-site v3".
 */
export function ParameterHelpSheet({ orgId, script, declared, values }: { orgId: string; script: string; declared: ScriptParameter[]; values: Record<string, string> }) {
  return (
    <Sheet>
      <SheetTrigger asChild>
        <Button type="button" variant="outline" size="sm">
          <CircleHelpIcon />
          How these reach the script
        </Button>
      </SheetTrigger>
      <SheetContent className="flex flex-col gap-0 overflow-y-auto sm:max-w-md">
        <SheetHeader>
          <SheetTitle>How these reach the script</SheetTitle>
          <SheetDescription>The Agent gives each value to {script} as an environment variable. With what is entered now, the script will see:</SheetDescription>
        </SheetHeader>
        <div className="flex flex-col gap-5 px-4 pb-4 text-sm">
          <ScriptEnvironment declared={declared} values={values} />
          <dl className="grid grid-cols-[6rem_1fr] gap-x-3 gap-y-2">
            {RULES.map(([term, rule]) => (
              <div key={term} className="contents">
                <dt className="font-medium">{term}</dt>
                <dd className="text-muted-foreground">{rule}</dd>
              </div>
            ))}
          </dl>
          <div className="flex flex-col gap-2 border-t pt-4">
            <GuideLink orgId={orgId} guide="deployment-scripts" section="values">
              How values reach the script
            </GuideLink>
            <GuideLink orgId={orgId} guide="deployment-scripts" section="example">
              An example script that reads them
            </GuideLink>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
