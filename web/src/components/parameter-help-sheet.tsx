import { CircleHelpIcon } from "lucide-react";
import { GuideLink } from "@/components/guide";
import { ScriptEnvironment } from "@/components/script-environment";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import type { ScriptParameter } from "@/lib/api";

const RULES: [string, string][] = [
  ["Blank", "Uses the default. With no default, the variable isn't set."],
  ["Limits", "One line, up to 1 KiB."],
  ["Renewals", "Every renewal and “Run again” uses these same values."],
  ["Changing", "You can edit them later on the Deployment. The next run uses the new ones."],
  ["Secrets", "Don't put them here: values are saved as plain text. Keep secrets in the Agent's own environment on its server."],
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
          What the script will get
        </Button>
      </SheetTrigger>
      <SheetContent className="flex flex-col gap-0 overflow-y-auto sm:max-w-md">
        <SheetHeader>
          <SheetTitle>What the script will get</SheetTitle>
          <SheetDescription>The Agent gives each value to {script} as an environment variable. With what you have entered, the script gets:</SheetDescription>
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
              What the script sees
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
