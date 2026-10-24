import { ChevronDownIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";

/**
 * The top of a page: its title, with its primary action beside it, then one sentence on what the page is for; the rest
 * of the explanation, if any, folded under "How it works" (or `howItWorksTitle`) until asked for.
 */
export function PageHeader({
  title,
  description,
  action,
  howItWorks,
  howItWorksTitle = "How it works",
}: {
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  howItWorks?: ReactNode;
  howItWorksTitle?: string;
}) {
  return (
    <header className="flex flex-col gap-1">
      <div className="flex min-h-9 items-center justify-between gap-4">
        <h1 className="min-w-0 text-xl font-semibold">{title}</h1>
        {action && <div className="flex shrink-0 items-center gap-2">{action}</div>}
      </div>
      {description && <p className="max-w-3xl text-sm text-muted-foreground">{description}</p>}
      {howItWorks && (
        <Collapsible className="group/how">
          <CollapsibleTrigger asChild>
            <Button type="button" variant="ghost" size="sm" className="-ml-2">
              <ChevronDownIcon className="transition-transform group-data-[state=closed]/how:-rotate-90" />
              {howItWorksTitle}
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="flex max-w-3xl flex-col gap-2 pt-1 text-sm text-muted-foreground">{howItWorks}</CollapsibleContent>
        </Collapsible>
      )}
    </header>
  );
}
