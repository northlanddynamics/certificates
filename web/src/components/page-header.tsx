import { CircleHelpIcon } from "lucide-react";
import type { ReactNode } from "react";
import { GUIDES, GuideLink, useHelp, type Guide } from "@/components/guide";
import { HelpSheet } from "@/components/help-sheet";
import { Button } from "@/components/ui/button";

/** A page action's words, which a phone leaves to its icon (still read out), so that the title keeps its line. */
export function ActionLabel({ children }: { children: ReactNode }) {
  return <span className="max-sm:sr-only">{children}</span>;
}

/**
 * The top of a page: its title, with its primary action beside it, then one sentence on what the page is for; the rest
 * of the explanation, if any, behind "How it works" (or `howItWorksTitle`), which opens it in the help panel over the page.
 */
export function PageHeader({
  title,
  description,
  action,
  howItWorks,
  howItWorksTitle = "How it works",
  guide,
}: {
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  howItWorks?: ReactNode;
  howItWorksTitle?: string;
  /** The page's full guide, which its explanation ends by pointing to. */
  guide?: Guide;
}) {
  const help = useHelp();
  return (
    <header className="flex flex-col gap-1">
      <div className="flex min-h-9 items-center justify-between gap-4">
        <h1 className="min-w-0 text-xl font-semibold">{title}</h1>
        {action && <div className="flex shrink-0 items-center gap-2">{action}</div>}
      </div>
      {description && <p className="max-w-3xl text-sm text-muted-foreground">{description}</p>}
      {howItWorks && (
        <>
          <Button type="button" variant="ghost" size="sm" className="-ml-2 self-start" aria-haspopup="dialog" onClick={help.openPageHelp}>
            <CircleHelpIcon />
            {howItWorksTitle}
          </Button>
          <HelpSheet open={help.pageHelp} onClose={help.close} title={`Help: ${howItWorksTitle}`} description={`How the ${typeof title === "string" ? title : "page"} page works.`}>
            <article className="flex flex-col gap-4 text-sm leading-relaxed text-muted-foreground">
              <header className="flex flex-col gap-1 pr-8">
                {typeof title === "string" && <span className="text-xs font-medium tracking-wide uppercase">{title}</span>}
                <h2 className="text-xl font-semibold text-foreground">{howItWorksTitle}</h2>
              </header>
              {howItWorks}
              {guide && (
                <p className="border-t pt-4">
                  More in <GuideLink guide={guide}>{GUIDES[guide].title}</GuideLink>.
                </p>
              )}
            </article>
          </HelpSheet>
        </>
      )}
    </header>
  );
}
