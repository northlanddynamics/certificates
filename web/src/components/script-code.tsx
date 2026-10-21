import { Suspense, lazy } from "react";
import { cn } from "cn";
import type { DeploymentScript } from "@/lib/api";

// The highlighter comes with the script editor, loaded the first time a script is shown; until then the text shows plain.
const ScriptView = lazy(() => import("@/components/script-editor").then((m) => ({ default: m.ScriptView })));

/** A Deployment Script's code, coloured for its interpreter, in a box that scrolls rather than wraps. */
export function ScriptCode({
  code,
  interpreter,
  label,
  lineNumbers = false,
  className,
}: {
  code: string;
  interpreter: DeploymentScript["interpreter"];
  label: string;
  lineNumbers?: boolean;
  className?: string;
}) {
  const box = cn("overflow-auto rounded-md border bg-muted/40 py-1", className);
  return (
    <Suspense
      fallback={
        <pre aria-label={label} className={cn(box, "px-3 font-mono text-xs leading-relaxed")}>
          {code}
        </pre>
      }
    >
      <ScriptView code={code} interpreter={interpreter} label={label} lineNumbers={lineNumbers} className={box} />
    </Suspense>
  );
}
