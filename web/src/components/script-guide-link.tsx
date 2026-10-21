import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";

/** The Deployment Scripts guide's sections, in order; each is an anchor the rest of the app links to. */
export const GUIDE_SECTIONS = {
  how: "How a script runs",
  receives: "What every script receives",
  declare: "Declaring parameters",
  values: "How values reach the script",
  example: "Example script",
  safety: "Secrets and safety",
  refused: "When an upload is refused",
} as const;
export type GuideSection = keyof typeof GUIDE_SECTIONS;

/** A link to the Deployment Scripts guide, at `section` when given; `newTab` from inside a form, so that what is typed in it is kept. */
export function GuideLink({ orgId, section, newTab = false, className, children }: { orgId: string; section?: GuideSection; newTab?: boolean; className?: string; children: ReactNode }) {
  return (
    <Link
      to="/organizations/$orgId/deployment-scripts/guide"
      params={{ orgId }}
      hash={section}
      {...(newTab && { target: "_blank", rel: "noopener" })}
      className={className ?? "font-medium underline underline-offset-4 hover:text-primary"}
    >
      {children}
      {newTab && <span className="sr-only"> (opens in a new tab)</span>}
    </Link>
  );
}
