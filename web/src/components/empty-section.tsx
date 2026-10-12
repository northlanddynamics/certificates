import { useId, type ReactNode } from "react";

/** A section of a page that is not built yet: says so, and what will appear in it. Nothing in it can be used. */
export function EmptySection({ title, children }: { title: string; children: ReactNode }) {
  const titleId = useId();
  return (
    <section aria-labelledby={titleId} className="flex flex-col items-center gap-2 rounded-lg border border-dashed p-10 text-center">
      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Not available yet</p>
      <h2 id={titleId} className="text-base font-medium">
        {title}
      </h2>
      <p className="max-w-md text-sm text-muted-foreground">{children}</p>
    </section>
  );
}
