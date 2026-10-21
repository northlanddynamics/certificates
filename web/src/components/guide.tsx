import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";

/**
 * The in-app guides: each a page of its own beside the page it explains, in sections that the rest of the app links into
 * by anchor. A section's title is its heading in the guide and its entry in the guide's own menu.
 */
export const GUIDES = {
  "deployment-scripts": {
    path: "/organizations/$orgId/deployment-scripts/guide",
    sections: {
      how: "How a script runs",
      receives: "What every script receives",
      declare: "Declaring parameters",
      values: "How values reach the script",
      example: "Example script",
      safety: "Secrets and safety",
      refused: "When an upload is refused",
    },
  },
  "private-cas": {
    path: "/organizations/$orgId/private-cas/guide",
    sections: {
      how: "How revocation is checked",
      url: "Your PKI base URL",
      reach: "Making it reachable",
      crl: "When CRLs change",
      trust: "Trusting the root",
      rollover: "Rolling over",
    },
  },
  "enrollment-profiles": {
    path: "/organizations/$orgId/enrollment-profiles/guide",
    sections: {
      flow: "How a device enrolls",
      choose: "Choosing a validator",
      intune: "Microsoft Intune",
      shared: "Shared Challenge",
      refused: "When a device is refused",
    },
  },
  dcv: {
    path: "/organizations/$orgId/dcv/guide",
    sections: {
      methods: "Direct or Delegated",
      rules: "Which rule applies",
      delegate: "Setting up delegation",
      fails: "When DCV fails",
    },
  },
} as const;
export type Guide = keyof typeof GUIDES;
export type GuideSection<G extends Guide> = keyof (typeof GUIDES)[G]["sections"] & string;

const LINK = "font-medium underline underline-offset-4 hover:text-primary";

/** A link to a guide, at `section` when given; `newTab` from inside a form, so that what is typed in it is kept. */
export function GuideLink<G extends Guide>({
  orgId,
  guide,
  section,
  newTab = false,
  className,
  children,
}: {
  orgId: string;
  guide: G;
  section?: GuideSection<G>;
  newTab?: boolean;
  className?: string;
  children: ReactNode;
}) {
  return (
    <Link to={GUIDES[guide].path} params={{ orgId }} hash={section} {...(newTab && { target: "_blank", rel: "noopener" })} className={className ?? LINK}>
      {children}
      {newTab && <span className="sr-only"> (opens in a new tab)</span>}
    </Link>
  );
}

/** A guide's page: its menu of sections, and the article with a way back to the page it explains. */
export function GuidePage<G extends Guide>({
  guide,
  title,
  lede,
  back,
  children,
}: {
  guide: G;
  title: string;
  lede: ReactNode;
  back: { to: string; label: string; orgId: string };
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-6 lg:flex-row lg:items-start lg:gap-10">
      <nav aria-label="Guide sections" className="flex flex-col gap-1 text-sm lg:sticky lg:top-4 lg:w-52 lg:shrink-0">
        <span className="px-2 pb-1 text-xs font-medium tracking-wide text-muted-foreground uppercase">On this page</span>
        {Object.entries(GUIDES[guide].sections).map(([id, sectionTitle]) => (
          <a key={id} href={`#${id}`} className="rounded-md px-2 py-1.5 text-muted-foreground hover:bg-muted hover:text-foreground">
            {sectionTitle}
          </a>
        ))}
      </nav>
      <article className="flex min-w-0 max-w-3xl flex-1 flex-col gap-12 text-sm leading-relaxed">
        <header className="flex flex-col gap-3">
          <Link to={back.to} params={{ orgId: back.orgId }} className="text-sm text-muted-foreground hover:text-foreground">
            ← {back.label}
          </Link>
          <h1 className="text-2xl font-semibold">{title}</h1>
          <div className="text-base text-muted-foreground">{lede}</div>
        </header>
        {children}
      </article>
    </div>
  );
}

/** One section of guide `guide`, headed by its title. */
export function GuideSection<G extends Guide>({ guide, id, children }: { guide: G; id: GuideSection<G>; children: ReactNode }) {
  const sections: Record<string, string> = GUIDES[guide].sections;
  return (
    <section id={id} aria-labelledby={`${id}-title`} className="flex scroll-mt-4 flex-col gap-4">
      <h2 id={`${id}-title`} className="text-lg font-semibold">
        {sections[id]}
      </h2>
      {children}
    </section>
  );
}

/** Numbered steps, each a sentence or two. */
export function Steps({ start = 1, children }: { start?: number; children: ReactNode[] }) {
  return (
    <ol className="flex flex-col gap-2.5">
      {children.map((step, i) => (
        <li key={i} className="flex gap-3">
          <span aria-hidden="true" className="flex size-6 shrink-0 items-center justify-center rounded-full bg-primary text-xs font-semibold text-primary-foreground">
            {start + i}
          </span>
          <span className="pt-0.5">{step}</span>
        </li>
      ))}
    </ol>
  );
}
