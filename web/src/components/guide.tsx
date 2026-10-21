import { Link, useLocation, useRouter } from "@tanstack/react-router";
import { createContext, useContext, type ReactNode } from "react";

/**
 * The in-app guides: each a page of its own beside the page it explains, in sections that the rest of the app links into
 * by anchor. A section's title is its heading in the guide and its entry in the guide's own menu.
 */
export const GUIDES = {
  "deployment-scripts": {
    title: "Writing Deployment Scripts",
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
    title: "Publishing a Private CA",
    path: "/organizations/$orgId/private-cas/guide",
    sections: {
      how: "How revocation is checked",
      url: "Where Certificates send relying parties",
      reach: "Checking your relying parties reach it",
      crl: "When CRLs change",
      trust: "Trusting the root",
      rollover: "Rolling over",
    },
  },
  "enrollment-profiles": {
    title: "Setting up device enrollment",
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
    title: "Choosing how names are validated",
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

export const isGuide = (value: unknown): value is Guide => typeof value === "string" && value in GUIDES;

/** Whether a guide is being shown in the help panel rather than as a page: the panel prefixes its anchors, so the two never clash. */
const InPanel = createContext(false);
export const GuidePanelFrame = ({ children }: { children: ReactNode }) => <InPanel.Provider value={true}>{children}</InPanel.Provider>;
/** The id a section's element has: its own on the guide's page, prefixed in the panel. */
export const sectionElementId = (id: string, inPanel: boolean) => (inPanel ? `help-${id}` : id);

/** The address of the current page with guide `guide` open in the help panel, at `section`. */
function helpHref(location: { pathname: string; searchStr: string }, guide: Guide, section?: string) {
  const params = new URLSearchParams(location.searchStr);
  params.set("help", guide);
  if (section) params.set("section", section);
  else params.delete("section");
  return `${location.pathname}?${params}`;
}

/**
 * The help panel's state, which lives in the address (`?help=<guide>&section=<id>`): opening a guide is a step in the
 * browser's history, so Back closes it, a reload keeps it, and a link to it can be shared.
 */
export function useHelp() {
  const router = useRouter();
  const location = useLocation();
  const search = location.search as Record<string, unknown>;
  const guide = isGuide(search.help) ? search.help : null;
  const section = typeof search.section === "string" ? search.section : null;
  return {
    guide,
    section,
    open: (to: Guide, at?: string) => router.history.push(helpHref(location, to, at)),
    close: () => {
      const params = new URLSearchParams(location.searchStr);
      params.delete("help");
      params.delete("section");
      router.history.replace(`${location.pathname}${params.size > 0 ? `?${params}` : ""}`);
    },
  };
}

/**
 * A link that opens a guide in the help panel, at `section` when given, over whatever is open: the page, and any dialog
 * on it, stay as they are. Opened in a new tab or window, it is the same page with the panel open.
 */
export function GuideLink<G extends Guide>({
  guide,
  section,
  className,
  children,
}: {
  /** Kept for the callers; the panel opens over the Organization's page that is open. */
  orgId?: string;
  guide: G;
  section?: GuideSection<G>;
  className?: string;
  children: ReactNode;
}) {
  const location = useLocation();
  const help = useHelp();
  // On the guide's own page, a link into it only scrolls there.
  const onItsPage = !useContext(InPanel) && location.pathname.endsWith(GUIDES[guide].path.split("$orgId")[1]!);
  if (onItsPage)
    return (
      <a href={`#${section ?? ""}`} className={className ?? LINK}>
        {children}
      </a>
    );
  return (
    <a
      href={helpHref(location, guide, section)}
      className={className ?? LINK}
      onClick={(e) => {
        // A new tab or window is the browser's to open.
        if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
        e.preventDefault();
        help.open(guide, section);
      }}
    >
      {children}
    </a>
  );
}

/** A guide's content: as a page, its menu of sections beside it and a way back to the page it explains; in the help panel, compact, with a way to open it as a page. */
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
  const inPanel = useContext(InPanel);
  const sections = Object.entries(GUIDES[guide].sections);
  if (inPanel) {
    return (
      <article className="flex min-w-0 flex-col gap-10 text-sm leading-relaxed">
        <header className="flex flex-col gap-3">
          <h2 className="pr-8 text-xl font-semibold">{title}</h2>
          <div className="text-muted-foreground">{lede}</div>
          <nav aria-label="Guide sections" className="flex flex-wrap gap-1.5">
            {sections.map(([id, sectionTitle]) => (
              <button
                key={id}
                type="button"
                className="rounded-full border px-2.5 py-1 text-xs text-muted-foreground hover:bg-muted hover:text-foreground"
                onClick={() => document.getElementById(sectionElementId(id, true))?.scrollIntoView({ behavior: "smooth", block: "start" })}
              >
                {sectionTitle}
              </button>
            ))}
          </nav>
          <Link to={GUIDES[guide].path} params={{ orgId: back.orgId }} className="self-start text-xs font-medium underline underline-offset-4 hover:text-primary">
            Open as a page
          </Link>
        </header>
        {children}
      </article>
    );
  }
  return (
    <div className="flex flex-col gap-6 lg:flex-row lg:items-start lg:gap-10">
      <nav aria-label="Guide sections" className="flex flex-col gap-1 text-sm lg:sticky lg:top-4 lg:w-52 lg:shrink-0">
        <span className="px-2 pb-1 text-xs font-medium tracking-wide text-muted-foreground uppercase">On this page</span>
        {sections.map(([id, sectionTitle]) => (
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
  const elementId = sectionElementId(id, useContext(InPanel));
  return (
    <section id={elementId} aria-labelledby={`${elementId}-title`} className="flex scroll-mt-4 flex-col gap-4">
      <h2 id={`${elementId}-title`} className="text-lg font-semibold">
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
