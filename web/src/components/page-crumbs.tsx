import { createContext, useContext, useEffect } from "react";

/** A step of the breadcrumb past the page the sidebar names, such as a Managed Certificate's name; `url` makes it a link. */
export interface Crumb {
  label: string;
  url?: string;
}

export const PageCrumbsContext = createContext<(crumbs: Crumb[]) => void>(() => {});

/** Adds `crumbs` after the sidebar's page in the shell's breadcrumb while the calling page is open. */
export function usePageCrumbs(crumbs: Crumb[]) {
  const set = useContext(PageCrumbsContext);
  const key = JSON.stringify(crumbs);
  useEffect(() => {
    set(JSON.parse(key) as Crumb[]);
    return () => set([]);
  }, [set, key]);
}
