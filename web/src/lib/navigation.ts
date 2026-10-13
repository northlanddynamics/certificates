import { BuildingIcon, BotIcon, LandmarkIcon, FileKey2Icon, FileTerminalIcon, KeyRoundIcon, RocketIcon, ShieldCheckIcon, UserRoundIcon, UsersIcon, type LucideIcon } from "lucide-react";
import { can, type Me } from "@/lib/api";

type Org = Me["organizations"][number];

export interface NavItem {
  title: string;
  /** The path of the page, which is also how the active item is found. */
  url: string;
  icon: LucideIcon;
}

export interface NavGroup {
  /** None for a group that stands without a heading. */
  label?: string;
  items: NavItem[];
}

/** The pages of one Organization that the caller may open, under the headings the sidebar gives them; a heading with no page left under it is not shown. */
export function organizationNavGroups(org: Org): NavGroup[] {
  const base = `/organizations/${org.id}`;
  const groups: NavGroup[] = [
    { label: "Inventory", items: [{ title: "Managed Certificates", url: `${base}/certificates`, icon: ShieldCheckIcon }] },
    // Generated in the browser and asking the platform for nothing, so there is no permission to check.
    { label: "Tools", items: [{ title: "CSR Generator", url: `${base}/tools/csr`, icon: FileKey2Icon }] },
    {
      label: "Organization",
      items: can(org, "invitation", "create")
        ? [
            { title: "Members", url: `${base}/members`, icon: UserRoundIcon },
            { title: "Teams", url: `${base}/teams`, icon: UsersIcon },
          ]
        : [],
    },
    {
      label: "Administration",
      items: [
        { title: "API keys", url: `${base}/api-keys`, icon: KeyRoundIcon },
        ...(can(org, "acmeAccount", "read") ? [{ title: "ACME accounts", url: `${base}/acme-accounts`, icon: LandmarkIcon }] : []),
      ],
    },
    {
      label: "Automation",
      items: [
        ...(can(org, "agent", "read") ? [{ title: "Agents", url: `${base}/agents`, icon: BotIcon }] : []),
        ...(can(org, "deployment", "read") ? [{ title: "Deployments", url: `${base}/deployments`, icon: RocketIcon }] : []),
        ...(can(org, "deploymentScript", "read") ? [{ title: "Deployment Scripts", url: `${base}/deployment-scripts`, icon: FileTerminalIcon }] : []),
      ],
    },
  ];
  return groups.filter((g) => g.items.length > 0);
}

/** The same pages in one list, to find the one that is open. */
export const organizationNav = (org: Org): NavItem[] => organizationNavGroups(org).flatMap((g) => g.items);

export const platformNav: NavItem[] = [{ title: "Organizations", url: "/platform/organizations", icon: BuildingIcon }];

/** Whether `pathname` is on the page `url`. */
export const isOnPage = (pathname: string, url: string) => pathname === url || pathname.startsWith(`${url}/`);
