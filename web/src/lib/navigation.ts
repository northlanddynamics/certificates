import { BellIcon, BuildingIcon, LockKeyholeIcon, PlugIcon, ScrollTextIcon, SendIcon, BotIcon, GlobeIcon, LandmarkIcon, FileKey2Icon, FileTerminalIcon, KeyRoundIcon, LogInIcon, RocketIcon, ShieldCheckIcon, ShieldEllipsisIcon, ShieldIcon, ShieldUserIcon, TabletSmartphoneIcon, UserRoundIcon, UsersIcon, type LucideIcon } from "lucide-react";
import { can, type Me } from "@/lib/api";

type Org = Me["organizations"][number];

export interface NavItem {
  title: string;
  /** The path of the page, which is also how the active item is found. */
  url: string;
  icon: LucideIcon;
}

/** Pages under a heading of their own inside a section. */
export interface NavSubgroup {
  title: string;
  items: NavItem[];
}

/** Pages folded under one expandable entry of a group. */
export interface NavSection {
  title: string;
  icon: LucideIcon;
  items: (NavItem | NavSubgroup)[];
}

export interface NavGroup {
  /** None for a group that stands without a heading. */
  label?: string;
  items: (NavItem | NavSection)[];
}

export const isNavSection = (entry: NavItem | NavSection): entry is NavSection => "items" in entry;
export const isNavSubgroup = (entry: NavItem | NavSubgroup): entry is NavSubgroup => "items" in entry;

/** The pages of a section, its subgroups' included. */
export const sectionPages = (section: NavSection): NavItem[] => section.items.flatMap((entry) => (isNavSubgroup(entry) ? entry.items : [entry]));

/** The pages of one Organization that the caller may open, under the headings the sidebar gives them; a heading, section or subgroup with no page left under it is not shown. */
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
        {
          title: "Integrations",
          icon: PlugIcon,
          items: [
            ...(can(org, "acmeAccount", "read") ? [{ title: "ACME accounts", url: `${base}/acme-accounts`, icon: LandmarkIcon }] : []),
            {
              title: "Certificate authorities",
              // Anyone may list them (to choose one for a Managed Certificate), but the page is for managing them.
              items: can(org, "privateCa", "create") ? [{ title: "Private CAs", url: `${base}/private-cas`, icon: ShieldEllipsisIcon }] : [],
            },
            ...(can(org, "dnsProvider", "read") ? [{ title: "DNS Providers", url: `${base}/dns-providers`, icon: GlobeIcon }] : []),
            // Anyone may list the channels (to choose one as a Subscriber), but the page is for configuring them.
            ...(can(org, "notificationChannel", "create") ? [{ title: "Notification channels", url: `${base}/notification-channels`, icon: BellIcon }] : []),
          ],
        },
        {
          title: "Security",
          icon: ShieldIcon,
          items: [
            ...(can(org, "loginPolicy", "read") ? [{ title: "Login policy", url: loginPolicyUrl(org.id), icon: LockKeyholeIcon }] : []),
            ...(can(org, "ssoConnection", "read") ? [{ title: "SSO connections", url: `${base}/sso-connections`, icon: LogInIcon }] : []),
          ],
        },
      ],
    },
    {
      label: "Device identity",
      items: can(org, "enrollmentProfile", "read") ? [{ title: "Enrollment Profiles", url: `${base}/enrollment-profiles`, icon: TabletSmartphoneIcon }] : [],
    },
    {
      label: "Audit",
      items: [
        ...(can(org, "audit", "read") ? [{ title: "Audit log", url: `${base}/audit-log`, icon: ScrollTextIcon }] : []),
        ...(can(org, "auditForwarder", "read") ? [{ title: "Audit forwarding", url: `${base}/audit-forwarding`, icon: SendIcon }] : []),
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
  const pruneSection = (section: NavSection): NavSection => ({ ...section, items: section.items.filter((entry) => !isNavSubgroup(entry) || entry.items.length > 0) });
  return groups
    .map((g) => ({ ...g, items: g.items.map((entry) => (isNavSection(entry) ? pruneSection(entry) : entry)).filter((entry) => !isNavSection(entry) || entry.items.length > 0) }))
    .filter((g) => g.items.length > 0);
}

/** The same pages in one list, to find the one that is open. */
export const organizationNav = (org: Org): NavItem[] =>
  [...organizationNavGroups(org).flatMap((g) => g.items.flatMap((entry) => (isNavSection(entry) ? sectionPages(entry) : [entry]))), ...organizationAccountNav(org)];

export const platformNav: NavItem[] = [{ title: "Organizations", url: "/platform/organizations", icon: BuildingIcon }];

/** An Organization's login policy, which stays open to a user it holds up, so that the requirement can be undone. */
export const loginPolicyUrl = (orgId: string) => `/organizations/${orgId}/login-policy`;

/** The signed-in user's own page, which the user menu opens. */
export const ACCOUNT_SECURITY_URL = "/account/security";
export const accountNav: NavItem[] = [{ title: "Account security", url: ACCOUNT_SECURITY_URL, icon: ShieldUserIcon }];

/** The signed-in user's pages within one Organization, which the user menu opens below their own. Anyone may make their own API keys, so the page is open to all. */
export const organizationAccountNav = (org: Org): NavItem[] => [{ title: "API keys", url: `/organizations/${org.id}/api-keys`, icon: KeyRoundIcon }];

/** Whether `pathname` is on the page `url`. */
export const isOnPage = (pathname: string, url: string) => pathname === url || pathname.startsWith(`${url}/`);
