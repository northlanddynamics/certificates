import { BadgeCheckIcon, LayoutDashboardIcon, FileBadgeIcon, BellIcon, BuildingIcon, PlugIcon, ScrollTextIcon, SendIcon, BotIcon, GlobeIcon, LandmarkIcon, FileKey2Icon, FileSearchIcon, FileTerminalIcon, KeyRoundIcon, LogInIcon, RocketIcon, SearchCheckIcon, ServerCogIcon, ShieldCheckIcon, ShieldEllipsisIcon, ShieldUserIcon, TabletSmartphoneIcon, UserRoundIcon, UsersIcon, type LucideIcon } from "lucide-react";
import { can, type Me } from "@/lib/api";

type Org = Me["organizations"][number];

export interface NavItem {
  title: string;
  /** The path of the page, which is also how the active item is found. */
  url: string;
  icon: LucideIcon;
}

/** Pages folded under one expandable entry of a group. */
export interface NavSection {
  title: string;
  icon: LucideIcon;
  items: NavItem[];
}

export interface NavGroup {
  /** None for a group that stands without a heading. */
  label?: string;
  items: (NavItem | NavSection)[];
}

export const isNavSection = (entry: NavItem | NavSection): entry is NavSection => "items" in entry;

/** The pages of one Organization that the caller may open, under the headings the sidebar gives them; a heading or section with no page left under it is not shown, and a section with one is just that page. */
export function organizationNavGroups(org: Org): NavGroup[] {
  const base = `/organizations/${org.id}`;
  const groups: NavGroup[] = [
    // Open to everyone: it shows each caller what they see in the inventory.
    { items: [{ title: "Dashboard", url: `${base}/dashboard`, icon: LayoutDashboardIcon }] },
    { label: "Inventory", items: [{ title: "Managed Certificates", url: `${base}/certificates`, icon: ShieldCheckIcon }] },
    // Run in the browser and asking the platform for nothing, so there is no permission to check.
    {
      label: "Tools",
      items: [
        { title: "CSR Generator", url: `${base}/tools/csr`, icon: FileKey2Icon },
        { title: "PEM Parser", url: `${base}/tools/viewer`, icon: FileSearchIcon },
      ],
    },
    {
      label: "Organization",
      items: [
        ...(can(org, "invitation", "create")
          ? [
              { title: "Members", url: `${base}/members`, icon: UserRoundIcon },
              { title: "Teams", url: `${base}/teams`, icon: UsersIcon },
            ]
          : []),
        // Shown to whoever may see either of its sections, which each check for themselves.
        ...(can(org, "loginPolicy", "read") || can(org, "ssoConnection", "read") ? [{ title: "Sign-in settings", url: signInSettingsUrl(org.id), icon: LogInIcon }] : []),
      ],
    },
    {
      label: "Administration",
      items: [
        {
          // Where certificates come from: the Organization's own CAs, and its accounts with ACME CAs.
          title: "Certificate authorities",
          icon: BadgeCheckIcon,
          items: [
            // Anyone may list them (to choose one for a Managed Certificate), but the page is for managing them.
            ...(can(org, "privateCa", "create") ? [{ title: "Private CAs", url: `${base}/private-cas`, icon: ShieldEllipsisIcon }] : []),
            ...(can(org, "adcsCa", "create") ? [{ title: "ADCS CAs", url: `${base}/adcs-cas`, icon: ServerCogIcon }] : []),
            ...(can(org, "acmeAccount", "read") ? [{ title: "ACME accounts", url: `${base}/acme-accounts`, icon: LandmarkIcon }] : []),
          ],
        },
        // Every member lists the enabled ones (to request against one), but the page is for managing them.
        ...(can(org, "certificateProfile", "create") ? [{ title: "Certificate Profiles", url: `${base}/certificate-profiles`, icon: FileBadgeIcon }] : []),
        {
          title: "Integrations",
          icon: PlugIcon,
          items: [
            ...(can(org, "dnsProvider", "read") ? [{ title: "DNS Providers", url: `${base}/dns-providers`, icon: GlobeIcon }] : []),
            ...(can(org, "dcvRule", "read") ? [{ title: "DCV", url: `${base}/dcv`, icon: SearchCheckIcon }] : []),
            // Anyone may list the channels (to choose one as a Subscriber), but the page is for configuring them.
            ...(can(org, "notificationChannel", "create") ? [{ title: "Notification channels", url: `${base}/notification-channels`, icon: BellIcon }] : []),
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
        // Anyone may make their own keys, so the page is open to all.
        { title: "API keys", url: `${base}/api-keys`, icon: KeyRoundIcon },
      ],
    },
  ];
  // A section with no page left under it is not shown, and one with a single page is that page, with nothing to fold.
  return groups
    .map((g) => ({ ...g, items: g.items.filter((entry) => !isNavSection(entry) || entry.items.length > 0).map((entry) => (isNavSection(entry) && entry.items.length === 1 ? entry.items[0]! : entry)) }))
    .filter((g) => g.items.length > 0);
}

/** The same pages in one list, to find the one that is open. */
export const organizationNav = (org: Org): NavItem[] => organizationNavGroups(org).flatMap((g) => g.items.flatMap((entry) => (isNavSection(entry) ? entry.items : [entry])));

export const platformNav: NavItem[] = [{ title: "Organizations", url: "/platform/organizations", icon: BuildingIcon }];

/** An Organization's sign-in settings (its login policy and SSO connections), which stay open to a user the login policy holds up, so that the requirement can be undone. */
export const signInSettingsUrl = (orgId: string) => `/organizations/${orgId}/sign-in-settings`;

/** The signed-in user's own page, which the user menu opens; an Organization's settings are in the sidebar. */
export const ACCOUNT_SECURITY_URL = "/account/security";
export const accountNav: NavItem[] = [{ title: "Account security", url: ACCOUNT_SECURITY_URL, icon: ShieldUserIcon }];

/** Whether `pathname` is on the page `url`. */
export const isOnPage = (pathname: string, url: string) => pathname === url || pathname.startsWith(`${url}/`);
