import type { ComponentProps } from "react";
import { NavMain } from "@/components/nav-main";
import { NavUser } from "@/components/nav-user";
import { OrgSwitcher } from "@/components/org-switcher";
import { Sidebar, SidebarContent, SidebarFooter, SidebarHeader, SidebarRail } from "@/components/ui/sidebar";
import type { Me } from "@/lib/api";
import { organizationNavGroups, platformNav } from "@/lib/navigation";

/** `active` is the Organization the pages in the sidebar belong to. */
export function AppSidebar({ me, active, ...props }: { me: Me; active: Me["organizations"][number] | undefined } & ComponentProps<typeof Sidebar>) {
  return (
    <Sidebar collapsible="icon" {...props}>
      <SidebarHeader>
        <OrgSwitcher organizations={me.organizations} active={active} />
      </SidebarHeader>
      <SidebarContent>
        {active && organizationNavGroups(active).map((group) => <NavMain key={group.label ?? "pages"} label={group.label} items={group.items} />)}
        {me.user.isPlatformOperator && <NavMain label="Platform" items={platformNav} />}
      </SidebarContent>
      <SidebarFooter>
        <NavUser user={me.user} />
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}
