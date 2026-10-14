import { useState } from "react";
import { Link, useLocation } from "@tanstack/react-router";
import { ChevronRightIcon } from "lucide-react";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import {
  SidebarGroup,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  useSidebar,
} from "@/components/ui/sidebar";
import { isNavSection, isOnPage, type NavItem, type NavSection } from "@/lib/navigation";

export function NavMain({ label, items }: { label?: string; items: (NavItem | NavSection)[] }) {
  const { pathname } = useLocation();
  return (
    <SidebarGroup>
      {label && <SidebarGroupLabel>{label}</SidebarGroupLabel>}
      <SidebarMenu>
        {items.map((entry) =>
          isNavSection(entry) ? (
            <NavMainSection key={entry.title} section={entry} pathname={pathname} />
          ) : (
            <SidebarMenuItem key={entry.url}>
              <SidebarMenuButton asChild isActive={isOnPage(pathname, entry.url)} tooltip={entry.title}>
                <Link to={entry.url}>
                  <entry.icon />
                  <span>{entry.title}</span>
                </Link>
              </SidebarMenuButton>
            </SidebarMenuItem>
          ),
        )}
      </SidebarMenu>
    </SidebarGroup>
  );
}

/** An expandable entry, open while one of its pages is. */
function NavMainSection({ section, pathname }: { section: NavSection; pathname: string }) {
  const sidebar = useSidebar();
  const containsActive = section.items.some((item) => isOnPage(pathname, item.url));
  const [open, setOpen] = useState(containsActive);
  const [wasActive, setWasActive] = useState(containsActive);
  // Arriving on one of its pages opens the section; leaving leaves it as the user had it.
  if (containsActive !== wasActive) {
    setWasActive(containsActive);
    if (containsActive) setOpen(true);
  }

  return (
    <Collapsible asChild open={open} onOpenChange={setOpen} className="group/collapsible">
      <SidebarMenuItem>
        {/* Its pages are hidden while the sidebar shows only icons, so there the button widens the sidebar and opens it. */}
        <CollapsibleTrigger asChild>
          <SidebarMenuButton
            tooltip={section.title}
            isActive={containsActive && !open}
            onClick={(event) => {
              if (sidebar.state !== "collapsed" || sidebar.isMobile) return;
              event.preventDefault();
              sidebar.setOpen(true);
              setOpen(true);
            }}
          >
            <section.icon />
            <span>{section.title}</span>
            <ChevronRightIcon className="ml-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
          </SidebarMenuButton>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <SidebarMenuSub>
            {section.items.map((item) => (
              <SidebarMenuSubItem key={item.url}>
                <SidebarMenuSubButton asChild isActive={isOnPage(pathname, item.url)}>
                  <Link to={item.url}>
                    <item.icon />
                    <span>{item.title}</span>
                  </Link>
                </SidebarMenuSubButton>
              </SidebarMenuSubItem>
            ))}
          </SidebarMenuSub>
        </CollapsibleContent>
      </SidebarMenuItem>
    </Collapsible>
  );
}
