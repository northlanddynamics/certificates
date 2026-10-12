import { useNavigate } from "@tanstack/react-router";
import { CheckIcon, ChevronsUpDownIcon, ShieldCheckIcon } from "lucide-react";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem, useSidebar } from "@/components/ui/sidebar";
import { roleLabel, type Me } from "@/lib/api";

type Org = Me["organizations"][number];

export function OrgSwitcher({ organizations, active }: { organizations: Org[]; active: Org | undefined }) {
  const { isMobile } = useSidebar();
  const navigate = useNavigate();

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild disabled={organizations.length < 2}>
            <SidebarMenuButton size="lg" className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground">
              <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-sidebar-primary text-sidebar-primary-foreground">
                <ShieldCheckIcon className="size-4" />
              </div>
              <div className="grid flex-1 text-left text-sm leading-tight">
                <span className="truncate font-medium">{active?.name ?? "Certificate platform"}</span>
                <span className="truncate text-xs">{active ? roleLabel(active.role) : "Platform"}</span>
              </div>
              {organizations.length > 1 && <ChevronsUpDownIcon className="ml-auto" />}
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="min-w-56" align="start" side={isMobile ? "bottom" : "right"} sideOffset={4}>
            <DropdownMenuLabel className="text-xs text-muted-foreground">Organizations</DropdownMenuLabel>
            {organizations.map((org) => (
              <DropdownMenuItem key={org.id} className="gap-2 p-2" onClick={() => navigate({ to: `/organizations/${org.id}/certificates` })}>
                <span className="flex-1 truncate">{org.name}</span>
                {org.id === active?.id && <CheckIcon className="size-4" />}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
