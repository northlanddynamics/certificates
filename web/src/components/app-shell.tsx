import { useQuery } from "@tanstack/react-query";
import { Link, Navigate, Outlet, useLocation, useParams } from "@tanstack/react-router";
import { AppSidebar } from "@/components/app-sidebar";
import { HelpPanel } from "@/components/help-panel";
import { Breadcrumb, BreadcrumbItem, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb";
import { Separator } from "@/components/ui/separator";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ApiError, api } from "@/lib/api";
import { ACCOUNT_SECURITY_URL, accountNav, isOnPage, organizationNav, platformNav, signInSettingsUrl } from "@/lib/navigation";

/** The signed-in pages: the left navigation around whichever page is open. */
export function AppShell() {
  const { pathname } = useLocation();
  const { orgId } = useParams({ strict: false });
  const me = useQuery({ queryKey: ["me"], queryFn: api.me });

  if (me.isPending) return <p className="p-6 text-muted-foreground">Loading…</p>;
  if (me.error instanceof ApiError && me.error.status === 401) {
    return (
      <p className="p-6">
        <Link to="/sign-in" className="underline">
          Sign in
        </Link>{" "}
        to continue.
      </p>
    );
  }
  if (me.error) return <p className="p-6 text-destructive">Something went wrong.</p>;
  // An Organization of theirs requires MFA and they have none: nothing else answers them until they set it up, except
  // the sign-in settings (where the login policy is), so that an Organization Administrator can still undo the requirement.
  if (me.data.user.mfa.setupRequired && pathname !== ACCOUNT_SECURITY_URL && !(orgId && pathname === signInSettingsUrl(orgId))) {
    return <Navigate to={ACCOUNT_SECURITY_URL} replace />;
  }

  // The Organization in the address, else the first one the caller belongs to.
  const active = me.data.organizations.find((o) => o.id === orgId) ?? me.data.organizations[0];
  const page = [...(active ? organizationNav(active) : []), ...platformNav, ...accountNav].find((item) => isOnPage(pathname, item.url));

  return (
    <TooltipProvider>
      <SidebarProvider>
        <AppSidebar me={me.data} active={active} />
        <SidebarInset className="min-w-0">
          <header className="flex h-14 shrink-0 items-center gap-2 border-b px-4">
            <SidebarTrigger className="-ml-1" />
            <Separator orientation="vertical" className="mr-2 data-[orientation=vertical]:h-4" />
            <Breadcrumb>
              <BreadcrumbList>
                {page && orgId && active && (
                  <>
                    <BreadcrumbItem>{active.name}</BreadcrumbItem>
                    <BreadcrumbSeparator />
                  </>
                )}
                <BreadcrumbItem>
                  <BreadcrumbPage>{page?.title ?? "Home"}</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          </header>
          <main className="flex min-w-0 flex-1 flex-col gap-6 p-6">
            <Outlet />
          </main>
        </SidebarInset>
      </SidebarProvider>
      <HelpPanel />
    </TooltipProvider>
  );
}
