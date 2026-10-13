import type { QueryClient } from "@tanstack/react-query";
import { Outlet, createRootRouteWithContext, createRoute, createRouter, redirect } from "@tanstack/react-router";
import { AppShell } from "./components/app-shell";
import { Toaster } from "./components/ui/sonner";
import { AcceptInvitationPage } from "./pages/accept-invitation";
import { AcmeAccountsPage } from "./pages/acme-accounts";
import { AgentsPage } from "./pages/agents";
import { ApiKeysPage } from "./pages/api-keys";
import { CertificatesPage } from "./pages/certificates";
import { CsrToolsPage } from "./pages/csr-tools";
import { DeploymentScriptsPage } from "./pages/deployment-scripts";
import { DeploymentsPage } from "./pages/deployments";
import { HomePage } from "./pages/home";
import { ManagedCertificateDetailsPage } from "./pages/managed-certificate-details";
import { ManagedCertificateOverview } from "./pages/managed-certificate-overview";
import { ActivityTab, IssuedCertificatesTab, NotificationsTab, ServicesTab } from "./pages/managed-certificate-tabs";
import { MembersPage } from "./pages/members";
import { PlatformOrganizationsPage } from "./pages/platform-organizations";
import { TeamsPage } from "./pages/teams";
import { SignInPage } from "./pages/sign-in";

const rootRoute = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: () => (
    <>
      <Outlet />
      <Toaster />
    </>
  ),
});

// Signing in and accepting an invitation happen before there is anyone to navigate for.
const publicRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "public",
  component: () => (
    <main className="mx-auto max-w-3xl p-6">
      <Outlet />
    </main>
  ),
});
// Everything else sits in the left navigation.
const appRoute = createRoute({ getParentRoute: () => rootRoute, id: "app", component: AppShell });

const homeRoute = createRoute({ getParentRoute: () => appRoute, path: "/", component: HomePage });
const signInRoute = createRoute({ getParentRoute: () => publicRoute, path: "/sign-in", component: SignInPage });
export const acceptInvitationRoute = createRoute({
  getParentRoute: () => publicRoute,
  path: "/accept-invitation/$invitationId",
  component: AcceptInvitationPage,
});

const certificatesRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/certificates",
  component: CertificatesPage,
});

// A Managed Certificate's page is a layout, and each of its tabs a route of its own.
const certificateRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/certificates/$id",
  component: ManagedCertificateDetailsPage,
});
const certificateOverviewRoute = createRoute({ getParentRoute: () => certificateRoute, path: "/", component: ManagedCertificateOverview });
const certificateIssuedRoute = createRoute({ getParentRoute: () => certificateRoute, path: "issued", component: IssuedCertificatesTab });
const certificateActivityRoute = createRoute({ getParentRoute: () => certificateRoute, path: "activity", component: ActivityTab });
const certificateServicesRoute = createRoute({ getParentRoute: () => certificateRoute, path: "services", component: ServicesTab });
const certificateNotificationsRoute = createRoute({ getParentRoute: () => certificateRoute, path: "notifications", component: NotificationsTab });
// Any other tab goes to Overview.
const certificateUnknownTabRoute = createRoute({
  getParentRoute: () => certificateRoute,
  path: "$",
  beforeLoad: ({ params }) => {
    throw redirect({ to: "/organizations/$orgId/certificates/$id", params: { orgId: params.orgId, id: params.id }, replace: true });
  },
});

const membersRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/members",
  component: MembersPage,
});

const teamsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/teams",
  component: TeamsPage,
});

const apiKeysRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/api-keys",
  component: ApiKeysPage,
});

const agentsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/agents",
  component: AgentsPage,
});

const deploymentScriptsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/deployment-scripts",
  component: DeploymentScriptsPage,
});

const deploymentsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/deployments",
  component: DeploymentsPage,
});

const acmeAccountsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/acme-accounts",
  component: AcmeAccountsPage,
});

const csrToolsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/tools/csr",
  component: CsrToolsPage,
});

const platformOrganizationsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/platform/organizations",
  component: PlatformOrganizationsPage,
});

const routeTree = rootRoute.addChildren([
  publicRoute.addChildren([signInRoute, acceptInvitationRoute]),
  appRoute.addChildren([
    homeRoute,
    certificatesRoute,
    certificateRoute.addChildren([
      certificateOverviewRoute,
      certificateIssuedRoute,
      certificateActivityRoute,
      certificateServicesRoute,
      certificateNotificationsRoute,
      certificateUnknownTabRoute,
    ]),
    membersRoute, teamsRoute, apiKeysRoute, agentsRoute, deploymentsRoute, deploymentScriptsRoute, acmeAccountsRoute, csrToolsRoute,
    platformOrganizationsRoute,
  ]),
]);

export const router = createRouter({ routeTree, context: { queryClient: undefined! } });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
