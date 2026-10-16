import type { QueryClient } from "@tanstack/react-query";
import { Outlet, createRootRouteWithContext, createRoute, createRouter, redirect } from "@tanstack/react-router";
import { AppShell } from "./components/app-shell";
import { Toaster } from "./components/ui/sonner";
import { AcceptInvitationPage } from "./pages/accept-invitation";
import { AccountSecurityPage } from "./pages/account-security";
import { AcmeAccountsPage } from "./pages/acme-accounts";
import { PrivateCasPage } from "./pages/private-cas";
import { DeviceCertificatesPage } from "./pages/device-certificates";
import { EnrollmentProfilesPage } from "./pages/enrollment-profiles";
import { AgentsPage } from "./pages/agents";
import { ApiKeysPage } from "./pages/api-keys";
import { CertificatesPage } from "./pages/certificates";
import { CsrToolsPage } from "./pages/csr-tools";
import { DeploymentScriptsPage } from "./pages/deployment-scripts";
import { DeploymentsPage } from "./pages/deployments";
import { DnsProvidersPage } from "./pages/dns-providers";
import { HomePage } from "./pages/home";
import { ManagedCertificateDetailsPage } from "./pages/managed-certificate-details";
import { ManagedCertificateOverview } from "./pages/managed-certificate-overview";
import { IssuedCertificatesTab } from "./pages/issued-certificates";
import { ActivityTab } from "./pages/managed-certificate-activity";
import { ServicesTab } from "./pages/managed-certificate-tabs";
import { NotificationsTab } from "./pages/subscriber-controls";
import { NotificationChannelsPage } from "./pages/notification-channels";
import { AuditLogPage } from "./pages/audit-log";
import { AuditForwardingPage } from "./pages/audit-forwarding";
import { LoginPolicyPage } from "./pages/login-policy";
import { SsoConnectionsPage } from "./pages/sso-connections";
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

const privateCasRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/private-cas",
  component: PrivateCasPage,
});

const enrollmentProfilesRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/enrollment-profiles",
  component: EnrollmentProfilesPage,
});

const deviceCertificatesRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/enrollment-profiles/$id/device-certificates",
  component: DeviceCertificatesPage,
});

const dnsProvidersRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/dns-providers",
  component: DnsProvidersPage,
});

const notificationChannelsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/notification-channels",
  component: NotificationChannelsPage,
});

const auditLogRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/audit-log",
  component: AuditLogPage,
});

const auditForwardingRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/audit-forwarding",
  component: AuditForwardingPage,
});

const loginPolicyRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/login-policy",
  component: LoginPolicyPage,
});

const ssoConnectionsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/organizations/$orgId/sso-connections",
  component: SsoConnectionsPage,
});

const accountSecurityRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/account/security",
  component: AccountSecurityPage,
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
    membersRoute, teamsRoute, apiKeysRoute, agentsRoute, deploymentsRoute, deploymentScriptsRoute, acmeAccountsRoute, privateCasRoute, enrollmentProfilesRoute, deviceCertificatesRoute, dnsProvidersRoute, notificationChannelsRoute, auditLogRoute, auditForwardingRoute, loginPolicyRoute,
    ssoConnectionsRoute, csrToolsRoute,
    accountSecurityRoute,
    platformOrganizationsRoute,
  ]),
]);

export const router = createRouter({ routeTree, context: { queryClient: undefined! } });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
