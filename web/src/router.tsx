import type { QueryClient } from "@tanstack/react-query";
import { Outlet, createRootRouteWithContext, createRoute, createRouter } from "@tanstack/react-router";
import { AcceptInvitationPage } from "./pages/accept-invitation";
import { HomePage } from "./pages/home";
import { PeoplePage } from "./pages/people";
import { SignInPage } from "./pages/sign-in";

const rootRoute = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: () => (
    <main className="mx-auto max-w-3xl p-6">
      <Outlet />
    </main>
  ),
});

const homeRoute = createRoute({ getParentRoute: () => rootRoute, path: "/", component: HomePage });
const signInRoute = createRoute({ getParentRoute: () => rootRoute, path: "/sign-in", component: SignInPage });
export const acceptInvitationRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/accept-invitation/$invitationId",
  component: AcceptInvitationPage,
});

const peopleRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/organizations/$orgId/people",
  component: PeoplePage,
});

const routeTree = rootRoute.addChildren([homeRoute, signInRoute, acceptInvitationRoute, peopleRoute]);

export const router = createRouter({ routeTree, context: { queryClient: undefined! } });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
