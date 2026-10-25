import "reflect-metadata"; // @peculiar/x509 needs a Reflect polyfill loaded before it
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ApiError } from "./lib/api";
import "./index.css";
import { router } from "./router";

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
// Who is signed in decides whether the app can show anything at all, so a failure other than "not signed in" is tried
// again (with the default backoff) before the app says it cannot reach the platform.
queryClient.setQueryDefaults(["me"], { retry: (failures, error) => !(error instanceof ApiError && error.status < 500) && failures < 3 });

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} context={{ queryClient }} />
    </QueryClientProvider>
  </StrictMode>,
);
