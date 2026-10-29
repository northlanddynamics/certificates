import { useQuery } from "@tanstack/react-query";
import { Navigate } from "@tanstack/react-router";
import { api } from "@/lib/api";

/** The landing page has nothing of its own: it sends the caller to the first page their navigation offers: their first Organization's Dashboard. */
export function HomePage() {
  const me = useQuery({ queryKey: ["me"], queryFn: api.me }).data;
  const first = me?.organizations[0];
  if (!me) return null;
  if (first) return <Navigate to="/organizations/$orgId/dashboard" params={{ orgId: first.id }} replace />;
  if (me.user.isPlatformOperator) return <Navigate to="/platform/organizations" replace />;
  return <p className="text-muted-foreground">You do not belong to an Organization yet.</p>;
}
