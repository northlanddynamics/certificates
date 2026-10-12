import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api, can, type Agent } from "@/lib/api";

const STATUS_LABEL: Record<Agent["status"], string> = { online: "Online", offline: "Offline", revoked: "Revoked" };
const OS_LABEL: Record<Agent["os"], string> = { linux: "Linux", windows: "Windows" };

/**
 * The Organization's Agents: each with its host, operating system, version, last contact and whether it is online, those
 * running an old version flagged. An Organization Administrator makes the single-use token an Agent registers with, and
 * revokes an Agent whose host is decommissioned or compromised.
 */
export function AgentsPage() {
  const { orgId } = useParams({ from: "/organizations/$orgId/agents" });
  const queryClient = useQueryClient();
  const org = useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.organizations.find((o) => o.id === orgId) }).data;
  const agents = useQuery({ queryKey: ["agents", orgId], queryFn: () => api.agents(orgId), enabled: org ? can(org, "agent", "read") : false, refetchInterval: 30_000 });
  // The token is shown once, when it is made, and never again.
  const [made, setMade] = useState<{ token: string; expiresAt: string } | null>(null);
  const makeToken = useMutation({ mutationFn: () => api.createAgentRegistrationToken(orgId), onSuccess: setMade });
  const revoke = useMutation({
    mutationFn: (agentId: string) => api.revokeAgent(orgId, agentId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["agents", orgId] }),
  });

  return (
    <div className="flex flex-col gap-6">
      <Link to="/" className="text-sm underline">
        Back
      </Link>
      <Card>
        <CardHeader>
          <CardTitle>Agents</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <p className="text-sm text-muted-foreground">
            An Agent runs on a host inside your network and only ever connects out to the platform. It registers once with a single-use token, and then identifies itself with a
            certificate of its own that it renews by itself. An Agent that has not been in touch for two minutes is shown as offline.
          </p>
          {org && !can(org, "agent", "read") && <p className="text-sm text-muted-foreground">Only Organization Administrators see the Agents.</p>}
          {agents.data?.items.length === 0 && <p className="text-sm text-muted-foreground">No Agent has registered yet.</p>}
          {agents.data && agents.data.items.length > 0 && (
            <table className="w-full text-left text-sm">
              <thead className="text-muted-foreground">
                <tr>
                  <th className="py-1 pr-2 font-normal">Host</th>
                  <th className="py-1 pr-2 font-normal">OS</th>
                  <th className="py-1 pr-2 font-normal">Version</th>
                  <th className="py-1 pr-2 font-normal">Last contact</th>
                  <th className="py-1 pr-2 font-normal">Status</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {agents.data.items.map((a) => (
                  <tr key={a.id} className="border-t">
                    <td className="py-2 pr-2">{a.hostName}</td>
                    <td className="py-2 pr-2">
                      {OS_LABEL[a.os]} {a.arch}
                    </td>
                    <td className="py-2 pr-2">
                      {a.version}
                      {a.outdated && (
                        <span className="ml-2 rounded border border-amber-500 px-1 text-xs" title={`The latest version is ${agents.data.latestVersion}`}>
                          Outdated
                        </span>
                      )}
                    </td>
                    <td className="py-2 pr-2">
                      <time dateTime={a.lastContactAt}>{new Date(a.lastContactAt).toLocaleString()}</time>
                    </td>
                    <td className={`py-2 pr-2 ${a.status === "online" ? "" : "text-muted-foreground"}`}>{STATUS_LABEL[a.status]}</td>
                    <td className="py-2 text-right">
                      {org && can(org, "agent", "revoke") && a.status !== "revoked" && (
                        <Button variant="outline" size="sm" aria-label={`Revoke ${a.hostName}`} disabled={revoke.isPending} onClick={() => revoke.mutate(a.id)}>
                          Revoke
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {revoke.error && <p className="text-sm text-destructive">{revoke.error.message}</p>}
        </CardContent>
      </Card>
      {org && can(org, "agent", "register") && (
        <Card>
          <CardHeader>
            <CardTitle>Register an Agent</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3 text-sm">
            <p className="text-muted-foreground">
              A token registers one Agent, once, into this Organization, and expires after seven days. Pass it to the Agent as <code>AGENT_REGISTRATION_TOKEN</code>.
            </p>
            {made && (
              <div role="status" className="flex flex-col gap-1 rounded-md border p-3">
                <span>
                  Copy the token now: it is not shown again. It expires {new Date(made.expiresAt).toLocaleDateString()}.
                </span>
                <code className="break-all font-mono">{made.token}</code>
              </div>
            )}
            {makeToken.error && <p className="text-destructive">{makeToken.error.message}</p>}
            <div>
              <Button disabled={makeToken.isPending} onClick={() => makeToken.mutate()}>
                Make a registration token
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
