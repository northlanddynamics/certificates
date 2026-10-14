import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { api, can, type LoginPolicy } from "@/lib/api";
import { useAction } from "@/lib/use-action";

const ROUTE = "/app/organizations/$orgId/login-policy";

/**
 * What the Organization asks of its users' sign-in. Requiring MFA holds up every member who signs in with a password
 * and has no authenticator app, the Organization Administrator who turns it on included, until they set one up. Requiring
 * SSO lets members sign in only through one of the Organization's SSO connections; the server refuses it until the
 * administrator has signed in through one themselves. Only Organization Administrators see or change it, and a change is audited.
 */
export function LoginPolicyPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.organizations.find((o) => o.id === orgId) }).data;
  const allowed = org ? can(org, "loginPolicy", "read") : false;
  const mayChange = org ? can(org, "loginPolicy", "update") : false;
  const policy = useQuery({ queryKey: ["login-policy", orgId], queryFn: () => api.loginPolicy(orgId), enabled: allowed });
  const change = useAction((policy: Partial<LoginPolicy>) => api.setLoginPolicy(orgId, policy), ["login-policy", "me", "audit-events"]);

  return (
    <div className="flex max-w-3xl flex-col gap-6">
      <h1 className="text-xl font-semibold">Login policy</h1>
      {policy.data && (
        <div className="flex items-start gap-3">
          <Checkbox
            id="require-mfa"
            checked={policy.data.requireMfa}
            disabled={!mayChange || change.isPending}
            onCheckedChange={(checked) => change.mutate({ requireMfa: checked === true })}
          />
          <div className="flex flex-col gap-1">
            <Label htmlFor="require-mfa">Require multi-factor authentication</Label>
            <p className="text-sm text-muted-foreground">
              Members who sign in with a password must set up an authenticator app before they can do anything else, you included. Signing in with a passkey alone is
              not affected, but a member who also has a password still needs the app.
            </p>
          </div>
        </div>
      )}
      {policy.data && (
        <div className="flex items-start gap-3">
          <Checkbox
            id="require-sso"
            checked={policy.data.requireSso}
            disabled={!mayChange || change.isPending}
            onCheckedChange={(checked) => change.mutate({ requireSso: checked === true })}
          />
          <div className="flex flex-col gap-1">
            <Label htmlFor="require-sso">Require SSO</Label>
            <p className="text-sm text-muted-foreground">
              Members sign in only through one of the Organization's{" "}
              <Link to="/organizations/$orgId/sso-connections" params={{ orgId }} className="underline">
                SSO connections
              </Link>
              : not with a password, nor a passkey. Sign in through a connection yourself before turning this on. Platform Operators can still sign in with a password.
            </p>
          </div>
        </div>
      )}
      {policy.isPending && allowed && <p className="text-sm text-muted-foreground">Loading…</p>}
      {(policy.error ?? change.error) && <p className="text-sm text-destructive">{(policy.error ?? change.error)!.message}</p>}
    </div>
  );
}
