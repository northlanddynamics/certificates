import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { isOwner } from "@/lib/managed-certificate";
import { api, can, subscriberFromKey, subscriberKey, subscriberLabel, type SubscriberRef } from "@/lib/api";
import { useManagedCertificatePage } from "@/lib/use-managed-certificate";

/**
 * Who is told of a Managed Certificate's events (upcoming expiry, Renewal succeeded or failed, Deployment Run failed, Agent
 * offline, Approval decided), and, for its Owners and Organization Administrators while it is not archived, the means to
 * change that. Nobody is subscribed until someone adds them, and being one shows a Subscriber nothing more in the portal.
 */
export function NotificationsTab() {
  const { orgId, id } = useParams({ from: "/app/organizations/$orgId/certificates/$id/notifications" });
  const { org, userId, certificate } = useManagedCertificatePage(orgId, id);
  const m = certificate.data;
  const queryClient = useQueryClient();
  const key = ["managed-certificate", orgId, id, "subscribers"];
  const subscribers = useQuery({ queryKey: key, queryFn: () => api.subscribers(orgId, id) });
  // The server decides; this only keeps the controls from those who surely may not (a Team's members may, too).
  const mayChange = !!org && !!m && !m.archivedAt && (can(org, "managedCertificate", "changeSubscribers") || isOwner(m, userId));
  const people = useQuery({ queryKey: ["members", orgId], queryFn: () => api.members(orgId), enabled: mayChange });
  const teams = useQuery({ queryKey: ["teams", orgId], queryFn: () => api.teams(orgId), enabled: mayChange });
  const channels = useQuery({ queryKey: ["notification-channels", orgId], queryFn: () => api.notificationChannels(orgId), enabled: mayChange });
  const onChanged = (data: Awaited<ReturnType<typeof api.subscribers>>) => queryClient.setQueryData(key, data);
  const add = useMutation({ mutationFn: (s: SubscriberRef) => api.addSubscriber(orgId, id, s), onSuccess: onChanged });
  const remove = useMutation({ mutationFn: (s: SubscriberRef) => api.removeSubscriber(orgId, id, s), onSuccess: onChanged });
  const [choice, setChoice] = useState("");
  if (!org || !m) return null;

  const items = subscribers.data?.items ?? [];
  const taken = new Set(items.map(subscriberKey));
  const error = subscribers.error ?? add.error ?? remove.error;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Subscribers</CardTitle>
        <CardDescription>
          Told by email or webhook of upcoming expiry, Renewals that succeed or fail, failed Deployment Runs, an Agent going offline and Approval decisions. Being a Subscriber
          does not let anyone see this Managed Certificate.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 text-sm">
        {subscribers.isPending ? (
          <p className="text-muted-foreground">Loading…</p>
        ) : items.length === 0 ? (
          <p className="text-muted-foreground">No Subscribers: nobody is told of this Managed Certificate's events.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {items.map((s) => (
              <li key={subscriberKey(s)} className="flex items-center justify-between gap-2">
                <span className="font-medium">{subscriberLabel(s)}</span>
                {mayChange && (
                  <Button variant="ghost" size="sm" aria-label={`Remove ${subscriberLabel(s)} as a Subscriber`} disabled={remove.isPending} onClick={() => remove.mutate(s)}>
                    Remove
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
        {mayChange && (
          <form
            className="flex items-center gap-2"
            onSubmit={(e: FormEvent) => {
              e.preventDefault();
              if (choice) add.mutate(subscriberFromKey(choice), { onSuccess: () => setChoice("") });
            }}
          >
            <Select value={choice} onValueChange={setChoice}>
              <SelectTrigger size="sm" aria-label={`Add a Subscriber to ${m.names.join(", ")}`}>
                <SelectValue placeholder="Add a Subscriber…" />
              </SelectTrigger>
              <SelectContent>
                {channels.data?.items.filter((c) => !taken.has(`channel:${c.id}`)).map((c) => (
                  <SelectItem key={c.id} value={`channel:${c.id}`}>
                    {c.name} ({c.kind} channel)
                  </SelectItem>
                ))}
                {teams.data?.items.filter((t) => !taken.has(`team:${t.id}`)).map((t) => (
                  <SelectItem key={t.id} value={`team:${t.id}`}>
                    {t.name} (Team)
                  </SelectItem>
                ))}
                {people.data?.items.filter((p) => !taken.has(`user:${p.userId}`)).map((p) => (
                  <SelectItem key={p.userId} value={`user:${p.userId}`}>
                    {p.email}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button type="submit" size="sm" variant="outline" disabled={!choice || add.isPending}>
              Add
            </Button>
          </form>
        )}
        {error && <p className="text-destructive">{error.message}</p>}
      </CardContent>
    </Card>
  );
}
