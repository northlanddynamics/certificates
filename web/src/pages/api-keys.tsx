import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";

/** Your API keys for an Organization: a script or pipeline that holds one acts as you there, to download Certificates. */
export function ApiKeysPage() {
  const { orgId } = useParams({ from: "/organizations/$orgId/api-keys" });
  const queryClient = useQueryClient();
  const keys = useQuery({ queryKey: ["api-keys", orgId], queryFn: () => api.apiKeys(orgId) });
  const [name, setName] = useState("");
  const [days, setDays] = useState("");
  // The value of a key is shown once, when it is made, and never again.
  const [made, setMade] = useState<{ name: string; key: string } | null>(null);
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["api-keys", orgId] });
  const create = useMutation({
    mutationFn: () => api.createApiKey(orgId, { name, ...(days && { expiresInDays: Number(days) }) }),
    onSuccess: async (created) => {
      setMade({ name: created.name, key: created.key });
      setName("");
      setDays("");
      await refresh();
    },
  });
  const revoke = useMutation({ mutationFn: (keyId: string) => api.revokeApiKey(orgId, keyId), onSuccess: refresh });

  return (
    <div className="flex flex-col gap-6">
      <Link to="/" className="text-sm underline">
        Back
      </Link>
      <Card>
        <CardHeader>
          <CardTitle>API keys</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <p className="text-sm text-muted-foreground">
            A key acts as you in this Organization, for what you may see and do, and is sent in the <code>x-api-key</code> header. So far it downloads Certificates.
            Every use is recorded in the audit log under your name.
          </p>
          <ul className="flex flex-col gap-2 text-sm">
            {keys.data?.items.length === 0 && <li className="text-muted-foreground">You have no API keys here.</li>}
            {keys.data?.items.map((k) => (
              <li key={k.id} className="flex items-center justify-between gap-2">
                <span>
                  {k.name} <span className="font-mono text-muted-foreground">{k.start}…</span>
                  <span className="text-muted-foreground">
                    {" "}
                    made {new Date(k.createdAt).toLocaleDateString()}
                    {k.expiresAt ? `, expires ${new Date(k.expiresAt).toLocaleDateString()}` : ""}
                  </span>
                </span>
                <Button variant="outline" size="sm" aria-label={`Revoke ${k.name}`} disabled={revoke.isPending} onClick={() => revoke.mutate(k.id)}>
                  Revoke
                </Button>
              </li>
            ))}
          </ul>
          {revoke.error && <p className="text-sm text-destructive">{revoke.error.message}</p>}
          {made && (
            <div role="status" className="flex flex-col gap-1 rounded-md border p-3 text-sm">
              <span>
                Key <strong>{made.name}</strong> is made. Copy it now: it is not shown again.
              </span>
              <code className="break-all font-mono">{made.key}</code>
            </div>
          )}
          <form
            className="flex flex-col gap-3"
            onSubmit={(e: FormEvent) => {
              e.preventDefault();
              create.mutate();
            }}
          >
            <div className="flex flex-col gap-2">
              <Label htmlFor="key-name">Name (what the key is for)</Label>
              <Input id="key-name" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} required />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="key-days">Expires after (days, optional)</Label>
              <Input id="key-days" type="number" min={1} max={365} value={days} onChange={(e) => setDays(e.target.value)} />
            </div>
            {create.error && <p className="text-sm text-destructive">{create.error.message}</p>}
            <Button type="submit" disabled={create.isPending}>
              Make an API key
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
