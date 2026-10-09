import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError, api, can, type Me } from "@/lib/api";

export function HomePage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const me = useQuery({ queryKey: ["me"], queryFn: api.me });
  const signOut = useMutation({
    mutationFn: api.signOut,
    onSuccess: async () => {
      queryClient.clear();
      await navigate({ to: "/sign-in" });
    },
  });

  if (me.isPending) return <p className="text-muted-foreground">Loading…</p>;
  if (me.error instanceof ApiError && me.error.status === 401) {
    return (
      <p>
        <Link to="/sign-in" className="underline">
          Sign in
        </Link>{" "}
        to continue.
      </p>
    );
  }
  if (me.error) return <p className="text-destructive">Something went wrong.</p>;

  const { user, organizations } = me.data;
  return (
    <div className="flex flex-col gap-6">
      <header className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">{user.email}</p>
        <Button variant="outline" onClick={() => signOut.mutate()}>
          Sign out
        </Button>
      </header>
      {user.isPlatformOperator && <OperatorConsole />}
      {organizations.map((org) => (
        <Inventory key={org.id} org={org} />
      ))}
      {!user.isPlatformOperator && organizations.length === 0 && (
        <p className="text-muted-foreground">You do not belong to an Organization yet.</p>
      )}
    </div>
  );
}

function Inventory({ org }: { org: Me["organizations"][number] }) {
  const inventory = useQuery({ queryKey: ["inventory", org.id], queryFn: () => api.managedCertificates(org.id) });
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          {org.name}: Managed Certificates
          {can(org, "invitation", "create") && (
            <Link to="/organizations/$orgId/people" params={{ orgId: org.id }} className="text-sm font-normal underline">
              People and Teams
            </Link>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {inventory.data?.items.length === 0 && <p className="text-muted-foreground">No Managed Certificates yet.</p>}
        {inventory.data && inventory.data.items.length > 0 && <p>{inventory.data.items.length} Managed Certificates</p>}
      </CardContent>
    </Card>
  );
}

function OperatorConsole() {
  const queryClient = useQueryClient();
  const orgs = useQuery({ queryKey: ["platform-orgs"], queryFn: api.platformOrganizations });
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [adminEmail, setAdminEmail] = useState("");
  const create = useMutation({
    mutationFn: () => api.createOrganization({ name, slug, adminEmail }),
    onSuccess: async () => {
      setName("");
      setSlug("");
      setAdminEmail("");
      await queryClient.invalidateQueries({ queryKey: ["platform-orgs"] });
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Platform: Organizations</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <ul className="text-sm">
          {orgs.data?.items.map((o) => (
            <li key={o.id}>
              {o.name} <span className="text-muted-foreground">({o.slug})</span>
            </li>
          ))}
        </ul>
        <form
          className="flex flex-col gap-3"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <div className="flex flex-col gap-2">
            <Label htmlFor="org-name">Organization name</Label>
            <Input id="org-name" value={name} onChange={(e) => setName(e.target.value)} required />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="org-slug">Slug</Label>
            <Input id="org-slug" pattern="[a-z0-9-]+" value={slug} onChange={(e) => setSlug(e.target.value)} required />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="org-admin">First administrator's email</Label>
            <Input id="org-admin" type="email" value={adminEmail} onChange={(e) => setAdminEmail(e.target.value)} required />
          </div>
          {create.error && <p className="text-sm text-destructive">{create.error.message}</p>}
          <Button type="submit" disabled={create.isPending}>
            Create and invite
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
