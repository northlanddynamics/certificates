import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";

export function PlatformOrganizationsPage() {
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
        <CardTitle>Organizations</CardTitle>
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
