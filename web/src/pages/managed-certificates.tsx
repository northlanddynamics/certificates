import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { api, can, type ManagedCertificate, type Me } from "@/lib/api";

const KEY_ALGORITHMS = [
  ["ecdsa-p256", "ECDSA P-256"],
  ["ecdsa-p384", "ECDSA P-384"],
  ["rsa-2048", "RSA 2048"],
  ["rsa-3072", "RSA 3072"],
  ["rsa-4096", "RSA 4096"],
];
const selectClass = "h-9 rounded-md border border-input bg-transparent px-2 text-sm";

/** What a Managed Certificate's latest Issuance has come to, in words. */
function status(m: ManagedCertificate) {
  if (m.issuance?.status === "running") return "Issuing…";
  if (m.issuance?.status === "failed") return "Issuance failed";
  return m.currentCertificate ? `Issued, valid until ${new Date(m.currentCertificate.notAfter).toLocaleDateString()}` : "Not issued";
}

export function ManagedCertificates({ org }: { org: Me["organizations"][number] }) {
  const queryClient = useQueryClient();
  const inventory = useQuery({
    queryKey: ["inventory", org.id],
    queryFn: () => api.managedCertificates(org.id),
    // Issuance runs in the background: look again until none is running.
    refetchInterval: (query) => (query.state.data?.items.some((m) => m.issuance?.status === "running") ? 2000 : false),
  });
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["inventory", org.id] });
  const retry = useMutation({ mutationFn: (id: string) => api.retryIssuance(org.id, id), onSuccess: refresh });
  const items = inventory.data?.items ?? [];

  return (
    <div className="flex flex-col gap-4">
      {inventory.data && items.length === 0 && <p className="text-muted-foreground">No Managed Certificates yet.</p>}
      <ul className="flex flex-col gap-3 text-sm">
        {items.map((m) => (
          <li key={m.id} className="flex flex-col gap-1 rounded-md border p-3">
            <span className="font-medium">{m.names.join(", ")}</span>
            <span className="text-muted-foreground">
              {m.keyAlgorithm}, {m.environment}: {status(m)}
            </span>
            {m.issuance?.failure && (
              <span className="text-destructive">
                {m.issuance.failure.message}
              </span>
            )}
            <span className="flex gap-3">
              {m.currentCertificate && (
                <a className="underline" href={api.certificateDownloadUrl(org.id, m.id)}>
                  Download PEM (full chain)
                </a>
              )}
              {m.issuance?.status === "failed" && can(org, "managedCertificate", "issue") && (
                <Button variant="link" size="sm" className="h-auto p-0" onClick={() => retry.mutate(m.id)}>
                  Try again
                </Button>
              )}
            </span>
          </li>
        ))}
      </ul>
      {retry.error && <p className="text-sm text-destructive">{retry.error.message}</p>}
      {can(org, "managedCertificate", "create") && <NewManagedCertificate org={org} onCreated={refresh} />}
    </div>
  );
}

function NewManagedCertificate({ org, onCreated }: { org: Me["organizations"][number]; onCreated: () => void }) {
  const [names, setNames] = useState("");
  const [keyAlgorithm, setKeyAlgorithm] = useState("ecdsa-p256");
  const [environment, setEnvironment] = useState<"staging" | "production">("staging");
  const [csr, setCsr] = useState("");
  const create = useMutation({
    mutationFn: () => api.createManagedCertificate(org.id, { names: names.split(/[\s,]+/).filter(Boolean), keyAlgorithm, csr, environment }),
    onSuccess: () => {
      setNames("");
      setCsr("");
      onCreated();
    },
  });

  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        create.mutate();
      }}
    >
      <h3 className="font-medium">New Managed Certificate</h3>
      <div className="flex flex-col gap-2">
        <Label htmlFor={`names-${org.id}`}>Names (one per line; wildcards as *.example.com)</Label>
        <Textarea id={`names-${org.id}`} value={names} onChange={(e) => setNames(e.target.value)} required />
      </div>
      <div className="flex gap-4">
        <div className="flex flex-col gap-2">
          <Label htmlFor={`algorithm-${org.id}`}>Key algorithm</Label>
          <select id={`algorithm-${org.id}`} className={selectClass} value={keyAlgorithm} onChange={(e) => setKeyAlgorithm(e.target.value)}>
            {KEY_ALGORITHMS.map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </div>
        <div className="flex flex-col gap-2">
          <Label htmlFor={`environment-${org.id}`}>ACME environment</Label>
          <select
            id={`environment-${org.id}`}
            className={selectClass}
            value={environment}
            onChange={(e) => setEnvironment(e.target.value as "staging" | "production")}
          >
            <option value="staging">Staging</option>
            <option value="production">Production</option>
          </select>
        </div>
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor={`csr-${org.id}`}>CSR (PEM, for a key you keep; it must ask for exactly these names)</Label>
        <Textarea id={`csr-${org.id}`} className="font-mono text-xs" rows={6} value={csr} onChange={(e) => setCsr(e.target.value)} required />
      </div>
      {create.error && <p className="text-sm text-destructive">{create.error.message}</p>}
      <Button type="submit" disabled={create.isPending}>
        Create and issue
      </Button>
    </form>
  );
}
