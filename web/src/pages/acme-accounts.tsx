import { useMutation, useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { createColumnHelper, tableFeatures, useTable } from "@tanstack/react-table";
import { PlusIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { DataTable } from "@/components/data-table/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, can, type AcmeAccount } from "@/lib/api";
import { useOrg } from "@/lib/use-org";
import { useAction } from "@/lib/use-action";

const ROUTE = "/app/organizations/$orgId/acme-accounts";
const ENVIRONMENTS: AcmeAccount["environment"][] = ["staging", "production"];
const ENVIRONMENT_LABEL: Record<AcmeAccount["environment"], string> = { staging: "Staging", production: "Production" };

// The server lists every account (at most one per environment), so there is nothing to page.
const features = tableFeatures({});
const columnHelper = createColumnHelper<typeof features, AcmeAccount>();
const columns = columnHelper.columns([
  columnHelper.accessor("environment", {
    header: "Environment",
    cell: ({ cell }) => <Badge variant={cell.getValue() === "production" ? "default" : "secondary"}>{ENVIRONMENT_LABEL[cell.getValue()]}</Badge>,
  }),
  columnHelper.accessor("accountUrl", { header: "Account", cell: ({ cell }) => <span className="break-all font-mono text-xs">{cell.getValue()}</span> }),
  columnHelper.accessor("contactEmail", { header: "Contact", cell: ({ cell }) => cell.getValue() ?? <span className="text-muted-foreground">None</span> }),
  columnHelper.display({ id: "actions", header: () => <span className="sr-only">Actions</span>, cell: ({ row }) => <TestAccount account={row.original} /> }),
]);
const noRows: AcmeAccount[] = [];

/**
 * The Organization's account with the CA, one for staging and one for production: a Managed Certificate is issued under
 * the account of its environment, and fails until there is one. The account's key is made and kept by the platform and
 * is never shown.
 */
export function AcmeAccountsPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const allowed = org ? can(org, "acmeAccount", "read") : false;
  const accounts = useQuery({ queryKey: ["acme-accounts", orgId], queryFn: () => api.acmeAccounts(orgId), enabled: allowed });
  const items = accounts.data?.items ?? noRows;
  const missing = ENVIRONMENTS.filter((environment) => !items.some((a) => a.environment === environment));
  const table = useTable({ features, columns, data: items, getRowId: (a) => a.id });

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">ACME accounts</h1>
        {org && can(org, "acmeAccount", "create") && missing.length > 0 && <RegisterAccountDialog orgId={orgId} environments={missing} />}
      </div>
      <p className="text-sm text-muted-foreground">
        A Managed Certificate is issued under the Organization's account with the CA for its environment. Staging and production are separate CAs, so each needs an account of
        its own; register staging first to try an Issuance before production.
      </p>
      {org && !allowed ? (
        <p className="text-sm text-muted-foreground">Only Organization Administrators see the ACME accounts.</p>
      ) : (
        <div className="flex flex-col gap-4">
          <DataTable table={table} empty={accounts.isPending ? "Loading…" : "No ACME account is registered yet."} />
          {missing.length > 0 && !accounts.isPending && (
            <p className="text-sm text-muted-foreground">No {missing.join(" or ")} account: a Managed Certificate in {missing.length > 1 ? "either" : "that"} environment cannot be issued yet.</p>
          )}
          {accounts.error && <p className="text-sm text-destructive">{accounts.error.message}</p>}
        </div>
      )}
    </div>
  );
}

function TestAccount({ account }: { account: AcmeAccount }) {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const test = useMutation({ mutationFn: () => api.testAcmeAccount(orgId, account.id) });
  if (!org || !can(org, "acmeAccount", "test")) return null;
  return (
    <div className="flex items-center justify-end gap-3">
      {test.data && (test.data.ok ? <span role="status" className="text-sm">The CA accepts the key.</span> : <span role="alert" className="text-sm text-destructive">{test.data.error}</span>)}
      {test.error && <span role="alert" className="text-sm text-destructive">{test.error.message}</span>}
      <Button variant="outline" size="sm" disabled={test.isPending} aria-label={`Test the ${account.environment} account`} onClick={() => test.mutate()}>
        Test
      </Button>
    </div>
  );
}

function RegisterAccountDialog({ orgId, environments }: { orgId: string; environments: AcmeAccount["environment"][] }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog
      open={open}
      onOpenChange={setOpen}
    >
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          Register an account
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Register an ACME account</DialogTitle>
          <DialogDescription>The platform makes the account's key and keeps it; it is never shown.</DialogDescription>
        </DialogHeader>
        {/* Only mounted while open, so each opening starts from a clean form. */}
        {open && <RegisterAccountForm orgId={orgId} environments={environments} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function RegisterAccountForm({ orgId, environments, onDone }: { orgId: string; environments: AcmeAccount["environment"][]; onDone: () => void }) {
  const [environment, setEnvironment] = useState(environments[0]!);
  const [contactEmail, setContactEmail] = useState("");
  const [agreed, setAgreed] = useState(false);
  const register = useAction(
    () => api.registerAcmeAccount(orgId, { environment, contactEmail: contactEmail.trim() || undefined }),
    ["acme-accounts"],
    onDone,
  );
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        register.mutate(undefined);
      }}
    >
      <div className="flex flex-col gap-2">
        <Label htmlFor="acme-environment">Environment</Label>
        <select
          id="acme-environment"
          className="h-9 rounded-md border bg-transparent px-3 text-sm"
          value={environment}
          onChange={(e) => setEnvironment(e.target.value as AcmeAccount["environment"])}
        >
          {environments.map((e) => (
            <option key={e} value={e}>
              {ENVIRONMENT_LABEL[e]}
            </option>
          ))}
        </select>
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="acme-contact">Contact email (optional)</Label>
        <Input id="acme-contact" type="email" value={contactEmail} onChange={(e) => setContactEmail(e.target.value)} />
      </div>
      <label className="flex items-start gap-2 text-sm">
        <input type="checkbox" className="mt-1" checked={agreed} onChange={(e) => setAgreed(e.target.checked)} />
        <span>I agree to the CA's terms of service on the Organization's behalf.</span>
      </label>
      {environment === "production" && <p className="text-sm text-muted-foreground">This is an account with the production CA, which rate-limits.</p>}
      {register.error && <p className="text-sm text-destructive">{register.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={!agreed || register.isPending}>
          Register
        </Button>
      </DialogFooter>
    </form>
  );
}
