import { useMutation, useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { createColumnHelper, tableFeatures, useTable } from "@tanstack/react-table";
import { PlusIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { AcmeCaTagBadge } from "@/components/acme-ca-tag";
import { DataTable } from "@/components/data-table/data-table";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, can, type AcmeAccount, type AcmeCa, type AcmeCaTag } from "@/lib/api";
import { ACME_CA_TAG_LABELS, useAcmeCas } from "@/lib/acme-cas";
import { useOrg } from "@/lib/use-org";
import { useAction } from "@/lib/use-action";

const ROUTE = "/app/organizations/$orgId/acme-accounts";

/** An ACME CA and the Organization's account with it, if it has one. */
interface Row {
  ca: AcmeCa;
  account?: AcmeAccount;
}

// The server lists every ACME CA and every account (at most one per ACME CA), so there is nothing to page.
const features = tableFeatures({});
const columnHelper = createColumnHelper<typeof features, Row>();
const columns = columnHelper.columns([
  columnHelper.accessor((r) => r.ca.name, {
    id: "ca",
    header: "ACME CA",
    cell: ({ row }) => (
      <span className="flex flex-col gap-1">
        <span className="flex items-center gap-2">
          {row.original.ca.name} <AcmeCaTagBadge tag={row.original.ca.tag} />
        </span>
        {row.original.ca.directoryUrl && <span className="break-all font-mono text-xs text-muted-foreground">{row.original.ca.directoryUrl}</span>}
        {row.original.ca.externalAccountBinding && (
          <span className="break-all text-xs text-muted-foreground">
            External Account Binding key id <span className="font-mono">{row.original.ca.externalAccountBinding.keyId}</span>
          </span>
        )}
        {row.original.ca.builtIn && <span className="text-xs text-muted-foreground">Built in; it cannot be changed.</span>}
      </span>
    ),
  }),
  columnHelper.accessor((r) => r.account?.accountUrl, {
    id: "account",
    header: "Account",
    cell: ({ cell }) => (cell.getValue() ? <span className="break-all font-mono text-xs">{cell.getValue()}</span> : <span className="text-muted-foreground">None yet</span>),
  }),
  columnHelper.accessor((r) => r.account?.contactEmail, { id: "contact", header: "Contact", cell: ({ cell }) => cell.getValue() ?? <span className="text-muted-foreground">None</span> }),
  columnHelper.display({ id: "actions", header: () => <span className="sr-only">Actions</span>, cell: ({ row }) => row.original.account && <TestAccount ca={row.original.ca} account={row.original.account} /> }),
]);

/**
 * The ACME CAs the Organization can use, and its account with each: a Managed Certificate is issued under the account
 * with its ACME CA, and fails until there is one. Let's Encrypt Staging and Production are built in, and shown as they
 * are; an Organization Administrator may add custom ones, each registered with as it is added. The account's key is
 * made and kept by the platform and is never shown.
 */
export function AcmeAccountsPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const allowed = org ? can(org, "acmeAccount", "read") : false;
  const acmeCas = useAcmeCas(orgId);
  const accounts = useQuery({ queryKey: ["acme-accounts", orgId], queryFn: () => api.acmeAccounts(orgId), enabled: allowed });
  const rows: Row[] = (acmeCas.data?.items ?? []).map((ca) => ({ ca, account: accounts.data?.items.find((a) => a.acmeCaId === ca.id) }));
  const missing = rows.filter((r) => !r.account).map((r) => r.ca);
  const table = useTable({ features, columns, data: rows, getRowId: (r) => r.ca.id });
  const loading = acmeCas.isPending || accounts.isPending;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">ACME accounts</h1>
        {org && can(org, "acmeAccount", "create") && !loading && <RegisterAccountDialog orgId={orgId} acmeCas={missing} />}
      </div>
      <p className="text-sm text-muted-foreground">
        A Managed Certificate is issued under the Organization's account with its ACME CA. Each ACME CA needs an account of its own; register with Let's Encrypt Staging first to try an
        Issuance before production.
      </p>
      {org && !allowed ? (
        <p className="text-sm text-muted-foreground">Only Organization Administrators see the ACME accounts.</p>
      ) : (
        <div className="flex flex-col gap-4">
          <DataTable table={table} empty={loading ? "Loading…" : "There is no ACME CA."} />
          {missing.length > 0 && !loading && (
            <p className="text-sm text-muted-foreground">
              No account with {missing.map((ca) => ca.name).join(" or ")}: a Managed Certificate on {missing.length > 1 ? "either" : "it"} cannot be issued yet.
            </p>
          )}
          {(acmeCas.error ?? accounts.error) && <p className="text-sm text-destructive">{(acmeCas.error ?? accounts.error)!.message}</p>}
        </div>
      )}
    </div>
  );
}

function TestAccount({ ca, account }: { ca: AcmeCa; account: AcmeAccount }) {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  const test = useMutation({ mutationFn: () => api.testAcmeAccount(orgId, account.id) });
  if (!org || !can(org, "acmeAccount", "test")) return null;
  return (
    <div className="flex items-center justify-end gap-3">
      {test.data && (test.data.ok ? <span role="status" className="text-sm">The CA accepts the key.</span> : <span role="alert" className="text-sm text-destructive">{test.data.error}</span>)}
      {test.error && <span role="alert" className="text-sm text-destructive">{test.error.message}</span>}
      <Button variant="outline" size="sm" disabled={test.isPending} aria-label={`Test the account with ${ca.name}`} onClick={() => test.mutate()}>
        Test
      </Button>
    </div>
  );
}

function RegisterAccountDialog({ orgId, acmeCas }: { orgId: string; acmeCas: AcmeCa[] }) {
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
          <DialogDescription>With a built-in ACME CA, or a custom one added in the same step. The platform makes the account's key and keeps it; it is never shown.</DialogDescription>
        </DialogHeader>
        {/* Only mounted while open, so each opening starts from a clean form. */}
        {open && <RegisterAccountForm orgId={orgId} acmeCas={acmeCas} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

/** The choice, in the ACME CA list, of adding a custom ACME CA rather than registering with an existing one. */
const CUSTOM = "custom";

function RegisterAccountForm({ orgId, acmeCas, onDone }: { orgId: string; acmeCas: AcmeCa[]; onDone: () => void }) {
  const [acmeCaId, setAcmeCaId] = useState(acmeCas[0]?.id ?? CUSTOM);
  const [name, setName] = useState("");
  const [directoryUrl, setDirectoryUrl] = useState("");
  const [tag, setTag] = useState<AcmeCaTag | "">("");
  const [externalAccountKeyId, setExternalAccountKeyId] = useState("");
  const [externalAccountHmacKey, setExternalAccountHmacKey] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [agreed, setAgreed] = useState(false);
  const chosen = acmeCas.find((ca) => ca.id === acmeCaId);
  const register = useAction(
    async () => {
      if (chosen) await api.registerAcmeAccount(orgId, { acmeCaId, contactEmail: contactEmail.trim() || undefined });
      else
        await api.createAcmeCa(orgId, {
          name: name.trim(),
          directoryUrl: directoryUrl.trim(),
          tag: tag || null,
          // Given together or not at all; the server says so when only one is.
          externalAccountBinding: externalAccountKeyId.trim() || externalAccountHmacKey.trim() ? { keyId: externalAccountKeyId.trim(), hmacKey: externalAccountHmacKey.trim() } : undefined,
          contactEmail: contactEmail.trim() || undefined,
        });
    },
    ["acme-accounts", "acme-cas"],
    onDone,
  );
  const caName = chosen?.name ?? (name.trim() || "the CA");
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        register.mutate(undefined);
      }}
    >
      <div className="flex flex-col gap-2">
        <Label htmlFor="acme-ca">ACME CA</Label>
        <select id="acme-ca" className="h-9 rounded-md border bg-transparent px-3 text-sm" value={acmeCaId} onChange={(e) => setAcmeCaId(e.target.value)}>
          {acmeCas.map((ca) => (
            <option key={ca.id} value={ca.id}>
              {ca.name}
            </option>
          ))}
          <option value={CUSTOM}>A custom ACME CA…</option>
        </select>
      </div>
      {chosen ? (
        /* An existing ACME CA's configuration is shown, not asked for: a built-in one cannot be changed. */
        <dl className="grid gap-1 rounded-md border p-3 text-sm sm:grid-cols-[7rem_1fr] sm:gap-x-4">
          <dt className="text-muted-foreground">Directory</dt>
          <dd className="min-w-0 break-all font-mono text-xs">{chosen.directoryUrl}</dd>
          <dt className="text-muted-foreground">Tag</dt>
          <dd>{chosen.tag ? <AcmeCaTagBadge tag={chosen.tag} /> : <span className="text-muted-foreground">None</span>}</dd>
        </dl>
      ) : (
        <>
          <div className="flex flex-col gap-2">
            <Label htmlFor="acme-ca-name">Name</Label>
            <Input id="acme-ca-name" required value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="acme-ca-directory">Directory URL</Label>
            <Input id="acme-ca-directory" type="url" required placeholder="https://ca.example.com/acme/directory" value={directoryUrl} onChange={(e) => setDirectoryUrl(e.target.value)} />
            <p className="text-xs text-muted-foreground">
              https, and not a loopback or link-local address; a private address is fine. It cannot be changed once the CA is added.
            </p>
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="acme-ca-tag">Tag (optional)</Label>
            <select id="acme-ca-tag" className="h-9 rounded-md border bg-transparent px-3 text-sm" value={tag} onChange={(e) => setTag(e.target.value as AcmeCaTag | "")}>
              <option value="">None</option>
              {(Object.keys(ACME_CA_TAG_LABELS) as AcmeCaTag[]).map((t) => (
                <option key={t} value={t}>
                  {ACME_CA_TAG_LABELS[t]}
                </option>
              ))}
            </select>
            <p className="text-xs text-muted-foreground">A label of what it is for, shown beside its name; it changes nothing about how it issues.</p>
          </div>
          <fieldset className="flex flex-col gap-3 rounded-md border p-3">
            <legend className="px-1 text-sm">External Account Binding (optional)</legend>
            <p className="text-xs text-muted-foreground">
              For a CA that requires one: the key id and HMAC key it gave you. The HMAC key is kept as a secret and never shown again. Neither can be changed once the CA is added.
            </p>
            <div className="flex flex-col gap-2">
              <Label htmlFor="acme-ca-eab-key-id">Key id</Label>
              <Input id="acme-ca-eab-key-id" autoComplete="off" required={externalAccountHmacKey.trim() !== ""} value={externalAccountKeyId} onChange={(e) => setExternalAccountKeyId(e.target.value)} />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="acme-ca-eab-hmac-key">HMAC key</Label>
              <Input id="acme-ca-eab-hmac-key" type="password" autoComplete="off" required={externalAccountKeyId.trim() !== ""} value={externalAccountHmacKey} onChange={(e) => setExternalAccountHmacKey(e.target.value)} />
            </div>
          </fieldset>
        </>
      )}
      <div className="flex flex-col gap-2">
        <Label htmlFor="acme-contact">Contact email (optional)</Label>
        <Input id="acme-contact" type="email" value={contactEmail} onChange={(e) => setContactEmail(e.target.value)} />
      </div>
      <label className="flex items-start gap-2 text-sm">
        <input type="checkbox" className="mt-1" checked={agreed} onChange={(e) => setAgreed(e.target.checked)} />
        <span>I agree to {caName}'s terms of service on the Organization's behalf.</span>
      </label>
      {(chosen?.tag ?? tag) === "production" && <p className="text-sm text-muted-foreground">This is an account with a production CA, which may rate-limit.</p>}
      {!chosen && <p className="text-sm text-muted-foreground">The account is registered with the CA as it is added; if the CA refuses, nothing is saved.</p>}
      {register.error && <p className="text-sm text-destructive">{register.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={!agreed || register.isPending}>
          {chosen ? "Register" : "Add and register"}
        </Button>
      </DialogFooter>
    </form>
  );
}
