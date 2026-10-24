import { useMutation, useQuery } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { createColumnHelper, tableFeatures, useTable } from "@tanstack/react-table";
import { ClipboardCheckIcon, KeyRoundIcon, LandmarkIcon, PlusIcon, ServerIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { AcmeCaTagBadge } from "@/components/acme-ca-tag";
import { SteppedForm, STEPPED_DIALOG, type Missing, type Step } from "@/components/stepped-form";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { DataTable } from "@/components/data-table/data-table";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
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
          {row.original.ca.name}
        </span>
        {row.original.ca.externalAccountBinding && (
          <span className="break-all text-xs text-muted-foreground">
            External Account Binding key id <span className="font-mono">{row.original.ca.externalAccountBinding.keyId}</span>
          </span>
        )}
      </span>
    ),
  }),
  columnHelper.accessor((r) => r.ca.tag, { id: "tag", header: "Tag", cell: ({ row }) => <AcmeCaTagBadge tag={row.original.ca.tag} /> }),
  columnHelper.accessor((r) => r.ca.directoryUrl, {
    id: "directory",
    header: "Directory",
    cell: ({ cell }) => <span className="block max-w-56 truncate font-mono text-xs" title={cell.getValue() ?? undefined}>{cell.getValue()}</span>,
  }),
  columnHelper.accessor((r) => r.account?.accountUrl, {
    id: "account",
    header: "Account",
    cell: ({ cell }) =>
      cell.getValue() ? (
        <span className="block max-w-56 truncate font-mono text-xs" title={cell.getValue()}>
          {cell.getValue()}
        </span>
      ) : (
        <span className="text-muted-foreground">None yet</span>
      ),
  }),
  columnHelper.accessor((r) => r.account?.contactEmail, { id: "contact", header: "Contact", cell: ({ cell }) => cell.getValue() ?? <span className="text-muted-foreground">None</span> }),
  columnHelper.display({ id: "actions", header: () => <span className="sr-only">Actions</span>, cell: ({ row }) => <AcmeCaActions ca={row.original.ca} account={row.original.account} /> }),
]);

/**
 * The ACME CAs the Organization can use, and its account with each: a Managed Certificate is issued under the account
 * with its ACME CA, and fails until there is one. Let's Encrypt Staging and Production are built in, and shown as they
 * are; an Organization Administrator may add custom ones, each registered with as it is added, change their names,
 * tags and contact emails, and delete one that is the issuer of nothing. The account's key is made and kept by the platform and is never shown.
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
        Issuance before production. For any other ACME CA, add it as a custom ACME CA, with External Account Binding if it requires one: its account is registered as it is added.
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

/** Testing the account, and, for a custom ACME CA, changing or deleting it: a built-in one cannot be changed. */
function AcmeCaActions({ ca, account }: { ca: AcmeCa; account?: AcmeAccount }) {
  const { orgId } = useParams({ from: ROUTE });
  const org = useOrg(orgId);
  if (!org) return null;
  return (
    <div className="flex items-center justify-end gap-2">
      {account && can(org, "acmeAccount", "test") && <TestAccount orgId={orgId} ca={ca} account={account} />}
      {!ca.builtIn && account && can(org, "acmeAccount", "update") && <EditAcmeCaDialog orgId={orgId} ca={ca} account={account} />}
      {!ca.builtIn && can(org, "acmeAccount", "delete") && <DeleteAcmeCa orgId={orgId} ca={ca} />}
    </div>
  );
}

function TestAccount({ orgId, ca, account }: { orgId: string; ca: AcmeCa; account: AcmeAccount }) {
  const test = useMutation({ mutationFn: () => api.testAcmeAccount(orgId, account.id) });
  return (
    <>
      {test.data && (test.data.ok ? <span role="status" className="text-sm">The CA accepts the key.</span> : <span role="alert" className="text-sm text-destructive">{test.data.error}</span>)}
      {test.error && <span role="alert" className="text-sm text-destructive">{test.error.message}</span>}
      <Button variant="outline" size="sm" disabled={test.isPending} aria-label={`Test the account with ${ca.name}`} onClick={() => test.mutate()}>
        Test
      </Button>
    </>
  );
}

function EditAcmeCaDialog({ orgId, ca, account }: { orgId: string; ca: AcmeCa; account: AcmeAccount }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" aria-label={`Edit ${ca.name}`}>
          Edit
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Edit {ca.name}</DialogTitle>
          <DialogDescription>Its name, tag and the account's contact email. A new contact email is sent to the CA.</DialogDescription>
        </DialogHeader>
        {/* Only mounted while open, so each opening starts from what it has now. */}
        {open && <EditAcmeCaForm orgId={orgId} ca={ca} account={account} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

function EditAcmeCaForm({ orgId, ca, account, onDone }: { orgId: string; ca: AcmeCa; account: AcmeAccount; onDone: () => void }) {
  const [name, setName] = useState(ca.name);
  const [tag, setTag] = useState<AcmeCaTag | "">(ca.tag ?? "");
  const [contactEmail, setContactEmail] = useState(account.contactEmail ?? "");
  const save = useAction(
    () => api.updateAcmeCa(orgId, ca.id, { name: name.trim(), tag: tag || null, contactEmail: contactEmail.trim() || null }),
    ["acme-accounts", "acme-cas"],
    onDone,
  );
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        save.mutate(undefined);
      }}
    >
      <div className="flex flex-col gap-2">
        <Label htmlFor="edit-acme-ca-name">Name</Label>
        <Input id="edit-acme-ca-name" required value={name} onChange={(e) => setName(e.target.value)} />
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="edit-acme-ca-tag">Tag (optional)</Label>
        <select id="edit-acme-ca-tag" className="h-9 rounded-md border bg-transparent px-3 text-sm" value={tag} onChange={(e) => setTag(e.target.value as AcmeCaTag | "")}>
          <option value="">None</option>
          {(Object.keys(ACME_CA_TAG_LABELS) as AcmeCaTag[]).map((t) => (
            <option key={t} value={t}>
              {ACME_CA_TAG_LABELS[t]}
            </option>
          ))}
        </select>
      </div>
      <div className="flex flex-col gap-2">
        <Label htmlFor="edit-acme-contact">Contact email (optional)</Label>
        <Input id="edit-acme-contact" type="email" value={contactEmail} onChange={(e) => setContactEmail(e.target.value)} />
      </div>
      <dl className="grid gap-1 rounded-md border p-3 text-sm sm:grid-cols-[7rem_1fr] sm:gap-x-4">
        <dt className="text-muted-foreground">Directory</dt>
        <dd className="min-w-0 break-all font-mono text-xs">{ca.directoryUrl}</dd>
        <dt className="text-muted-foreground">External Account Binding</dt>
        <dd className="min-w-0 break-all text-xs">{ca.externalAccountBinding ? <span className="font-mono">{ca.externalAccountBinding.keyId}</span> : <span className="text-muted-foreground">None</span>}</dd>
      </dl>
      <p className="text-xs text-muted-foreground">
        The directory URL and External Account Binding cannot be changed, so the account cannot be pointed somewhere else. To change them, delete this ACME CA and add it again.
      </p>
      {save.error && <p className="text-sm text-destructive">{save.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={save.isPending}>
          Save
        </Button>
      </DialogFooter>
    </form>
  );
}

function DeleteAcmeCa({ orgId, ca }: { orgId: string; ca: AcmeCa }) {
  const [open, setOpen] = useState(false);
  const remove = useAction(() => api.deleteAcmeCa(orgId, ca.id), ["acme-accounts", "acme-cas"], () => setOpen(false));
  return (
    <>
      <Button variant="ghost" size="sm" aria-label={`Delete ${ca.name}`} onClick={() => setOpen(true)}>
        Delete
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) remove.reset();
        }}
        title={`Delete ${ca.name}?`}
        description="Its account and the account's key go with it. It cannot be deleted while it is the issuer of any Managed Certificate or Certificate, archived ones included."
        confirmLabel="Delete"
        pending={remove.isPending}
        error={remove.error}
        onConfirm={() => remove.mutate(undefined)}
      />
    </>
  );
}

function RegisterAccountDialog({ orgId, acmeCas }: { orgId: string; acmeCas: AcmeCa[] }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          Register an account
        </Button>
      </DialogTrigger>
      <DialogContent className={STEPPED_DIALOG}>
        <DialogTitle className="sr-only">Register an ACME account</DialogTitle>
        <DialogDescription className="sr-only">
          With a built-in ACME CA, or a custom one added in the same step. The platform makes the account's key and keeps it; it is never shown.
        </DialogDescription>
        {/* Only mounted while open, so each opening starts from a clean form. */}
        {open && <RegisterAccountForm orgId={orgId} acmeCas={acmeCas} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

/** The choice, in the ACME CA list, of adding a custom ACME CA rather than registering with an existing one. */
const CUSTOM = "custom";

const CA_STEP: Step<RegisterStepId> = { id: "ca", title: "ACME CA", icon: LandmarkIcon };
const DETAILS_STEP: Step<RegisterStepId> = { id: "details", title: "Custom ACME CA", icon: ServerIcon };
const BINDING_STEP: Step<RegisterStepId> = { id: "binding", title: "External Account Binding", icon: KeyRoundIcon };
const ACCOUNT_STEP: Step<RegisterStepId> = { id: "account", title: "Account", icon: ClipboardCheckIcon };
type RegisterStepId = "ca" | "details" | "binding" | "account";
// Only a custom ACME CA has details and a binding to ask for.
const BUILT_IN_STEPS = [CA_STEP, ACCOUNT_STEP] as const satisfies readonly Step<RegisterStepId>[];
const CUSTOM_STEPS = [CA_STEP, DETAILS_STEP, BINDING_STEP, ACCOUNT_STEP] as const satisfies readonly Step<RegisterStepId>[];

function RegisterAccountForm({ orgId, acmeCas, onDone }: { orgId: string; acmeCas: AcmeCa[]; onDone: () => void }) {
  const [step, setStep] = useState<RegisterStepId>("ca");
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
  const bindingOk = (externalAccountKeyId.trim() === "") === (externalAccountHmacKey.trim() === "");
  const missing: Partial<Record<RegisterStepId, Missing>> = {
    details:
      name.trim() === ""
        ? { reason: "Give the CA a name.", field: "acme-ca-name" }
        : directoryUrl.trim() === ""
          ? { reason: "Give the CA's ACME directory URL.", field: "acme-ca-directory" }
          : undefined,
    binding: bindingOk
      ? undefined
      : { reason: "Give both the key id and the HMAC key, or neither.", field: externalAccountKeyId.trim() === "" ? "acme-ca-eab-key-id" : "acme-ca-eab-hmac-key" },
    account: agreed ? undefined : { reason: `Agree to ${caName}'s terms of service.`, field: "acme-terms" },
  };
  return (
    <SteppedForm
      title="Register an ACME account"
      steps={chosen ? BUILT_IN_STEPS : CUSTOM_STEPS}
      step={step}
      onStep={setStep}
      missing={missing}
      submitLabel={chosen ? "Register" : "Add and register"}
      pending={register.isPending}
      onSubmit={() => register.mutate(undefined)}
    >
      {step === "ca" && (
        <FieldSet>
          <FieldLegend>ACME CA</FieldLegend>
          <FieldDescription>With a built-in ACME CA, or a custom one added in the same step. The platform makes the account's key and keeps it; it is never shown.</FieldDescription>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="acme-ca">ACME CA</FieldLabel>
              <select id="acme-ca" className="h-9 rounded-md border bg-transparent px-3 text-sm" value={acmeCaId} onChange={(e) => setAcmeCaId(e.target.value)}>
                {acmeCas.map((ca) => (
                  <option key={ca.id} value={ca.id}>
                    {ca.name}
                  </option>
                ))}
                <option value={CUSTOM}>A custom ACME CA…</option>
              </select>
            </Field>
            {chosen && (
              /* An existing ACME CA's configuration is shown, not asked for: a built-in one cannot be changed. */
              <dl className="grid gap-1 rounded-md border p-3 text-sm sm:grid-cols-[7rem_1fr] sm:gap-x-4">
                <dt className="text-muted-foreground">Directory</dt>
                <dd className="min-w-0 break-all font-mono text-xs">{chosen.directoryUrl}</dd>
                <dt className="text-muted-foreground">Tag</dt>
                <dd>{chosen.tag ? <AcmeCaTagBadge tag={chosen.tag} /> : <span className="text-muted-foreground">None</span>}</dd>
              </dl>
            )}
          </FieldGroup>
        </FieldSet>
      )}
      {step === "details" && (
        <FieldSet>
          <FieldLegend>Custom ACME CA</FieldLegend>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="acme-ca-name">Name</FieldLabel>
              <Input id="acme-ca-name" autoFocus value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field>
              <FieldLabel htmlFor="acme-ca-directory">Directory URL</FieldLabel>
              <Input id="acme-ca-directory" type="url" placeholder="e.g. https://ca.example.com/acme/directory" value={directoryUrl} onChange={(e) => setDirectoryUrl(e.target.value)} />
              <FieldDescription>https, and not a loopback or link-local address; a private address is fine. It cannot be changed once the CA is added.</FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor="acme-ca-tag">Tag (optional)</FieldLabel>
              <select id="acme-ca-tag" className="h-9 rounded-md border bg-transparent px-3 text-sm" value={tag} onChange={(e) => setTag(e.target.value as AcmeCaTag | "")}>
                <option value="">None</option>
                {(Object.keys(ACME_CA_TAG_LABELS) as AcmeCaTag[]).map((t) => (
                  <option key={t} value={t}>
                    {ACME_CA_TAG_LABELS[t]}
                  </option>
                ))}
              </select>
              <FieldDescription>A label of what it is for, shown beside its name; it changes nothing about how it issues.</FieldDescription>
            </Field>
          </FieldGroup>
        </FieldSet>
      )}
      {step === "binding" && (
        <FieldSet>
          <FieldLegend>External Account Binding (optional)</FieldLegend>
          <FieldDescription>
            For a CA that requires one: the key id and HMAC key it gave you. The HMAC key is kept as a secret and never shown again. Neither can be changed once the CA is added.
          </FieldDescription>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="acme-ca-eab-key-id">Key id</FieldLabel>
              <Input id="acme-ca-eab-key-id" autoComplete="off" autoFocus value={externalAccountKeyId} onChange={(e) => setExternalAccountKeyId(e.target.value)} />
            </Field>
            <Field>
              <FieldLabel htmlFor="acme-ca-eab-hmac-key">HMAC key</FieldLabel>
              <Input id="acme-ca-eab-hmac-key" type="password" autoComplete="off" value={externalAccountHmacKey} onChange={(e) => setExternalAccountHmacKey(e.target.value)} />
              {!bindingOk && <FieldError>Give both the key id and the HMAC key, or neither.</FieldError>}
            </Field>
          </FieldGroup>
        </FieldSet>
      )}
      {step === "account" && (
        <FieldSet>
          <FieldLegend>Account with {caName}</FieldLegend>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="acme-contact">Contact email (optional)</FieldLabel>
              <Input id="acme-contact" type="email" autoFocus value={contactEmail} onChange={(e) => setContactEmail(e.target.value)} />
            </Field>
            <label className="flex items-start gap-2 text-sm">
              <input id="acme-terms" type="checkbox" className="mt-1" checked={agreed} onChange={(e) => setAgreed(e.target.checked)} />
              <span>I agree to {caName}'s terms of service on the Organization's behalf.</span>
            </label>
            {(chosen?.tag ?? tag) === "production" && <p className="text-sm text-muted-foreground">This is an account with a production CA, which may rate-limit.</p>}
            {!chosen && <p className="text-sm text-muted-foreground">The account is registered with the CA as it is added; if the CA refuses, nothing is saved.</p>}
            {register.error && <p className="text-sm text-destructive">{register.error.message}</p>}
          </FieldGroup>
        </FieldSet>
      )}
    </SteppedForm>
  );
}
