import { useMutation, useQuery } from "@tanstack/react-query";
import { PencilIcon, RefreshCwIcon } from "lucide-react";
import { useState, type ReactNode } from "react";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { KeySource, csrOf, emptyKeySource, keyAtRisk, useKeySourceReady, type KeySourceState } from "@/components/csr-key-source";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Field, FieldDescription, FieldError, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { api, can, type ManagedCertificate, type Me } from "@/lib/api";
import { KEY_ALGORITHM_LABELS, type KeyAlgorithm } from "@/lib/csr-generator";
import { nameProblems, normalizedNames, splitNames } from "@/lib/csr-names";
import { isOwner } from "@/lib/managed-certificate";
import { daysLabel, findIssuingCa, isValidityDays, permitsOnlyLabel } from "@/lib/private-ca";

type Org = Me["organizations"][number];
type Change = "replace" | "names";

/**
 * The key of a Managed Certificate whose Owners hold it: what it is, that Renewal reuses it, and for those who may, the
 * means to replace it or to change the names, each with a CSR made the same ways as at creation.
 */
export function KeyAndCsrCard({ org, m, userId, onChanged }: { org: Org; m: ManagedCertificate; userId?: string; onChanged: () => void }) {
  const [change, setChange] = useState<Change | null>(null);
  // Whether closing the sheet would lose a generated key nobody has saved, and whether we are asking about that.
  const [atRisk, setAtRisk] = useState(false);
  const [confirmingClose, setConfirmingClose] = useState(false);

  // The server decides; this only keeps the actions from those who surely may not (a Team's members may, too).
  const owns = isOwner(m, userId);
  const settled = m.approval.status !== "pending" && m.approval.status !== "rejected";
  const mayReplace = settled && (can(org, "managedCertificate", "replaceCsr") || owns);
  const direct = can(org, "managedCertificate", "changeNames");
  const mayChangeNames = settled && !m.pendingNameChange && (direct || can(org, "managedCertificate", "proposeNameChange") || owns);
  if (m.archivedAt || m.keyCustody !== "owner") return null;

  const close = () => {
    setAtRisk(false);
    setConfirmingClose(false);
    setChange(null);
  };
  const keyType = KEY_ALGORITHM_LABELS[m.keyAlgorithm as KeyAlgorithm] ?? m.keyAlgorithm;
  return (
    <Card className="lg:col-span-2">
      <CardHeader>
        <CardTitle>Key and CSR</CardTitle>
        <CardDescription>Its Owners hold the private key; the platform has only the CSR, and every Renewal reuses it until it is replaced.</CardDescription>
        {(mayReplace || mayChangeNames) && (
          <CardAction className="flex flex-wrap gap-2">
            {mayReplace && (
              <Button variant="outline" size="sm" onClick={() => setChange("replace")}>
                <RefreshCwIcon />
                Replace key
              </Button>
            )}
            {mayChangeNames && (
              <Button variant="outline" size="sm" onClick={() => setChange("names")}>
                <PencilIcon />
                {direct ? "Change names" : "Propose a name change"}
              </Button>
            )}
          </CardAction>
        )}
      </CardHeader>
      <CardContent>
        <dl className="grid gap-x-8 gap-y-3 text-sm sm:grid-cols-3">
          <Fact label="Key type">{keyType}</Fact>
          <Fact label="Held by">The Owners, outside the platform</Fact>
          <Fact label="Next Renewal">
            {settled && m.renewal.dueAt ? `Reuses this key, from ${new Date(m.renewal.dueAt).toLocaleDateString()}` : "Reuses this key"}
          </Fact>
        </dl>
      </CardContent>
      <ConfirmDialog
        open={confirmingClose}
        onOpenChange={setConfirmingClose}
        title="Discard the key you have not saved?"
        description="It was made in this browser and exists nowhere else."
        confirmLabel="Discard it and close"
        dismissLabel="Keep editing"
        pending={false}
        error={null}
        onConfirm={close}
      />
      <Sheet open={change !== null} onOpenChange={(open) => !open && (atRisk ? setConfirmingClose(true) : close())}>
        <SheetContent className="w-full overflow-y-auto data-[side=right]:sm:max-w-xl">
          {change && (
            <ChangeKey
              key={change}
              org={org}
              m={m}
              change={change}
              direct={direct}
              mayRenew={!!m.currentCertificate && (can(org, "managedCertificate", "renew") || owns)}
              onAtRisk={setAtRisk}
              onDone={() => {
                close();
                onChanged();
              }}
            />
          )}
        </SheetContent>
      </Sheet>
    </Card>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}

/** A new key for the same names (`replace`), or new names and a key for them (`names`). Only mounted while open, so each starts afresh. */
function ChangeKey({
  org,
  m,
  change,
  direct,
  mayRenew,
  onAtRisk,
  onDone,
}: {
  org: Org;
  m: ManagedCertificate;
  change: Change;
  direct: boolean;
  mayRenew: boolean;
  onAtRisk: (atRisk: boolean) => void;
  onDone: () => void;
}) {
  const keyAlgorithm = m.keyAlgorithm as KeyAlgorithm;
  const [typed, setTyped] = useState(m.names.join("\n"));
  const [keySource, setKeySourceState] = useState<KeySourceState>(emptyKeySource());
  const setKeySource = (next: KeySourceState) => {
    setKeySourceState(next);
    onAtRisk(keyAtRisk(next));
  };
  const [renewNow, setRenewNow] = useState(true);
  // For a Private CA, the validity it is to have, in days: its own to begin with, and empty for the Private CA's default.
  const [validity, setValidity] = useState(m.validityDays === null ? "" : String(m.validityDays));
  const validityDays = validity.trim() === "" ? null : Number(validity);

  const names = change === "names" ? splitNames(typed) : m.names;
  const problems = nameProblems(names);
  const changed = change === "replace" || (problems.length === 0 && normalizedNames(names).join("\n") !== m.names.join("\n"));
  const ready = useKeySourceReady(keySource, names, keyAlgorithm);

  // An Issuing CA issues only for its permitted names, which the new names must keep within.
  const issuingCaId = m.issuer.kind === "private_ca" ? m.issuer.issuingCa.id : null;
  const issuingCa = useQuery({
    queryKey: ["private-cas", org.id],
    queryFn: () => api.privateCas(org.id),
    enabled: change === "names" && issuingCaId !== null && can(org, "privateCa", "read"),
    select: (cas) => findIssuingCa(cas.items, issuingCaId!),
  }).data;
  const validityOk = validityDays === null || isValidityDays(validity, issuingCa?.validity.maximumDays);

  const save = useMutation({
    mutationFn: async () => {
      const csr = csrOf(keySource, names, keyAlgorithm);
      if (change === "names") {
        await api.changeNames(org.id, m.id, {
          names,
          csr,
          // Sent only when changed, so that the Managed Certificate otherwise keeps its own.
          ...(m.issuer.kind === "private_ca" && validityDays !== m.validityDays && { validityDays }),
        });
        return;
      }
      await api.uploadCsr(org.id, m.id, csr);
      if (mayRenew && renewNow) await api.renewNow(org.id, m.id);
    },
    onSuccess: onDone,
  });

  const renewing = change === "replace" && mayRenew && renewNow;
  return (
    <>
      <SheetHeader>
        <SheetTitle>{change === "replace" ? "Replace the key" : direct ? "Change names" : "Propose a name change"}</SheetTitle>
        <SheetDescription>
          {change === "replace"
            ? renewing
              ? "A new key and CSR for the same names, and a Renewal with it straight away. The current Certificate keeps working until it expires."
              : "A new key and CSR for the same names. The next Renewal uses it; the current Certificate keeps working until then."
            : direct
              ? "The names change at once, and an Issuance of the new names starts for the new key."
              : "An Approver must approve it. Until then Renewal continues with the current names and key."}
        </SheetDescription>
      </SheetHeader>
      <div className="flex flex-col gap-6 px-4">
        {change === "names" && (
          <FieldSet>
            <Field data-invalid={problems.length > 0}>
              <FieldLabel htmlFor={`change-names-${m.id}`}>All the names it is to have</FieldLabel>
              <Textarea id={`change-names-${m.id}`} rows={5} value={typed} onChange={(e) => setTyped(e.target.value)} />
              <FieldDescription>One per line; wildcards as *.example.com.</FieldDescription>
              {issuingCa && <FieldDescription>{permitsOnlyLabel(issuingCa)}</FieldDescription>}
              {problems.map((problem) => (
                <FieldError key={problem}>{problem}</FieldError>
              ))}
            </Field>
            {problems.length === 0 && <NamesDiff before={m.names} after={normalizedNames(names)} />}
            {m.issuer.kind === "private_ca" && (
              <Field data-invalid={!validityOk}>
                <FieldLabel htmlFor={`change-validity-${m.id}`}>Validity (days)</FieldLabel>
                <Input
                  id={`change-validity-${m.id}`}
                  type="number"
                  min={1}
                  max={issuingCa?.validity.maximumDays}
                  className="w-32"
                  value={validity}
                  placeholder={issuingCa ? String(issuingCa.validity.defaultDays) : undefined}
                  onChange={(e) => setValidity(e.target.value)}
                />
                <FieldDescription>
                  {issuingCa
                    ? `Leave empty for ${issuingCa.name}'s default of ${daysLabel(issuingCa.validity.defaultDays)}; at most ${daysLabel(issuingCa.validity.maximumDays)}.`
                    : "Leave empty for the Issuing CA's default."}
                </FieldDescription>
              </Field>
            )}
          </FieldSet>
        )}
        <FieldSet disabled={!changed} className={!changed ? "opacity-50" : undefined}>
          <FieldLegend variant="label">{change === "replace" ? "CSR for a new key" : "CSR for the new names"}</FieldLegend>
          <FieldDescription>{KEY_ALGORITHM_LABELS[keyAlgorithm] ?? m.keyAlgorithm}, the same as now.</FieldDescription>
          <KeySource names={names} keyAlgorithm={keyAlgorithm} state={keySource} onChange={setKeySource} idPrefix={`change-key-${m.id}`} />
        </FieldSet>
        {change === "replace" && mayRenew && (
          <Field orientation="horizontal" className="rounded-md border p-3">
            <Checkbox id={`renew-now-${m.id}`} checked={renewNow} onCheckedChange={(checked) => setRenewNow(checked === true)} />
            <FieldLabel htmlFor={`renew-now-${m.id}`} className="flex-col items-start gap-0.5 font-normal">
              <span className="font-medium">Renew now with the new key</span>
              <span className="text-muted-foreground">Otherwise the old key stays in use until the next Renewal is due.</span>
            </FieldLabel>
          </Field>
        )}
        {save.error && <FieldError>{save.error.message}</FieldError>}
      </div>
      <SheetFooter>
        <Button disabled={!changed || !ready || !validityOk || save.isPending} onClick={() => save.mutate()}>
          {change === "replace" ? (renewing ? "Use this CSR and renew now" : "Use this CSR from the next Renewal") : direct ? "Change names" : "Propose"}
        </Button>
      </SheetFooter>
    </>
  );
}

/** The names added, removed and kept, so a name change says what it changes. */
function NamesDiff({ before, after }: { before: string[]; after: string[] }) {
  const added = after.filter((name) => !before.includes(name));
  const removed = before.filter((name) => !after.includes(name));
  if (added.length === 0 && removed.length === 0) return <p className="text-sm text-muted-foreground">No change to the names yet.</p>;
  return (
    <ul className="flex flex-col gap-0.5 rounded-md border p-3 font-mono text-xs">
      {added.map((name) => (
        <li key={`+${name}`} className="text-emerald-700 dark:text-emerald-400">
          + {name}
        </li>
      ))}
      {removed.map((name) => (
        <li key={`-${name}`} className="text-destructive line-through">
          − {name}
        </li>
      ))}
      {before
        .filter((name) => after.includes(name))
        .map((name) => (
          <li key={name} className="text-muted-foreground">
            {"  "}
            {name}
          </li>
        ))}
    </ul>
  );
}
