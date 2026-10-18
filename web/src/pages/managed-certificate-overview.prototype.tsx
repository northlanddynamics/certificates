// PROTOTYPE (branch prototype/csr-ux): throwaway. Two alternatives to how a Managed Certificate's page handles its
// CSR, switched with `?variant=` on the Overview tab (A is today's page). Nothing is sent: the last button shows what would be.
//   B  A "Key and CSR" card; replacing the key or changing names opens a side sheet with the shared key step
//   C  A key banner across the top with the key's age, and guided dialogs (names diff → key → save → what happens next)
// The API reports no CSR fingerprint or key history yet; what this shows of them is made up and marked (mock).
import { ArrowRightIcon, ClipboardCheckIcon, GlobeIcon, KeyRoundIcon, PencilIcon, RefreshCwIcon, ShieldCheckIcon } from "lucide-react";
import { useState, type ReactNode } from "react";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { KeySource, SaveKey, csrOf, emptyKey, keyAtRisk, useKeyReady, type KeyState } from "@/components/csr-key-source.prototype";
import { isPrototypeSwitcher } from "@/components/prototype-switcher";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Field, FieldDescription, FieldError, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { can, type ManagedCertificate, type Me } from "@/lib/api";
import { KEY_ALGORITHM_LABELS, type KeyAlgorithm } from "@/lib/csr-generator";
import { nameProblems, normalizedNames, splitNames } from "@/lib/csr-names";
import { Wizard, type Step } from "./new-managed-certificate-dialog.prototype";

type Org = Me["organizations"][number];

export const OVERVIEW_VARIANTS = [
  { key: "A", name: "Today" },
  { key: "B", name: "Key and CSR card + side sheet" },
  { key: "C", name: "Key banner + guided dialogs" },
];

type Action = "rotate" | "names";

const DAY = 24 * 60 * 60 * 1000;
const MOCK_FINGERPRINT = "4f:2a:9c:01:e7:5b:3d:88";

/** How long the key has been in use, from the first Certificate we know of (mock: the current one's issue date). */
function keyAge(m: ManagedCertificate) {
  const since = m.currentCertificate?.issuedAt;
  if (!since) return null;
  const days = Math.max(0, Math.round((Date.now() - Date.parse(since)) / DAY));
  return { since: new Date(since).toLocaleDateString(), days };
}

/** An open sheet or dialog that asks before throwing away a generated key nobody has saved. */
function useGuardedOpen() {
  const [action, setAction] = useState<Action | null>(null);
  const [atRisk, setAtRisk] = useState(false);
  const [asking, setAsking] = useState(false);
  const request = (next: Action | null) => (next === null && atRisk ? setAsking(true) : setAction(next));
  const confirm = (
    <ConfirmDialog
      open={asking}
      onOpenChange={setAsking}
      title="Discard the key you have not saved?"
      description="It was made in this browser and exists nowhere else."
      confirmLabel="Discard it and close"
      dismissLabel="Keep editing"
      pending={false}
      error={null}
      onConfirm={() => {
        setAsking(false);
        setAtRisk(false);
        setAction(null);
      }}
    />
  );
  return { action, request, setAtRisk, confirm };
}

function mayChangeNames(org: Org, m: ManagedCertificate) {
  return !m.pendingNameChange && m.approval.status !== "pending" && m.approval.status !== "rejected";
}
const direct = (org: Org) => can(org, "managedCertificate", "changeNames");

function NamesDiff({ before, after }: { before: string[]; after: string[] }) {
  const added = after.filter((n) => !before.includes(n));
  const removed = before.filter((n) => !after.includes(n));
  const kept = before.filter((n) => after.includes(n));
  if (added.length === 0 && removed.length === 0) return <p className="text-sm text-muted-foreground">No change to the names yet.</p>;
  return (
    <ul className="flex flex-col gap-0.5 rounded-md border p-3 font-mono text-xs">
      {added.map((n) => (
        <li key={`+${n}`} className="text-emerald-700 dark:text-emerald-400">
          + {n}
        </li>
      ))}
      {removed.map((n) => (
        <li key={`-${n}`} className="text-destructive line-through">
          − {n}
        </li>
      ))}
      {kept.map((n) => (
        <li key={n} className="text-muted-foreground">
          {"  "}
          {n}
        </li>
      ))}
    </ul>
  );
}

function WouldSend({ what, body, onDone }: { what: string; body: object; onDone: () => void }) {
  return (
    <div className="flex flex-col gap-4 p-4">
      <p className="flex items-center gap-2 font-medium">
        <ShieldCheckIcon className="size-5 text-emerald-600" />
        PROTOTYPE: this is where it would {what}. Nothing was sent.
      </p>
      <pre className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs">{JSON.stringify(body, null, 2)}</pre>
      <div>
        <Button onClick={onDone}>Close</Button>
      </div>
    </div>
  );
}

const trimCsr = (csr: string) => (csr ? `${csr.slice(0, 64)}…` : "(none)");

// --- B: a Key and CSR card, and a side sheet ------------------------------------------------------------------------

export function KeyAndCsrCard({ org, m }: { org: Org; m: ManagedCertificate }) {
  const guard = useGuardedOpen();
  const age = keyAge(m);
  const changeable = mayChangeNames(org, m);
  return (
    <Card className="lg:col-span-2">
      <CardHeader>
        <CardTitle>Key and CSR</CardTitle>
        <CardDescription>You hold the private key; the platform has only the CSR, and every Renewal reuses it until you replace it.</CardDescription>
        <CardAction className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => guard.request("rotate")}>
            <RefreshCwIcon />
            Replace key
          </Button>
          {changeable && (
            <Button variant="outline" size="sm" onClick={() => guard.request("names")}>
              <PencilIcon />
              {direct(org) ? "Change names" : "Propose a name change"}
            </Button>
          )}
        </CardAction>
      </CardHeader>
      <CardContent>
        <dl className="grid gap-x-8 gap-y-3 text-sm sm:grid-cols-4">
          <Fact label="Key type">{KEY_ALGORITHM_LABELS[m.keyAlgorithm as KeyAlgorithm] ?? m.keyAlgorithm}</Fact>
          <Fact label="CSR in use">
            <span className="font-mono text-xs">{MOCK_FINGERPRINT}</span> <span className="text-xs text-muted-foreground">(mock)</span>
          </Fact>
          <Fact label="Key in use since">{age ? `${age.since} (${age.days} days)` : "Not used yet"}</Fact>
          <Fact label="Next Renewal">{m.renewal.dueAt ? `reuses this key, ${new Date(m.renewal.dueAt).toLocaleDateString()}` : "reuses this key"}</Fact>
        </dl>
        {m.pendingNameChange && (
          <p className="mt-3 text-sm text-muted-foreground">
            A name change is waiting for Approval, with its own CSR: {m.pendingNameChange.names.join(", ")}.
          </p>
        )}
      </CardContent>
      {guard.confirm}
      <Sheet open={guard.action !== null} onOpenChange={(open) => !open && guard.request(null)}>
        <SheetContent
          className="w-full overflow-y-auto data-[side=right]:sm:max-w-xl"
          onInteractOutside={(e) => isPrototypeSwitcher(e.target) && e.preventDefault()}
        >
          {guard.action && <SheetBody key={guard.action} org={org} m={m} action={guard.action} onAtRisk={guard.setAtRisk} onDone={() => guard.request(null)} />}
        </SheetContent>
      </Sheet>
    </Card>
  );
}

function SheetBody({ org, m, action, onAtRisk, onDone }: { org: Org; m: ManagedCertificate; action: Action; onAtRisk: (r: boolean) => void; onDone: () => void }) {
  const [names, setNames] = useState(m.names.join("\n"));
  const [key, setKeyState] = useState<KeyState>(emptyKey());
  const [sent, setSent] = useState(false);
  const [renewNow, setRenewNow] = useState(true);
  const setKey = (k: KeyState) => {
    setKeyState(k);
    onAtRisk(keyAtRisk(k));
  };
  const keyAlgorithm = m.keyAlgorithm as KeyAlgorithm;
  const parsed = action === "names" ? splitNames(names) : m.names;
  const problems = nameProblems(parsed);
  const normal = problems.length === 0 ? normalizedNames(parsed) : [];
  const changed = action === "rotate" || normal.join("\n") !== m.names.join("\n");
  const ready = useKeyReady(key, parsed, keyAlgorithm);
  const title = action === "rotate" ? "Replace the key" : direct(org) ? "Change names" : "Propose a name change";

  if (sent)
    return (
      <WouldSend
        what={action === "rotate" ? "upload the CSR for the next Renewal" : direct(org) ? "change the names and start an Issuance" : "propose the name change"}
        body={action === "rotate" ? { csr: trimCsr(csrOf(key, parsed, keyAlgorithm)), thenRenewNow: renewNow } : { names: normal, csr: trimCsr(csrOf(key, parsed, keyAlgorithm)) }}
        onDone={() => {
          onAtRisk(false);
          onDone();
        }}
      />
    );
  return (
    <>
      <SheetHeader>
        <SheetTitle>{title}</SheetTitle>
        <SheetDescription>
          {action === "rotate"
            ? renewNow && m.currentCertificate
              ? "A new key and CSR for the same names, and a Renewal with it straight away. The current Certificate keeps working until it expires."
              : "A new key and CSR for the same names. The next Renewal uses it; the current Certificate keeps working until then."
            : direct(org)
              ? "An Issuance of the new names starts at once."
              : "An Approver must approve it. Until then Renewal continues with the current names and key."}
        </SheetDescription>
      </SheetHeader>
      <div className="flex flex-col gap-6 px-4">
        {action === "names" && (
          <FieldSet>
            <Field data-invalid={problems.length > 0}>
              <FieldLabel htmlFor="proto-sheet-names">All the names it is to have</FieldLabel>
              <Textarea id="proto-sheet-names" rows={5} value={names} onChange={(e) => setNames(e.target.value)} />
              {problems.map((p) => (
                <FieldError key={p}>{p}</FieldError>
              ))}
            </Field>
            <NamesDiff before={m.names} after={normal} />
          </FieldSet>
        )}
        <FieldSet className={!changed || problems.length > 0 ? "pointer-events-none opacity-50" : ""}>
          <FieldLegend variant="label">CSR for {action === "rotate" ? "a new key" : "the new names"}</FieldLegend>
          <FieldDescription>{KEY_ALGORITHM_LABELS[keyAlgorithm]}, the same as now.</FieldDescription>
          <KeySource names={parsed} keyAlgorithm={keyAlgorithm} state={key} onChange={setKey} idPrefix="proto-sheet" />
        </FieldSet>
        {action === "rotate" && m.currentCertificate && <RenewNowChoice checked={renewNow} onChange={setRenewNow} id="proto-sheet-renew" />}
      </div>
      <SheetFooter>
        <Button disabled={!changed || !ready} onClick={() => setSent(true)}>
          {action === "rotate" ? (renewNow && m.currentCertificate ? "Use this CSR and renew now" : "Use this CSR from the next Renewal") : direct(org) ? "Change names" : "Propose"}
        </Button>
      </SheetFooter>
    </>
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

// --- C: a key banner, and guided dialogs ----------------------------------------------------------------------------

export function KeyBanner({ org, m }: { org: Org; m: ManagedCertificate }) {
  const guard = useGuardedOpen();
  const age = keyAge(m);
  const old = age !== null && age.days > 365;
  return (
    <div className="flex flex-col gap-3 rounded-lg border bg-muted/40 p-4 sm:flex-row sm:items-center lg:col-span-2">
      <KeyRoundIcon className="size-8 shrink-0 rounded-md bg-background p-1.5 text-muted-foreground" />
      <div className="flex min-w-0 flex-1 flex-col gap-0.5 text-sm">
        <span className="font-medium">
          {KEY_ALGORITHM_LABELS[m.keyAlgorithm as KeyAlgorithm] ?? m.keyAlgorithm} key, held by its Owner
          {age && <span className="font-normal text-muted-foreground"> · in use for {age.days} days · 3 Certificates signed with it (mock)</span>}
        </span>
        <span className={old ? "text-amber-700 dark:text-amber-400" : "text-muted-foreground"}>
          {old ? "This key is over a year old. Many policies ask for a new one each year." : "Each Renewal reuses this key until you replace it."}
        </span>
      </div>
      <div className="flex shrink-0 gap-2">
        <Button variant={old ? "default" : "outline"} size="sm" onClick={() => guard.request("rotate")}>
          <RefreshCwIcon />
          Rotate key
        </Button>
        {mayChangeNames(org, m) && (
          <Button variant="outline" size="sm" onClick={() => guard.request("names")}>
            <PencilIcon />
            {direct(org) ? "Change names" : "Propose a name change"}
          </Button>
        )}
      </div>
      {guard.confirm}
      <Dialog open={guard.action !== null} onOpenChange={(open) => !open && guard.request(null)}>
        <DialogContent
          className="gap-0 overflow-hidden p-0 sm:max-w-[calc(100%-2rem)] md:max-w-[760px]"
          onInteractOutside={(e) => isPrototypeSwitcher(e.target) && e.preventDefault()}
        >
          <DialogTitle className="sr-only">{guard.action === "rotate" ? "Rotate the key" : "Change names"}</DialogTitle>
          <DialogDescription className="sr-only">A new key and CSR for this Managed Certificate.</DialogDescription>
          {guard.action && <GuidedChange key={guard.action} org={org} m={m} action={guard.action} onAtRisk={guard.setAtRisk} onDone={() => guard.request(null)} />}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function GuidedChange({ org, m, action, onAtRisk, onDone }: { org: Org; m: ManagedCertificate; action: Action; onAtRisk: (r: boolean) => void; onDone: () => void }) {
  const [names, setNames] = useState(m.names.join("\n"));
  const [key, setKeyState] = useState<KeyState>(emptyKey());
  const [sent, setSent] = useState(false);
  const [renewNow, setRenewNow] = useState(true);
  const setKey = (k: KeyState) => {
    setKeyState(k);
    onAtRisk(keyAtRisk(k));
  };
  const keyAlgorithm = m.keyAlgorithm as KeyAlgorithm;
  const parsed = action === "names" ? splitNames(names) : m.names;
  const problems = nameProblems(parsed);
  const normal = problems.length === 0 ? normalizedNames(parsed) : [];
  const changed = normal.join("\n") !== m.names.join("\n");
  const ready = useKeyReady(key, parsed, keyAlgorithm);
  const generatedFits = csrOf(key, parsed, keyAlgorithm) !== "";

  if (sent)
    return (
      <WouldSend
        what={action === "rotate" ? "upload the CSR for the next Renewal" : "change or propose the names"}
        body={{ ...(action === "names" && { names: normal }), csr: trimCsr(csrOf(key, parsed, keyAlgorithm)), ...(action === "rotate" && { thenRenewNow: renewNow }) }}
        onDone={() => {
          onAtRisk(false);
          onDone();
        }}
      />
    );

  const steps: Step[] = [
    ...(action === "names"
      ? [
          {
            id: "names",
            title: "New names",
            icon: GlobeIcon,
            complete: problems.length === 0 && changed,
            body: (
              <div className="grid gap-4 md:grid-cols-2">
                <Field data-invalid={problems.length > 0}>
                  <FieldLabel htmlFor="proto-guided-names">All the names it is to have</FieldLabel>
                  <Textarea id="proto-guided-names" rows={8} value={names} onChange={(e) => setNames(e.target.value)} />
                  {problems.map((p) => (
                    <FieldError key={p}>{p}</FieldError>
                  ))}
                </Field>
                <div className="flex flex-col gap-2">
                  <span className="text-sm font-medium">What changes</span>
                  <NamesDiff before={m.names} after={normal} />
                </div>
              </div>
            ),
          },
        ]
      : []),
    {
      id: "key",
      title: "Key",
      icon: KeyRoundIcon,
      complete: key.mode === "generate" ? generatedFits : ready,
      body: (
        <FieldSet>
          <FieldLegend>{action === "rotate" ? "A new key" : "A CSR for the new names"}</FieldLegend>
          <FieldDescription>{KEY_ALGORITHM_LABELS[keyAlgorithm]}, the same as now.</FieldDescription>
          <KeySource names={parsed} keyAlgorithm={keyAlgorithm} state={key} onChange={setKey} saveInline={false} idPrefix="proto-guided" />
        </FieldSet>
      ),
    },
    ...(key.mode === "generate"
      ? [
          {
            id: "save",
            title: "Save your key",
            icon: ShieldCheckIcon,
            complete: key.keySaved && key.confirmed,
            body: (
              <FieldSet>
                <FieldLegend>Save the new key</FieldLegend>
                <FieldDescription>Keep the old one too, until the new Certificate is in place.</FieldDescription>
                <SaveKey state={key} onChange={setKey} />
              </FieldSet>
            ),
          },
        ]
      : []),
    {
      id: "next",
      title: "What happens next",
      icon: ClipboardCheckIcon,
      complete: true,
      body: (
        <div className="flex flex-col gap-6">
          <WhatNext org={org} m={m} action={action} renewNow={renewNow && !!m.currentCertificate} />
          {action === "rotate" && m.currentCertificate && <RenewNowChoice checked={renewNow} onChange={setRenewNow} id="proto-guided-renew" />}
        </div>
      ),
    },
  ];
  return (
    <Wizard
      steps={steps}
      title={action === "rotate" ? "Rotate the key" : direct(org) ? "Change names" : "Propose a name change"}
      finishLabel={action === "rotate" ? (renewNow && m.currentCertificate ? "Use it and renew now" : "Use from the next Renewal") : direct(org) ? "Change names" : "Propose"}
      onFinish={() => setSent(true)}
    />
  );
}

function RenewNowChoice({ checked, onChange, id }: { checked: boolean; onChange: (on: boolean) => void; id: string }) {
  return (
    <Field orientation="horizontal" className="rounded-md border p-3">
      <Checkbox id={id} checked={checked} onCheckedChange={(on) => onChange(on === true)} />
      <FieldLabel htmlFor={id} className="flex-col items-start gap-0.5 font-normal">
        <span className="font-medium">Renew now with the new key</span>
        <span className="text-muted-foreground">Otherwise the old key stays in use until the next Renewal is due.</span>
      </FieldLabel>
    </Field>
  );
}

function WhatNext({ org, m, action, renewNow }: { org: Org; m: ManagedCertificate; action: Action; renewNow: boolean }) {
  const lines =
    action === "rotate" && renewNow
      ? [
          "The platform keeps the new CSR, and a Renewal starts at once.",
          "Install the new key with the Certificate it produces; the old Certificate keeps working until it expires.",
          "Later Renewals reuse the new key.",
        ]
      : action === "rotate"
      ? [
          "The platform keeps the new CSR; the current Certificate is untouched.",
          m.renewal.dueAt ? `The next Renewal, from ${new Date(m.renewal.dueAt).toLocaleDateString()}, is issued for the new key.` : "The next Renewal is issued for the new key.",
          "Install the new key with that Certificate. Renew now if you want it sooner.",
        ]
      : direct(org)
        ? ["The names change at once.", "An Issuance of the new names starts, for the new key.", "Install the new key with the Certificate it produces."]
        : [
            "An Approver is asked to approve the new names.",
            "Until then, Renewal continues with the current names and the current key.",
            "Once approved, an Issuance of the new names starts, for the new key.",
          ];
  return (
    <ol className="flex flex-col gap-3 text-sm">
      {lines.map((line, i) => (
        <li key={line} className="flex items-start gap-3">
          <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-medium">{i + 1}</span>
          <span className="pt-0.5">{line}</span>
        </li>
      ))}
      <li className="flex items-center gap-2 pt-2 text-muted-foreground">
        <ArrowRightIcon className="size-4" /> Subscribers are told when the Certificate is issued.
      </li>
    </ol>
  );
}
