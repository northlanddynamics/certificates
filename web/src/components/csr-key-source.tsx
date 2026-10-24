import { CheckIcon, CircleAlertIcon, ClipboardPasteIcon, CopyIcon, DownloadIcon, EyeIcon, EyeOffIcon, KeyRoundIcon, LoaderIcon, SquareTerminalIcon, XIcon } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { CsrSignatureWarning } from "@/components/csr-signature-warning";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Field, FieldContent, FieldDescription, FieldLabel, FieldLegend, FieldSet, FieldTitle } from "@/components/ui/field";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Textarea } from "@/components/ui/textarea";
import { KEY_ALGORITHM_LABELS, MAX_COMMON_NAME_LENGTH, NO_KEY_ALGORITHMS, generateCsr, type KeyAlgorithm } from "@/lib/csr-generator";
import { inspectCsr, matchCsr, opensslCommand, type CsrFacts } from "@/lib/csr-inspect";
import { fileBaseOf } from "@/lib/pki-convert";
import { normalizedNames } from "@/lib/csr-names";
import { cn } from "@/lib/utils";

/** How the CSR is provided: a key made in this browser, a key made with openssl where it is to live, or a CSR made elsewhere. */
export type KeySourceMode = "generate" | "command" | "paste";

export interface GeneratedKey {
  keyPem: string;
  csrPem: string;
  fileBase: string;
  /** The names and key algorithm it was made for, to tell when they have since changed. */
  madeFor: string;
}

/** A form's state of providing a CSR; kept by the form, so moving between its steps loses nothing. */
export interface KeySourceState {
  mode: KeySourceMode;
  /** What was pasted, in the command and paste modes. */
  pasted: string;
  generated: GeneratedKey | null;
  /** The generated key has been downloaded or copied. */
  keySaved: boolean;
  /** The user has said they stored it. */
  confirmed: boolean;
}

export const emptyKeySource = (mode: KeySourceMode = "generate"): KeySourceState => ({ mode, pasted: "", generated: null, keySaved: false, confirmed: false });

const madeFor = (names: string[], keyAlgorithm: KeyAlgorithm) => `${normalizedNames(names).join("\n")}|${keyAlgorithm}`;

/** The CSR the state would submit for these names and key algorithm: a generated one only if it was made for them. */
export function csrOf(state: KeySourceState, names: string[], keyAlgorithm: KeyAlgorithm): string {
  if (state.mode !== "generate") return state.pasted;
  return state.generated?.madeFor === madeFor(names, keyAlgorithm) ? state.generated.csrPem : "";
}

/** A generated key that has been neither downloaded nor copied exists nowhere else: closing would lose it. */
export const keyAtRisk = (state: KeySourceState) => state.mode === "generate" && state.generated !== null && !state.keySaved;

/** Asks before the page is left while `atRisk`. */
export function useUnloadGuard(atRisk: boolean) {
  useEffect(() => {
    if (!atRisk) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [atRisk]);
}

/** A pasted CSR's facts, read as it changes; a string when it cannot be read, null while there is nothing. */
export function useCsrFacts(pem: string) {
  const [facts, setFacts] = useState<CsrFacts | string | null>(null);
  useEffect(() => {
    let current = true;
    void inspectCsr(pem).then((read) => current && setFacts(read));
    return () => {
      current = false;
    };
  }, [pem]);
  return facts;
}

/** Whether the state holds a CSR the server will take for these names and key algorithm, and for a generated one, a saved key. */
export function useKeySourceReady(state: KeySourceState, names: string[], keyAlgorithm: KeyAlgorithm) {
  const facts = useCsrFacts(state.mode === "generate" ? "" : state.pasted);
  if (state.mode === "generate") return csrOf(state, names, keyAlgorithm) !== "" && state.keySaved;
  return typeof facts === "object" && facts !== null && matchCsr(facts, names, keyAlgorithm).ok;
}

const KEY_ALGORITHM_HINTS: Record<KeyAlgorithm, string> = {
  "ecdsa-p256": "Recommended. Small, fast, and taken by every modern client.",
  "ecdsa-p384": "A stronger curve, where a policy asks for one.",
  "rsa-2048": "For older clients and appliances that cannot use ECDSA.",
  "rsa-3072": "RSA where a policy asks for more than 2048 bits.",
  "rsa-4096": "The largest RSA key; slower to make and to use.",
  "ml-dsa-44": "Post-quantum, with the smallest ML-DSA keys and signatures. Your server and its clients must support ML-DSA (OpenSSL 3.5 or later).",
  "ml-dsa-65": "Post-quantum, stronger than ML-DSA-44. Your server and its clients must support ML-DSA (OpenSSL 3.5 or later).",
  "ml-dsa-87": "Post-quantum, the strongest ML-DSA, as CNSA 2.0 asks. Your server and its clients must support ML-DSA (OpenSSL 3.5 or later).",
};

/** The key algorithms offered (`options`) as a row of choices, with a line on when to choose the chosen one. */
export function KeyAlgorithmChoice<T extends KeyAlgorithm>({ value, options, onChange, idPrefix }: { value: T; options: readonly T[]; onChange: (value: T) => void; idPrefix: string }) {
  return (
    <FieldSet>
      <FieldLegend variant="label">Key type</FieldLegend>
      <RadioGroup value={value} onValueChange={(v) => onChange(v as T)} className="flex flex-wrap gap-2">
        {options.map((alg) => (
          <FieldLabel key={alg} htmlFor={`${idPrefix}-${alg}`} className="w-auto! flex-none whitespace-nowrap">
            <Field orientation="horizontal" className="gap-3 py-2!">
              <FieldContent>
                <FieldTitle>{KEY_ALGORITHM_LABELS[alg]}</FieldTitle>
              </FieldContent>
              <RadioGroupItem value={alg} id={`${idPrefix}-${alg}`} />
            </Field>
          </FieldLabel>
        ))}
      </RadioGroup>
      <FieldDescription>{KEY_ALGORITHM_HINTS[value]}</FieldDescription>
    </FieldSet>
  );
}

function Line({ ok, children }: { ok: boolean; children: ReactNode }) {
  return (
    <span className="flex items-center gap-2">
      {ok ? <CheckIcon className="size-4 shrink-0 text-emerald-600 dark:text-emerald-400" /> : <XIcon className="size-4 shrink-0 text-destructive" />}
      <span>{children}</span>
    </span>
  );
}

/**
 * Under a textarea that takes a pasted CSR: what it asks for, and whether that is what the form asks for. Where the
 * form lets the CSR decide the key type, it says so (`keyTypeFromCsr`); where it lets the CSR's names replace its own,
 * it offers to (`onUseNames`). It never blocks; the server has the last word.
 */
export function CsrCheck({
  pem,
  names,
  keyAlgorithm,
  keyTypeFromCsr = false,
  onUseNames,
}: {
  pem: string;
  names: string[];
  keyAlgorithm: KeyAlgorithm;
  keyTypeFromCsr?: boolean;
  onUseNames?: (names: string[]) => void;
}) {
  const facts = useCsrFacts(pem);
  if (facts === null) return null;
  if (typeof facts === "string")
    return (
      <p className="flex items-start gap-2 text-sm text-destructive">
        <CircleAlertIcon className="mt-0.5 size-4 shrink-0" />
        {facts}
      </p>
    );
  const match = matchCsr(facts, names, keyAlgorithm);
  const namesOk = match.missing.length === 0 && match.extra.length === 0;
  return (
    <div className={cn("flex flex-col gap-1 rounded-md border p-3 text-sm", match.ok ? "border-emerald-600/40 bg-emerald-600/5" : "border-destructive/40 bg-destructive/5")}>
      <Line ok={match.algorithmOk}>
        {facts.keyLabel} key
        {match.algorithmOk && keyTypeFromCsr && <span className="text-muted-foreground"> — the key type is taken from the CSR</span>}
        {!match.algorithmOk && (facts.keyAlgorithm ? `, but this certificate is ${KEY_ALGORITHM_LABELS[keyAlgorithm]}` : "")}
      </Line>
      <Line ok={namesOk}>
        {facts.names.length} {facts.names.length === 1 ? "name" : "names"}
        {namesOk && " — exactly the ones asked for"}
      </Line>
      {match.missing.map((name) => (
        <span key={`-${name}`} className="pl-6 font-mono text-xs text-destructive">
          − missing {name}
        </span>
      ))}
      {match.extra.map((name) => (
        <span key={`+${name}`} className="pl-6 font-mono text-xs text-destructive">
          + not asked for {name}
        </span>
      ))}
      {!namesOk && onUseNames && (
        <span className="pl-6">
          <Button type="button" variant="outline" size="sm" className="mt-1" onClick={() => onUseNames(facts.names)}>
            Use the CSR's {facts.names.length === 1 ? "name" : `${facts.names.length} names`} instead
          </Button>
        </span>
      )}
      <span className="pl-6 font-mono text-xs text-muted-foreground">CSR {facts.fingerprint}</span>
      <CsrSignatureWarning pem={pem} />
    </div>
  );
}

export function downloadPem(filename: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/x-pem-file" }));
  Object.assign(document.createElement("a"), { href: url, download: filename }).click();
  URL.revokeObjectURL(url);
}

/**
 * A generated key's download and copy, which mark it saved, and with `confirm` the box saying it is stored. The CSR
 * is shown only on request (`showCsr`): a form submits it itself.
 */
export function SaveKey({
  state,
  onChange,
  confirm = false,
  showCsr = true,
}: {
  state: KeySourceState;
  onChange: (state: KeySourceState) => void;
  confirm?: boolean;
  showCsr?: boolean;
}) {
  const [showKey, setShowKey] = useState(false);
  const [csrOpen, setCsrOpen] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);
  useUnloadGuard(keyAtRisk(state));
  const generated = state.generated;
  if (!generated) return null;
  const saved = () => onChange({ ...state, keySaved: true });
  return (
    <div className="flex flex-col gap-3">
      <div className={cn("flex flex-col gap-3 rounded-md border p-4", state.keySaved ? "border-emerald-600/40" : "border-amber-500/60 bg-amber-500/5")}>
        <div className="flex items-center gap-2 text-sm font-medium">
          <KeyRoundIcon className="size-4" />
          {generated.fileBase}.key.pem
          {state.keySaved ? (
            <span className="ml-auto flex items-center gap-1 text-xs text-emerald-700 dark:text-emerald-400">
              <CheckIcon className="size-3" /> saved
            </span>
          ) : (
            <span className="ml-auto text-xs text-amber-700 dark:text-amber-400">not saved yet</span>
          )}
        </div>
        <p className="text-sm text-muted-foreground">Made in this browser and never sent to the platform. There is no other copy: if it is lost, you will need a new key and CSR.</p>
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            size="sm"
            onClick={() => {
              downloadPem(`${generated.fileBase}.key.pem`, generated.keyPem);
              saved();
            }}
          >
            <DownloadIcon />
            Download key
          </Button>
          <Button type="button" variant="outline" size="sm" onClick={() => navigator.clipboard.writeText(generated.keyPem).then(saved, () => setCopyFailed(true))}>
            <CopyIcon />
            Copy key
          </Button>
          <Button type="button" variant="ghost" size="sm" onClick={() => setShowKey(!showKey)}>
            {showKey ? <EyeOffIcon /> : <EyeIcon />}
            {showKey ? "Hide" : "Show"}
          </Button>
        </div>
        {copyFailed && <p className="text-sm text-destructive">The browser would not let this page copy; download the key instead.</p>}
        {showKey && <Textarea readOnly className="font-mono text-xs field-sizing-fixed" rows={6} value={generated.keyPem} aria-label="Private key" />}
        {confirm && (
          <Field orientation="horizontal">
            <Checkbox id="save-key-confirm" disabled={!state.keySaved} checked={state.confirmed} onCheckedChange={(checked) => onChange({ ...state, confirmed: checked === true })} />
            <FieldLabel htmlFor="save-key-confirm" className="font-normal">
              I've stored the key somewhere safe.
            </FieldLabel>
          </Field>
        )}
      </div>
      {showCsr && (
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="text-muted-foreground">The CSR goes to the platform with the rest; you need not save it.</span>
            <Button type="button" variant="link" size="sm" className="h-auto p-0" onClick={() => setCsrOpen(!csrOpen)}>
              {csrOpen ? "Hide CSR" : "Show CSR"}
            </Button>
          </div>
          {csrOpen && <Textarea readOnly className="font-mono text-xs field-sizing-fixed" rows={6} value={generated.csrPem} aria-label="CSR" />}
        </div>
      )}
    </div>
  );
}

const MODES: { mode: KeySourceMode; title: string; icon: typeof KeyRoundIcon }[] = [
  { mode: "generate", title: "Generate here", icon: KeyRoundIcon },
  { mode: "command", title: "Run a command", icon: SquareTerminalIcon },
  { mode: "paste", title: "Paste a CSR", icon: ClipboardPasteIcon },
];

/**
 * How the CSR for a form's names is provided. The key algorithm is the form's: fixed, unless the form passes
 * `onKeyAlgorithmChange`, when it is chosen here from `keyAlgorithms` (what the CA takes) and a pasted CSR's own is
 * taken. `onNamesChange` lets a pasted CSR's names replace the form's. With `saveInline` the generated key is saved
 * here; otherwise the form has a step for it.
 */
export function KeySource({
  names,
  keyAlgorithm,
  keyAlgorithms: taken = NO_KEY_ALGORITHMS,
  onKeyAlgorithmChange,
  onNamesChange,
  state,
  onChange,
  saveInline = true,
  idPrefix,
}: {
  names: string[];
  keyAlgorithm: KeyAlgorithm;
  keyAlgorithms?: readonly KeyAlgorithm[];
  onKeyAlgorithmChange?: (keyAlgorithm: KeyAlgorithm) => void;
  onNamesChange?: (names: string[]) => void;
  state: KeySourceState;
  onChange: (state: KeySourceState) => void;
  saveInline?: boolean;
  idPrefix: string;
}) {
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useUnloadGuard(keyAtRisk(state));
  // Until the form knows what its CA takes, only its own key algorithm is offered.
  const keyAlgorithms = taken.length > 0 ? taken : [keyAlgorithm];
  const distinct = normalizedNames(names);
  const stale = state.generated !== null && state.generated.madeFor !== madeFor(names, keyAlgorithm);
  const facts = useCsrFacts(state.mode === "generate" ? "" : state.pasted);

  // A pasted CSR is for one kind of key; where the form lets it, that settles the key type.
  const pastedKeyAlgorithm = typeof facts === "object" && facts !== null ? facts.keyAlgorithm : null;
  useEffect(() => {
    if (onKeyAlgorithmChange && pastedKeyAlgorithm && pastedKeyAlgorithm !== keyAlgorithm && (taken.length === 0 || taken.includes(pastedKeyAlgorithm))) onKeyAlgorithmChange(pastedKeyAlgorithm);
  }, [onKeyAlgorithmChange, pastedKeyAlgorithm, keyAlgorithm, taken]);

  async function generate() {
    setWorking(true);
    setError(null);
    try {
      const made = await generateCsr({ keyAlgorithm, names: distinct, commonName: distinct.find((n) => n.length <= MAX_COMMON_NAME_LENGTH) ?? null });
      onChange({ ...state, generated: { ...made, fileBase: fileBaseOf(distinct[0] ?? null, "csr"), madeFor: madeFor(names, keyAlgorithm) }, keySaved: false, confirmed: false });
    } catch (err) {
      setError(err instanceof Error ? err.message : "The browser could not make a key.");
    } finally {
      setWorking(false);
    }
  }

  return (
    <div className="@container flex min-w-0 flex-col gap-5">
      {/* Three across only where the container has room; a narrow dialog stacks them. */}
      <RadioGroup value={state.mode} onValueChange={(mode) => onChange({ ...state, mode: mode as KeySourceMode })} className="grid gap-2 @lg:grid-cols-3">
        {MODES.map(({ mode, title, icon: Icon }) => (
          <FieldLabel key={mode} htmlFor={`${idPrefix}-mode-${mode}`}>
            <Field orientation="horizontal">
              <FieldContent>
                <FieldTitle>
                  <Icon className="size-4" />
                  {title}
                </FieldTitle>
              </FieldContent>
              <RadioGroupItem value={mode} id={`${idPrefix}-mode-${mode}`} />
            </Field>
          </FieldLabel>
        ))}
      </RadioGroup>

      {onKeyAlgorithmChange && state.mode !== "paste" && <KeyAlgorithmChoice value={keyAlgorithm} options={keyAlgorithms} onChange={onKeyAlgorithmChange} idPrefix={`${idPrefix}-alg`} />}

      {state.mode === "generate" && (
        <div className="flex flex-col gap-3">
          {stale && (
            <p className="flex items-start gap-2 rounded-md border border-amber-500/60 bg-amber-500/5 p-3 text-sm">
              <CircleAlertIcon className="mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-400" />
              The names or key type changed since this key was made, so its CSR no longer fits. Generate a new one.
            </p>
          )}
          {(!state.generated || stale) && (
            <div className="flex flex-wrap items-center gap-3">
              <Button type="button" disabled={working || distinct.length === 0} onClick={generate}>
                {working ? <LoaderIcon className="animate-spin" /> : <KeyRoundIcon />}
                {working ? "Generating…" : "Generate key and CSR"}
              </Button>
              <span className="text-sm text-muted-foreground">
                {KEY_ALGORITHM_LABELS[keyAlgorithm]}, for {distinct.length === 1 ? distinct[0] : `these ${distinct.length} names`}.
              </span>
            </div>
          )}
          {state.generated && !stale && saveInline && <SaveKey state={state} onChange={onChange} />}
          {state.generated && !stale && !saveInline && (
            <p className="flex items-center gap-2 text-sm text-emerald-700 dark:text-emerald-400">
              <CheckIcon className="size-4" /> {KEY_ALGORITHM_LABELS[keyAlgorithm]} key and CSR made. You save the key next.
            </p>
          )}
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
      )}

      {state.mode === "command" && (
        <div className="flex flex-col gap-2">
          <p className="text-sm text-muted-foreground">Run this where the key is to live. It writes the key and the CSR next to each other.</p>
          <div className="relative">
            <pre className="overflow-x-auto rounded-md bg-muted p-3 pr-12 font-mono text-xs">{opensslCommand(distinct, keyAlgorithm)}</pre>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="absolute top-1 right-1 size-7"
              aria-label="Copy the command"
              onClick={() => navigator.clipboard.writeText(opensslCommand(distinct, keyAlgorithm))}
            >
              <CopyIcon />
            </Button>
          </div>
        </div>
      )}

      {state.mode !== "generate" && (
        <Field>
          <FieldLabel htmlFor={`${idPrefix}-pasted`}>{state.mode === "command" ? "Paste the .csr.pem it wrote" : "CSR (PEM)"}</FieldLabel>
          <Textarea
            id={`${idPrefix}-pasted`}
            className="max-h-36 font-mono text-xs field-sizing-fixed"
            rows={6}
            placeholder="-----BEGIN CERTIFICATE REQUEST-----"
            value={state.pasted}
            onChange={(e) => onChange({ ...state, pasted: e.target.value })}
          />
          <CsrCheck pem={state.pasted} names={names} keyAlgorithm={keyAlgorithm} keyTypeFromCsr={!!onKeyAlgorithmChange} onUseNames={onNamesChange} />
        </Field>
      )}
    </div>
  );
}
