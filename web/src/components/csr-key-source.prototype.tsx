// PROTOTYPE (branch prototype/csr-ux): throwaway. The pieces the CSR prototypes share: where the CSR comes from
// (generated here, pasted, or made with openssl), a live check of a pasted CSR against the names and key algorithm,
// and the "save your key" checkpoint.
import { CheckIcon, CircleAlertIcon, CopyIcon, DownloadIcon, EyeIcon, EyeOffIcon, KeyRoundIcon, LoaderIcon, ClipboardPasteIcon, TerminalIcon, XIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { CsrSignatureWarning } from "@/components/csr-signature-warning";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Field, FieldContent, FieldDescription, FieldLabel, FieldTitle } from "@/components/ui/field";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Textarea } from "@/components/ui/textarea";
import { KEY_ALGORITHMS, KEY_ALGORITHM_LABELS, MAX_COMMON_NAME_LENGTH, generateCsr, type KeyAlgorithm } from "@/lib/csr-generator";
import { normalizedNames } from "@/lib/csr-names";
import { fileBase, inspectCsr, matchCsr, opensslCommand, type CsrFacts } from "@/lib/csr-inspect.prototype";
import { cn } from "@/lib/utils";

export type KeyMode = "generate" | "paste" | "command";

export interface GeneratedKey {
  keyPem: string;
  csrPem: string;
  fileBase: string;
  /** The names and key algorithm it was made for. */
  madeFor: string;
}

export interface KeyState {
  mode: KeyMode;
  /** What was pasted (paste and command modes). */
  pasted: string;
  generated: GeneratedKey | null;
  /** Downloaded or copied. */
  keySaved: boolean;
  /** The user ticked "I have stored it". */
  confirmed: boolean;
}

export const emptyKey = (mode: KeyMode = "generate"): KeyState => ({ mode, pasted: "", generated: null, keySaved: false, confirmed: false });

export const madeFor = (names: string[], keyAlgorithm: KeyAlgorithm) => `${names.join("\n")}|${keyAlgorithm}`;

/** The CSR this state would submit, if any, for these names and this key algorithm. */
export function csrOf(state: KeyState, names: string[], keyAlgorithm: KeyAlgorithm): string {
  if (state.mode !== "generate") return state.pasted;
  return state.generated && state.generated.madeFor === madeFor(names, keyAlgorithm) ? state.generated.csrPem : "";
}

/** An unsaved generated key: closing would lose it. */
export const keyAtRisk = (state: KeyState) => state.mode === "generate" && state.generated !== null && !state.keySaved;

export async function makeKey(names: string[], keyAlgorithm: KeyAlgorithm): Promise<GeneratedKey> {
  const distinct = normalizedNames(names);
  const made = await generateCsr({ keyAlgorithm, names: distinct, commonName: distinct.find((n) => n.length <= MAX_COMMON_NAME_LENGTH) ?? null });
  return { ...made, fileBase: fileBase(distinct[0]), madeFor: madeFor(names, keyAlgorithm) };
}

export function useCsrFacts(pem: string) {
  const [facts, setFacts] = useState<CsrFacts | string | null>(null);
  useEffect(() => {
    let live = true;
    void inspectCsr(pem).then((f) => live && setFacts(f));
    return () => {
      live = false;
    };
  }, [pem]);
  return facts;
}

/** Whether the state holds a CSR the server will take for these names and key algorithm (and, for a generated one, a saved key). */
export function useKeyReady(state: KeyState, names: string[], keyAlgorithm: KeyAlgorithm, { needConfirmation = false } = {}) {
  const facts = useCsrFacts(state.mode === "generate" ? "" : state.pasted);
  if (state.mode === "generate") return csrOf(state, names, keyAlgorithm) !== "" && state.keySaved && (!needConfirmation || state.confirmed);
  return typeof facts === "object" && facts !== null && matchCsr(facts, names, keyAlgorithm).ok;
}

export const KEY_ALGORITHM_HINTS: Record<KeyAlgorithm, string> = {
  "ecdsa-p256": "Recommended. Small, fast, and taken by every modern client.",
  "ecdsa-p384": "A stronger curve, where a policy asks for one.",
  "rsa-2048": "For older clients and appliances that cannot use ECDSA.",
  "rsa-3072": "RSA where a policy asks for more than 2048 bits.",
  "rsa-4096": "The largest RSA key; slower to make and to use.",
};

/** The five key algorithms as radio cards, each with when to choose it. */
export function KeyAlgorithmCards({ value, onChange, idPrefix, compact = false }: { value: KeyAlgorithm; onChange: (v: KeyAlgorithm) => void; idPrefix: string; compact?: boolean }) {
  return (
    <>
    <RadioGroup value={value} onValueChange={(v) => onChange(v as KeyAlgorithm)} className={cn(compact ? "flex flex-wrap gap-2" : "grid gap-2 sm:grid-cols-2")}>
      {KEY_ALGORITHMS.map((alg) => (
        <FieldLabel key={alg} htmlFor={`${idPrefix}-${alg}`} className={compact ? "w-auto! flex-none whitespace-nowrap" : undefined}>
          <Field orientation="horizontal" className={compact ? "gap-3 py-2!" : undefined}>
            <FieldContent>
              <FieldTitle>{KEY_ALGORITHM_LABELS[alg]}</FieldTitle>
              {!compact && <FieldDescription>{KEY_ALGORITHM_HINTS[alg]}</FieldDescription>}
            </FieldContent>
            <RadioGroupItem value={alg} id={`${idPrefix}-${alg}`} />
          </Field>
        </FieldLabel>
      ))}
    </RadioGroup>
    {compact && <FieldDescription>{KEY_ALGORITHM_HINTS[value]}</FieldDescription>}
    </>
  );
}

/** What the pasted CSR is, and whether it matches: shown as soon as something is pasted. */
export function CsrCheck({ pem, names, keyAlgorithm }: { pem: string; names: string[]; keyAlgorithm: KeyAlgorithm | null }) {
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
  return (
    <div className={cn("flex flex-col gap-1 rounded-md border p-3 text-sm", match.ok ? "border-emerald-600/40 bg-emerald-600/5" : "border-destructive/40 bg-destructive/5")}>
      <Line ok={match.algorithmOk}>
        {facts.keyLabel} key{!match.algorithmOk && keyAlgorithm && `, but this certificate is ${KEY_ALGORITHM_LABELS[keyAlgorithm]}`}
      </Line>
      <Line ok={match.missing.length === 0 && match.extra.length === 0}>
        {facts.names.length} {facts.names.length === 1 ? "name" : "names"}
        {match.missing.length === 0 && match.extra.length === 0 ? " — exactly the ones asked for" : ""}
      </Line>
      {match.missing.map((n) => (
        <span key={n} className="pl-6 font-mono text-xs text-destructive">
          − missing {n}
        </span>
      ))}
      {match.extra.map((n) => (
        <span key={n} className="pl-6 font-mono text-xs text-destructive">
          + not asked for {n}
        </span>
      ))}
      <span className="pl-6 font-mono text-xs text-muted-foreground">CSR {facts.fingerprint}</span>
      <CsrSignatureWarning pem={pem} />
    </div>
  );
}

function Line({ ok, children }: { ok: boolean; children: React.ReactNode }) {
  return (
    <span className="flex items-center gap-2">
      {ok ? <CheckIcon className="size-4 text-emerald-600" /> : <XIcon className="size-4 text-destructive" />}
      {children}
    </span>
  );
}

function download(filename: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/x-pem-file" }));
  Object.assign(document.createElement("a"), { href: url, download: filename }).click();
  URL.revokeObjectURL(url);
}

/** Download and copy for a generated key, the box to tick, and (optionally) the CSR. */
export function SaveKey({ state, onChange, confirm = true, showCsr = true }: { state: KeyState; onChange: (s: KeyState) => void; confirm?: boolean; showCsr?: boolean }) {
  const [showKey, setShowKey] = useState(false);
  const [csrOpen, setCsrOpen] = useState(false);
  const g = state.generated;
  if (!g) return null;
  const saved = () => onChange({ ...state, keySaved: true });
  return (
    <div className="flex flex-col gap-3">
      <div className={cn("flex flex-col gap-3 rounded-md border p-4", state.keySaved ? "border-emerald-600/40" : "border-amber-500/60 bg-amber-500/5")}>
        <div className="flex items-center gap-2 text-sm font-medium">
          <KeyRoundIcon className="size-4" />
          {g.fileBase}.key.pem
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
              download(`${g.fileBase}.key.pem`, g.keyPem);
              saved();
            }}
          >
            <DownloadIcon />
            Download key
          </Button>
          <Button type="button" variant="outline" size="sm" onClick={() => navigator.clipboard.writeText(g.keyPem).then(saved)}>
            <CopyIcon />
            Copy key
          </Button>
          <Button type="button" variant="ghost" size="sm" onClick={() => setShowKey(!showKey)}>
            {showKey ? <EyeOffIcon /> : <EyeIcon />}
            {showKey ? "Hide" : "Show"}
          </Button>
        </div>
        {showKey && <Textarea readOnly className="font-mono text-xs field-sizing-fixed" rows={6} value={g.keyPem} aria-label="Private key" />}
        {confirm && (
          <Field orientation="horizontal">
            <Checkbox id="prototype-key-confirm" disabled={!state.keySaved} checked={state.confirmed} onCheckedChange={(c) => onChange({ ...state, confirmed: c === true })} />
            <FieldLabel htmlFor="prototype-key-confirm" className="font-normal">
              I have put the key where the server that will use this certificate can read it, or somewhere safe.
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
          {csrOpen && <Textarea readOnly className="font-mono text-xs field-sizing-fixed" rows={6} value={g.csrPem} aria-label="CSR" />}
        </div>
      )}
    </div>
  );
}

const MODES: { mode: KeyMode; title: string; description: string; icon: typeof KeyRoundIcon; recommended?: boolean }[] = [
  { mode: "generate", title: "Generate here", description: "In this browser. The key never reaches the platform.", icon: KeyRoundIcon, recommended: true },
  { mode: "paste", title: "Paste a CSR", description: "Made with your own tools.", icon: ClipboardPasteIcon },
  { mode: "command", title: "Run a command", description: "openssl on your server; the key never touches a browser.", icon: TerminalIcon },
];

/**
 * Where the CSR comes from, for names and a key algorithm the form fixes. `saveInline` puts the save-your-key panel
 * under the Generate button; otherwise the form shows it as a step of its own.
 */
export function KeySource({
  names,
  keyAlgorithm,
  state,
  onChange,
  saveInline = true,
  idPrefix,
}: {
  names: string[];
  keyAlgorithm: KeyAlgorithm;
  state: KeyState;
  onChange: (s: KeyState) => void;
  saveInline?: boolean;
  idPrefix: string;
}) {
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const stale = state.generated !== null && state.generated.madeFor !== madeFor(names, keyAlgorithm);
  const command = opensslCommand(normalizedNames(names), keyAlgorithm);

  async function generate() {
    setWorking(true);
    setError(null);
    try {
      onChange({ ...state, generated: await makeKey(names, keyAlgorithm), keySaved: false, confirmed: false });
    } catch (err) {
      setError(err instanceof Error ? err.message : "The browser could not make a key.");
    } finally {
      setWorking(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <RadioGroup value={state.mode} onValueChange={(m) => onChange({ ...state, mode: m as KeyMode })} className="grid gap-2 sm:grid-cols-3">
        {MODES.map(({ mode, title, description, icon: Icon, recommended }) => (
          <FieldLabel key={mode} htmlFor={`${idPrefix}-mode-${mode}`}>
            <Field orientation="horizontal">
              <FieldContent>
                <FieldTitle>
                  <Icon className="size-4" />
                  {title}
                </FieldTitle>
                <FieldDescription>
                  {recommended && <strong className="font-medium text-primary">Recommended. </strong>}
                  {description}
                </FieldDescription>
              </FieldContent>
              <RadioGroupItem value={mode} id={`${idPrefix}-mode-${mode}`} />
            </Field>
          </FieldLabel>
        ))}
      </RadioGroup>

      {state.mode === "generate" && (
        <div className="flex flex-col gap-3">
          {stale && (
            <p className="flex items-start gap-2 rounded-md border border-amber-500/60 bg-amber-500/5 p-3 text-sm">
              <CircleAlertIcon className="mt-0.5 size-4 shrink-0 text-amber-600" />
              The names or key algorithm changed since this key was made, so its CSR no longer fits. Generate a new one.
            </p>
          )}
          {(!state.generated || stale) && (
            <div className="flex flex-col gap-2">
              <p className="text-sm text-muted-foreground">
                A {KEY_ALGORITHM_LABELS[keyAlgorithm]} key and a CSR for {names.length === 1 ? names[0] : `these ${names.length} names`}.
              </p>
              <div>
                <Button type="button" disabled={working || names.length === 0} onClick={generate}>
                  {working ? <LoaderIcon className="animate-spin" /> : <KeyRoundIcon />}
                  {working ? "Generating…" : "Generate key and CSR"}
                </Button>
              </div>
            </div>
          )}
          {state.generated && !stale && saveInline && <SaveKey state={state} onChange={onChange} confirm={false} />}
          {state.generated && !stale && !saveInline && (
            <p className="flex items-center gap-2 text-sm text-emerald-700 dark:text-emerald-400">
              <CheckIcon className="size-4" /> Key and CSR made. You will save the key in the next step.
            </p>
          )}
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
      )}

      {state.mode === "command" && (
        <div className="flex flex-col gap-2">
          <p className="text-sm text-muted-foreground">Run this where the key is to live. It writes the key and the CSR next to each other.</p>
          <div className="relative">
            <pre className="overflow-x-auto rounded-md bg-muted p-3 pr-12 font-mono text-xs">{command}</pre>
            <Button type="button" variant="ghost" size="icon" className="absolute top-1 right-1 size-7" aria-label="Copy the command" onClick={() => navigator.clipboard.writeText(command)}>
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
          <CsrCheck pem={state.pasted} names={names} keyAlgorithm={keyAlgorithm} />
        </Field>
      )}
    </div>
  );
}
