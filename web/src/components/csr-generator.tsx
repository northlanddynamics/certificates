import { ChevronDownIcon, CopyIcon, DownloadIcon, EyeIcon, EyeOffIcon } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import {
  DEFAULT_KEY_ALGORITHM,
  KEY_ALGORITHMS,
  KEY_ALGORITHM_LABELS,
  MAX_COMMON_NAME_LENGTH,
  SIGNATURE_HASHES,
  defaultHash,
  generateCsr,
  hashNote,
  isRsa,
  type GeneratedCsr,
  type KeyAlgorithm,
  type SignatureHash,
} from "@/lib/csr-generator";
import { nameProblems, normalizedNames, splitNames } from "@/lib/csr-names";

const NO_COMMON_NAME = "__none__";

export interface CsrGeneratorProps {
  /** The names to ask for. Typed in by the user unless `locked`. */
  names?: string[];
  /** The key algorithm. Chosen by the user unless `locked`. */
  keyAlgorithm?: KeyAlgorithm;
  /** Whether a form that has its own names and key algorithm fixes them here, so the CSR cannot be refused for not matching. */
  locked?: boolean;
}

/** A file name for a name, safe for a wildcard: `*.example.com` is `wildcard.example.com`. */
export const safeFileBase = (name: string | undefined) => (name ?? "csr").replace(/^\*\./, "wildcard.").replace(/[^a-z0-9.-]/gi, "_");

function download(filename: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/x-pem-file" }));
  const link = Object.assign(document.createElement("a"), { href: url, download: filename });
  link.click();
  URL.revokeObjectURL(url);
}

/**
 * Makes a key and a CSR in the browser; the key is never sent anywhere, and only the CSR is ever submitted. It stands
 * alone on the Tools page, and a form that takes a CSR can embed it with its own names and key algorithm locked.
 */
export function CsrGenerator({ names: givenNames, keyAlgorithm: givenKeyAlgorithm, locked = false }: CsrGeneratorProps) {
  const [typedNames, setTypedNames] = useState((givenNames ?? []).join("\n"));
  const names = locked ? (givenNames ?? []) : splitNames(typedNames);
  const [chosenKeyAlgorithm, setChosenKeyAlgorithm] = useState<KeyAlgorithm>(givenKeyAlgorithm ?? DEFAULT_KEY_ALGORITHM);
  const keyAlgorithm = locked && givenKeyAlgorithm ? givenKeyAlgorithm : chosenKeyAlgorithm;
  const [hashChoice, setHashChoice] = useState<SignatureHash | null>(null);
  // Every hash is valid for every key algorithm, so a choice outlives a change of key; until one is made the key's default applies.
  const hash = hashChoice ?? defaultHash(keyAlgorithm);
  const [commonNameChoice, setCommonNameChoice] = useState<string | null>(null);
  const [subject, setSubject] = useState({ organization: "", organizationalUnit: "", country: "", state: "", locality: "" });
  const [result, setResult] = useState<(GeneratedCsr & { fileBase: string }) | null>(null);
  const [keySaved, setKeySaved] = useState(false);
  const [showKey, setShowKey] = useState(false);
  const [copied, setCopied] = useState<"key" | "csr" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [working, setWorking] = useState(false);

  const problems = nameProblems(names);
  const shownProblems = !locked && typedNames.trim() === "" ? [] : problems;
  const distinct = problems.length === 0 ? normalizedNames(names) : [];
  // The CN is one of the names that fit in a CN, or none; it is the first name until the user says otherwise.
  const commonNames = distinct.filter((n) => n.length <= MAX_COMMON_NAME_LENGTH);
  const firstName = commonNames[0] === distinct[0] ? commonNames[0] : undefined;
  const chosen = commonNameChoice && commonNames.includes(commonNameChoice) ? commonNameChoice : undefined;
  const commonName = commonNameChoice === NO_COMMON_NAME ? null : (chosen ?? firstName ?? null);
  const countryProblem = subject.country !== "" && !/^[A-Za-z]{2}$/.test(subject.country.trim()) ? "Country is exactly two letters, such as US." : null;
  const note = hashNote(keyAlgorithm, hash);

  // A key that has not been downloaded or copied exists nowhere else.
  useEffect(() => {
    if (!result || keySaved) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [result, keySaved]);

  async function generate(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setWorking(true);
    try {
      const made = await generateCsr({
        keyAlgorithm,
        hash,
        names: distinct,
        commonName,
        subject: { ...subject, country: subject.country.trim().toUpperCase() },
      });
      setResult({ ...made, fileBase: safeFileBase(distinct[0]) });
      setKeySaved(false);
      setShowKey(false);
      setCopied(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "The browser could not make a key.");
    } finally {
      setWorking(false);
    }
  }

  async function copy(what: "key" | "csr", text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(what);
      if (what === "key") setKeySaved(true);
    } catch {
      setError("The browser would not let this page copy; download it instead.");
    }
  }

  const setSubjectField = (field: keyof typeof subject) => (e: { target: { value: string } }) => setSubject({ ...subject, [field]: e.target.value });

  return (
    <div className="flex flex-col gap-6">
      <form onSubmit={generate}>
        <FieldGroup>
          <Field data-invalid={shownProblems.length > 0}>
            <FieldLabel htmlFor="csr-names">Names</FieldLabel>
            {locked ? (
              <ul id="csr-names" className="font-mono text-sm">
                {names.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            ) : (
              <Textarea id="csr-names" value={typedNames} onChange={(e) => setTypedNames(e.target.value)} aria-invalid={shownProblems.length > 0} rows={4} />
            )}
            <FieldDescription>{locked ? "Fixed by the Managed Certificate." : "One per line; wildcards as *.example.com."}</FieldDescription>
            {shownProblems.map((p) => (
              <FieldError key={p}>{p}</FieldError>
            ))}
          </Field>
          <div className="grid gap-5 sm:grid-cols-2">
            <Field>
              <FieldLabel htmlFor="csr-key-algorithm">Key algorithm</FieldLabel>
              <Select value={keyAlgorithm} onValueChange={(v) => setChosenKeyAlgorithm(v as KeyAlgorithm)} disabled={locked && !!givenKeyAlgorithm}>
                <SelectTrigger id="csr-key-algorithm" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {KEY_ALGORITHMS.map((value) => (
                    <SelectItem key={value} value={value}>
                      {KEY_ALGORITHM_LABELS[value]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            <Field>
              <FieldLabel htmlFor="csr-common-name">Common name (CN)</FieldLabel>
              <Select value={commonName ?? NO_COMMON_NAME} onValueChange={setCommonNameChoice} disabled={commonNames.length === 0}>
                <SelectTrigger id="csr-common-name" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {commonNames.map((n) => (
                    <SelectItem key={n} value={n}>
                      {n}
                    </SelectItem>
                  ))}
                  <SelectItem value={NO_COMMON_NAME}>None</SelectItem>
                </SelectContent>
              </Select>
            </Field>
          </div>

          <Collapsible className="group/subject">
            <CollapsibleTrigger asChild>
              <Button type="button" variant="ghost" size="sm" className="-ml-2">
                <ChevronDownIcon className="transition-transform group-data-[state=closed]/subject:-rotate-90" />
                Subject details (optional)
              </Button>
            </CollapsibleTrigger>
            <CollapsibleContent className="pt-3">
              <FieldGroup>
                <FieldDescription>For a CSR you take to another CA. Let's Encrypt ignores all of them. Empty ones are left out.</FieldDescription>
                <div className="grid gap-5 sm:grid-cols-2">
                  <Field>
                    <FieldLabel htmlFor="csr-o">Organization (O)</FieldLabel>
                    <Input id="csr-o" value={subject.organization} onChange={setSubjectField("organization")} />
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="csr-ou">Organizational Unit (OU)</FieldLabel>
                    <Input id="csr-ou" value={subject.organizationalUnit} onChange={setSubjectField("organizationalUnit")} />
                  </Field>
                  <Field data-invalid={!!countryProblem}>
                    <FieldLabel htmlFor="csr-c">Country (C)</FieldLabel>
                    <Input id="csr-c" maxLength={2} className="uppercase" value={subject.country} onChange={setSubjectField("country")} aria-invalid={!!countryProblem} />
                    {countryProblem && <FieldError>{countryProblem}</FieldError>}
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="csr-st">State or province (ST)</FieldLabel>
                    <Input id="csr-st" value={subject.state} onChange={setSubjectField("state")} />
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="csr-l">Locality (L)</FieldLabel>
                    <Input id="csr-l" value={subject.locality} onChange={setSubjectField("locality")} />
                  </Field>
                </div>
              </FieldGroup>
            </CollapsibleContent>
          </Collapsible>

          <Collapsible className="group/advanced">
            <CollapsibleTrigger asChild>
              <Button type="button" variant="ghost" size="sm" className="-ml-2">
                <ChevronDownIcon className="transition-transform group-data-[state=closed]/advanced:-rotate-90" />
                Advanced
              </Button>
            </CollapsibleTrigger>
            <CollapsibleContent className="pt-3">
              <Field>
                <FieldLabel htmlFor="csr-hash">Signature algorithm</FieldLabel>
                <Select value={hash} onValueChange={(v) => setHashChoice(v as SignatureHash)}>
                  <SelectTrigger id="csr-hash" className="w-full sm:w-80">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SIGNATURE_HASHES.map((h) => (
                      <SelectItem key={h} value={h}>
                        {isRsa(keyAlgorithm) ? `RSASSA-PKCS1-v1_5 with ${h}` : `ECDSA with ${h}`}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {note && (
                  <FieldDescription role="note">
                    {note} You can still use it.
                  </FieldDescription>
                )}
              </Field>
            </CollapsibleContent>
          </Collapsible>

          {error && <FieldError>{error}</FieldError>}
          {countryProblem && <FieldError>{countryProblem}</FieldError>}
          <div>
            <Button type="submit" disabled={working || problems.length > 0 || !!countryProblem}>
              {working ? "Generating…" : result ? "Generate a new key and CSR" : "Generate key and CSR"}
            </Button>
          </div>
        </FieldGroup>
      </form>

      {result && (
        <div className="flex flex-col gap-6" aria-live="polite">
          <section className="flex flex-col gap-2" aria-label="Private key">
            <h2 className="text-sm font-medium">Private key (PKCS#8 PEM)</h2>
            <p role="alert" className="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm">
              This key was made in your browser and is never sent to the platform. It cannot be recovered: download or copy it now, and keep it secret.
              {!keySaved && " You will be warned if you leave this page before you have."}
            </p>
            {showKey && <Textarea readOnly className="font-mono text-xs" rows={8} value={result.keyPem} aria-label="Private key" />}
            <div className="flex flex-wrap gap-2">
              <Button type="button" variant="outline" size="sm" onClick={() => setShowKey(!showKey)}>
                {showKey ? <EyeOffIcon /> : <EyeIcon />}
                {showKey ? "Hide" : "Show"}
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => {
                  download(`${result.fileBase}.key.pem`, result.keyPem);
                  setKeySaved(true);
                }}
              >
                <DownloadIcon />
                Download key
              </Button>
              <Button type="button" variant="outline" size="sm" onClick={() => copy("key", result.keyPem)}>
                <CopyIcon />
                {copied === "key" ? "Copied" : "Copy key"}
              </Button>
            </div>
          </section>

          <section className="flex flex-col gap-2" aria-label="CSR">
            <h2 className="text-sm font-medium">CSR (PEM)</h2>
            <Textarea readOnly className="font-mono text-xs" rows={8} value={result.csrPem} aria-label="CSR" />
            <div className="flex flex-wrap gap-2">
              <Button type="button" variant="outline" size="sm" onClick={() => download(`${result.fileBase}.csr.pem`, result.csrPem)}>
                <DownloadIcon />
                Download CSR
              </Button>
              <Button type="button" variant="outline" size="sm" onClick={() => copy("csr", result.csrPem)}>
                <CopyIcon />
                {copied === "csr" ? "Copied" : "Copy CSR"}
              </Button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
