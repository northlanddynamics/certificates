import { ChevronDownIcon, CopyIcon, DownloadIcon, KeyRoundIcon, LoaderIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { KeyAlgorithmChoice, SaveKey, downloadPem, emptyKeySource, type KeySourceState } from "@/components/csr-key-source";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
  isClassical,
  isRsa,
  type KeyAlgorithm,
  type SignatureHash,
  type SubjectDetails,
} from "@/lib/csr-generator";
import { opensslCommand, safeFileBase } from "@/lib/csr-inspect";
import { nameProblems, normalizedNames, splitNames } from "@/lib/csr-names";

const NO_COMMON_NAME = "__none__";

type Subject = Required<SubjectDetails>;
const SUBJECT_FIELDS: [keyof Subject, string, string][] = [
  ["organization", "O", "Organization"],
  ["organizationalUnit", "OU", "Organizational Unit"],
  ["country", "C", "Country"],
  ["state", "ST", "State or province"],
  ["locality", "L", "Locality"],
];

/**
 * A key and a CSR made in the browser, for anyone who keeps their own key: what to ask for on the left, and on the
 * right what the CSR will hold, as it is typed, and then the key and the CSR. Nothing here talks to the platform.
 */
export function CsrToolsPage() {
  const [typedNames, setTypedNames] = useState("");
  const [keyAlgorithm, setKeyAlgorithm] = useState<KeyAlgorithm>(DEFAULT_KEY_ALGORITHM);
  const [hashChoice, setHashChoice] = useState<SignatureHash | null>(null);
  // Every hash is valid for every classical key algorithm, so a choice outlives a change of key; until one is made the key's default applies.
  // ML-DSA signs with no hash, so it has none to choose.
  const classical = isClassical(keyAlgorithm);
  const hash = classical ? (hashChoice ?? defaultHash(keyAlgorithm)) : null;
  const [commonNameChoice, setCommonNameChoice] = useState<string | null>(null);
  const [subject, setSubject] = useState<Subject>({ organization: "", organizationalUnit: "", country: "", state: "", locality: "" });
  const [keySource, setKeySource] = useState<KeySourceState>(emptyKeySource());
  // What the shown key and CSR were made from, so that changing anything since says they no longer match it.
  const [madeFrom, setMadeFrom] = useState<string | null>(null);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const names = splitNames(typedNames);
  const problems = nameProblems(names);
  // Nothing is said about names not yet typed.
  const shownProblems = names.length === 0 ? [] : problems;
  const distinct = problems.length === 0 ? normalizedNames(names) : [];
  // The CN is one of the names that fit in a CN, or none; it is the first name until the user says otherwise.
  const commonNames = distinct.filter((n) => n.length <= MAX_COMMON_NAME_LENGTH);
  const firstName = commonNames[0] === distinct[0] ? commonNames[0] : undefined;
  const chosen = commonNameChoice && commonNames.includes(commonNameChoice) ? commonNameChoice : undefined;
  const commonName = commonNameChoice === NO_COMMON_NAME ? null : (chosen ?? firstName ?? null);
  const countryProblem = subject.country !== "" && !/^[A-Za-z]{2}$/.test(subject.country.trim()) ? "Country is exactly two letters, such as US." : null;
  const note = classical && hash ? hashNote(keyAlgorithm, hash) : null;
  const inputs = JSON.stringify([distinct, keyAlgorithm, hash, commonName, subject]);
  const generated = keySource.generated;
  const stale = generated !== null && madeFrom !== inputs;

  const subjectLine = [
    ...SUBJECT_FIELDS.filter(([field]) => subject[field].trim() !== "").map(([field, short]) => `${short}=${field === "country" ? subject[field].trim().toUpperCase() : subject[field].trim()}`),
    ...(commonName ? [`CN=${commonName}`] : []),
  ].join(", ");

  async function generate(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setWorking(true);
    try {
      const made = await generateCsr({ keyAlgorithm, hash: hash ?? undefined, names: distinct, commonName, subject: { ...subject, country: subject.country.trim().toUpperCase() } });
      setKeySource({ ...emptyKeySource(), generated: { ...made, fileBase: safeFileBase(distinct[0]), madeFor: inputs } });
      setMadeFrom(inputs);
    } catch (err) {
      setError(err instanceof Error ? err.message : "The browser could not make a key.");
    } finally {
      setWorking(false);
    }
  }

  const setSubjectField = (field: keyof Subject) => (e: { target: { value: string } }) => setSubject({ ...subject, [field]: e.target.value });

  return (
    <form className="flex flex-col gap-6" onSubmit={generate}>
      <div>
        <h1 className="text-xl font-semibold">CSR Generator</h1>
        <p className="text-sm text-muted-foreground">
          A key and a CSR made in your browser. The key is never sent to the platform, which cannot recover it for you: keep it, and give the CSR to whoever signs it.
        </p>
      </div>
      <div className="grid items-start gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>What to ask for</CardTitle>
          </CardHeader>
          <CardContent>
            <FieldGroup>
              <Field data-invalid={shownProblems.length > 0}>
                <FieldLabel htmlFor="csr-names">Names</FieldLabel>
                <Textarea id="csr-names" rows={4} value={typedNames} onChange={(e) => setTypedNames(e.target.value)} aria-invalid={shownProblems.length > 0} />
                <FieldDescription>One per line; wildcards as *.example.com.</FieldDescription>
                {shownProblems.map((p) => (
                  <FieldError key={p}>{p}</FieldError>
                ))}
              </Field>
              <KeyAlgorithmChoice value={keyAlgorithm} options={KEY_ALGORITHMS} onChange={setKeyAlgorithm} idPrefix="csr-key-algorithm" />
              <Field>
                <FieldLabel htmlFor="csr-common-name">Common name (CN)</FieldLabel>
                <Select value={commonName ?? NO_COMMON_NAME} onValueChange={setCommonNameChoice} disabled={commonNames.length === 0}>
                  <SelectTrigger id="csr-common-name" className="w-full sm:w-80">
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
                      {SUBJECT_FIELDS.map(([field, short, label]) => (
                        <Field key={field} data-invalid={field === "country" && !!countryProblem}>
                          <FieldLabel htmlFor={`csr-${short.toLowerCase()}`}>
                            {label} ({short})
                          </FieldLabel>
                          <Input
                            id={`csr-${short.toLowerCase()}`}
                            maxLength={field === "country" ? 2 : undefined}
                            className={field === "country" ? "uppercase" : undefined}
                            value={subject[field]}
                            onChange={setSubjectField(field)}
                            aria-invalid={field === "country" && !!countryProblem}
                          />
                          {field === "country" && countryProblem && <FieldError>{countryProblem}</FieldError>}
                        </Field>
                      ))}
                    </div>
                  </FieldGroup>
                </CollapsibleContent>
              </Collapsible>

              {/* ML-DSA signs with no hash, so there is no signature choice to show. */}
              {classical && hash && (
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
                      {note && <FieldDescription role="note">{note} You can still use it.</FieldDescription>}
                    </Field>
                  </CollapsibleContent>
                </Collapsible>
              )}
            </FieldGroup>
          </CardContent>
        </Card>

        <div className="flex flex-col gap-6 lg:sticky lg:top-4">
          <Card>
            <CardHeader>
              <CardTitle>The CSR will hold</CardTitle>
              <CardDescription>As you type.</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4 text-sm">
              <dl className="grid grid-cols-[7rem_1fr] gap-x-4 gap-y-2">
                <dt className="text-muted-foreground">Subject</dt>
                <dd className="font-mono text-xs break-all">{subjectLine || <span className="font-sans text-muted-foreground">Empty</span>}</dd>
                <dt className="text-muted-foreground">Names</dt>
                <dd>
                  {distinct.length > 0 ? (
                    <ul className="font-mono text-xs">
                      {distinct.map((n) => (
                        <li key={n}>{n}</li>
                      ))}
                    </ul>
                  ) : (
                    <span className="text-muted-foreground">None yet</span>
                  )}
                </dd>
                <dt className="text-muted-foreground">Key</dt>
                <dd>{KEY_ALGORITHM_LABELS[keyAlgorithm]}{hash && `, signed with ${hash}`}</dd>
              </dl>
              {distinct.length > 0 && (
                <Collapsible className="group/openssl">
                  <CollapsibleTrigger asChild>
                    <Button type="button" variant="ghost" size="sm" className="-ml-2">
                      <ChevronDownIcon className="transition-transform group-data-[state=closed]/openssl:-rotate-90" />
                      Or make the key where it is to live, with openssl
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="pt-2">
                    <pre className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs">{opensslCommand(distinct, keyAlgorithm)}</pre>
                  </CollapsibleContent>
                </Collapsible>
              )}
              {error && <FieldError>{error}</FieldError>}
              <div>
                <Button type="submit" disabled={working || problems.length > 0 || !!countryProblem}>
                  {working ? <LoaderIcon className="animate-spin" /> : <KeyRoundIcon />}
                  {working ? "Generating…" : generated ? "Generate a new key and CSR" : "Generate key and CSR"}
                </Button>
              </div>
            </CardContent>
          </Card>

          {generated && (
            <Card aria-live="polite">
              <CardContent className="flex flex-col gap-5">
                {stale && <p className="text-sm text-amber-700 dark:text-amber-400">You have changed what to ask for since these were made; generate again for a CSR that holds it.</p>}
                <section className="flex flex-col gap-2" aria-label="Private key">
                  <h2 className="text-sm font-medium">1. Private key (PKCS#8 PEM)</h2>
                  <SaveKey state={keySource} onChange={setKeySource} showCsr={false} />
                </section>
                <section className="flex flex-col gap-2" aria-label="CSR">
                  <h2 className="text-sm font-medium">2. CSR (PEM), for whoever signs it</h2>
                  <Textarea readOnly className="font-mono text-xs field-sizing-fixed" rows={6} value={generated.csrPem} aria-label="CSR" />
                  <div className="flex flex-wrap gap-2">
                    <Button type="button" variant="outline" size="sm" onClick={() => downloadPem(`${generated.fileBase}.csr.pem`, generated.csrPem)}>
                      <DownloadIcon />
                      Download CSR
                    </Button>
                    <Button type="button" variant="outline" size="sm" onClick={() => navigator.clipboard.writeText(generated.csrPem)}>
                      <CopyIcon />
                      Copy CSR
                    </Button>
                  </div>
                </section>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </form>
  );
}
