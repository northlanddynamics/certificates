// PROTOTYPE (branch prototype/csr-ux): throwaway. Two alternatives to the CSR Generator page, switched with
// `?variant=` (A is today's page).
//   B  Two columns: the inputs, and a live preview of what the CSR will hold (and the openssl that would make the same)
//   C  Purpose first (public TLS, another CA, a Private CA), then only the fields that purpose needs, then a hand-off
import { useNavigate } from "@tanstack/react-router";
import { ArrowLeftIcon, BuildingIcon, CopyIcon, DownloadIcon, GlobeIcon, KeyRoundIcon, LandmarkIcon, LoaderIcon, PlusIcon } from "lucide-react";
import { useState, type ReactNode } from "react";
import { KeyAlgorithmCards, SaveKey, emptyKey, madeFor, type KeyState } from "@/components/csr-key-source.prototype";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet, FieldTitle } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Textarea } from "@/components/ui/textarea";
import { DEFAULT_KEY_ALGORITHM, KEY_ALGORITHM_LABELS, MAX_COMMON_NAME_LENGTH, generateCsr, type KeyAlgorithm, type SubjectDetails } from "@/lib/csr-generator";
import { fileBase, opensslCommand } from "@/lib/csr-inspect.prototype";
import { nameProblems, normalizedNames, splitNames } from "@/lib/csr-names";
import { cn } from "@/lib/utils";

export const TOOLS_VARIANTS = [
  { key: "A", name: "Today" },
  { key: "B", name: "Two columns, live preview" },
  { key: "C", name: "Purpose first, then hand-off" },
];

type Subject = Required<SubjectDetails>;
const NO_SUBJECT: Subject = { organization: "", organizationalUnit: "", country: "", state: "", locality: "" };
const SUBJECT_FIELDS: [keyof Subject, string, string][] = [
  ["organization", "O", "Organization"],
  ["organizationalUnit", "OU", "Organizational Unit"],
  ["country", "C", "Country"],
  ["locality", "L", "Locality"],
  ["state", "ST", "State or province"],
];

function useGenerator() {
  const [names, setNames] = useState("");
  const [keyAlgorithm, setKeyAlgorithm] = useState<KeyAlgorithm>(DEFAULT_KEY_ALGORITHM);
  const [subject, setSubject] = useState<Subject>(NO_SUBJECT);
  const [key, setKey] = useState<KeyState>(emptyKey());
  const [working, setWorking] = useState(false);
  const parsed = splitNames(names);
  const problems = parsed.length === 0 ? [] : nameProblems(parsed);
  const distinct = parsed.length > 0 && problems.length === 0 ? normalizedNames(parsed) : [];
  const commonName = distinct.find((n) => n.length <= MAX_COMMON_NAME_LENGTH) ?? null;
  const fits = key.generated?.madeFor === madeFor(parsed, keyAlgorithm) + JSON.stringify(subject);
  async function generate() {
    setWorking(true);
    try {
      const made = await generateCsr({ keyAlgorithm, names: distinct, commonName, subject: { ...subject, country: subject.country.toUpperCase() } });
      setKey({ ...emptyKey(), generated: { ...made, fileBase: fileBase(distinct[0]), madeFor: madeFor(parsed, keyAlgorithm) + JSON.stringify(subject) } });
    } finally {
      setWorking(false);
    }
  }
  return { names, setNames, parsed, problems, distinct, commonName, keyAlgorithm, setKeyAlgorithm, subject, setSubject, key, setKey, working, generate, fits };
}
type Gen = ReturnType<typeof useGenerator>;

function download(filename: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/x-pem-file" }));
  Object.assign(document.createElement("a"), { href: url, download: filename }).click();
  URL.revokeObjectURL(url);
}

function NamesField({ g, rows = 4 }: { g: Gen; rows?: number }) {
  return (
    <Field data-invalid={g.problems.length > 0}>
      <FieldLabel htmlFor="proto-tools-names">Names</FieldLabel>
      <Textarea id="proto-tools-names" rows={rows} value={g.names} onChange={(e) => g.setNames(e.target.value)} placeholder={"www.example.com\nexample.com"} />
      <FieldDescription>One per line; wildcards as *.example.com.</FieldDescription>
      {g.problems.map((p) => (
        <FieldError key={p}>{p}</FieldError>
      ))}
    </Field>
  );
}

function SubjectFields({ g }: { g: Gen }) {
  return (
    <div className="grid gap-4 sm:grid-cols-2">
      {SUBJECT_FIELDS.map(([field, short, label]) => (
        <Field key={field}>
          <FieldLabel htmlFor={`proto-tools-${field}`}>
            {label} ({short})
          </FieldLabel>
          <Input
            id={`proto-tools-${field}`}
            maxLength={field === "country" ? 2 : undefined}
            className={field === "country" ? "uppercase" : undefined}
            value={g.subject[field]}
            onChange={(e) => g.setSubject({ ...g.subject, [field]: e.target.value })}
          />
        </Field>
      ))}
    </div>
  );
}

/** The key and the CSR, once made: the key's checkpoint, then the CSR to download or copy. */
function Result({ g, after }: { g: Gen; after?: ReactNode }) {
  const csr = g.key.generated?.csrPem;
  if (!csr || !g.fits) return null;
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <span className="text-sm font-medium">1. Private key</span>
        <SaveKey state={g.key} onChange={g.setKey} confirm={false} showCsr={false} />
      </div>
      <div className="flex flex-col gap-2">
        <span className="text-sm font-medium">2. CSR — give this to whoever signs it</span>
        <Textarea readOnly className="font-mono text-xs field-sizing-fixed" rows={5} value={csr} aria-label="CSR" />
        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="outline" size="sm" onClick={() => download(`${g.key.generated!.fileBase}.csr.pem`, csr)}>
            <DownloadIcon />
            Download CSR
          </Button>
          <Button type="button" variant="outline" size="sm" onClick={() => navigator.clipboard.writeText(csr)}>
            <CopyIcon />
            Copy CSR
          </Button>
        </div>
      </div>
      {after}
    </div>
  );
}

// --- B: two columns, live preview -----------------------------------------------------------------------------------

export function ToolsVariantB() {
  const g = useGenerator();
  const [showSubject, setShowSubject] = useState(false);
  const subjectLine = [
    ...SUBJECT_FIELDS.filter(([f]) => g.subject[f].trim()).map(([f, short]) => `${short}=${f === "country" ? g.subject[f].toUpperCase() : g.subject[f]}`),
    ...(g.commonName ? [`CN=${g.commonName}`] : []),
  ].join(", ");
  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">CSR Generator</h1>
        <p className="text-sm text-muted-foreground">A key and a CSR made in your browser. The key is never sent to the platform.</p>
      </div>
      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <Card>
          <CardHeader>
            <CardTitle>What to ask for</CardTitle>
          </CardHeader>
          <CardContent>
            <FieldGroup>
              <NamesField g={g} />
              <FieldSet>
                <FieldLegend variant="label">Key type</FieldLegend>
                <KeyAlgorithmCards value={g.keyAlgorithm} onChange={g.setKeyAlgorithm} idPrefix="proto-tools-b-alg" />
              </FieldSet>
              <div>
                <Button type="button" variant="link" className="h-auto p-0" onClick={() => setShowSubject(!showSubject)}>
                  {showSubject ? "Hide subject details" : "Add subject details (only for a CA other than Let's Encrypt)"}
                </Button>
              </div>
              {showSubject && <SubjectFields g={g} />}
            </FieldGroup>
          </CardContent>
        </Card>
        <div className="flex flex-col gap-4 lg:sticky lg:top-4">
          <Card>
            <CardHeader>
              <CardTitle>The CSR will hold</CardTitle>
              <CardDescription>Updated as you type.</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4 text-sm">
              <dl className="grid grid-cols-[6rem_1fr] gap-x-4 gap-y-2">
                <dt className="text-muted-foreground">Subject</dt>
                <dd className="font-mono text-xs break-all">{subjectLine || <span className="font-sans text-muted-foreground">—</span>}</dd>
                <dt className="text-muted-foreground">Names (SAN)</dt>
                <dd>
                  {g.distinct.length > 0 ? (
                    <ul className="font-mono text-xs">
                      {g.distinct.map((n) => (
                        <li key={n}>{n}</li>
                      ))}
                    </ul>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </dd>
                <dt className="text-muted-foreground">Key</dt>
                <dd>{KEY_ALGORITHM_LABELS[g.keyAlgorithm]}</dd>
              </dl>
              {g.distinct.length > 0 && (
                <details className="text-xs">
                  <summary className="cursor-pointer text-muted-foreground">The same with openssl, on your own machine</summary>
                  <pre className="mt-2 overflow-x-auto rounded-md bg-muted p-3 font-mono">{opensslCommand(g.distinct, g.keyAlgorithm)}</pre>
                </details>
              )}
              <div>
                <Button type="button" disabled={g.distinct.length === 0 || g.working} onClick={g.generate}>
                  {g.working ? <LoaderIcon className="animate-spin" /> : <KeyRoundIcon />}
                  {g.fits ? "Generate a new key and CSR" : "Generate key and CSR"}
                </Button>
              </div>
            </CardContent>
          </Card>
          {g.fits && (
            <Card>
              <CardContent>
                <Result g={g} />
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

// --- C: purpose first, then a hand-off ------------------------------------------------------------------------------

type Purpose = "public" | "other-ca" | "private-ca";
const PURPOSES: { value: Purpose; title: string; description: string; icon: typeof GlobeIcon }[] = [
  { value: "public", title: "A public website or API", description: "Let's Encrypt through this platform. Names only; nothing else in the CSR matters.", icon: GlobeIcon },
  { value: "private-ca", title: "An internal service", description: "One of this Organization's Private CAs. Names only.", icon: LandmarkIcon },
  { value: "other-ca", title: "Another CA", description: "DigiCert, Sectigo, a partner's CA… Adds the subject fields they may ask for.", icon: BuildingIcon },
];

export function ToolsVariantC({ orgId }: { orgId: string }) {
  const g = useGenerator();
  const navigate = useNavigate();
  const [purpose, setPurpose] = useState<Purpose | null>(null);
  const [handedOff, setHandedOff] = useState(false);

  if (!purpose)
    return (
      <div className="flex max-w-3xl flex-col gap-6">
        <div>
          <h1 className="text-xl font-semibold">CSR Generator</h1>
          <p className="text-sm text-muted-foreground">A key and a CSR made in your browser. The key is never sent to the platform.</p>
        </div>
        <FieldSet>
          <FieldLegend>What is the certificate for?</FieldLegend>
          <RadioGroup className="grid gap-3 sm:grid-cols-3" value="" onValueChange={(v) => setPurpose(v as Purpose)}>
            {PURPOSES.map(({ value, title, description, icon: Icon }) => (
              <FieldLabel key={value} htmlFor={`proto-purpose-${value}`}>
                <Field orientation="horizontal" className="h-full items-start">
                  <FieldContent>
                    <Icon className="mb-2 size-6 text-muted-foreground" />
                    <FieldTitle>{title}</FieldTitle>
                    <FieldDescription>{description}</FieldDescription>
                  </FieldContent>
                  <RadioGroupItem value={value} id={`proto-purpose-${value}`} className="sr-only" />
                </Field>
              </FieldLabel>
            ))}
          </RadioGroup>
        </FieldSet>
      </div>
    );

  const chosen = PURPOSES.find((p) => p.value === purpose)!;
  const managed = purpose !== "other-ca";
  return (
    <div className="flex max-w-2xl flex-col gap-6">
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="icon" aria-label="Back" onClick={() => setPurpose(null)}>
          <ArrowLeftIcon />
        </Button>
        <div>
          <h1 className="text-xl font-semibold">{chosen.title}</h1>
          <p className="text-sm text-muted-foreground">{chosen.description}</p>
        </div>
      </div>
      <Card>
        <CardContent className="flex flex-col gap-6">
          <FieldGroup>
            <NamesField g={g} rows={3} />
            <FieldSet>
              <FieldLegend variant="label">Key type</FieldLegend>
              <KeyAlgorithmCards value={g.keyAlgorithm} onChange={g.setKeyAlgorithm} idPrefix="proto-tools-c-alg" compact />
            </FieldSet>
            {purpose === "other-ca" && (
              <FieldSet>
                <FieldLegend variant="label">Subject details</FieldLegend>
                <FieldDescription>Only what the CA asks for; leave the rest empty.</FieldDescription>
                <SubjectFields g={g} />
              </FieldSet>
            )}
            <div>
              <Button type="button" disabled={g.distinct.length === 0 || g.working} onClick={g.generate}>
                {g.working ? <LoaderIcon className="animate-spin" /> : <KeyRoundIcon />}
                {g.fits ? "Generate a new key and CSR" : "Generate key and CSR"}
              </Button>
            </div>
          </FieldGroup>
          <Result
            g={g}
            after={
              managed && (
                <div className={cn("flex flex-col gap-2 rounded-md border border-dashed p-4", !g.key.keySaved && "opacity-60")}>
                  <span className="text-sm font-medium">3. Have the platform issue and renew it</span>
                  <span className="text-sm text-muted-foreground">Opens New Managed Certificate with these names, this key type and this CSR filled in.</span>
                  <div>
                    <Button type="button" disabled={!g.key.keySaved} onClick={() => setHandedOff(true)}>
                      <PlusIcon />
                      Create a Managed Certificate with this CSR
                    </Button>
                  </div>
                  {!g.key.keySaved && <span className="text-xs text-muted-foreground">Save the key first.</span>}
                  {handedOff && (
                    <span className="text-sm">
                      PROTOTYPE: would open the dialog prefilled.{" "}
                      <Button variant="link" className="h-auto p-0" onClick={() => navigate({ to: "/organizations/$orgId/certificates", params: { orgId } })}>
                        Go to Certificates
                      </Button>
                    </span>
                  )}
                </div>
              )
            }
          />
        </CardContent>
      </Card>
    </div>
  );
}
