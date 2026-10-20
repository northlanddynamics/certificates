import { FileSearchIcon, LoaderIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { CertificateDetailsView } from "@/components/certificate-details-view";
import { CsrDetailsView } from "@/components/csr-details-view";
import { PemDropField } from "@/components/pem-drop-field";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { parseCertificateDetails, type CertificateReading } from "@/lib/certificate-details";
import { parseCsrDetails, type CsrReading } from "@/lib/csr-details";
import { readPkiText, type PkiItem } from "@/lib/pki-input";

type Read = { kind: "csr"; reading: CsrReading } | { kind: "certificate"; reading: CertificateReading };

const readItem = async (item: PkiItem): Promise<Read> =>
  item.kind === "csr" ? { kind: "csr", reading: await parseCsrDetails(item.pem) } : { kind: "certificate", reading: await parseCertificateDetails(item.pem) };

type Reading = { status: "empty" } | { status: "reading" } | { status: "refused"; problem: string } | { status: "read"; reads: Read[] };

/** What the text holds, as it changes: every CSR and certificate in it, read once the text has any. A reading that arrives after the text has changed again is dropped. */
function useReading(text: string): Reading {
  const input = readPkiText(text);
  const items = input?.kind === "items" ? input.items : null;
  // The items' text, which is what makes a reading this one's.
  const key = items?.map((item) => item.pem).join("\n") ?? null;
  const [done, setDone] = useState<{ key: string; reads: Read[] } | null>(null);
  useEffect(() => {
    if (items === null || key === null) return;
    let current = true;
    void Promise.all(items.map(readItem)).then((reads) => current && setDone({ key, reads }));
    return () => {
      current = false;
    };
  }, [key]);
  if (input === null) return { status: "empty" };
  if (input.kind === "refused") return { status: "refused", problem: input.problem };
  return done?.key === key ? { status: "read", reads: done.reads } : { status: "reading" };
}

/** What names one item among several: its common name, or failing that its first name. */
function nameOf(read: Read): string | null {
  if (!read.reading.ok) return null;
  const { details } = read.reading;
  const common = details.subject.find((field) => field.type === "CN")?.value;
  return common ?? details.names[0]?.value ?? null;
}

function ReadView({ read }: { read: Read }) {
  if (!read.reading.ok)
    return (
      <Alert variant="destructive">
        <AlertDescription>{read.reading.error}</AlertDescription>
      </Alert>
    );
  return read.kind === "csr" ? <CsrDetailsView details={read.reading.details} /> : <CertificateDetailsView details={read.reading.details} />;
}

/**
 * Everything a CSR or a certificate says: one box takes either, as PEM or DER, pasted, dropped or chosen as a file, and
 * says which it is. A file with several, such as a certificate chain, is shown one at a time. A CSR is also checked
 * against what the platform would take. It is read in the browser and nothing here talks to the platform.
 */
export function ViewerPage() {
  const [text, setText] = useState("");
  const reading = useReading(text);
  // Which of several the user is looking at, for as long as the text holds the same ones.
  const [pick, setPick] = useState<{ count: number; index: number } | null>(null);
  const reads = reading.status === "read" ? reading.reads : [];
  const index = pick && pick.count === reads.length && pick.index < reads.length ? pick.index : 0;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">CSR and Certificate Viewer</h1>
        <p className="text-sm text-muted-foreground">
          Paste, drop or choose a CSR or a certificate; you need not say which. See what it holds, and for a CSR whether the platform would take it. It is read in your browser; nothing is sent.
        </p>
      </div>
      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <Card className="lg:sticky lg:top-4">
          <CardHeader>
            <CardTitle>CSR or certificate</CardTitle>
            <CardDescription>PEM, or a DER file. A chain is shown one certificate at a time.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <PemDropField id="viewer-text" value={text} onChange={setText} />
            {reading.status === "refused" && (
              <p role="alert" className="text-sm text-destructive">
                {reading.problem}
              </p>
            )}
          </CardContent>
        </Card>

        <div className="flex flex-col gap-4" aria-live="polite">
          {reads.length > 1 && (
            <Tabs value={String(index)} onValueChange={(value) => setPick({ count: reads.length, index: Number(value) })}>
              <div className="overflow-x-auto">
                <TabsList>
                  {reads.map((read, i) => (
                    <TabsTrigger key={i} value={String(i)} className="max-w-56">
                      <span className="truncate">
                        {i + 1}. {read.kind === "csr" ? "CSR" : "Certificate"}
                        {nameOf(read) && ` · ${nameOf(read)}`}
                      </span>
                    </TabsTrigger>
                  ))}
                </TabsList>
              </div>
            </Tabs>
          )}
          {reads[index] && <ReadView read={reads[index]} />}
          {reading.status === "reading" && (
            <p className="flex items-center gap-2 text-sm text-muted-foreground">
              <LoaderIcon className="size-4 animate-spin" />
              Reading…
            </p>
          )}
          {(reading.status === "empty" || reading.status === "refused") && (
            <Empty className="rounded-lg border border-dashed">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <FileSearchIcon />
                </EmptyMedia>
                <EmptyTitle>Nothing to read yet</EmptyTitle>
                <EmptyDescription>
                  A CSR shows its names, key and signature and whether the platform would take it. A certificate shows who it is for and from, when it is valid, and its names, key and extensions.
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          )}
        </div>
      </div>
    </div>
  );
}
