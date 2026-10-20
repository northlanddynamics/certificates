import { FileSearchIcon, LoaderIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { CsrDetailsView } from "@/components/csr-details-view";
import { CsrDropField } from "@/components/csr-drop-field";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { parseCsrDetails, type CsrReading } from "@/lib/csr-details";
import { readCsrText } from "@/lib/csr-input";

type Reading = { status: "empty" } | { status: "reading" } | { status: "refused"; problem: string } | ({ status: "read" } & CsrReading);

/** What the text is, as it changes; a CSR is read once the text is one. A reading that arrives after the text has changed again is dropped. */
function useReading(text: string): { reading: Reading; ignored: number } {
  const input = readCsrText(text);
  const pem = input?.kind === "csr" ? input.pem : null;
  const [csr, setCsr] = useState<{ pem: string; reading: CsrReading } | null>(null);
  useEffect(() => {
    if (pem === null) return;
    let current = true;
    void parseCsrDetails(pem).then((reading) => current && setCsr({ pem, reading }));
    return () => {
      current = false;
    };
  }, [pem]);
  if (input === null) return { reading: { status: "empty" }, ignored: 0 };
  if (input.kind === "refused") return { reading: { status: "refused", problem: input.problem }, ignored: 0 };
  return { reading: csr?.pem === input.pem ? { status: "read", ...csr.reading } : { status: "reading" }, ignored: input.ignored };
}

/**
 * Everything a CSR says, and whether the platform would take it: a CSR pasted, dropped or chosen as a file on the left,
 * and what it holds on the right. It is read in the browser and nothing here talks to the platform.
 */
export function CsrViewerPage() {
  const [text, setText] = useState("");
  const { reading, ignored } = useReading(text);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">CSR Viewer</h1>
        <p className="text-sm text-muted-foreground">
          Paste, drop or choose a CSR to see what it asks for and whether the platform would take it. It is read in your browser; nothing is sent.
        </p>
      </div>
      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <Card className="lg:sticky lg:top-4">
          <CardHeader>
            <CardTitle>CSR</CardTitle>
            <CardDescription>A PEM CSR, or a DER file.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <CsrDropField id="csr-viewer-text" value={text} onChange={setText} />
            {ignored > 0 && <p className="text-sm text-muted-foreground">There are {ignored + 1} CSRs here; this shows the first.</p>}
            {reading.status === "refused" && (
              <p role="alert" className="text-sm text-destructive">
                {reading.problem}
              </p>
            )}
          </CardContent>
        </Card>

        <div aria-live="polite">
          {reading.status === "read" && reading.ok && <CsrDetailsView details={reading.details} />}
          {reading.status === "read" && !reading.ok && (
            <Alert variant="destructive">
              <AlertDescription>{reading.error}</AlertDescription>
            </Alert>
          )}
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
                <EmptyTitle>No CSR yet</EmptyTitle>
                <EmptyDescription>Its subject, names, key, signature and requested extensions, and whether the platform would take it, appear here.</EmptyDescription>
              </EmptyHeader>
            </Empty>
          )}
        </div>
      </div>
    </div>
  );
}
