import * as x509 from "@peculiar/x509";
import { useQuery } from "@tanstack/react-query";
import { CopyButton } from "@/components/copy-button";
import { GuideLink } from "@/components/guide";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api, type PkiPublication, type PrivateCa } from "@/lib/api";
import { publicationUrls } from "@/lib/pki-publication";
import { commonNameOf } from "@/lib/private-ca";
import { TRUST_STORES } from "@/lib/trust-stores";

/** A file name from the Private CA's name, as the server names its download. */
const fileBase = (name: string) => name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "private-ca";

const hex = (bytes: ArrayBuffer) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join(":").toUpperCase();

/** The root, read from its download: its PEM, its DER and its SHA-256 fingerprint, worked out in the browser. */
async function rootOf(orgId: string, ca: PrivateCa) {
  const res = await fetch(api.privateCaRootUrl(orgId, ca.id), { credentials: "include" });
  if (!res.ok) throw new Error(`The root could not be downloaded (${res.status})`);
  const pem = await res.text();
  const certificate = new x509.X509Certificate(pem);
  return { pem, der: certificate.rawData, fingerprint: hex(await crypto.subtle.digest("SHA-256", certificate.rawData)) };
}

/** Offers `bytes` to save as `name`. */
function saveFile(bytes: ArrayBuffer, name: string) {
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/pkix-cert" }));
  const link = Object.assign(document.createElement("a"), { href: url, download: name });
  link.click();
  URL.revokeObjectURL(url);
}

/**
 * How to make a Private CA's root trusted: its download in both encodings, its fingerprint to compare once installed, the
 * steps for common trust stores, and the CRL addresses relying parties fetch, to test from their side.
 */
export function TrustRootDialog({
  orgId,
  ca,
  publication,
  open,
  onOpenChange,
}: {
  orgId: string;
  ca: PrivateCa;
  publication: PkiPublication | undefined;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const root = useQuery({ queryKey: ["private-cas", orgId, ca.id, "root"], queryFn: () => rootOf(orgId, ca), enabled: open && ca.root !== null });
  const base = fileBase(ca.name);
  const files = { pem: `${base}.root.pem`, der: `${base}.root.crt` };
  const crls = publication
    ? [
        // Only a platform-made root publishes a CRL here; the Organization's own root publishes its own.
        ...(ca.kind === "platform_root" ? [{ label: "Root", url: publicationUrls(publication.baseUrl, { signer: "root", id: ca.id }).crl }] : []),
        ...ca.issuingCas
          .filter((i) => i.notAfter !== null)
          .map((i) => ({ label: `Issuing CA ${commonNameOf(i.subject)}`, url: publicationUrls(publication.baseUrl, { signer: "issuing", id: i.id }).crl })),
      ]
    : [];
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>Trust {ca.name}'s root</DialogTitle>
          <DialogDescription>Install it once wherever Certificates from this Private CA must be trusted. It covers every Issuing CA under it, including ones added later.</DialogDescription>
        </DialogHeader>
        <div className="flex min-w-0 flex-col gap-5 text-sm">
          <div className="flex flex-wrap items-center gap-3">
            <Button asChild>
              <a href={api.privateCaRootUrl(orgId, ca.id)} download={files.pem}>
                Download root (PEM)
              </a>
            </Button>
            <Button variant="outline" disabled={!root.data} onClick={() => root.data && saveFile(root.data.der, files.der)}>
              DER (.crt)
            </Button>
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-muted-foreground">SHA-256 fingerprint: compare it after installing</span>
            {root.data ? (
              <span className="flex items-center gap-1">
                <code className="break-all text-xs">{root.data.fingerprint}</code>
                <CopyButton text={root.data.fingerprint} label="Copy the fingerprint" />
              </span>
            ) : (
              <span className="text-muted-foreground">{root.error ? root.error.message : "Reading the root…"}</span>
            )}
          </div>

          <Tabs defaultValue={TRUST_STORES[0]!.id} className="min-w-0">
            <TabsList className="flex-wrap">
              {TRUST_STORES.map((t) => (
                <TabsTrigger key={t.id} value={t.id}>
                  {t.label}
                </TabsTrigger>
              ))}
            </TabsList>
            {TRUST_STORES.map((t) => (
              <TabsContent key={t.id} value={t.id} className="flex flex-col gap-2">
                <p className="text-muted-foreground">{t.how}</p>
                <div className="relative">
                  <pre className="overflow-x-auto rounded-md border bg-muted p-3 pr-10 font-mono text-xs leading-relaxed">{t.command(files)}</pre>
                  <div className="absolute top-1.5 right-1.5">
                    <CopyButton text={t.command(files)} label={`Copy the ${t.label} command`} />
                  </div>
                </div>
              </TabsContent>
            ))}
          </Tabs>

          {crls.length > 0 && (
            <div className="flex flex-col gap-2 border-t pt-4">
              <span className="font-medium">What relying parties fetch</span>
              <ul className="flex flex-col gap-1">
                {crls.map((c) => (
                  <li key={c.url} className="grid grid-cols-[minmax(0,12rem)_minmax(0,1fr)_auto] items-center gap-2">
                    <span className="truncate text-muted-foreground">{c.label}</span>
                    <code className="truncate text-xs">{c.url}</code>
                    <CopyButton text={c.url} label={`Copy the CRL address of ${c.label}`} />
                  </li>
                ))}
              </ul>
              <span className="text-muted-foreground">
                Each must answer over plain HTTP from your relying parties' network.{" "}
                <GuideLink orgId={orgId} guide="private-cas" section="reach">
                  How to check
                </GuideLink>
              </span>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
