import { CheckIcon, CopyIcon, DownloadIcon } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { conversionsOf, type Conversion } from "@/lib/pki-convert";
import type { PkiItem } from "@/lib/pki-input";

/** One conversion, to copy as text where it is text, or to save as a file. Made when asked for, so a conversion that cannot be made says so here. */
function ConversionRow({ conversion, fileBase }: { conversion: Conversion; fileBase: string }) {
  const [state, setState] = useState<"copied" | "failed" | null>(null);

  function download() {
    try {
      const data = conversion.make();
      const url = URL.createObjectURL(new Blob([data as BlobPart], { type: conversion.text ? "text/plain" : "application/octet-stream" }));
      Object.assign(document.createElement("a"), { href: url, download: `${fileBase}${conversion.extension}` }).click();
      URL.revokeObjectURL(url);
      setState(null);
    } catch {
      setState("failed");
    }
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(conversion.make() as string);
      setState("copied");
    } catch {
      setState("failed");
    }
  }

  return (
    <li className="flex flex-col gap-2 p-3">
      <div>
        <p className="text-sm font-medium">{conversion.label}</p>
        <p className="text-xs text-muted-foreground">{conversion.description}</p>
      </div>
      <div className="flex flex-wrap gap-2">
        {conversion.text && (
          <Button type="button" variant="outline" size="sm" onClick={() => void copy()}>
            {state === "copied" ? <CheckIcon /> : <CopyIcon />}
            {state === "copied" ? "Copied" : "Copy"}
          </Button>
        )}
        <Button type="button" variant="outline" size="sm" title={`${fileBase}${conversion.extension}`} onClick={download}>
          <DownloadIcon />
          Download {conversion.extension}
        </Button>
      </div>
      {state === "failed" && (
        <p role="alert" className="text-sm text-destructive">
          {conversion.text ? "That could not be converted, or the browser would not let this page copy it." : "That could not be converted."}
        </p>
      )}
    </li>
  );
}

function Conversions({ title, items, fileBase }: { title: string; items: PkiItem[]; fileBase: string }) {
  return (
    <section className="flex flex-col gap-2" aria-label={title}>
      <h3 className="text-sm font-medium">{title}</h3>
      <ul className="divide-y rounded-lg border">
        {conversionsOf(items).map((conversion) => (
          <ConversionRow key={conversion.format} conversion={conversion} fileBase={fileBase} />
        ))}
      </ul>
    </section>
  );
}

/**
 * Offers what is shown in the other encodings: PEM, DER, bare base64 and PKCS#7. `shown` is the CSR or certificate being
 * looked at; `bundle` is every certificate in the file when there are several, for one PEM file or PKCS#7 bundle of them
 * all. The same bytes are written another way, so a signature stays valid. It is made in the browser and nothing is sent.
 */
export function PemConverter({ shown, shownTitle, shownFileBase, bundle, bundleFileBase }: { shown: PkiItem; shownTitle: string; shownFileBase: string; bundle: PkiItem[]; bundleFileBase: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Convert</CardTitle>
        <CardDescription>The same bytes written another way, so the signature stays valid. Done in your browser; nothing is sent.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <Conversions title={shownTitle} items={[shown]} fileBase={shownFileBase} />
        {bundle.length > 1 && <Conversions title={`All ${bundle.length} certificates`} items={bundle} fileBase={bundleFileBase} />}
      </CardContent>
    </Card>
  );
}
