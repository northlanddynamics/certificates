// The other encodings a CSR or a certificate can be had in, and a PKCS#7 bundle of certificates: PEM, DER, bare
// base64, and PKCS#7 as PEM or DER. Every one holds the same signed bytes, so a conversion changes how they are written
// and never what they say, and a signature stays valid. Pure, with no fetch, so what is converted goes nowhere; it holds
// no private key and will not take one.
import * as x509 from "@peculiar/x509";
import { wrapPem, type PkiItem } from "./pki-input";

export type ConversionFormat = "pem" | "der" | "base64" | "pkcs7-pem" | "pkcs7-der";

export interface Conversion {
  format: ConversionFormat;
  label: string;
  description: string;
  /** With the dot, for a file name. */
  extension: string;
  /** Whether it can be read and copied as text; DER cannot. */
  text: boolean;
  /** The conversion, made when asked for. */
  make: () => string | Uint8Array;
}

const bodyOf = (pem: string) => pem.replace(/-----[A-Z0-9 ]+-----|\s+/g, "");
const derOf = (pem: string) => Uint8Array.from(atob(bodyOf(pem)), (c) => c.charCodeAt(0));
const pkcs7DerOf = (items: PkiItem[]) => new Uint8Array(new x509.X509Certificates(items.map((item) => new x509.X509Certificate(item.pem))).export("raw"));
const base64Of = (bytes: Uint8Array) => btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""));

/**
 * What `items` can be converted to. One CSR or certificate can be PEM, DER or bare base64; certificates can also be a
 * PKCS#7 bundle, and several can only be one PEM file or a bundle, since a DER file holds one. A CSR is never bundled.
 */
export function conversionsOf(items: PkiItem[]): Conversion[] {
  const [first] = items;
  if (!first) return [];
  const only = items.length === 1;
  const certificates = items.every((item) => item.kind === "certificate");
  const noun = only ? (first.kind === "csr" ? "CSR" : "certificate") : "certificates";
  const list: Conversion[] = [
    {
      format: "pem",
      label: only ? "PEM" : "PEM bundle",
      description: only ? "Base64 between BEGIN and END lines. What most servers and tools take." : `One PEM file holding all ${items.length} ${noun}, in this order.`,
      extension: only && first.kind === "csr" ? ".csr" : ".pem",
      text: true,
      make: () => `${items.map((item) => item.pem).join("\n")}\n`,
    },
  ];
  if (only) {
    list.push(
      {
        format: "der",
        label: "DER",
        description: "The binary form, as Windows and Java read it (.der, .cer).",
        extension: ".der",
        text: false,
        make: () => derOf(first.pem),
      },
      {
        format: "base64",
        label: "Base64, no header",
        description: `The ${noun} as one line of base64, without the BEGIN and END lines.`,
        extension: ".txt",
        text: true,
        make: () => `${bodyOf(first.pem)}\n`,
      },
    );
  }
  if (certificates) {
    list.push(
      {
        format: "pkcs7-pem",
        label: "PKCS#7, PEM",
        description: `${only ? "The certificate" : "The certificates"} as a PKCS#7 bundle in PEM (BEGIN PKCS7), as Windows and Java import.`,
        extension: ".p7b",
        text: true,
        make: () => `${wrapPem("PKCS7", base64Of(pkcs7DerOf(items)))}\n`,
      },
      {
        format: "pkcs7-der",
        label: "PKCS#7, DER",
        description: `${only ? "The certificate" : "The certificates"} as a binary PKCS#7 bundle (.p7b, .p7c).`,
        extension: ".p7b",
        text: false,
        make: () => pkcs7DerOf(items),
      },
    );
  }
  return list;
}

/** A name safe for a file: the characters a file name can hold, and a stand-in where there is none. */
export function fileBaseOf(name: string | null, fallback: string): string {
  const base = (name ?? "").replace(/^\*\./, "wildcard.").replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^[._]+|[._]+$/g, "");
  return base === "" ? fallback : base.slice(0, 80);
}
