// Turns what a user pastes or drops (PEM text holding CSRs and certificates, bare base64, or a DER file) into the PEM
// of each CSR or certificate in it, or says in words why it holds none. A CSR and a certificate need not be told apart
// by the user: the label says which, and for DER the shape does. A PKCS#7 bundle (a .p7b file) is read as the
// certificates it holds. Pure, with no fetch, so what is pasted goes nowhere. It
// never decides whether any of them is good: csr-details.ts and certificate-details.ts read them, and the server's
// parseCsr decides about a CSR.

import * as x509 from "@peculiar/x509";

/** Far more than any CSR for the names a Managed Certificate may have; a copy of MAX_CSR_LENGTH in server/src/pki/csr.ts, which csr-viewer.test.ts holds it to. It also bounds a pasted chain. */
export const MAX_CSR_LENGTH = 64_000;

export type PkiKind = "csr" | "certificate";

/** What the label of a PEM block says a PKCS#7 bundle is (OpenSSL writes PKCS7; the library this page converts with writes CMS). */
const PKCS7_LABELS = ["PKCS7", "CMS"];

export interface PkiItem {
  kind: PkiKind;
  /** One clean PEM block. */
  pem: string;
}

export type PkiText =
  | { kind: "items"; items: PkiItem[] }
  /** Neither a CSR nor a certificate; `clear` when what was given must not be kept on the page, as a private key must not. */
  | { kind: "refused"; problem: string; clear: boolean };

const BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
const LABELS: Record<PkiKind, string> = { csr: "CERTIFICATE REQUEST", certificate: "CERTIFICATE" };
const KIND_OF_LABEL: Record<string, PkiKind> = {
  "CERTIFICATE REQUEST": "csr",
  "NEW CERTIFICATE REQUEST": "csr",
  CERTIFICATE: "certificate",
  "X509 CERTIFICATE": "certificate",
};
const NOT_PEM = "This is not PEM. A CSR starts with -----BEGIN CERTIFICATE REQUEST-----, a certificate with -----BEGIN CERTIFICATE----- and a PKCS#7 bundle with -----BEGIN PKCS7-----.";

/** A PEM block: `label` around `base64`, in lines of 64. */
export const wrapPem = (label: string, base64: string) => `-----BEGIN ${label}-----\n${base64.match(/.{1,64}/g)?.join("\n") ?? ""}\n-----END ${label}-----`;
const wrap = (kind: PkiKind, base64: string) => wrapPem(LABELS[kind], base64);

/** The tag, and where the content starts and ends, of the DER element at `at`; null when it is not one. */
function element(bytes: Uint8Array, at: number): { tag: number; start: number; end: number } | null {
  const tag = bytes[at];
  let length = bytes[at + 1];
  if (tag === undefined || length === undefined) return null;
  let start = at + 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 3) return null;
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + (bytes[start++] ?? 0);
  }
  return { tag, start, end: start + length };
}

/** Which a DER SEQUENCE is: a CSR's first field is its version, the INTEGER 0, and a certificate's is `[0]` for its version, or, for a version 1 certificate, its serial number. */
export function kindOfDer(bytes: Uint8Array): PkiKind | null {
  const outer = element(bytes, 0);
  const info = outer?.tag === 0x30 ? element(bytes, outer.start) : null;
  if (!info || info.tag !== 0x30) return null;
  const first = bytes[info.start];
  if (first === 0xa0) return "certificate";
  if (first !== 0x02) return null;
  return bytes[info.start + 1] === 1 && bytes[info.start + 2] === 0 ? "csr" : "certificate";
}

/** The OBJECT IDENTIFIER of PKCS#7 signedData, 1.2.840.113549.1.7.2, as DER: what a .p7b file's outer SEQUENCE starts with. */
const SIGNED_DATA_OID = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];

/** Whether a DER SEQUENCE is a PKCS#7 signedData, which is how a bundle of certificates (.p7b, .p7c) is sent. */
export function isPkcs7Der(bytes: Uint8Array): boolean {
  const outer = element(bytes, 0);
  return outer?.tag === 0x30 && SIGNED_DATA_OID.every((byte, i) => bytes[outer.start + i] === byte);
}

const bytesOfBase64 = (base64: string) => Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
const base64OfBytes = (bytes: Uint8Array) => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
};

/** The certificates in a PKCS#7 bundle, as PEM, or why there are none. */
function certificatesOfPkcs7(base64: string): { items: PkiItem[] } | { problem: string } {
  try {
    const items = [...new x509.X509Certificates(base64)].map((certificate) => ({ kind: "certificate" as const, pem: wrap("certificate", base64OfBytes(new Uint8Array(certificate.rawData))) }));
    return items.length > 0 ? { items } : { problem: "This PKCS#7 bundle holds no certificates." };
  } catch {
    return { problem: "This could not be read as a PKCS#7 bundle of certificates." };
  }
}

/** Reads pasted text: the CSRs and certificates in its PEM, or the bare base64 of one; null while there is nothing. */
export function readPkiText(text: string): PkiText | null {
  const trimmed = text.trim();
  if (trimmed === "") return null;
  if (trimmed.length > MAX_CSR_LENGTH) return { kind: "refused", problem: `This is far larger than a CSR or a certificate chain (more than ${MAX_CSR_LENGTH.toLocaleString("en-US")} characters).`, clear: false };
  // Even a block cut short or with a mismatched footer, which would not be a block below, is a key that must not be kept.
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(trimmed))
    return { kind: "refused", problem: "That is a private key, which is never needed here, so it has been cleared. Paste the CSR or certificate, not the key.", clear: true };
  const blocks = [...trimmed.matchAll(BLOCK)].map((m) => ({ label: m[1]!, body: m[2]!.replace(/\s+/g, "") }));
  if (blocks.length > 0) {
    let problem: string | null = null;
    const items = blocks.flatMap(({ label, body }) => {
      if (PKCS7_LABELS.includes(label)) {
        const bundle = certificatesOfPkcs7(body);
        if ("problem" in bundle) problem ??= bundle.problem;
        return "items" in bundle ? bundle.items : [];
      }
      const kind = KIND_OF_LABEL[label];
      return kind ? [{ kind, pem: wrap(kind, body) }] : [];
    });
    if (items.length > 0) return { kind: "items", items };
    if (problem) return { kind: "refused", problem, clear: false };
    return { kind: "refused", problem: `This is a ${blocks[0]!.label.toLowerCase()}, not a CSR or a certificate.`, clear: false };
  }
  // Headers lost in copying: only the base64 of the DER remains.
  const bare = trimmed.replace(/\s+/g, "");
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(bare) && bare.startsWith("MI")) {
    try {
      const bytes = bytesOfBase64(bare);
      const kind = kindOfDer(bytes);
      if (kind) return { kind: "items", items: [{ kind, pem: wrap(kind, bare) }] };
      if (isPkcs7Der(bytes)) {
        const bundle = certificatesOfPkcs7(bare);
        return "items" in bundle ? { kind: "items", items: bundle.items } : { kind: "refused", problem: bundle.problem, clear: false };
      }
    } catch {
      // Not base64 after all.
    }
  }
  return { kind: "refused", problem: NOT_PEM, clear: false };
}

/** The text of a file's bytes, as PEM when it is a DER CSR, certificate or PKCS#7 bundle; what a textarea can then show. */
export function textOfPkiFile(bytes: Uint8Array): string {
  const kind = kindOfDer(bytes);
  if (kind) return wrap(kind, base64OfBytes(bytes));
  if (isPkcs7Der(bytes)) return wrapPem("PKCS7", base64OfBytes(bytes));
  return new TextDecoder().decode(bytes);
}

/** The text of a file, or why it cannot be read. A file larger than any CSR or chain is refused unread. */
export async function readPkiFile(file: File): Promise<{ text: string } | { problem: string }> {
  if (file.size > MAX_CSR_LENGTH) return { problem: `${file.name} is far larger than a CSR or a certificate chain (${file.size.toLocaleString("en-US")} bytes).` };
  try {
    return { text: textOfPkiFile(new Uint8Array(await file.arrayBuffer())) };
  } catch {
    return { problem: `${file.name} could not be read.` };
  }
}
