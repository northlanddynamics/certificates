// Turns what a user pastes or drops (PEM text holding CSRs and certificates, bare base64, or a DER file) into the PEM
// of each CSR or certificate in it, or says in words why it holds none. A CSR and a certificate need not be told apart
// by the user: the label says which, and for DER the shape does. Pure, with no fetch, so what is pasted goes nowhere. It
// never decides whether any of them is good: csr-details.ts and certificate-details.ts read them, and the server's
// parseCsr decides about a CSR.

/** Far more than any CSR for the names a Managed Certificate may have; a copy of MAX_CSR_LENGTH in server/src/pki/csr.ts, which csr-viewer.test.ts holds it to. It also bounds a pasted chain. */
export const MAX_CSR_LENGTH = 64_000;

export type PkiKind = "csr" | "certificate";

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
const NOT_PEM = "This is not PEM. A CSR starts with -----BEGIN CERTIFICATE REQUEST----- and a certificate with -----BEGIN CERTIFICATE-----.";

const wrap = (kind: PkiKind, base64: string) => `-----BEGIN ${LABELS[kind]}-----\n${base64.match(/.{1,64}/g)?.join("\n") ?? ""}\n-----END ${LABELS[kind]}-----`;

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

const bytesOfBase64 = (base64: string) => Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));

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
    const items = blocks.flatMap(({ label, body }) => {
      const kind = KIND_OF_LABEL[label];
      return kind ? [{ kind, pem: wrap(kind, body) }] : [];
    });
    if (items.length > 0) return { kind: "items", items };
    return { kind: "refused", problem: `This is a ${blocks[0]!.label.toLowerCase()}, not a CSR or a certificate.`, clear: false };
  }
  // Headers lost in copying: only the base64 of the DER remains.
  const bare = trimmed.replace(/\s+/g, "");
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(bare) && bare.startsWith("MI")) {
    try {
      const kind = kindOfDer(bytesOfBase64(bare));
      if (kind) return { kind: "items", items: [{ kind, pem: wrap(kind, bare) }] };
    } catch {
      // Not base64 after all.
    }
  }
  return { kind: "refused", problem: NOT_PEM, clear: false };
}

/** The text of a file's bytes, as PEM when it is a DER CSR or certificate; what a textarea can then show. */
export function textOfPkiFile(bytes: Uint8Array): string {
  const kind = kindOfDer(bytes);
  if (!kind) return new TextDecoder().decode(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return wrap(kind, btoa(binary));
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
