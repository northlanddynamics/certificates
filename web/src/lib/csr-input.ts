// Turns what a user pastes or drops (PEM text, bare base64, or a DER file) into the PEM text of one CSR, or says in
// words why it cannot be one. Pure, with no fetch, so what is pasted goes nowhere. It never decides whether the CSR is
// good: csr-details.ts reads it, and the server's parseCsr decides.

/** Far more than any CSR for the names a Managed Certificate may have; a copy of MAX_CSR_LENGTH in server/src/pki/csr.ts, which csr-generator.test.ts holds it to. */
export const MAX_CSR_LENGTH = 64_000;

const BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
const CSR_LABELS = ["CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"];

export type CsrText =
  | { kind: "csr"; pem: string; /** More CSRs than the one read. */ ignored: number }
  /** Not a CSR; `clear` when what was given must not be kept on the page, as a private key must not. */
  | { kind: "refused"; problem: string; clear: boolean };

const wrap = (base64: string) => `-----BEGIN CERTIFICATE REQUEST-----\n${base64.match(/.{1,64}/g)?.join("\n") ?? ""}\n-----END CERTIFICATE REQUEST-----`;

/** Reads pasted text: PEM (its first CSR), or the bare base64 of a DER CSR; null while there is nothing. */
export function readCsrText(text: string): CsrText | null {
  const trimmed = text.trim();
  if (trimmed === "") return null;
  if (trimmed.length > MAX_CSR_LENGTH) return { kind: "refused", problem: `This is far larger than any CSR (more than ${MAX_CSR_LENGTH.toLocaleString("en-US")} characters).`, clear: false };
  const blocks = [...trimmed.matchAll(BLOCK)].map((m) => ({ label: m[1]!, body: m[2]!.replace(/\s+/g, "") }));
  // Even a block cut short or with a mismatched footer, which would not be a block above, is a key that must not be kept.
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(trimmed))
    return { kind: "refused", problem: "That is a private key, which is never needed here, so it has been cleared. Paste the CSR (the .csr file), not the key.", clear: true };
  if (blocks.length > 0) {
    const [first] = blocks;
    const requests = blocks.filter((b) => CSR_LABELS.includes(b.label));
    if (requests.length === 0) {
      if (first?.label === "CERTIFICATE") return { kind: "refused", problem: "This is a certificate, not a CSR. A CSR starts with -----BEGIN CERTIFICATE REQUEST-----.", clear: false };
      return { kind: "refused", problem: `This is a ${first?.label.toLowerCase()}, not a CSR. A CSR starts with -----BEGIN CERTIFICATE REQUEST-----.`, clear: false };
    }
    return { kind: "csr", pem: wrap(requests[0]!.body), ignored: requests.length - 1 };
  }
  // Headers lost in copying: only the base64 of the DER remains.
  const bare = trimmed.replace(/\s+/g, "");
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(bare) && bare.startsWith("MI")) return { kind: "csr", pem: wrap(bare), ignored: 0 };
  return { kind: "refused", problem: "This is not a PEM CSR. One starts with -----BEGIN CERTIFICATE REQUEST-----.", clear: false };
}

/** A DER SEQUENCE, which is how a binary CSR starts, where text would start with "-" or a letter. */
const looksLikeDer = (bytes: Uint8Array) => bytes.length > 4 && bytes[0] === 0x30 && (bytes[1] ?? 0) >= 0x80;

/** The text of a file's bytes, as PEM when it is a DER CSR; what a textarea can then show. */
export function textOfCsrFile(bytes: Uint8Array): string {
  if (!looksLikeDer(bytes)) return new TextDecoder().decode(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return wrap(btoa(binary));
}

/** The text of a file, or why it cannot be read as a CSR. A file larger than any CSR is refused unread. */
export async function readCsrFile(file: File): Promise<{ text: string } | { problem: string }> {
  if (file.size > MAX_CSR_LENGTH) return { problem: `${file.name} is far larger than any CSR (${file.size.toLocaleString("en-US")} bytes).` };
  try {
    return { text: textOfCsrFile(new Uint8Array(await file.arrayBuffer())) };
  } catch {
    return { problem: `${file.name} could not be read.` };
  }
}
