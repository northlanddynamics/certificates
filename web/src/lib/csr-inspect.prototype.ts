// PROTOTYPE (branch prototype/csr-ux): throwaway. Reads a pasted CSR's key algorithm and names in the browser, so a
// form can say at once whether the server will take it, and builds the openssl command that makes one. Pure, no fetch.
import * as x509 from "@peculiar/x509";
import { KEY_ALGORITHM_LABELS, type KeyAlgorithm } from "@/lib/csr-generator";
import { normalizeName } from "@/lib/csr-names";

const SUBJECT_ALTERNATIVE_NAME = "2.5.29.17";

export interface CsrFacts {
  keyAlgorithm: KeyAlgorithm | null;
  keyLabel: string;
  names: string[];
  /** SHA-256 of the DER, the first 16 hex digits: enough to tell two CSRs apart on screen. */
  fingerprint: string;
}

async function keyAlgorithmOf(spki: ArrayBuffer): Promise<{ keyAlgorithm: KeyAlgorithm | null; keyLabel: string }> {
  for (const [curve, alg] of [["P-256", "ecdsa-p256"], ["P-384", "ecdsa-p384"]] as const) {
    try {
      await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: curve }, true, ["verify"]);
      return { keyAlgorithm: alg, keyLabel: KEY_ALGORITHM_LABELS[alg] };
    } catch {
      /* not this curve */
    }
  }
  try {
    const key = await crypto.subtle.importKey("spki", spki, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, true, ["verify"]);
    const bits = (key.algorithm as RsaHashedKeyAlgorithm).modulusLength;
    const alg = `rsa-${bits}` as KeyAlgorithm;
    return { keyAlgorithm: alg in KEY_ALGORITHM_LABELS ? alg : null, keyLabel: `RSA ${bits}` };
  } catch {
    return { keyAlgorithm: null, keyLabel: "an unsupported key" };
  }
}

/** The CSR's facts; null while the text is empty, or a string saying why it cannot be read. */
export async function inspectCsr(pem: string): Promise<CsrFacts | string | null> {
  if (pem.trim() === "") return null;
  let csr: x509.Pkcs10CertificateRequest;
  try {
    csr = new x509.Pkcs10CertificateRequest(pem.trim());
  } catch {
    return "This is not a PEM CSR yet. It starts with -----BEGIN CERTIFICATE REQUEST-----.";
  }
  if (!(await csr.verify().catch(() => false))) return "This CSR's signature does not verify; it may be damaged.";
  const san = csr.getExtension(SUBJECT_ALTERNATIVE_NAME) as x509.SubjectAlternativeNameExtension | null;
  const asked = [...(san?.names.items.map((i) => i.value) ?? []), ...csr.subjectName.getField("CN")];
  const names = [...new Set(asked.map((n) => normalizeName(n) ?? n))];
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", csr.rawData));
  const fingerprint = [...digest.slice(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join(":");
  return { ...(await keyAlgorithmOf(csr.publicKey.rawData)), names, fingerprint };
}

export interface CsrMatch {
  missing: string[];
  extra: string[];
  algorithmOk: boolean;
  ok: boolean;
}

export function matchCsr(facts: CsrFacts, names: string[], keyAlgorithm: KeyAlgorithm | null): CsrMatch {
  const want = new Set(names.map((n) => normalizeName(n) ?? n));
  const have = new Set(facts.names);
  const missing = [...want].filter((n) => !have.has(n));
  const extra = [...have].filter((n) => !want.has(n));
  const algorithmOk = keyAlgorithm === null || facts.keyAlgorithm === keyAlgorithm;
  return { missing, extra, algorithmOk, ok: missing.length === 0 && extra.length === 0 && algorithmOk };
}

const fileBase = (name: string | undefined) => (name ?? "csr").replace(/^\*\./, "wildcard.").replace(/[^a-z0-9.-]/gi, "_");

/** An openssl command that makes the key and the CSR on the user's own machine, for exactly these names. */
export function opensslCommand(names: string[], keyAlgorithm: KeyAlgorithm): string {
  const base = fileBase(names[0]);
  const newKey =
    keyAlgorithm === "ecdsa-p256"
      ? "-newkey ec -pkeyopt ec_paramgen_curve:P-256"
      : keyAlgorithm === "ecdsa-p384"
        ? "-newkey ec -pkeyopt ec_paramgen_curve:P-384"
        : `-newkey rsa:${keyAlgorithm.slice(4)}`;
  const cn = names.find((n) => n.length <= 64);
  return [
    `openssl req -new ${newKey} -nodes \\`,
    `  -keyout ${base}.key.pem -out ${base}.csr.pem \\`,
    `  -subj "/${cn ? `CN=${cn}` : ""}" \\`,
    `  -addext "subjectAltName=${names.map((n) => `DNS:${n}`).join(",")}"`,
  ].join("\n");
}

export { fileBase };
