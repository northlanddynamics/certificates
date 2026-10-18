// Reads a pasted CSR's key algorithm and names in the browser, so a form can say at once whether the server will take
// it, and builds the openssl command that makes a key and a CSR on the user's own machine. It decides nothing: the
// server's parseCsr does. Pure, with no fetch, so a pasted CSR goes nowhere.
import * as x509 from "@peculiar/x509";
import { KEY_ALGORITHM_LABELS, MAX_COMMON_NAME_LENGTH, type KeyAlgorithm } from "./csr-generator";
import { normalizeName } from "./csr-names";

// By OID: looked up by class, an extension is not found when two copies of the library are loaded.
const SUBJECT_ALTERNATIVE_NAME = "2.5.29.17";

export interface CsrFacts {
  /** One the platform accepts, or null for any other key. */
  keyAlgorithm: KeyAlgorithm | null;
  /** The key in words, such as "RSA 2048", whether or not the platform accepts it. */
  keyLabel: string;
  /** Its alternative names and CN, normalised as the server normalises them, without repeats. */
  names: string[];
  /** The start of the SHA-256 of its DER, enough to tell two CSRs apart on screen. */
  fingerprint: string;
}

// WebCrypto names no curve and no modulus length for a key until it is imported as one, so each is tried in turn.
async function keyOf(spki: ArrayBuffer): Promise<Pick<CsrFacts, "keyAlgorithm" | "keyLabel">> {
  for (const [namedCurve, keyAlgorithm] of [["P-256", "ecdsa-p256"], ["P-384", "ecdsa-p384"]] as const) {
    const ok = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve }, true, ["verify"]).then(() => true, () => false);
    if (ok) return { keyAlgorithm, keyLabel: KEY_ALGORITHM_LABELS[keyAlgorithm] };
  }
  const rsa = await crypto.subtle.importKey("spki", spki, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, true, ["verify"]).catch(() => null);
  if (!rsa) return { keyAlgorithm: null, keyLabel: "a key the platform does not accept" };
  const bits = (rsa.algorithm as RsaHashedKeyAlgorithm).modulusLength;
  const keyAlgorithm = `rsa-${bits}`;
  return { keyAlgorithm: keyAlgorithm in KEY_ALGORITHM_LABELS ? (keyAlgorithm as KeyAlgorithm) : null, keyLabel: `RSA ${bits}` };
}

/** What a pasted CSR asks for; null while there is nothing to read, or why it cannot be read, in words. */
export async function inspectCsr(pem: string): Promise<CsrFacts | string | null> {
  if (pem.trim() === "") return null;
  let csr: x509.Pkcs10CertificateRequest;
  try {
    csr = new x509.Pkcs10CertificateRequest(pem.trim());
  } catch {
    return "This is not a PEM CSR. One starts with -----BEGIN CERTIFICATE REQUEST-----.";
  }
  if (!(await csr.verify().catch(() => false))) return "This CSR's signature does not verify; it may have been damaged in copying.";
  const alternativeNames = csr.getExtension(SUBJECT_ALTERNATIVE_NAME) as x509.SubjectAlternativeNameExtension | null;
  const asked = [...(alternativeNames?.names.items.map((item) => item.value) ?? []), ...csr.subjectName.getField("CN")];
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", csr.rawData));
  return {
    ...(await keyOf(csr.publicKey.rawData)),
    names: [...new Set(asked.map((name) => normalizeName(name) ?? name))],
    fingerprint: [...digest.slice(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join(":"),
  };
}

export interface CsrMatch {
  /** Names asked for that the CSR lacks. */
  missing: string[];
  /** Names in the CSR that were not asked for. */
  extra: string[];
  algorithmOk: boolean;
  ok: boolean;
}

/** How a CSR's facts compare with the names and key algorithm a form asks for, as the server compares them. */
export function matchCsr(facts: CsrFacts, names: string[], keyAlgorithm: KeyAlgorithm): CsrMatch {
  const wanted = new Set(names.map((name) => normalizeName(name) ?? name));
  const missing = [...wanted].filter((name) => !facts.names.includes(name));
  const extra = facts.names.filter((name) => !wanted.has(name));
  const algorithmOk = facts.keyAlgorithm === keyAlgorithm;
  return { missing, extra, algorithmOk, ok: missing.length === 0 && extra.length === 0 && algorithmOk };
}

/** A file name for a name, safe for a wildcard: `*.example.com` is `wildcard.example.com`. */
export const safeFileBase = (name: string | undefined) => (name ?? "csr").replace(/^\*\./, "wildcard.").replace(/[^a-z0-9.-]/gi, "_");

const NEW_KEY: Record<KeyAlgorithm, string> = {
  "ecdsa-p256": "-newkey ec -pkeyopt ec_paramgen_curve:P-256",
  "ecdsa-p384": "-newkey ec -pkeyopt ec_paramgen_curve:P-384",
  "rsa-2048": "-newkey rsa:2048",
  "rsa-3072": "-newkey rsa:3072",
  "rsa-4096": "-newkey rsa:4096",
};

/** An openssl (1.1.1 or later) command that writes a key and a CSR for exactly these names, which are already checked. */
export function opensslCommand(names: string[], keyAlgorithm: KeyAlgorithm): string {
  const base = safeFileBase(names[0]);
  const commonName = names.find((name) => name.length <= MAX_COMMON_NAME_LENGTH);
  return [
    `openssl req -new ${NEW_KEY[keyAlgorithm]} -nodes \\`,
    `  -keyout ${base}.key.pem -out ${base}.csr.pem \\`,
    `  -subj "/${commonName ? `CN=${commonName}` : ""}" \\`,
    `  -addext "subjectAltName=${names.map((name) => `DNS:${name}`).join(",")}"`,
  ].join("\n");
}
