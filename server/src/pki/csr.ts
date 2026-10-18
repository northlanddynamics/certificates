// What the platform checks in a CSR before anything is issued from it: that it is one (signed with the key it
// carries, so whoever submitted it holds that key), which key algorithm it is for, and which names it asks for.
import * as x509 from "@peculiar/x509";
import { createPublicKey, webcrypto } from "node:crypto";
import { normalizeName } from "./names";
import { fingerprintOf } from "./fingerprint";

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

export * from "./key-algorithms";
import { KEY_ALGORITHMS, type KeyAlgorithm } from "./key-algorithms";
export const KEY_CUSTODIES = ["owner", "agent"] as const;
export type KeyCustody = (typeof KEY_CUSTODIES)[number];

// By OID: looked up by class, an extension is not found when two copies of the library are loaded.
const SUBJECT_ALTERNATIVE_NAME = "2.5.29.17";

/** Far more than any CSR for the names a Managed Certificate may have (MAX_NAMES), so a larger body is refused before it is parsed. */
export const MAX_CSR_LENGTH = 64_000;

export class CsrError extends Error {}

export interface ParsedCsr {
  keyAlgorithm: KeyAlgorithm;
  /** Every name the CSR asks for: its subject alternative names and its common name, normalised, without repeats. */
  names: string[];
  /** The CSR's public key, as DER SubjectPublicKeyInfo: what a Certificate issued for it must carry. */
  publicKey: Buffer;
  /** SHA-256 of the CSR's DER, lower-case hex: how an audit trail names the CSR without holding it. */
  fingerprint: string;
}

function keyAlgorithmOf(spki: ArrayBuffer): KeyAlgorithm {
  const key = createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" });
  const { asymmetricKeyType: type, asymmetricKeyDetails: details } = key;
  if (type === "ec") {
    if (details?.namedCurve === "prime256v1") return "ecdsa-p256";
    if (details?.namedCurve === "secp384r1") return "ecdsa-p384";
    throw new CsrError(`the CSR's key is on the curve ${details?.namedCurve}; only P-256 and P-384 are supported`);
  }
  if (type === "rsa") {
    const algorithm = `rsa-${details?.modulusLength}`;
    if ((KEY_ALGORITHMS as readonly string[]).includes(algorithm)) return algorithm as KeyAlgorithm;
    throw new CsrError(`the CSR's RSA key has ${details?.modulusLength} bits; only 2048, 3072 and 4096 are supported`);
  }
  throw new CsrError(`the CSR's key is ${type}; only ECDSA (P-256, P-384) and RSA (2048, 3072, 4096) are supported`);
}

/** Reads a PEM CSR and checks its signature, or throws a CsrError saying what is wrong with it. */
export async function parseCsr(pem: string): Promise<ParsedCsr> {
  let csr: x509.Pkcs10CertificateRequest;
  try {
    csr = new x509.Pkcs10CertificateRequest(pem);
  } catch {
    throw new CsrError("not a PEM-encoded certificate signing request");
  }
  if (!(await csr.verify().catch(() => false))) throw new CsrError("the CSR's signature does not verify against its own public key");
  const keyAlgorithm = keyAlgorithmOf(csr.publicKey.rawData);

  const asked: string[] = [];
  const alternativeNames = csr.getExtension(SUBJECT_ALTERNATIVE_NAME) as x509.SubjectAlternativeNameExtension | null;
  for (const item of alternativeNames?.names.items ?? []) {
    if (item.type !== "dns") throw new CsrError(`the CSR names a ${item.type} (${item.value}); only DNS names are supported`);
    asked.push(item.value);
  }
  asked.push(...csr.subjectName.getField("CN"));

  const names = new Set<string>();
  for (const name of asked) {
    const normal = normalizeName(name);
    if (normal === null) throw new CsrError(`the CSR asks for "${name}", which cannot be a name to issue for`);
    names.add(normal);
  }
  if (names.size === 0) throw new CsrError("the CSR asks for no names");
  return {
    keyAlgorithm,
    names: [...names],
    publicKey: Buffer.from(csr.publicKey.rawData),
    fingerprint: fingerprintOf(csr.rawData),
  };
}
