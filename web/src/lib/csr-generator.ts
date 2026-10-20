// Makes a key pair and a CSR in the browser, with WebCrypto (or, for ML-DSA in a browser without it, noble), so the
// private key never leaves it (ADR 0002). Pure: it imports nothing from api.ts and does not use fetch, so there is
// nowhere in it for the key to be sent.
import * as x509 from "@peculiar/x509";

/** ECDSA and RSA: the key algorithms made here, as the server names them. */
export const CLASSICAL_KEY_ALGORITHMS = ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"] as const;
export type ClassicalKeyAlgorithm = (typeof CLASSICAL_KEY_ALGORITHMS)[number];
/** The key algorithms the platform accepts in a CSR, as the server names them. Which a CA takes is the server's to say. */
export const KEY_ALGORITHMS = [...CLASSICAL_KEY_ALGORITHMS, "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"] as const;
export type KeyAlgorithm = (typeof KEY_ALGORITHMS)[number];
export const DEFAULT_KEY_ALGORITHM: ClassicalKeyAlgorithm = "ecdsa-p256";

export const KEY_ALGORITHM_LABELS: Record<KeyAlgorithm, string> = {
  "ecdsa-p256": "ECDSA P-256",
  "ecdsa-p384": "ECDSA P-384",
  "rsa-2048": "RSA 2048",
  "rsa-3072": "RSA 3072",
  "rsa-4096": "RSA 4096",
  "ml-dsa-44": "ML-DSA-44",
  "ml-dsa-65": "ML-DSA-65",
  "ml-dsa-87": "ML-DSA-87",
};

/** None known yet: a stable empty list, for a default that does not change between renders. */
export const NO_KEY_ALGORITHMS: readonly KeyAlgorithm[] = [];

export type MlDsaKeyAlgorithm = Extract<KeyAlgorithm, `ml-dsa-${string}`>;
export const isMlDsa = (keyAlgorithm: KeyAlgorithm): keyAlgorithm is MlDsaKeyAlgorithm => keyAlgorithm.startsWith("ml-dsa-");

/** Whether the algorithm is one of the classical ones, which sign with a chosen hash; ML-DSA signs with none. */
export const isClassical = (keyAlgorithm: KeyAlgorithm): keyAlgorithm is ClassicalKeyAlgorithm => (CLASSICAL_KEY_ALGORITHMS as readonly string[]).includes(keyAlgorithm);

// No SHA-1, MD5 or RSA-PSS: a CA would refuse them.
export const SIGNATURE_HASHES = ["SHA-256", "SHA-384", "SHA-512"] as const;
export type SignatureHash = (typeof SIGNATURE_HASHES)[number];

export const isRsa = (keyAlgorithm: ClassicalKeyAlgorithm) => keyAlgorithm.startsWith("rsa");

/** The longest a subject's CN may be (X.520); a CA refuses a longer one, so a longer name cannot be the CN. */
export const MAX_COMMON_NAME_LENGTH = 64;

/** The hash a key algorithm signs with unless the user chooses another: SHA-384 for P-384, SHA-256 otherwise. */
export const defaultHash = (keyAlgorithm: ClassicalKeyAlgorithm): SignatureHash => (keyAlgorithm === "ecdsa-p384" ? "SHA-384" : "SHA-256");

/** A soft note, never a refusal, when the hash is weaker than the key; null when there is nothing to say. */
export const hashNote = (keyAlgorithm: ClassicalKeyAlgorithm, hash: SignatureHash): string | null =>
  keyAlgorithm === "ecdsa-p384" && hash === "SHA-256" ? "SHA-256 is weaker than a P-384 key; SHA-384 is the usual match." : null;

export interface SubjectDetails {
  organization?: string;
  organizationalUnit?: string;
  /** Exactly two letters. */
  country?: string;
  state?: string;
  locality?: string;
}

export interface CsrInput {
  keyAlgorithm: KeyAlgorithm;
  /** The DNS names the CSR asks for, as subject alternative names. Already checked against the name rules. */
  names: string[];
  /** One of `names`, or none: the subject's CN. */
  commonName?: string | null;
  subject?: SubjectDetails;
  /** Defaults to the key algorithm's own; ignored for ML-DSA, which signs with no hash. */
  hash?: SignatureHash;
}

export interface GenerateOptions {
  /** Makes an ML-DSA key with noble even where WebCrypto could: for a test of the path a browser without ML-DSA takes. */
  forceNoble?: boolean;
}

export interface GeneratedCsr {
  /** Unencrypted PKCS#8. */
  keyPem: string;
  csrPem: string;
}

const RSA_BITS = { "rsa-2048": 2048, "rsa-3072": 3072, "rsa-4096": 4096 } as const;

function keyParams(keyAlgorithm: ClassicalKeyAlgorithm, hash: SignatureHash): RsaHashedKeyGenParams | EcKeyGenParams {
  switch (keyAlgorithm) {
    case "ecdsa-p256":
      return { name: "ECDSA", namedCurve: "P-256" };
    case "ecdsa-p384":
      return { name: "ECDSA", namedCurve: "P-384" };
    default:
      return { name: "RSASSA-PKCS1-v1_5", modulusLength: RSA_BITS[keyAlgorithm], publicExponent: new Uint8Array([1, 0, 1]), hash };
  }
}

const subjectName = (commonName: string | null | undefined, subject: SubjectDetails = {}): x509.JsonName => {
  const fields: [string, string | undefined][] = [
    ["C", subject.country],
    ["ST", subject.state],
    ["L", subject.locality],
    ["O", subject.organization],
    ["OU", subject.organizationalUnit],
    ["CN", commonName ?? undefined],
  ];
  return fields.filter((f): f is [string, string] => !!f[1]?.trim()).map(([type, value]) => ({ [type]: [value.trim()] }));
};

/** The subject alternative names a CSR asks for, all DNS names. */
export const sanExtension = (names: string[]) => new x509.SubjectAlternativeNameExtension(names.map((value) => ({ type: "dns" as const, value })));

/** RFC 9881's seed form: a 54-byte PrivateKeyInfo whose privateKey is `[0] IMPLICIT OCTET STRING` of the 32-byte seed. */
const isSeedForm = (pkcs8: ArrayBuffer) => pkcs8.byteLength === 54 && new Uint8Array(pkcs8)[20] === 0x80 && new Uint8Array(pkcs8)[21] === 0x20;

/** An ML-DSA key and CSR made by the browser's WebCrypto; null when it cannot make the key (detected by trying), or does not export it in the seed form. */
async function generateNativeMlDsa(input: CsrInput & { keyAlgorithm: MlDsaKeyAlgorithm }, name: x509.JsonName): Promise<GeneratedCsr | null> {
  const algorithm = { name: input.keyAlgorithm.toUpperCase() };
  let keys: CryptoKeyPair;
  try {
    keys = (await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"])) as CryptoKeyPair;
  } catch {
    return null;
  }
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
  if (!isSeedForm(pkcs8)) return null;
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({ name, keys, signingAlgorithm: algorithm, extensions: [sanExtension(input.names)] });
  return { keyPem: x509.PemConverter.encode(pkcs8, "PRIVATE KEY"), csrPem: csr.toString("pem") };
}

/**
 * A new key pair and a CSR signed with it. The key is made extractable only so it can be exported here, once. An
 * ML-DSA key is made by the browser's WebCrypto where it can, and otherwise by noble, which is loaded only then.
 */
export async function generateCsr(input: CsrInput, options: GenerateOptions = {}): Promise<GeneratedCsr> {
  const name = subjectName(input.commonName, input.subject);
  if (isMlDsa(input.keyAlgorithm)) {
    const mlDsa = { ...input, keyAlgorithm: input.keyAlgorithm };
    const native = options.forceNoble ? null : await generateNativeMlDsa(mlDsa, name);
    return native ?? (await import("./csr-ml-dsa")).generateMlDsaCsrWithNoble(mlDsa.keyAlgorithm, name, input.names);
  }
  const hash = input.hash ?? defaultHash(input.keyAlgorithm);
  const keys = (await crypto.subtle.generateKey(keyParams(input.keyAlgorithm, hash), true, ["sign", "verify"])) as CryptoKeyPair;
  const algorithm = isRsa(input.keyAlgorithm) ? { name: "RSASSA-PKCS1-v1_5", hash } : { name: "ECDSA", hash };
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name,
    keys,
    signingAlgorithm: algorithm,
    extensions: [sanExtension(input.names)],
  });
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
  return { keyPem: x509.PemConverter.encode(pkcs8, "PRIVATE KEY"), csrPem: csr.toString("pem") };
}
