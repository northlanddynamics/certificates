// Makes a key pair and a CSR in the browser, with WebCrypto, so the private key never leaves it (ADR 0002). Pure: it
// imports nothing from api.ts and does not use fetch, so there is nowhere in it for the key to be sent.
import * as x509 from "@peculiar/x509";

/** The key algorithms the platform accepts in a CSR, as the server names them. */
export const KEY_ALGORITHMS = ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"] as const;
export type KeyAlgorithm = (typeof KEY_ALGORITHMS)[number];
export const DEFAULT_KEY_ALGORITHM: KeyAlgorithm = "ecdsa-p256";

export const KEY_ALGORITHM_LABELS: Record<KeyAlgorithm, string> = {
  "ecdsa-p256": "ECDSA P-256",
  "ecdsa-p384": "ECDSA P-384",
  "rsa-2048": "RSA 2048",
  "rsa-3072": "RSA 3072",
  "rsa-4096": "RSA 4096",
};

// No SHA-1, MD5 or RSA-PSS: a CA would refuse them.
export const SIGNATURE_HASHES = ["SHA-256", "SHA-384", "SHA-512"] as const;
export type SignatureHash = (typeof SIGNATURE_HASHES)[number];

export const isRsa = (keyAlgorithm: KeyAlgorithm) => keyAlgorithm.startsWith("rsa");

/** The longest a subject's CN may be (X.520); a CA refuses a longer one, so a longer name cannot be the CN. */
export const MAX_COMMON_NAME_LENGTH = 64;

/** The hash a key algorithm signs with unless the user chooses another: SHA-384 for P-384, SHA-256 otherwise. */
export const defaultHash = (keyAlgorithm: KeyAlgorithm): SignatureHash => (keyAlgorithm === "ecdsa-p384" ? "SHA-384" : "SHA-256");

/** A soft note, never a refusal, when the hash is weaker than the key; null when there is nothing to say. */
export const hashNote = (keyAlgorithm: KeyAlgorithm, hash: SignatureHash): string | null =>
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
  /** Defaults to the key algorithm's own. */
  hash?: SignatureHash;
}

export interface GeneratedCsr {
  /** Unencrypted PKCS#8. */
  keyPem: string;
  csrPem: string;
}

const RSA_BITS = { "rsa-2048": 2048, "rsa-3072": 3072, "rsa-4096": 4096 } as const;

function keyParams(keyAlgorithm: KeyAlgorithm, hash: SignatureHash): RsaHashedKeyGenParams | EcKeyGenParams {
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

/** A new key pair and a CSR signed with it. The key is made extractable only so it can be exported here, once. */
export async function generateCsr(input: CsrInput): Promise<GeneratedCsr> {
  const hash = input.hash ?? defaultHash(input.keyAlgorithm);
  const keys = (await crypto.subtle.generateKey(keyParams(input.keyAlgorithm, hash), true, ["sign", "verify"])) as CryptoKeyPair;
  const algorithm = isRsa(input.keyAlgorithm) ? { name: "RSASSA-PKCS1-v1_5", hash } : { name: "ECDSA", hash };
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: subjectName(input.commonName, input.subject),
    keys,
    signingAlgorithm: algorithm,
    extensions: [new x509.SubjectAlternativeNameExtension(input.names.map((value) => ({ type: "dns" as const, value })))],
  });
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
  return { keyPem: x509.PemConverter.encode(pkcs8, "PRIVATE KEY"), csrPem: csr.toString("pem") };
}
