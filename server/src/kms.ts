// The key management service. It wraps each Organization's data key (see secrets.ts), and holds Private CA signing
// keys, which never leave it (ADR 0007). The platform holds only wrapped keys and key references, so what opens or
// signs with them is the KMS: AWS KMS and Azure Key Vault are meant to plug in behind this interface; the local
// implementation below is for development and tests.
import { constants, createECDH, createPrivateKey, createPublicKey, generateKeyPairSync, privateEncrypt, randomBytes, type KeyObject } from "node:crypto";
import { open, seal } from "./aead";
import type { KeyAlgorithm } from "./csr";

/** The hash each key algorithm signs with; `sign` takes a digest made with it. */
export const SIGNATURE_HASH: Record<KeyAlgorithm, "SHA-256" | "SHA-384"> = {
  "ecdsa-p256": "SHA-256",
  "ecdsa-p384": "SHA-384",
  "rsa-2048": "SHA-256",
  "rsa-3072": "SHA-256",
  "rsa-4096": "SHA-256",
};

const HASH_BYTES = { "SHA-256": 32, "SHA-384": 48 };

export interface Kms {
  /** Wraps `dataKey`, binding it to `context` (an Organization's id) so it unwraps only for the same context. */
  wrap(dataKey: Uint8Array, context: string): Promise<Uint8Array>;
  /** Throws when `wrapped` was not produced by this KMS for this `context`. */
  unwrap(wrapped: Uint8Array, context: string): Promise<Uint8Array>;
  /**
   * Makes a non-exportable signing key bound to `context` (an Organization's id) and returns an opaque reference to
   * it, which is all the platform stores.
   */
  createSigningKey(algorithm: KeyAlgorithm, context: string): Promise<string>;
  /** The key's public key as a DER SubjectPublicKeyInfo. Throws when `key` was not made by this KMS for `context`. */
  publicKey(key: string, context: string): Promise<Uint8Array>;
  /**
   * Signs `digest`, made with the key algorithm's SIGNATURE_HASH, and returns the signature as WebCrypto gives it:
   * ECDSA as r ‖ s, RSA as PKCS#1 v1.5. Throws when `key` was not made by this KMS for `context`.
   */
  sign(key: string, context: string, digest: Uint8Array): Promise<Uint8Array>;
}

/** A KMS whose master key is a base64 string of 32 bytes held in the platform's own configuration. */
export function createLocalKms(masterKeyBase64: string): Kms {
  const masterKey = Buffer.from(masterKeyBase64, "base64");
  if (masterKey.length !== 32) throw new Error("the local KMS key must be 32 bytes, base64-encoded");

  // A local key reference carries the key itself, wrapped under the master key and bound to its algorithm and context.
  const PREFIX = "local-signing-key:v1";
  const signingAad = (algorithm: string, context: string) => Buffer.from(`signing-key:${algorithm}:${context}`);

  function openSigningKey(reference: string, context: string): { algorithm: KeyAlgorithm; privateKey: KeyObject } {
    const [prefix, version, algorithm, wrapped] = reference.split(":");
    if (`${prefix}:${version}` !== PREFIX || !algorithm || !wrapped) throw new Error("not a signing key of this KMS");
    const pkcs8 = open(masterKey, Buffer.from(wrapped, "base64url"), signingAad(algorithm, context));
    return { algorithm: algorithm as KeyAlgorithm, privateKey: createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" }) };
  }

  return {
    wrap: async (dataKey, context) => seal(masterKey, dataKey, Buffer.from(context)),
    unwrap: async (wrapped, context) => open(masterKey, wrapped, Buffer.from(context)),
    async createSigningKey(algorithm, context) {
      const { privateKey } = generateKeyPair(algorithm);
      const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" });
      return `${PREFIX}:${algorithm}:${seal(masterKey, pkcs8, signingAad(algorithm, context)).toString("base64url")}`;
    },
    async publicKey(reference, context) {
      const { privateKey } = openSigningKey(reference, context);
      return new Uint8Array(createPublicKey(privateKey).export({ format: "der", type: "spki" }));
    },
    async sign(reference, context, digest) {
      const { algorithm, privateKey } = openSigningKey(reference, context);
      return new Uint8Array(signDigest(algorithm, privateKey, Buffer.from(digest)));
    },
  };
}

function generateKeyPair(algorithm: KeyAlgorithm) {
  if (algorithm === "ecdsa-p256" || algorithm === "ecdsa-p384") return generateKeyPairSync("ec", { namedCurve: CURVES[algorithm].openssl });
  return generateKeyPairSync("rsa", { modulusLength: RSA_BITS[algorithm] });
}

const RSA_BITS = { "rsa-2048": 2048, "rsa-3072": 3072, "rsa-4096": 4096 };

// Node signs only messages, which it hashes itself, and a KMS signs digests (a CRL can outgrow what a KMS takes to
// hash for you). So ECDSA is done here from its definition, with OpenSSL's scalar multiplication (ECDH) for k·G.
interface Curve {
  openssl: string;
  /** The length of the order n, and of r and s. */
  bytes: number;
  n: bigint;
}

const CURVES: Record<"ecdsa-p256" | "ecdsa-p384", Curve> = {
  "ecdsa-p256": { openssl: "prime256v1", bytes: 32, n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n },
  "ecdsa-p384": {
    openssl: "secp384r1",
    bytes: 48,
    n: 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
  },
};

function signDigest(algorithm: KeyAlgorithm, privateKey: KeyObject, digest: Buffer): Buffer {
  if (digest.length !== HASH_BYTES[SIGNATURE_HASH[algorithm]]) throw new Error(`a ${algorithm} key signs a ${SIGNATURE_HASH[algorithm]} digest`);
  if (algorithm === "ecdsa-p256" || algorithm === "ecdsa-p384") return ecdsaSign(CURVES[algorithm], privateKey, digest);
  // RSASSA-PKCS1-v1_5 is the padded DigestInfo of the digest, raised to the private exponent.
  return privateEncrypt({ key: privateKey, padding: constants.RSA_PKCS1_PADDING }, Buffer.concat([SHA256_DIGEST_INFO, digest]));
}

/** The DER DigestInfo for SHA-256, up to the digest itself (RFC 8017, section 9.2). */
const SHA256_DIGEST_INFO = Buffer.from("3031300d060960864801650304020105000420", "hex");

function ecdsaSign(curve: Curve, privateKey: KeyObject, digest: Buffer): Buffer {
  const { n, bytes, openssl } = curve;
  const d = toBigInt(Buffer.from(privateKey.export({ format: "jwk" }).d!, "base64url"));
  const e = toBigInt(digest) % n; // the digest is as long as n, so no bits need dropping
  for (;;) {
    const k = toBigInt(randomBytes(bytes));
    if (k === 0n || k >= n) continue;
    const ecdh = createECDH(openssl);
    ecdh.setPrivateKey(toBytes(k, bytes));
    const x = toBigInt(ecdh.getPublicKey().subarray(1, 1 + bytes)); // uncompressed point: 04 ‖ x ‖ y
    const r = x % n;
    if (r === 0n) continue;
    const s = (inverse(k, n) * (e + r * d)) % n;
    if (s === 0n) continue;
    return Buffer.concat([toBytes(r, bytes), toBytes(s, bytes)]);
  }
}

const toBigInt = (bytes: Uint8Array) => (bytes.length === 0 ? 0n : BigInt(`0x${Buffer.from(bytes).toString("hex")}`));
const toBytes = (value: bigint, length: number) => Buffer.from(value.toString(16).padStart(length * 2, "0"), "hex");

/** a⁻¹ mod m, for prime m: Fermat's little theorem. */
function inverse(a: bigint, m: bigint) {
  let result = 1n;
  let base = a % m;
  for (let exponent = m - 2n; exponent > 0n; exponent >>= 1n) {
    if (exponent & 1n) result = (result * base) % m;
    base = (base * base) % m;
  }
  return result;
}
