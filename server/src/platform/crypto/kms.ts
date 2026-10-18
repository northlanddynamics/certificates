// The key management service. It wraps each Organization's data key (see secrets.ts), and holds Private CA signing
// keys, which never leave it (ADR 0007, ADR 0009). The platform holds only wrapped keys and key references, so what
// opens or signs with them is the KMS: AWS KMS, Google Cloud KMS and Azure Key Vault are meant to plug in behind this interface; the
// local implementation below is for development and tests.
import { constants, createECDH, createHash, createPrivateKey, createPublicKey, generateKeyPairSync, privateEncrypt, randomBytes, type KeyObject } from "node:crypto";
import { ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { open, seal } from "./aead";
import { KEY_ALGORITHMS, isMlDsa, type ClassicalKeyAlgorithm, type KeyAlgorithm } from "../../pki/key-algorithms";

/** The key algorithms the KMS makes signing keys of: every one but ML-DSA-44, too weak for a CA key. */
export type SigningKeyAlgorithm = Exclude<KeyAlgorithm, "ml-dsa-44">;
export const SIGNING_KEY_ALGORITHMS = KEY_ALGORITHMS.filter((algorithm): algorithm is SigningKeyAlgorithm => algorithm !== "ml-dsa-44");

/** The hash each ECDSA and RSA key algorithm signs with; `sign` takes a digest made with it. */
export const SIGNATURE_HASH: Record<ClassicalKeyAlgorithm, "SHA-256" | "SHA-384"> = {
  "ecdsa-p256": "SHA-256",
  "ecdsa-p384": "SHA-384",
  "rsa-2048": "SHA-256",
  "rsa-3072": "SHA-256",
  "rsa-4096": "SHA-256",
};

const HASH_BYTES = { "SHA-256": 32, "SHA-384": 48 };

/** The length of an ML-DSA public key, which ends its DER SubjectPublicKeyInfo (FIPS 204, table 2). */
const ML_DSA_PUBLIC_KEY_BYTES = { "ml-dsa-65": 1952, "ml-dsa-87": 2592 };
const MU_BYTES = 64;

const shake256 = (...parts: Uint8Array[]) => {
  const hash = createHash("shake256", { outputLength: MU_BYTES });
  for (const part of parts) hash.update(part);
  return new Uint8Array(hash.digest());
};

/**
 * The external μ of `message` for the ML-DSA key whose DER SubjectPublicKeyInfo is `spki`: what `sign` takes for an
 * ML-DSA key, after which the signature is a pure ML-DSA one, with an empty context, over the whole message (FIPS 204,
 * algorithms 2 and 7). tr = SHAKE256(publicKey), μ = SHAKE256(tr ‖ 0x00 ‖ 0x00 ‖ message), both 64 bytes.
 */
export function externalMu(algorithm: "ml-dsa-65" | "ml-dsa-87", spki: Uint8Array, message: Uint8Array): Uint8Array {
  const publicKey = spki.subarray(spki.length - ML_DSA_PUBLIC_KEY_BYTES[algorithm]);
  return shake256(shake256(publicKey), new Uint8Array([0, 0]), message);
}

export interface Kms {
  /** Wraps `dataKey`, binding it to `context` (an Organization's id) so it unwraps only for the same context. */
  wrap(dataKey: Uint8Array, context: string): Promise<Uint8Array>;
  /** Throws when `wrapped` was not produced by this KMS for this `context`. */
  unwrap(wrapped: Uint8Array, context: string): Promise<Uint8Array>;
  /**
   * Makes a non-exportable signing key bound to `context` (an Organization's id) and returns an opaque reference to
   * it, which is all the platform stores.
   */
  createSigningKey(algorithm: SigningKeyAlgorithm, context: string): Promise<string>;
  /** The key's public key as a DER SubjectPublicKeyInfo. Throws when `key` was not made by this KMS for `context`. */
  publicKey(key: string, context: string): Promise<Uint8Array>;
  /**
   * Signs, with an ECDSA or RSA key, a digest made with the key algorithm's SIGNATURE_HASH, and returns the signature
   * as WebCrypto gives it: ECDSA as r ‖ s, RSA as PKCS#1 v1.5. With an ML-DSA key it signs the message's `externalMu`
   * and returns the signature raw, as X.509 carries it. Throws when `key` was not made by this KMS for `context`.
   */
  sign(key: string, context: string, toSign: Uint8Array): Promise<Uint8Array>;
}

/** A KMS whose master key is a base64 string of 32 bytes held in the platform's own configuration. */
export function createLocalKms(masterKeyBase64: string): Kms {
  const masterKey = Buffer.from(masterKeyBase64, "base64");
  if (masterKey.length !== 32) throw new Error("the local KMS key must be 32 bytes, base64-encoded");

  // A local key reference carries the key itself, wrapped under the master key and bound to its algorithm and context.
  const PREFIX = "local-signing-key:v1";
  const signingAad = (algorithm: string, context: string) => Buffer.from(`signing-key:${algorithm}:${context}`);

  function openSigningKey(reference: string, context: string): { algorithm: SigningKeyAlgorithm; privateKey: KeyObject } {
    const [prefix, version, algorithm, wrapped] = reference.split(":");
    if (`${prefix}:${version}` !== PREFIX || !algorithm || !wrapped) throw new Error("not a signing key of this KMS");
    const pkcs8 = open(masterKey, Buffer.from(wrapped, "base64url"), signingAad(algorithm, context));
    return { algorithm: algorithm as SigningKeyAlgorithm, privateKey: createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" }) };
  }

  return {
    wrap: async (dataKey, context) => seal(masterKey, dataKey, Buffer.from(context)),
    unwrap: async (wrapped, context) => open(masterKey, wrapped, Buffer.from(context)),
    async createSigningKey(algorithm, context) {
      if (!(SIGNING_KEY_ALGORITHMS as readonly string[]).includes(algorithm)) throw new Error(`the KMS makes no ${algorithm} signing keys`);
      const { privateKey } = generateKeyPair(algorithm);
      const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" });
      return `${PREFIX}:${algorithm}:${seal(masterKey, pkcs8, signingAad(algorithm, context)).toString("base64url")}`;
    },
    async publicKey(reference, context) {
      const { privateKey } = openSigningKey(reference, context);
      return new Uint8Array(createPublicKey(privateKey).export({ format: "der", type: "spki" }));
    },
    async sign(reference, context, toSign) {
      const { algorithm, privateKey } = openSigningKey(reference, context);
      if (isMlDsa(algorithm)) return signMu(algorithm, privateKey, toSign);
      return new Uint8Array(signDigest(algorithm, privateKey, Buffer.from(toSign)));
    },
  };
}

function generateKeyPair(algorithm: SigningKeyAlgorithm) {
  // Bun's own ML-DSA, which exports the private key in the seed form (RFC 9881). Node's types do not know it yet.
  if (isMlDsa(algorithm)) return (generateKeyPairSync as unknown as (type: string) => { privateKey: KeyObject })(algorithm);
  if (algorithm === "ecdsa-p256" || algorithm === "ecdsa-p384") return generateKeyPairSync("ec", { namedCurve: CURVES[algorithm].openssl });
  return generateKeyPairSync("rsa", { modulusLength: RSA_BITS[algorithm] });
}

const RSA_BITS = { "rsa-2048": 2048, "rsa-3072": 3072, "rsa-4096": 4096 };

const NOBLE_ML_DSA = { "ml-dsa-65": ml_dsa65, "ml-dsa-87": ml_dsa87 };
/** How a seed-form ML-DSA PrivateKeyInfo ends: privateKey as [0] IMPLICIT OCTET STRING of 32 bytes, then the seed. */
const SEED_TAG = Buffer.from("8020", "hex");
const SEED_BYTES = 32;

// Node signs only a whole message, and a KMS signs μ (a CRL can outgrow what a KMS takes), so ML-DSA is signed with
// noble's internal signing, which takes an external μ, from the key's seed.
function signMu(algorithm: "ml-dsa-65" | "ml-dsa-87", privateKey: KeyObject, mu: Uint8Array): Uint8Array {
  if (mu.length !== MU_BYTES) throw new Error(`a ${algorithm} key signs a ${MU_BYTES}-byte μ`);
  const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" });
  if (!pkcs8.subarray(-SEED_BYTES - SEED_TAG.length, -SEED_BYTES).equals(SEED_TAG)) throw new Error(`the ${algorithm} key is not in the seed form`);
  const { secretKey } = NOBLE_ML_DSA[algorithm].keygen(pkcs8.subarray(-SEED_BYTES));
  return NOBLE_ML_DSA[algorithm].internal.sign(mu, secretKey, { externalMu: true });
}

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

function signDigest(algorithm: ClassicalKeyAlgorithm, privateKey: KeyObject, digest: Buffer): Buffer {
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
