import type { KeyObject } from "node:crypto";
import type { DigestAlgorithm, EncryptionAlgorithm, KeyTransportAlgorithm } from "./constants.js";
import { type BytesLike } from "./util.js";
/** Private keys may be given as KeyObjects, PEM text or PKCS#8 DER. */
export type PrivateKeyLike = KeyObject | string | Uint8Array;
/** Public keys may be given as KeyObjects, PEM text or SPKI DER. */
export type PublicKeyLike = KeyObject | string | Uint8Array;
export declare function toPrivateKey(key: PrivateKeyLike): KeyObject;
export declare function toPublicKey(key: PublicKeyLike): KeyObject;
/** Generate an RSA key pair suitable for SCEP (RSA is required for CMS key transport). */
export declare function generateRsaKeyPair(modulusLength?: number): {
    publicKey: KeyObject;
    privateKey: KeyObject;
};
export declare const DIGEST_OIDS: Record<DigestAlgorithm, string>;
export declare const RSA_SIGNATURE_OIDS: Record<DigestAlgorithm, string>;
export declare function digestAlgorithmFromOid(oid: string): DigestAlgorithm;
/**
 * Determine the digest used by a signature algorithm identifier, falling back to the
 * separately-specified digest algorithm (CMS signerInfos commonly use plain rsaEncryption).
 */
export declare function signatureDigest(signatureOid: string, fallback: DigestAlgorithm): DigestAlgorithm;
export declare function digest(algorithm: DigestAlgorithm, data: BytesLike): Buffer;
export declare function sign(algorithm: DigestAlgorithm, key: KeyObject, data: BytesLike): Buffer;
export declare function verify(algorithm: DigestAlgorithm, key: KeyObject, data: BytesLike, signature: BytesLike): boolean;
/** Signature algorithm OID for a key and digest (used for X.509 certificates, CRLs and CSRs). */
export declare function signatureAlgorithmOid(key: KeyObject, algorithm: DigestAlgorithm): string;
/** A key-transport scheme with its defaults filled in. */
export type ResolvedKeyTransport = {
    scheme: "rsa-pkcs1";
} | {
    scheme: "rsa-oaep";
    hash: DigestAlgorithm;
    label: Buffer;
};
export declare function resolveKeyTransport(algorithm?: KeyTransportAlgorithm): ResolvedKeyTransport;
export declare function rsaEncrypt(key: KeyObject, data: BytesLike, keyTransport?: ResolvedKeyTransport): Buffer;
/**
 * Decrypt a content-encryption key. As with PKCS #1 v1.5, an OAEP decoding failure is turned
 * into a random key of the expected length (when known) so that every failure surfaces as the
 * same content-decryption error, leaving no padding oracle (Manger's attack).
 */
export declare function rsaDecrypt(key: KeyObject, data: BytesLike, expectedLength?: number, keyTransport?: ResolvedKeyTransport): Buffer;
/**
 * Key-derivation key for implicit rejection: HMAC-SHA256 keyed with SHA-256 of the private
 * exponent (big-endian, modulus length), over the ciphertext left-padded to the modulus length.
 * @internal
 */
export declare function implicitRejectionKdk(key: KeyObject, ciphertext: Uint8Array): Buffer;
/** HMAC-SHA256 counter-mode PRF of draft-irtf-cfrg-rsa-guidance. @internal */
export declare function rsaPrf(kdk: Buffer, label: string, length: number): Buffer;
/**
 * Decode EM = 0x00 || 0x02 || PS || 0x00 || M (|PS| >= 8) with implicit rejection: on malformed
 * padding, return a synthetic message whose length and content are derived from `kdk`. The work
 * done does not depend on the padding.
 * @internal
 */
export declare function pkcs1v15DecodeImplicit(em: Uint8Array, kdk: Buffer): Buffer;
interface CipherInfo {
    oid: string;
    keyLength: number;
    ivLength: number;
}
export declare const CONTENT_ENCRYPTION: Record<EncryptionAlgorithm, CipherInfo>;
export declare function encryptionAlgorithmFromOid(oid: string): EncryptionAlgorithm;
export declare function encryptContent(algorithm: EncryptionAlgorithm, plaintext: BytesLike): {
    key: Buffer;
    iv: Buffer;
    ciphertext: Buffer;
};
export declare function decryptContent(algorithm: EncryptionAlgorithm, key: BytesLike, iv: BytesLike, ciphertext: BytesLike): Buffer;
export declare function randomBytes(length: number): Buffer;
export {};
