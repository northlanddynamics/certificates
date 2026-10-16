/**
 * SCEP pkiMessage encoding and decoding (RFC 8894 §3).
 *
 * ```
 * pkiMessage = ContentInfo(SignedData {
 *   encapContentInfo: id-data, eContent = pkcsPKIEnvelope (EnvelopedData) — omitted for
 *                     CertRep with pkiStatus FAILURE or PENDING
 *   signerInfo.signedAttrs: transactionID, messageType, senderNonce, [recipientNonce],
 *                           [pkiStatus], [failInfo], [failInfoText], contentType, messageDigest
 * })
 * ```
 */
import type { KeyObject, X509Certificate } from "node:crypto";
import { FailInfo, MessageType, PkiStatus, type DigestAlgorithm, type EncryptionAlgorithm, type KeyTransportAlgorithm } from "./constants.js";
import { type PublicKeyLike } from "./crypto.js";
import { type BytesLike } from "./util.js";
import { type CertificateLike, type NameInput } from "./x509.js";
/** Size of sender/recipient nonces (RFC 8894 §3.2.1.5: 16 bytes of random data). */
export declare const NONCE_LENGTH = 16;
/** A certificate and its private key, used to sign SCEP messages and decrypt replies. */
export interface ScepIdentity {
    certificate: X509Certificate;
    privateKey: KeyObject;
}
export interface EncodePkiMessageOptions {
    messageType: MessageType;
    transactionId: string;
    /** 16 random bytes are generated when omitted. */
    senderNonce?: BytesLike;
    /** Required on CertRep: the senderNonce of the request being answered. */
    recipientNonce?: BytesLike;
    pkiStatus?: PkiStatus;
    failInfo?: FailInfo;
    failInfoText?: string;
    /** messageData, sent inside the pkcsPKIEnvelope encrypted for `recipient`. */
    messageData?: BytesLike;
    /** Certificate the pkcsPKIEnvelope is encrypted for. Required with `messageData`. */
    recipient?: X509Certificate;
    signer: ScepIdentity;
    digestAlgorithm?: DigestAlgorithm;
    encryptionAlgorithm?: EncryptionAlgorithm;
    /** Key-transport scheme for the pkcsPKIEnvelope (default rsa-pkcs1). */
    keyTransport?: KeyTransportAlgorithm;
    /** Additional certificates to include in the SignedData (the signer certificate is always included). */
    certificates?: X509Certificate[];
    /** signingTime attribute; defaults to now, `false` omits it. */
    signingTime?: Date | false;
}
/** Build a signed (and, where there is message data, enveloped) SCEP pkiMessage. */
export declare function encodePkiMessage(opts: EncodePkiMessageOptions): Buffer;
/** A decoded and signature-verified pkiMessage. */
export interface PkiMessage {
    messageType: MessageType;
    transactionId: string;
    senderNonce: Buffer;
    recipientNonce?: Buffer;
    pkiStatus?: PkiStatus;
    failInfo?: FailInfo;
    failInfoText?: string;
    signingTime?: Date;
    /** Certificate that signed the message. */
    signerCertificate: X509Certificate;
    /** All certificates carried in the SignedData. */
    certificates: X509Certificate[];
    digestAlgorithm: DigestAlgorithm;
    /** The encrypted pkcsPKIEnvelope (ContentInfo DER), if present. */
    envelope?: Buffer;
    /** Decrypted messageData, if an envelope was present and recipient credentials were supplied. */
    messageData?: Buffer;
    /** Content-encryption algorithm of the envelope, once decrypted. */
    encryptionAlgorithm?: EncryptionAlgorithm;
    /** Key-transport scheme of the envelope, once decrypted. */
    keyTransport?: KeyTransportAlgorithm;
}
export interface DecodePkiMessageOptions {
    /** Credentials to decrypt the pkcsPKIEnvelope. Without them `messageData` is left undefined. */
    recipient?: ScepIdentity;
    /** Candidate signer certificates, for messages that do not carry their signer's certificate. */
    signerCertificates?: X509Certificate[];
}
/** Decode a pkiMessage, verifying its signature and (optionally) decrypting its envelope. */
export declare function decodePkiMessage(der: BytesLike, opts?: DecodePkiMessageOptions): PkiMessage;
/**
 * Read the SCEP attributes of a message without verifying it. Useful for a server that
 * must reply with a FAILURE CertRep to a message whose signature does not verify.
 */
export declare function peekPkiMessage(der: BytesLike): {
    messageType?: number;
    transactionId?: string;
    senderNonce?: Buffer;
    signerCertificate?: X509Certificate;
} | undefined;
/** IssuerAndSerialNumber — messageData of GetCert and GetCRL. */
export declare function encodeIssuerAndSerialNumber(issuer: NameInput, serialNumber: BytesLike): Buffer;
/** IssuerAndSerialNumber identifying an existing certificate. */
export declare function issuerAndSerialNumberOfCertificate(cert: CertificateLike): Buffer;
export declare function decodeIssuerAndSerialNumber(der: BytesLike): {
    issuer: Buffer;
    serialNumber: Buffer;
};
/** IssuerAndSubject — messageData of CertPoll. */
export declare function encodeIssuerAndSubject(issuer: NameInput, subject: NameInput): Buffer;
export declare function decodeIssuerAndSubject(der: BytesLike): {
    issuer: Buffer;
    subject: Buffer;
};
/**
 * Derive a transactionID from a public key: upper-case hex SHA-256 of the SubjectPublicKeyInfo.
 * Deterministic IDs let a client resume a transaction after a restart. Any unique
 * PrintableString is acceptable (RFC 8894 §3.2.1.1).
 */
export declare function transactionIdFromPublicKey(key: PublicKeyLike): string;
/** A random transactionID (32 hex characters). */
export declare function randomTransactionId(): string;
