/**
 * The subset of CMS (RFC 5652) that SCEP uses: SignedData with signed attributes, degenerate
 * certificates-only SignedData, and EnvelopedData with RSA key transport.
 */
import type { KeyObject, X509Certificate } from "node:crypto";
import * as cms from "@peculiar/asn1-cms";
import { ScepSignedData } from "./asn1.js";
import type { DigestAlgorithm, EncryptionAlgorithm, KeyTransportAlgorithm } from "./constants.js";
import { type BytesLike } from "./util.js";
export declare function encodeContentInfo(contentType: string, content: BytesLike): Buffer;
export declare function decodeContentInfo(der: BytesLike, expectedType?: string): {
    contentType: string;
    content: Buffer;
};
export interface Signer {
    certificate: X509Certificate;
    privateKey: KeyObject;
    digestAlgorithm: DigestAlgorithm;
    /** Additional signed attributes (type OID → DER-encoded values). */
    attributes?: Array<{
        type: string;
        values: BytesLike[];
    }>;
    /** Include a signingTime attribute. Defaults to the current time; `false` omits it. */
    signingTime?: Date | false;
}
export interface CreateSignedDataOptions {
    /** Encapsulated content (eContentType id-data). Omitted for degenerate or content-less SignedData. */
    content?: BytesLike;
    signer?: Signer;
    certificates?: X509Certificate[];
    /** DER-encoded CRLs. */
    crls?: BytesLike[];
}
/** Build a CMS ContentInfo wrapping SignedData. */
export declare function createSignedData(opts: CreateSignedDataOptions): Buffer;
/** A certificates-only ("degenerate") SignedData carrying certificates and/or CRLs (RFC 8894 §3.4). */
export declare function createDegenerateSignedData(certificates: X509Certificate[], crls?: BytesLike[]): Buffer;
export interface ParsedSignedData {
    /** eContentType of the encapsulated content. */
    contentType: string;
    /** Encapsulated content, if present. */
    content?: Buffer;
    certificates: X509Certificate[];
    /** DER-encoded CRLs. */
    crls: Buffer[];
    signerInfos: cms.SignerInfo[];
    asn: ScepSignedData;
}
/** Parse a ContentInfo carrying SignedData. Signatures are not checked; see {@link verifySignerInfo}. */
export declare function parseSignedData(der: BytesLike): ParsedSignedData;
export interface VerifiedSigner {
    certificate: X509Certificate;
    digestAlgorithm: DigestAlgorithm;
    /** Signed attributes: OID → list of DER-encoded values. */
    attributes: Map<string, Buffer[]>;
    signingTime?: Date;
}
/**
 * Verify a SignerInfo: locate the signer certificate (in the SignedData or among
 * `candidates`), check the messageDigest and contentType attributes and the signature.
 */
export declare function verifySignerInfo(sd: ParsedSignedData, signerInfo: cms.SignerInfo, candidates?: X509Certificate[]): VerifiedSigner;
/** Encrypt `content` for `recipient` (RSA key transport) and wrap it in a ContentInfo. */
export declare function createEnvelopedData(content: BytesLike, recipient: X509Certificate, algorithm: EncryptionAlgorithm, keyTransport?: KeyTransportAlgorithm): Buffer;
export interface OpenedEnvelope {
    content: Buffer;
    algorithm: EncryptionAlgorithm;
    /** Key-transport scheme the sender used for the content-encryption key. */
    keyTransport: KeyTransportAlgorithm;
}
/** Decrypt a ContentInfo carrying EnvelopedData using the recipient's certificate and key. */
export declare function openEnvelopedData(der: BytesLike, certificate: X509Certificate, privateKey: KeyObject): OpenedEnvelope;
