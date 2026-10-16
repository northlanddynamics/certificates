/**
 * X.509 helpers: distinguished names, certificates, PKCS #10 requests and CRLs.
 * Certificates are exposed as Node.js `X509Certificate` objects.
 */
import { X509Certificate, type KeyObject } from "node:crypto";
import * as x509 from "@peculiar/asn1-x509";
import { CertificationRequest } from "@peculiar/asn1-csr";
import type { DigestAlgorithm } from "./constants.js";
import { type PrivateKeyLike, type PublicKeyLike } from "./crypto.js";
import { type BytesLike } from "./util.js";
/** Certificates may be given as `X509Certificate`, PEM text or DER bytes. */
export type CertificateLike = X509Certificate | string | Uint8Array;
export declare function toCertificate(cert: CertificateLike): X509Certificate;
/** Parse one or more certificates from PEM text or a single DER certificate. */
export declare function parseCertificates(input: string | Uint8Array): X509Certificate[];
/**
 * A distinguished name. Accepts:
 * - an RFC 4514 string (`"CN=device-1,O=Example,C=US"`, most-specific RDN first),
 * - an OpenSSL-style string (`"/C=US/O=Example/CN=device-1"`, encoding order),
 * - an array of `[type, value]` pairs in encoding order (type may be a short name or an OID),
 * - a DER-encoded Name, or an already-built asn1-x509 `Name`.
 */
export type NameInput = string | Array<[string, string]> | Uint8Array | x509.Name;
export declare function buildName(input: NameInput): x509.Name;
/** DER encoding of a distinguished name. */
export declare function encodeName(input: NameInput): Buffer;
/** Render a Name as an RFC 4514 string (most-specific RDN first). */
export declare function nameToString(input: NameInput): string;
export declare function parseCertificateAsn(cert: CertificateLike): x509.Certificate;
/** DER issuer Name of a certificate. */
export declare function certificateIssuer(cert: CertificateLike): Buffer;
/** DER subject Name of a certificate. */
export declare function certificateSubject(cert: CertificateLike): Buffer;
/** Serial number bytes (as encoded, possibly with a leading zero). */
export declare function certificateSerialNumber(cert: CertificateLike): Buffer;
export declare function certificateSubjectKeyIdentifier(cert: CertificateLike): Buffer | undefined;
export declare function certificateKeyUsage(cert: CertificateLike): number | undefined;
/** True if the certificate's subject equals its issuer and it verifies with its own key. */
export declare function isSelfSigned(cert: CertificateLike): boolean;
/** True if `cert` was issued (and signed) by `issuer`. */
export declare function isIssuedBy(cert: CertificateLike, issuer: CertificateLike): boolean;
export declare function sameCertificate(a: CertificateLike, b: CertificateLike): boolean;
export declare function samePublicKey(a: PublicKeyLike, b: PublicKeyLike): boolean;
export interface SubjectAltNames {
    dns?: string[];
    email?: string[];
    uri?: string[];
    ip?: string[];
    /** Raw GeneralName objects for anything else (e.g. otherName UPNs). */
    other?: x509.GeneralName[];
}
export type KeyUsageName = keyof typeof x509.KeyUsageFlags;
/** Extension options shared by certificate and CSR builders. */
export interface ExtensionOptions {
    subjectAltNames?: SubjectAltNames;
    keyUsage?: KeyUsageName[];
    /** Extended key usage OIDs, e.g. `"1.3.6.1.5.5.7.3.2"` (clientAuth). */
    extendedKeyUsage?: string[];
    /** Additional pre-built extensions. */
    extensions?: x509.Extension[];
}
export interface CreateCertificateOptions extends ExtensionOptions {
    subject: NameInput;
    /** Public key to certify. */
    publicKey: PublicKeyLike;
    /** Key that signs the certificate (the CA key, or the subject's own key for a self-signed certificate). */
    signingKey: PrivateKeyLike;
    /** Issuer certificate; omit for a self-signed certificate. */
    issuer?: CertificateLike;
    /** Serial number bytes; a random positive 128-bit value by default. */
    serialNumber?: Uint8Array;
    notBefore?: Date;
    notAfter?: Date;
    /** Mark as CA certificate (basicConstraints cA=TRUE). */
    isCA?: boolean;
    pathLength?: number;
    digestAlgorithm?: DigestAlgorithm;
}
export declare function randomSerialNumber(): Buffer;
/** Create and sign an X.509 v3 certificate. */
export declare function createCertificate(opts: CreateCertificateOptions): X509Certificate;
/**
 * Create the self-signed certificate a SCEP client uses to sign its first request and to
 * receive the encrypted CertRep (RFC 8894 §2.3).
 */
export declare function createSelfSignedCertificate(opts: {
    subject: NameInput;
    privateKey: PrivateKeyLike;
    validityDays?: number;
    digestAlgorithm?: DigestAlgorithm;
}): X509Certificate;
export interface CreateCsrOptions extends ExtensionOptions {
    subject: NameInput;
    privateKey: PrivateKeyLike;
    /** Shared secret for authorising the request (PKCS #9 challengePassword, RFC 8894 §2.2). */
    challengePassword?: string;
    digestAlgorithm?: DigestAlgorithm;
}
/** Create a DER-encoded PKCS #10 certification request. */
export declare function createCsr(opts: CreateCsrOptions): Buffer;
export interface ParsedCsr {
    /** DER of the whole request. */
    der: Buffer;
    /** DER of the subject Name. */
    subject: Buffer;
    /** RFC 4514 rendering of the subject. */
    subjectString: string;
    publicKey: KeyObject;
    challengePassword?: string;
    /** Requested extensions (from the PKCS #9 extensionRequest attribute). */
    extensions: x509.Extension[];
    /** Whether the self-signature verifies. */
    signatureValid: boolean;
    asn: CertificationRequest;
}
/** Parse a DER (or PEM) PKCS #10 request and verify its self-signature. */
export declare function parseCsr(input: BytesLike | string): ParsedCsr;
export interface CreateCrlOptions {
    issuer: CertificateLike;
    signingKey: PrivateKeyLike;
    revoked?: Array<{
        serialNumber: Uint8Array;
        revocationDate?: Date;
    }>;
    thisUpdate?: Date;
    nextUpdate?: Date;
    digestAlgorithm?: DigestAlgorithm;
}
/** Create a DER-encoded X.509 v2 CRL. */
export declare function createCrl(opts: CreateCrlOptions): Buffer;
