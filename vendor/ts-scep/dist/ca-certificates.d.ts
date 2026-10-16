import type { X509Certificate } from "node:crypto";
/**
 * The CA (and optional RA) certificates returned by GetCACert, classified by role
 * (RFC 8894 §4.2). When an RA is in use, requests are encrypted for the RA's encryption
 * certificate and responses are signed by the RA's signing certificate.
 */
export declare class CACertificates {
    readonly all: X509Certificate[];
    /** The issuing CA certificate. */
    readonly ca: X509Certificate;
    /** RA certificates (non-CA certificates), if any. */
    readonly ra: X509Certificate[];
    constructor(all: X509Certificate[]);
    /** Certificate a client encrypts its pkcsPKIEnvelope for. */
    get encryptionCertificate(): X509Certificate;
    /** Certificate expected to sign CertRep messages. */
    get signingCertificate(): X509Certificate;
    /** True if `cert` belongs to this set or was issued by the CA (e.g. a rolled-over RA certificate). */
    isTrustedSigner(cert: X509Certificate): boolean;
    private pick;
}
