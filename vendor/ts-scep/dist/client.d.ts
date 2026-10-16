/**
 * SCEP client (RFC 8894 §4): CA discovery, enrolment, renewal, polling and certificate/CRL
 * retrieval over HTTP.
 */
import { X509Certificate } from "node:crypto";
import { CACapabilities } from "./capabilities.js";
import { CACertificates } from "./ca-certificates.js";
import { PkiStatus, type DigestAlgorithm, type EncryptionAlgorithm, type KeyTransportAlgorithm } from "./constants.js";
import { type PrivateKeyLike } from "./crypto.js";
import { type PkiMessage, type ScepIdentity } from "./message.js";
import { type BytesLike } from "./util.js";
import { type CertificateLike, type NameInput } from "./x509.js";
export type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;
export interface ScepClientOptions {
    /** SCEP endpoint, e.g. `http://ca.example.com/cgi-bin/pkiclient.exe`. */
    url: string | URL;
    /** Value of the `message` parameter for GetCACert/GetCACaps/GetNextCACert (a CA identifier). */
    caIdentifier?: string;
    /**
     * Expected fingerprint (SHA-256 or SHA-1, hex with or without colons) of the CA certificate.
     * Strongly recommended: GetCACert runs over unauthenticated HTTP (RFC 8894 §2.2).
     */
    caFingerprint?: string;
    /** Pre-provisioned CA/RA certificates; GetCACert is skipped when given. */
    caCertificates?: CertificateLike[];
    /** Pre-known capabilities; GetCACaps is skipped when given. */
    capabilities?: string[];
    /** Override the negotiated digest algorithm. */
    digestAlgorithm?: DigestAlgorithm;
    /** Override the negotiated content-encryption algorithm. */
    encryptionAlgorithm?: EncryptionAlgorithm;
    /**
     * Key-transport scheme for request envelopes (default `rsa-pkcs1`). RFC 8894 defines no
     * capability keyword for RSAES-OAEP, so only enable it for CAs known to accept it.
     */
    keyTransport?: KeyTransportAlgorithm;
    /** Force (true) or forbid (false) HTTP POST for PKIOperation. Negotiated from capabilities by default. */
    usePost?: boolean;
    /** Extra HTTP headers on every request. */
    headers?: Record<string, string>;
    /** Request timeout in milliseconds (default 60 s). */
    timeoutMs?: number;
    /** Custom fetch implementation (defaults to the global fetch). */
    fetch?: FetchLike;
}
export interface EnrollOptions {
    /** DER (or PEM) PKCS #10 request. */
    csr: BytesLike | string;
    /** Private key matching the request's public key. */
    privateKey: PrivateKeyLike;
    /**
     * Existing identity to sign the request with: a certificate previously issued by this CA,
     * for renewal or re-enrolment. Defaults to a fresh self-signed certificate for `privateKey`.
     */
    signer?: {
        certificate: CertificateLike;
        privateKey: PrivateKeyLike;
    };
    /**
     * Send a RenewalReq instead of a PKCSReq. Defaults to true when `signer` is given and the
     * CA advertises the Renewal capability.
     */
    renewal?: boolean;
    /** transactionID; defaults to a hash of the request's public key. */
    transactionId?: string;
}
/** State needed to poll for a pending (manually approved) enrolment. */
export interface PendingEnrollment {
    transactionId: string;
    /** DER issuer Name (the CA). */
    issuer: Buffer;
    /** DER subject Name from the request. */
    subject: Buffer;
    /** Identity that signed the original request; polls must be signed by it too. */
    identity: ScepIdentity;
    /** DER PKCS #10 request (used to select the issued certificate). */
    csr: Buffer;
}
export type EnrollmentResult = {
    status: PkiStatus.SUCCESS;
    transactionId: string;
    /** The newly issued certificate. */
    certificate: X509Certificate;
    /** Every certificate in the CertRep (issued certificate plus any chain). */
    certificates: X509Certificate[];
    response: PkiMessage;
} | {
    status: PkiStatus.PENDING;
    transactionId: string;
    /** Pass to {@link ScepClient.poll} or {@link ScepClient.waitForCertificate}. */
    pending: PendingEnrollment;
    response: PkiMessage;
};
export declare class ScepClient {
    private readonly options;
    private readonly url;
    private readonly fetchImpl;
    private caCertsPromise?;
    private capsPromise?;
    constructor(options: ScepClientOptions);
    /**
     * GetCACaps (RFC 8894 §3.5.1). Cached after the first call. A server that answers with an
     * HTTP error predates GetCACaps and is treated as advertising no capabilities.
     */
    getCACaps(): Promise<CACapabilities>;
    /** GetCACert (RFC 8894 §4.2). Cached after the first call. */
    getCACert(): Promise<CACertificates>;
    private fetchCACert;
    /**
     * GetNextCACert (RFC 8894 §4.7): retrieve the CA's rollover certificates. The response is
     * verified against the current CA certificate.
     */
    getNextCACert(): Promise<X509Certificate[]>;
    /**
     * Enrol (PKCSReq) or renew (RenewalReq) a certificate (RFC 8894 §3.3.1).
     * Resolves with the issued certificate or a pending state; throws {@link ScepFailureError}
     * when the CA rejects the request.
     */
    enroll(opts: EnrollOptions): Promise<EnrollmentResult>;
    /** Poll once for a pending enrolment (CertPoll, RFC 8894 §3.3.3). */
    poll(pending: PendingEnrollment): Promise<EnrollmentResult>;
    /** Poll until the enrolment is approved or rejected, or the timeout elapses. */
    waitForCertificate(pending: PendingEnrollment, opts?: {
        intervalMs?: number;
        timeoutMs?: number;
        signal?: AbortSignal;
    }): Promise<Extract<EnrollmentResult, {
        status: PkiStatus.SUCCESS;
    }>>;
    /** GetCert (RFC 8894 §3.3.4): retrieve a certificate by issuer and serial number. */
    getCert(opts: {
        serialNumber: BytesLike;
        /** Issuer name; defaults to the CA's subject. */
        issuer?: NameInput;
        /** Identity to sign the request with (typically a certificate issued by this CA). */
        signer: {
            certificate: CertificateLike;
            privateKey: PrivateKeyLike;
        };
        transactionId?: string;
    }): Promise<X509Certificate[]>;
    /**
     * GetCRL (RFC 8894 §3.3.5): retrieve the CRL covering `certificate` (which defaults to the
     * signer's certificate). Returns the DER-encoded CRL.
     */
    getCRL(opts: {
        signer: {
            certificate: CertificateLike;
            privateKey: PrivateKeyLike;
        };
        certificate?: CertificateLike;
        transactionId?: string;
    }): Promise<Buffer>;
    /** Send a raw pkiMessage and return the raw response (PKIOperation, RFC 8894 §4.3). */
    pkiOperation(message: BytesLike, usePost?: boolean): Promise<Buffer>;
    private transact;
    private enrollmentResult;
    private successCertificates;
    private digestFor;
    private operationUrl;
    private get;
    private request;
    private body;
}
