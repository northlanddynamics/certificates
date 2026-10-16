/**
 * SCEP server (CA / RA side, RFC 8894 §4): serves GetCACaps, GetCACert, GetNextCACert and
 * PKIOperation, delegating authorisation and issuance decisions to a {@link ScepHandler}.
 *
 * The server is framework-agnostic: use {@link ScepServer.handle} with any HTTP stack,
 * {@link ScepServer.fetchHandler} with Fetch-API runtimes (Bun, Hono, …), or {@link ScepServer.nodeHandler}
 * with `node:http` / Express.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import type { X509Certificate } from "node:crypto";
import { FailInfo, type KeyTransportAlgorithm } from "./constants.js";
import { type PrivateKeyLike } from "./crypto.js";
import { type PkiMessage } from "./message.js";
import { type BytesLike } from "./util.js";
import { type CertificateLike, type ParsedCsr } from "./x509.js";
/** Context common to every PKIOperation passed to a handler. */
export interface ScepRequestContext {
    /** The verified, decrypted request. */
    message: PkiMessage;
    transactionId: string;
    /** Certificate that signed the request. */
    signerCertificate: X509Certificate;
    /** True if the signer certificate is self-signed (a first-time enrolment). */
    selfSigned: boolean;
    /** True if the signer certificate was issued by this CA (renewal / re-enrolment). */
    signerIssuedByCa: boolean;
}
/** PKCSReq or RenewalReq. The CSR signature has already been verified. */
export interface EnrollmentRequest extends ScepRequestContext {
    csr: ParsedCsr;
    renewal: boolean;
}
/** CertPoll. */
export interface PollRequest extends ScepRequestContext {
    /** DER issuer Name. */
    issuer: Buffer;
    /** DER subject Name. */
    subject: Buffer;
}
/** GetCert or GetCRL. */
export interface IssuerAndSerialRequest extends ScepRequestContext {
    /** DER issuer Name. */
    issuer: Buffer;
    /** Serial number bytes (no sign padding). */
    serialNumber: Buffer;
}
/** Outcome of a handler. */
export type ScepResult = {
    status: "success";
    /** Issued/requested certificates (issued certificate first), returned in a degenerate SignedData. */
    certificates?: CertificateLike[];
    /** DER-encoded CRLs (GetCRL). */
    crls?: BytesLike[];
} | {
    status: "pending";
} | {
    status: "failure";
    failInfo?: FailInfo;
    failInfoText?: string;
};
export interface ScepHandler {
    /** PKCSReq and RenewalReq. Verify the challenge password / authorisation here and issue. */
    enroll(request: EnrollmentRequest): ScepResult | Promise<ScepResult>;
    /** CertPoll for a previously pending enrolment. */
    poll?(request: PollRequest): ScepResult | Promise<ScepResult>;
    /** GetCert. */
    getCert?(request: IssuerAndSerialRequest): ScepResult | Promise<ScepResult>;
    /** GetCRL. */
    getCRL?(request: IssuerAndSerialRequest): ScepResult | Promise<ScepResult>;
}
export interface ScepServerOptions {
    /** The issuing CA. `privateKey` is required unless an RA handles messages, and for GetNextCACert. */
    ca: {
        certificate: CertificateLike;
        privateKey?: PrivateKeyLike;
        chain?: CertificateLike[];
    };
    /** Registration authority that decrypts requests and signs responses on behalf of the CA. */
    ra?: {
        certificate: CertificateLike;
        privateKey: PrivateKeyLike;
    };
    /** Rollover CA (and RA) certificates served by GetNextCACert. */
    nextCaCertificates?: CertificateLike[];
    /** Capabilities advertised by GetCACaps. Sensible RFC 8894 defaults are used when omitted. */
    capabilities?: string[];
    /**
     * Key-transport scheme for CertRep envelopes. `"mirror"` (the default) answers with the scheme
     * the request used, so OAEP clients get OAEP and everyone else gets RSAES-PKCS1-v1_5.
     */
    keyTransport?: "mirror" | KeyTransportAlgorithm;
    /** Reject requests whose pkcsPKIEnvelope uses RSAES-PKCS1-v1_5 key transport (badAlg). */
    requireOaep?: boolean;
    /** Reject requests whose signingTime differs from local time by more than this (badTime). */
    maxClockSkewMs?: number;
    /**
     * Largest PKIOperation POST body accepted by {@link ScepServer.fetchHandler} and
     * {@link ScepServer.nodeHandler}, in bytes; larger requests get HTTP 413. Default 1 MiB.
     */
    maxBodyBytes?: number;
    handler: ScepHandler;
}
/** Options for {@link ScepServer.handleFetch}. */
export interface ScepFetchOptions {
    /**
     * The request body, if middleware has already read it (for example Hono's `c.req.arrayBuffer()`),
     * which leaves `request.body` unusable.
     */
    body?: BytesLike;
    /** Overrides {@link ScepServerOptions.maxBodyBytes} for this request. */
    maxBodyBytes?: number;
}
/** Transport-neutral HTTP request. */
export interface ScepHttpRequest {
    method: string;
    /** Query parameters (`operation`, `message`). */
    query: URLSearchParams | Record<string, string | string[] | undefined>;
    body?: Uint8Array;
}
export interface ScepHttpResponse {
    status: number;
    headers: Record<string, string>;
    body: Buffer;
}
export declare class ScepServer {
    private readonly options;
    private readonly caCert;
    private readonly caKey?;
    private readonly chain;
    private readonly identity;
    private readonly raCert?;
    private readonly nextCa;
    readonly capabilities: string[];
    constructor(options: ScepServerOptions);
    /** Handle a SCEP HTTP request. Never throws; protocol errors become HTTP 4xx/5xx responses. */
    handle(req: ScepHttpRequest): Promise<ScepHttpResponse>;
    /**
     * Fetch-API handler (Bun, Deno, Hono, Next.js route handlers, …). Bound, so it can be passed
     * directly: `Bun.serve({ fetch: scep.fetchHandler })` or `app.all(path, (c) => scep.fetchHandler(c.req.raw))`.
     */
    fetchHandler: (request: Request) => Promise<Response>;
    /** Like {@link fetchHandler}, with per-request options such as a body already read by middleware. */
    handleFetch(request: Request, opts?: ScepFetchOptions): Promise<Response>;
    /**
     * `node:http` / Express adapter. Mount it at the SCEP path. Works with a raw request stream
     * or with a body already read into a Buffer by middleware such as `express.raw()`.
     */
    nodeHandler(opts?: {
        maxBodyBytes?: number;
    }): (req: IncomingMessage, res: ServerResponse) => void;
    private getCACert;
    private getNextCACert;
    /** Process a pkiMessage and return the DER CertRep. */
    pkiOperation(der: Buffer): Promise<Buffer>;
    private dispatch;
    private responseKeyTransport;
    private certRep;
}
