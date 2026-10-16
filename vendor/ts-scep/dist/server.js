import { createDegenerateSignedData, createSignedData } from "./cms.js";
import { Capability, ContentTypes, FailInfo, MessageType, Operation, PkiStatus, } from "./constants.js";
import { toPrivateKey } from "./crypto.js";
import { ScepError, ScepProtocolError } from "./errors.js";
import { decodeIssuerAndSerialNumber, decodeIssuerAndSubject, decodePkiMessage, encodePkiMessage, peekPkiMessage, } from "./message.js";
import { toBuffer } from "./util.js";
import { isIssuedBy, isSelfSigned, parseCsr, samePublicKey, toCertificate, } from "./x509.js";
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
export class ScepServer {
    constructor(options) {
        this.options = options;
        /**
         * Fetch-API handler (Bun, Deno, Hono, Next.js route handlers, …). Bound, so it can be passed
         * directly: `Bun.serve({ fetch: scep.fetchHandler })` or `app.all(path, (c) => scep.fetchHandler(c.req.raw))`.
         */
        this.fetchHandler = (request) => this.handleFetch(request);
        this.caCert = toCertificate(options.ca.certificate);
        this.caKey = options.ca.privateKey ? toPrivateKey(options.ca.privateKey) : undefined;
        this.chain = (options.ca.chain ?? []).map(toCertificate);
        this.nextCa = (options.nextCaCertificates ?? []).map(toCertificate);
        if (options.ra) {
            this.raCert = toCertificate(options.ra.certificate);
            this.identity = { certificate: this.raCert, privateKey: toPrivateKey(options.ra.privateKey) };
        }
        else {
            if (!this.caKey)
                throw new ScepError("ca.privateKey is required when no RA is configured");
            this.identity = { certificate: this.caCert, privateKey: this.caKey };
        }
        if (this.nextCa.length && !this.caKey)
            throw new ScepError("GetNextCACert requires ca.privateKey");
        this.capabilities = options.capabilities ?? [
            Capability.AES,
            Capability.DES3,
            ...(this.nextCa.length ? [Capability.GetNextCACert] : []),
            Capability.POSTPKIOperation,
            Capability.Renewal,
            Capability.SHA1,
            Capability.SHA256,
            Capability.SHA512,
            Capability.SCEPStandard,
        ];
    }
    // -------------------------------------------------------------------------
    // HTTP entry points
    // -------------------------------------------------------------------------
    /** Handle a SCEP HTTP request. Never throws; protocol errors become HTTP 4xx/5xx responses. */
    async handle(req) {
        const param = (name) => {
            if (req.query instanceof URLSearchParams)
                return req.query.get(name) ?? undefined;
            const v = req.query[name];
            return Array.isArray(v) ? v[0] : v;
        };
        try {
            const operation = param("operation");
            switch (operation) {
                case Operation.GetCACaps:
                    return respond(200, ContentTypes.text, Buffer.from(this.capabilities.join("\n") + "\n"));
                case Operation.GetCACert:
                    return this.getCACert();
                case Operation.GetNextCACert:
                    return this.getNextCACert();
                case Operation.PKIOperation: {
                    const method = req.method.toUpperCase();
                    let message;
                    if (method === "POST")
                        message = req.body ? toBuffer(req.body) : undefined;
                    else if (method === "GET") {
                        // Unescaped '+' in base64 decodes as ' ' in query strings.
                        const m = param("message");
                        message = m ? Buffer.from(m.replace(/ /g, "+"), "base64") : undefined;
                    }
                    else
                        return respond(405, ContentTypes.text, Buffer.from("Method not allowed\n"));
                    if (!message?.length)
                        return respond(400, ContentTypes.text, Buffer.from("Missing message\n"));
                    return respond(200, ContentTypes.pkiMessage, await this.pkiOperation(message));
                }
                default:
                    return respond(400, ContentTypes.text, Buffer.from("Unknown or missing operation\n"));
            }
        }
        catch (err) {
            const status = err instanceof ScepProtocolError ? 400 : 500;
            return respond(status, ContentTypes.text, Buffer.from(`${err.message}\n`));
        }
    }
    /** Like {@link fetchHandler}, with per-request options such as a body already read by middleware. */
    async handleFetch(request, opts = {}) {
        const limit = opts.maxBodyBytes ?? this.options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
        let body;
        if (request.method.toUpperCase() === "POST") {
            body = opts.body !== undefined ? toBuffer(opts.body) : await readBody(request, limit);
            if (!body || body.length > limit)
                return new Response(null, { status: 413 });
        }
        const url = new URL(request.url);
        const res = await this.handle({ method: request.method, query: url.searchParams, body });
        return new Response(res.body, { status: res.status, headers: res.headers });
    }
    /**
     * `node:http` / Express adapter. Mount it at the SCEP path. Works with a raw request stream
     * or with a body already read into a Buffer by middleware such as `express.raw()`.
     */
    nodeHandler(opts = {}) {
        const limit = opts.maxBodyBytes ?? this.options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
        return (req, res) => {
            const dispatch = (body) => {
                const url = new URL(req.url ?? "/", "http://localhost");
                this.handle({ method: req.method ?? "GET", query: url.searchParams, body })
                    .then((r) => res.writeHead(r.status, { ...r.headers, "content-length": String(r.body.length) }).end(r.body))
                    .catch(() => res.writeHead(500).end());
            };
            // Body already consumed by middleware (e.g. express.raw())?
            const parsed = req.body;
            if (parsed instanceof Uint8Array)
                return dispatch(toBuffer(parsed));
            const chunks = [];
            let size = 0;
            let aborted = false;
            req.on("data", (chunk) => {
                size += chunk.length;
                if (size > limit) {
                    aborted = true;
                    res.writeHead(413).end();
                    req.destroy();
                    return;
                }
                chunks.push(chunk);
            });
            req.on("end", () => {
                if (!aborted)
                    dispatch(Buffer.concat(chunks));
            });
        };
    }
    // -------------------------------------------------------------------------
    // Operations
    // -------------------------------------------------------------------------
    getCACert() {
        if (!this.raCert && this.chain.length === 0) {
            return respond(200, ContentTypes.caCert, this.caCert.raw);
        }
        const certs = [this.caCert, ...(this.raCert ? [this.raCert] : []), ...this.chain];
        return respond(200, ContentTypes.caRaCert, createDegenerateSignedData(certs));
    }
    getNextCACert() {
        if (!this.nextCa.length || !this.caKey) {
            return respond(404, ContentTypes.text, Buffer.from("No rollover certificate available\n"));
        }
        const body = createSignedData({
            content: createDegenerateSignedData(this.nextCa),
            signer: { certificate: this.caCert, privateKey: this.caKey, digestAlgorithm: "sha256" },
        });
        return respond(200, ContentTypes.nextCaCert, body);
    }
    /** Process a pkiMessage and return the DER CertRep. */
    async pkiOperation(der) {
        let message;
        try {
            message = decodePkiMessage(der, { recipient: this.identity });
        }
        catch (err) {
            // Answer with a signed FAILURE where the request is identifiable (RFC 8894 §3.3.2).
            const peek = peekPkiMessage(der);
            if (!peek?.transactionId || !peek.senderNonce)
                throw err;
            const failInfo = err instanceof ScepProtocolError ? err.failInfo : FailInfo.badRequest;
            return this.certRep({ transactionId: peek.transactionId, senderNonce: peek.senderNonce, digestAlgorithm: "sha256" }, { status: "failure", failInfo, failInfoText: err.message });
        }
        const result = await this.dispatch(message).catch((err) => {
            if (err instanceof ScepProtocolError)
                return { status: "failure", failInfo: err.failInfo, failInfoText: err.message };
            throw err;
        });
        return this.certRep(message, result);
    }
    async dispatch(message) {
        const { handler, maxClockSkewMs, requireOaep } = this.options;
        if (maxClockSkewMs !== undefined && message.signingTime) {
            if (Math.abs(message.signingTime.getTime() - Date.now()) > maxClockSkewMs) {
                return { status: "failure", failInfo: FailInfo.badTime };
            }
        }
        if (!message.messageData) {
            return { status: "failure", failInfo: FailInfo.badRequest, failInfoText: "Missing pkcsPKIEnvelope" };
        }
        if (requireOaep && message.keyTransport === "rsa-pkcs1") {
            return { status: "failure", failInfo: FailInfo.badAlg, failInfoText: "RSAES-OAEP key transport is required" };
        }
        const signer = message.signerCertificate;
        const ctx = {
            message,
            transactionId: message.transactionId,
            signerCertificate: signer,
            selfSigned: isSelfSigned(signer),
            signerIssuedByCa: isIssuedBy(signer, this.caCert),
        };
        switch (message.messageType) {
            case MessageType.PKCSReq:
            case MessageType.RenewalReq: {
                const renewal = message.messageType === MessageType.RenewalReq;
                const csr = parseCsr(message.messageData);
                if (!csr.signatureValid) {
                    return { status: "failure", failInfo: FailInfo.badMessageCheck, failInfoText: "Invalid CSR signature" };
                }
                if (ctx.selfSigned && !samePublicKey(signer.publicKey, csr.publicKey)) {
                    return {
                        status: "failure",
                        failInfo: FailInfo.badMessageCheck,
                        failInfoText: "Self-signed signer key does not match the CSR",
                    };
                }
                if (renewal && !ctx.signerIssuedByCa) {
                    return {
                        status: "failure",
                        failInfo: FailInfo.badRequest,
                        failInfoText: "RenewalReq must be signed with a certificate issued by this CA",
                    };
                }
                return handler.enroll({ ...ctx, csr, renewal });
            }
            case MessageType.CertPoll: {
                if (!handler.poll)
                    return notSupported();
                const { issuer, subject } = decodeIssuerAndSubject(message.messageData);
                return handler.poll({ ...ctx, issuer, subject });
            }
            case MessageType.GetCert: {
                if (!handler.getCert)
                    return notSupported();
                return handler.getCert({ ...ctx, ...decodeIssuerAndSerialNumber(message.messageData) });
            }
            case MessageType.GetCRL: {
                if (!handler.getCRL)
                    return notSupported();
                return handler.getCRL({ ...ctx, ...decodeIssuerAndSerialNumber(message.messageData) });
            }
            default:
                return notSupported();
        }
    }
    responseKeyTransport(requested) {
        const configured = this.options.keyTransport ?? "mirror";
        return configured === "mirror" ? (requested ?? "rsa-pkcs1") : configured;
    }
    certRep(request, result) {
        const common = {
            messageType: MessageType.CertRep,
            transactionId: request.transactionId,
            recipientNonce: request.senderNonce,
            signer: this.identity,
            digestAlgorithm: request.digestAlgorithm,
        };
        if (result.status === "success") {
            if (!request.signerCertificate)
                throw new ScepError("Cannot encrypt CertRep without a requester certificate");
            const messageData = createDegenerateSignedData((result.certificates ?? []).map(toCertificate), result.crls ?? []);
            return encodePkiMessage({
                ...common,
                pkiStatus: PkiStatus.SUCCESS,
                messageData,
                recipient: request.signerCertificate,
                encryptionAlgorithm: request.encryptionAlgorithm ?? "aes-128-cbc",
                keyTransport: this.responseKeyTransport(request.keyTransport),
            });
        }
        if (result.status === "pending")
            return encodePkiMessage({ ...common, pkiStatus: PkiStatus.PENDING });
        return encodePkiMessage({
            ...common,
            pkiStatus: PkiStatus.FAILURE,
            failInfo: result.failInfo ?? FailInfo.badRequest,
            failInfoText: result.failInfoText,
        });
    }
}
function notSupported() {
    return { status: "failure", failInfo: FailInfo.badRequest, failInfoText: "Operation not supported" };
}
/** Read a request body, giving up (undefined) once it exceeds `limit` bytes. */
async function readBody(request, limit) {
    const declared = Number(request.headers.get("content-length") ?? NaN);
    if (declared > limit)
        return undefined;
    if (!request.body)
        return new Uint8Array();
    const reader = request.body.getReader();
    const chunks = [];
    let size = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done)
            break;
        size += value.byteLength;
        if (size > limit) {
            await reader.cancel().catch(() => { });
            return undefined;
        }
        chunks.push(value);
    }
    return Buffer.concat(chunks, size);
}
function respond(status, contentType, body) {
    return { status, headers: { "content-type": contentType }, body };
}
