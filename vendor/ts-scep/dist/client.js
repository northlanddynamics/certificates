/**
 * SCEP client (RFC 8894 §4): CA discovery, enrolment, renewal, polling and certificate/CRL
 * retrieval over HTTP.
 */
import { X509Certificate } from "node:crypto";
import { CACapabilities } from "./capabilities.js";
import { CACertificates } from "./ca-certificates.js";
import { parseSignedData, verifySignerInfo } from "./cms.js";
import { ContentTypes, MessageType, Operation, PkiStatus, } from "./constants.js";
import { randomBytes, toPrivateKey } from "./crypto.js";
import { ScepError, ScepFailureError, ScepHttpError, ScepProtocolError } from "./errors.js";
import { decodePkiMessage, encodeIssuerAndSerialNumber, encodeIssuerAndSubject, encodePkiMessage, NONCE_LENGTH, transactionIdFromPublicKey, } from "./message.js";
import { bytesEqual, toBuffer } from "./util.js";
import { certificateIssuer, certificateSerialNumber, certificateSubject, createSelfSignedCertificate, parseCertificates, parseCsr, samePublicKey, encodeName, toCertificate, } from "./x509.js";
export class ScepClient {
    constructor(options) {
        this.options = options;
        this.url = new URL(options.url);
        const f = options.fetch ?? globalThis.fetch;
        if (!f)
            throw new ScepError("No fetch implementation available");
        this.fetchImpl = f;
        if (options.caCertificates) {
            this.caCertsPromise = Promise.resolve(new CACertificates(options.caCertificates.map(toCertificate)));
        }
        if (options.capabilities)
            this.capsPromise = Promise.resolve(new CACapabilities(options.capabilities));
    }
    // -------------------------------------------------------------------------
    // CA discovery
    // -------------------------------------------------------------------------
    /**
     * GetCACaps (RFC 8894 §3.5.1). Cached after the first call. A server that answers with an
     * HTTP error predates GetCACaps and is treated as advertising no capabilities.
     */
    getCACaps() {
        this.capsPromise ??= this.get(Operation.GetCACaps, this.options.caIdentifier)
            .then(async (res) => CACapabilities.parse(new TextDecoder().decode(await this.body(res))))
            .catch((err) => {
            if (err instanceof ScepHttpError && err.status >= 400 && err.status < 500)
                return new CACapabilities([]);
            this.capsPromise = undefined;
            throw err;
        });
        return this.capsPromise;
    }
    /** GetCACert (RFC 8894 §4.2). Cached after the first call. */
    getCACert() {
        this.caCertsPromise ??= this.fetchCACert().catch((err) => {
            this.caCertsPromise = undefined;
            throw err;
        });
        return this.caCertsPromise;
    }
    async fetchCACert() {
        const res = await this.get(Operation.GetCACert, this.options.caIdentifier);
        const body = await this.body(res);
        const type = (res.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
        let certs;
        if (type === ContentTypes.caCert) {
            certs = [new X509Certificate(body)];
        }
        else if (type === ContentTypes.caRaCert) {
            certs = parseSignedData(body).certificates;
        }
        else {
            certs = parseCaCertBody(body);
        }
        const ca = new CACertificates(certs);
        if (this.options.caFingerprint)
            checkFingerprint(ca, this.options.caFingerprint);
        return ca;
    }
    /**
     * GetNextCACert (RFC 8894 §4.7): retrieve the CA's rollover certificates. The response is
     * verified against the current CA certificate.
     */
    async getNextCACert() {
        const current = await this.getCACert();
        const res = await this.get(Operation.GetNextCACert, this.options.caIdentifier);
        const sd = parseSignedData(await this.body(res));
        if (sd.signerInfos.length === 0)
            throw new ScepProtocolError("GetNextCACert response is not signed");
        const signer = verifySignerInfo(sd, sd.signerInfos[0], current.all);
        if (!current.isTrustedSigner(signer.certificate)) {
            throw new ScepProtocolError("GetNextCACert response not signed by the current CA");
        }
        if (sd.content?.length)
            return parseSignedData(sd.content).certificates;
        return sd.certificates.filter((c) => !c.raw.equals(signer.certificate.raw));
    }
    // -------------------------------------------------------------------------
    // Enrolment
    // -------------------------------------------------------------------------
    /**
     * Enrol (PKCSReq) or renew (RenewalReq) a certificate (RFC 8894 §3.3.1).
     * Resolves with the issued certificate or a pending state; throws {@link ScepFailureError}
     * when the CA rejects the request.
     */
    async enroll(opts) {
        const csr = parseCsr(typeof opts.csr === "string" ? opts.csr : toBuffer(opts.csr));
        const privateKey = toPrivateKey(opts.privateKey);
        if (!samePublicKey(privateKey, csr.publicKey)) {
            throw new ScepError("privateKey does not match the certification request");
        }
        const [ca, caps] = await Promise.all([this.getCACert(), this.getCACaps()]);
        const identity = opts.signer
            ? { certificate: toCertificate(opts.signer.certificate), privateKey: toPrivateKey(opts.signer.privateKey) }
            : {
                certificate: createSelfSignedCertificate({
                    subject: csr.subject,
                    privateKey,
                    digestAlgorithm: this.digestFor(caps),
                }),
                privateKey,
            };
        const renewal = opts.renewal ?? (!!opts.signer && caps.supportsRenewal);
        const transactionId = opts.transactionId ?? transactionIdFromPublicKey(csr.publicKey);
        const pending = {
            transactionId,
            issuer: certificateSubject(ca.ca),
            subject: csr.subject,
            identity,
            csr: csr.der,
        };
        const response = await this.transact(renewal ? MessageType.RenewalReq : MessageType.PKCSReq, transactionId, csr.der, identity, ca, caps);
        return this.enrollmentResult(response, pending);
    }
    /** Poll once for a pending enrolment (CertPoll, RFC 8894 §3.3.3). */
    async poll(pending) {
        const [ca, caps] = await Promise.all([this.getCACert(), this.getCACaps()]);
        const response = await this.transact(MessageType.CertPoll, pending.transactionId, encodeIssuerAndSubject(pending.issuer, pending.subject), pending.identity, ca, caps);
        return this.enrollmentResult(response, pending);
    }
    /** Poll until the enrolment is approved or rejected, or the timeout elapses. */
    async waitForCertificate(pending, opts = {}) {
        const interval = opts.intervalMs ?? 60_000;
        const deadline = opts.timeoutMs !== undefined ? Date.now() + opts.timeoutMs : Infinity;
        for (;;) {
            opts.signal?.throwIfAborted();
            const result = await this.poll(pending);
            if (result.status === PkiStatus.SUCCESS)
                return result;
            if (Date.now() + interval > deadline)
                throw new ScepError("Timed out waiting for certificate issuance");
            await new Promise((resolve, reject) => {
                const t = setTimeout(resolve, interval);
                opts.signal?.addEventListener("abort", () => (clearTimeout(t), reject(opts.signal.reason)), { once: true });
            });
        }
    }
    // -------------------------------------------------------------------------
    // Certificate and CRL access
    // -------------------------------------------------------------------------
    /** GetCert (RFC 8894 §3.3.4): retrieve a certificate by issuer and serial number. */
    async getCert(opts) {
        const [ca, caps] = await Promise.all([this.getCACert(), this.getCACaps()]);
        const identity = toIdentity(opts.signer);
        const issuer = opts.issuer !== undefined ? encodeName(opts.issuer) : certificateSubject(ca.ca);
        const response = await this.transact(MessageType.GetCert, opts.transactionId ?? transactionIdFromPublicKey(identity.certificate.publicKey), encodeIssuerAndSerialNumber(issuer, opts.serialNumber), identity, ca, caps);
        return this.successCertificates(response).certificates;
    }
    /**
     * GetCRL (RFC 8894 §3.3.5): retrieve the CRL covering `certificate` (which defaults to the
     * signer's certificate). Returns the DER-encoded CRL.
     */
    async getCRL(opts) {
        const [ca, caps] = await Promise.all([this.getCACert(), this.getCACaps()]);
        const identity = toIdentity(opts.signer);
        const target = opts.certificate ? toCertificate(opts.certificate) : identity.certificate;
        const response = await this.transact(MessageType.GetCRL, opts.transactionId ?? transactionIdFromPublicKey(identity.certificate.publicKey), encodeIssuerAndSerialNumber(certificateIssuer(target), certificateSerialNumber(target)), identity, ca, caps);
        const { crls } = this.successCertificates(response);
        if (!crls[0])
            throw new ScepProtocolError("CertRep did not contain a CRL");
        return crls[0];
    }
    // -------------------------------------------------------------------------
    // Transport
    // -------------------------------------------------------------------------
    /** Send a raw pkiMessage and return the raw response (PKIOperation, RFC 8894 §4.3). */
    async pkiOperation(message, usePost) {
        const post = usePost ?? this.options.usePost ?? (await this.getCACaps()).supportsPost;
        const res = post
            ? await this.request(this.operationUrl(Operation.PKIOperation), {
                method: "POST",
                headers: { "content-type": ContentTypes.pkiMessage },
                body: toBuffer(message),
            })
            : await this.get(Operation.PKIOperation, toBuffer(message).toString("base64"));
        return this.body(res);
    }
    async transact(messageType, transactionId, messageData, identity, ca, caps) {
        const senderNonce = randomBytes(NONCE_LENGTH);
        const request = encodePkiMessage({
            messageType,
            transactionId,
            senderNonce,
            messageData,
            recipient: ca.encryptionCertificate,
            signer: identity,
            digestAlgorithm: this.digestFor(caps),
            encryptionAlgorithm: this.options.encryptionAlgorithm ?? caps.encryptionAlgorithm,
            keyTransport: this.options.keyTransport,
        });
        const raw = await this.pkiOperation(request, this.options.usePost ?? caps.supportsPost);
        const response = decodePkiMessage(raw, { recipient: identity, signerCertificates: ca.all });
        if (response.messageType !== MessageType.CertRep) {
            throw new ScepProtocolError(`Expected CertRep, received messageType ${response.messageType}`);
        }
        if (!ca.isTrustedSigner(response.signerCertificate)) {
            throw new ScepProtocolError("CertRep is not signed by the CA or an RA");
        }
        if (response.transactionId !== transactionId)
            throw new ScepProtocolError("CertRep transactionID mismatch");
        if (!response.recipientNonce || !bytesEqual(response.recipientNonce, senderNonce)) {
            throw new ScepProtocolError("CertRep recipientNonce does not match the request senderNonce");
        }
        if (response.pkiStatus === PkiStatus.FAILURE) {
            throw new ScepFailureError(response.failInfo, response.failInfoText, transactionId);
        }
        return response;
    }
    enrollmentResult(response, pending) {
        if (response.pkiStatus === PkiStatus.PENDING) {
            return { status: PkiStatus.PENDING, transactionId: pending.transactionId, pending, response };
        }
        const { certificates } = this.successCertificates(response);
        const requestedKey = parseCsr(pending.csr).publicKey;
        const certificate = certificates.find((c) => samePublicKey(c.publicKey, requestedKey));
        if (!certificate)
            throw new ScepProtocolError("CertRep does not contain a certificate for the requested key");
        return { status: PkiStatus.SUCCESS, transactionId: pending.transactionId, certificate, certificates, response };
    }
    successCertificates(response) {
        if (response.pkiStatus !== PkiStatus.SUCCESS) {
            throw new ScepProtocolError(`Unexpected pkiStatus ${response.pkiStatus}`);
        }
        if (!response.messageData)
            throw new ScepProtocolError("Successful CertRep has no pkcsPKIEnvelope");
        const inner = parseSignedData(response.messageData);
        return { certificates: inner.certificates, crls: inner.crls };
    }
    digestFor(caps) {
        return this.options.digestAlgorithm ?? caps.digestAlgorithm;
    }
    operationUrl(operation, message) {
        const url = new URL(this.url);
        url.searchParams.set("operation", operation);
        if (message !== undefined)
            url.searchParams.set("message", message);
        return url;
    }
    get(operation, message) {
        return this.request(this.operationUrl(operation, message), { method: "GET" });
    }
    async request(url, init) {
        const res = await this.fetchImpl(url, {
            ...init,
            headers: { ...this.options.headers, ...init.headers },
            signal: AbortSignal.timeout(this.options.timeoutMs ?? 60_000),
        });
        if (!res.ok) {
            const body = new Uint8Array(await res.arrayBuffer().catch(() => new ArrayBuffer(0)));
            throw new ScepHttpError(`SCEP server responded with HTTP ${res.status}`, res.status, body);
        }
        return res;
    }
    async body(res) {
        return Buffer.from(await res.arrayBuffer());
    }
}
function toIdentity(signer) {
    return { certificate: toCertificate(signer.certificate), privateKey: toPrivateKey(signer.privateKey) };
}
function parseCaCertBody(body) {
    const text = body.toString("latin1");
    if (text.includes("-----BEGIN CERTIFICATE-----"))
        return parseCertificates(text);
    try {
        return [new X509Certificate(body)];
    }
    catch {
        return parseSignedData(body).certificates;
    }
}
function checkFingerprint(ca, expected) {
    const want = expected.replace(/[^0-9a-f]/gi, "").toUpperCase();
    const match = ca.all.some((c) => [c.fingerprint256, c.fingerprint].some((fp) => fp.replace(/:/g, "").toUpperCase() === want));
    if (!match)
        throw new ScepError("CA certificate fingerprint does not match the expected value");
}
