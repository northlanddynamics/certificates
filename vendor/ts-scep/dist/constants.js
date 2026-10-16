/** SCEP messageType values (RFC 8894 §3.2.1.2). */
export var MessageType;
(function (MessageType) {
    /** Response to a certificate or CRL request. */
    MessageType[MessageType["CertRep"] = 3] = "CertRep";
    /** Renewal request for an existing certificate. */
    MessageType[MessageType["RenewalReq"] = 17] = "RenewalReq";
    /** Initial certificate enrolment request (PKCS #10). */
    MessageType[MessageType["PKCSReq"] = 19] = "PKCSReq";
    /** Certificate polling in manual enrolment (formerly GetCertInitial). */
    MessageType[MessageType["CertPoll"] = 20] = "CertPoll";
    /** Retrieve a certificate by issuer and serial number. */
    MessageType[MessageType["GetCert"] = 21] = "GetCert";
    /** Retrieve a CRL. */
    MessageType[MessageType["GetCRL"] = 22] = "GetCRL";
})(MessageType || (MessageType = {}));
/** SCEP pkiStatus values (RFC 8894 §3.2.1.3). */
export var PkiStatus;
(function (PkiStatus) {
    PkiStatus[PkiStatus["SUCCESS"] = 0] = "SUCCESS";
    PkiStatus[PkiStatus["FAILURE"] = 2] = "FAILURE";
    PkiStatus[PkiStatus["PENDING"] = 3] = "PENDING";
})(PkiStatus || (PkiStatus = {}));
/** SCEP failInfo values (RFC 8894 §3.2.1.4). */
export var FailInfo;
(function (FailInfo) {
    /** Unrecognized or unsupported algorithm. */
    FailInfo[FailInfo["badAlg"] = 0] = "badAlg";
    /** Integrity check (meaning signature verification of the CMS message) failed. */
    FailInfo[FailInfo["badMessageCheck"] = 1] = "badMessageCheck";
    /** Transaction not permitted or supported. */
    FailInfo[FailInfo["badRequest"] = 2] = "badRequest";
    /** The signingTime attribute from the CMS authenticatedAttributes was not sufficiently close to the system time. */
    FailInfo[FailInfo["badTime"] = 3] = "badTime";
    /** No certificate could be identified matching the provided criteria. */
    FailInfo[FailInfo["badCertId"] = 4] = "badCertId";
})(FailInfo || (FailInfo = {}));
/** CA capability keywords returned by GetCACaps (RFC 8894 §3.5.2). Matching is case-insensitive. */
export var Capability;
(function (Capability) {
    Capability["AES"] = "AES";
    Capability["DES3"] = "DES3";
    Capability["GetNextCACert"] = "GetNextCACert";
    Capability["POSTPKIOperation"] = "POSTPKIOperation";
    Capability["Renewal"] = "Renewal";
    Capability["SHA1"] = "SHA-1";
    Capability["SHA256"] = "SHA-256";
    Capability["SHA512"] = "SHA-512";
    Capability["SCEPStandard"] = "SCEPStandard";
})(Capability || (Capability = {}));
/** HTTP "operation" values (RFC 8894 §4). */
export var Operation;
(function (Operation) {
    Operation["GetCACert"] = "GetCACert";
    Operation["GetCACaps"] = "GetCACaps";
    Operation["GetNextCACert"] = "GetNextCACert";
    Operation["PKIOperation"] = "PKIOperation";
})(Operation || (Operation = {}));
/** MIME types used by SCEP over HTTP (RFC 8894 §4). */
export const ContentTypes = {
    /** GetCACert response: a single DER-encoded CA certificate. */
    caCert: "application/x-x509-ca-cert",
    /** GetCACert response: degenerate certificates-only CMS SignedData with CA and RA certificates. */
    caRaCert: "application/x-x509-ca-ra-cert",
    /** GetNextCACert response: CMS SignedData, signed by the current CA, carrying the next CA (and RA) certificates. */
    nextCaCert: "application/x-x509-next-ca-cert",
    /** PKIOperation request (POST) and response body. */
    pkiMessage: "application/x-pki-message",
    /** GetCACaps response. */
    text: "text/plain",
};
/** Default CGI path historically used by SCEP servers. */
export const DEFAULT_SCEP_PATH = "/cgi-bin/pkiclient.exe";
