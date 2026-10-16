/**
 * Object identifiers used by SCEP (RFC 8894) and the CMS / PKCS structures it builds on.
 */
export declare const OID: {
    readonly data: "1.2.840.113549.1.7.1";
    readonly signedData: "1.2.840.113549.1.7.2";
    readonly envelopedData: "1.2.840.113549.1.7.3";
    readonly contentType: "1.2.840.113549.1.9.3";
    readonly messageDigest: "1.2.840.113549.1.9.4";
    readonly signingTime: "1.2.840.113549.1.9.5";
    readonly challengePassword: "1.2.840.113549.1.9.7";
    readonly extensionRequest: "1.2.840.113549.1.9.14";
    readonly emailAddress: "1.2.840.113549.1.9.1";
    readonly rsaEncryption: "1.2.840.113549.1.1.1";
    readonly rsaesOaep: "1.2.840.113549.1.1.7";
    readonly mgf1: "1.2.840.113549.1.1.8";
    readonly pSpecified: "1.2.840.113549.1.1.9";
    readonly sha1WithRSAEncryption: "1.2.840.113549.1.1.5";
    readonly sha256WithRSAEncryption: "1.2.840.113549.1.1.11";
    readonly sha384WithRSAEncryption: "1.2.840.113549.1.1.12";
    readonly sha512WithRSAEncryption: "1.2.840.113549.1.1.13";
    readonly sha224WithRSAEncryption: "1.2.840.113549.1.1.14";
    readonly sha1: "1.3.14.3.2.26";
    readonly sha256: "2.16.840.1.101.3.4.2.1";
    readonly sha384: "2.16.840.1.101.3.4.2.2";
    readonly sha512: "2.16.840.1.101.3.4.2.3";
    readonly sha224: "2.16.840.1.101.3.4.2.4";
    readonly md5: "1.2.840.113549.2.5";
    readonly aes128CBC: "2.16.840.1.101.3.4.1.2";
    readonly aes192CBC: "2.16.840.1.101.3.4.1.22";
    readonly aes256CBC: "2.16.840.1.101.3.4.1.42";
    readonly desEde3CBC: "1.2.840.113549.3.7";
    readonly desCBC: "1.3.14.3.2.7";
    readonly scepMessageType: "2.16.840.1.113733.1.9.2";
    readonly scepPkiStatus: "2.16.840.1.113733.1.9.3";
    readonly scepFailInfo: "2.16.840.1.113733.1.9.4";
    readonly scepSenderNonce: "2.16.840.1.113733.1.9.5";
    readonly scepRecipientNonce: "2.16.840.1.113733.1.9.6";
    readonly scepTransactionId: "2.16.840.1.113733.1.9.7";
    readonly scepFailInfoText: "1.3.6.1.5.5.7.24.1";
    readonly subjectKeyIdentifier: "2.5.29.14";
    readonly keyUsage: "2.5.29.15";
    readonly subjectAltName: "2.5.29.17";
    readonly basicConstraints: "2.5.29.19";
    readonly authorityKeyIdentifier: "2.5.29.35";
    readonly extKeyUsage: "2.5.29.37";
};
