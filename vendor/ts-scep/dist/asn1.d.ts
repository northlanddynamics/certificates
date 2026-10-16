import { AsnArray } from "@peculiar/asn1-schema";
import { DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignerInfos } from "@peculiar/asn1-cms";
import { AlgorithmIdentifier, Name } from "@peculiar/asn1-x509";
import { type BytesLike } from "./util.js";
/** SET OF ANY — used for SignedData certificates and CRLs so that any encoding round-trips. */
export declare class AnySet extends AsnArray<ArrayBuffer> {
    constructor(items?: ArrayBuffer[]);
}
/**
 * CMS SignedData (RFC 5652 §5.1) with certificates and CRLs kept as raw DER. The upstream
 * schema cannot represent plain CRLs in RevocationInfoChoices, which SCEP's GetCRL relies on.
 */
export declare class ScepSignedData {
    version: number;
    digestAlgorithms: DigestAlgorithmIdentifiers;
    encapContentInfo: EncapsulatedContentInfo;
    certificates?: AnySet;
    crls?: AnySet;
    signerInfos: SignerInfos;
    constructor(params?: Partial<ScepSignedData>);
}
/**
 * ```asn
 * IssuerAndSubject ::= SEQUENCE {
 *   issuer     Name,
 *   subject    Name }
 * ```
 * Message data of a CertPoll request (RFC 8894 §3.3.3).
 */
export declare class IssuerAndSubject {
    issuer: Name;
    subject: Name;
    constructor(params?: Partial<IssuerAndSubject>);
}
/**
 * ```asn
 * RSAES-OAEP-params ::= SEQUENCE {
 *   hashAlgorithm      [0] HashAlgorithm     DEFAULT sha1Identifier,
 *   maskGenAlgorithm   [1] MaskGenAlgorithm  DEFAULT mgf1SHA1Identifier,
 *   pSourceAlgorithm   [2] PSourceAlgorithm  DEFAULT pSpecifiedEmptyIdentifier }
 * ```
 * RFC 4055 §4.1. Defaulted fields are modelled as optional so that absent fields stay
 * distinguishable after parsing (the upstream schema substitutes a non-empty pSpecified label).
 */
export declare class OaepParams {
    hashAlgorithm?: AlgorithmIdentifier;
    maskGenAlgorithm?: AlgorithmIdentifier;
    pSourceAlgorithm?: AlgorithmIdentifier;
    constructor(params?: Partial<OaepParams>);
}
export declare function printableString(value: string): ArrayBuffer;
export declare function utf8String(value: string): ArrayBuffer;
export declare function octetString(value: BytesLike): ArrayBuffer;
export declare function objectIdentifier(oid: string): ArrayBuffer;
export declare function readObjectIdentifier(value: BytesLike): string;
/** Read any ASN.1 character string type (implementations are not uniform about the string type used). */
export declare function readString(value: BytesLike): string;
/** Read an OCTET STRING (primitive or constructed). */
export declare function readOctetString(value: BytesLike): Buffer;
/** DER-encode and sort a list of encoded SET OF elements, as DER requires. */
export declare function sortDerSet<T>(items: T[], encode: (item: T) => ArrayBuffer): T[];
export declare function serialize(value: unknown): Buffer;
export declare function parse<T>(data: BytesLike, type: new () => T, what?: string): T;
