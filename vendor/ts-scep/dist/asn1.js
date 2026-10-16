var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var AnySet_1;
/**
 * ASN.1 schemas that SCEP needs beyond what the @peculiar/asn1-* packages provide, plus
 * small helpers for building and reading attribute values.
 */
import * as asn1js from "asn1js";
import { AsnArray, AsnConvert, AsnProp, AsnPropTypes, AsnType, AsnTypeTypes } from "@peculiar/asn1-schema";
import { DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignerInfos } from "@peculiar/asn1-cms";
import { AlgorithmIdentifier, Name } from "@peculiar/asn1-x509";
import { ScepProtocolError } from "./errors.js";
import { FailInfo } from "./constants.js";
import { toArrayBuffer, toBuffer } from "./util.js";
/** SET OF ANY — used for SignedData certificates and CRLs so that any encoding round-trips. */
let AnySet = AnySet_1 = class AnySet extends AsnArray {
    constructor(items) {
        super(items);
        Object.setPrototypeOf(this, AnySet_1.prototype);
    }
};
AnySet = AnySet_1 = __decorate([
    AsnType({ type: AsnTypeTypes.Set, itemType: AsnPropTypes.Any })
], AnySet);
export { AnySet };
/**
 * CMS SignedData (RFC 5652 §5.1) with certificates and CRLs kept as raw DER. The upstream
 * schema cannot represent plain CRLs in RevocationInfoChoices, which SCEP's GetCRL relies on.
 */
export class ScepSignedData {
    constructor(params = {}) {
        this.version = 1;
        this.digestAlgorithms = new DigestAlgorithmIdentifiers();
        this.encapContentInfo = new EncapsulatedContentInfo();
        this.signerInfos = new SignerInfos();
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AsnPropTypes.Integer })
], ScepSignedData.prototype, "version", void 0);
__decorate([
    AsnProp({ type: DigestAlgorithmIdentifiers })
], ScepSignedData.prototype, "digestAlgorithms", void 0);
__decorate([
    AsnProp({ type: EncapsulatedContentInfo })
], ScepSignedData.prototype, "encapContentInfo", void 0);
__decorate([
    AsnProp({ type: AnySet, context: 0, implicit: true, optional: true })
], ScepSignedData.prototype, "certificates", void 0);
__decorate([
    AsnProp({ type: AnySet, context: 1, implicit: true, optional: true })
], ScepSignedData.prototype, "crls", void 0);
__decorate([
    AsnProp({ type: SignerInfos })
], ScepSignedData.prototype, "signerInfos", void 0);
/**
 * ```asn
 * IssuerAndSubject ::= SEQUENCE {
 *   issuer     Name,
 *   subject    Name }
 * ```
 * Message data of a CertPoll request (RFC 8894 §3.3.3).
 */
export class IssuerAndSubject {
    constructor(params = {}) {
        this.issuer = new Name();
        this.subject = new Name();
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: Name })
], IssuerAndSubject.prototype, "issuer", void 0);
__decorate([
    AsnProp({ type: Name })
], IssuerAndSubject.prototype, "subject", void 0);
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
export class OaepParams {
    constructor(params = {}) {
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AlgorithmIdentifier, context: 0, optional: true })
], OaepParams.prototype, "hashAlgorithm", void 0);
__decorate([
    AsnProp({ type: AlgorithmIdentifier, context: 1, optional: true })
], OaepParams.prototype, "maskGenAlgorithm", void 0);
__decorate([
    AsnProp({ type: AlgorithmIdentifier, context: 2, optional: true })
], OaepParams.prototype, "pSourceAlgorithm", void 0);
export function printableString(value) {
    if (!/^[A-Za-z0-9 '()+,\-./:=?]*$/.test(value)) {
        throw new TypeError(`"${value}" contains characters not allowed in a PrintableString`);
    }
    return new asn1js.PrintableString({ value }).toBER(false);
}
export function utf8String(value) {
    return new asn1js.Utf8String({ value }).toBER(false);
}
export function octetString(value) {
    return new asn1js.OctetString({ valueHex: toArrayBuffer(value) }).toBER(false);
}
function parseBer(value) {
    const parsed = asn1js.fromBER(toArrayBuffer(value));
    if (parsed.offset === -1)
        throw new ScepProtocolError("Malformed ASN.1 value", FailInfo.badRequest);
    return parsed.result;
}
export function objectIdentifier(oid) {
    return new asn1js.ObjectIdentifier({ value: oid }).toBER(false);
}
export function readObjectIdentifier(value) {
    const node = parseBer(value);
    if (!(node instanceof asn1js.ObjectIdentifier)) {
        throw new ScepProtocolError("Expected an OBJECT IDENTIFIER value", FailInfo.badRequest);
    }
    return node.getValue();
}
/** Read any ASN.1 character string type (implementations are not uniform about the string type used). */
export function readString(value) {
    const node = parseBer(value);
    if (node instanceof asn1js.BaseStringBlock || typeof node.getValue === "function") {
        const v = node.getValue();
        if (typeof v === "string")
            return v;
    }
    throw new ScepProtocolError("Expected an ASN.1 string value", FailInfo.badRequest);
}
/** Read an OCTET STRING (primitive or constructed). */
export function readOctetString(value) {
    const node = parseBer(value);
    if (!(node instanceof asn1js.OctetString)) {
        throw new ScepProtocolError("Expected an OCTET STRING value", FailInfo.badRequest);
    }
    return collectOctets(node);
}
function collectOctets(node) {
    if (!node.idBlock.isConstructed)
        return Buffer.from(node.valueBlock.valueHexView);
    const parts = node.valueBlock.value.map(collectOctets);
    return Buffer.concat(parts);
}
/** DER-encode and sort a list of encoded SET OF elements, as DER requires. */
export function sortDerSet(items, encode) {
    return items
        .map((item) => ({ item, der: toBuffer(encode(item)) }))
        .sort((a, b) => Buffer.compare(a.der, b.der))
        .map((e) => e.item);
}
export function serialize(value) {
    return toBuffer(AsnConvert.serialize(value));
}
export function parse(data, type, what = type.name) {
    try {
        return AsnConvert.parse(toArrayBuffer(data), type);
    }
    catch (err) {
        throw new ScepProtocolError(`Malformed ${what}`, FailInfo.badRequest, { cause: err });
    }
}
