import { Capability, type DigestAlgorithm, type EncryptionAlgorithm } from "./constants.js";
/**
 * The capability set returned by GetCACaps (RFC 8894 §3.5.2), with the algorithm
 * negotiation rules a client applies to it.
 */
export declare class CACapabilities {
    readonly keywords: readonly string[];
    private readonly set;
    constructor(keywords: readonly string[]);
    /** Parse a GetCACaps response body (one keyword per line, case-insensitive). */
    static parse(text: string): CACapabilities;
    has(capability: Capability | string): boolean;
    /** SCEPStandard implies AES, POSTPKIOperation and SHA-256 (RFC 8894 §3.5.2). */
    get scepStandard(): boolean;
    get supportsPost(): boolean;
    get supportsRenewal(): boolean;
    get supportsGetNextCACert(): boolean;
    get supportsAes(): boolean;
    /** Strongest content-encryption algorithm the CA advertises. */
    get encryptionAlgorithm(): EncryptionAlgorithm;
    /** Preferred digest algorithm the CA advertises. */
    get digestAlgorithm(): DigestAlgorithm;
    toString(): string;
}
