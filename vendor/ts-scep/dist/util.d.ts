/** Bytes-like input accepted throughout the SDK. */
export type BytesLike = Uint8Array | ArrayBuffer;
export declare function toBuffer(data: BytesLike | ArrayBufferView): Buffer;
/** Copy into a standalone ArrayBuffer (asn1 libraries expect exact-length ArrayBuffers). */
export declare function toArrayBuffer(data: BytesLike | ArrayBufferView): ArrayBuffer;
export declare function bytesEqual(a: BytesLike, b: BytesLike): boolean;
/** Strip leading zero bytes so that INTEGER encodings with and without sign padding compare equal. */
export declare function normalizeInteger(data: BytesLike): Buffer;
/** Convert PEM text to DER. If several blocks are present, all are returned. */
export declare function pemToDerList(pem: string, label?: string): Buffer[];
export declare function derToPem(der: BytesLike, label: string): string;
