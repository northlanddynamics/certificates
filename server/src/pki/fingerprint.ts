// The fingerprint of a certificate or CSR: the SHA-256 of its DER, lower-case hex, as the platform stores, shows and
// matches it (sha256.ts).
import { sha256Hex } from "../platform/crypto/sha256";

/** The fingerprint of the DER of a certificate or CSR, however the library holding it gives its bytes. */
export const fingerprintOf = (der: ArrayBuffer | Uint8Array) => sha256Hex(der instanceof Uint8Array ? der : new Uint8Array(der));
