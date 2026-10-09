// The key management service that wraps each Organization's data key (see secrets.ts). The platform holds only
// wrapped keys, so what opens them is the KMS: AWS KMS and Azure Key Vault are meant to plug in behind this
// interface; the local implementation below is for development and tests.
import { open, seal } from "./aead";

export interface Kms {
  /** Wraps `dataKey`, binding it to `context` (an Organization's id) so it unwraps only for the same context. */
  wrap(dataKey: Uint8Array, context: string): Promise<Uint8Array>;
  /** Throws when `wrapped` was not produced by this KMS for this `context`. */
  unwrap(wrapped: Uint8Array, context: string): Promise<Uint8Array>;
}

/** A KMS whose master key is a base64 string of 32 bytes held in the platform's own configuration. */
export function createLocalKms(masterKeyBase64: string): Kms {
  const masterKey = Buffer.from(masterKeyBase64, "base64");
  if (masterKey.length !== 32) throw new Error("the local KMS key must be 32 bytes, base64-encoded");
  return {
    wrap: async (dataKey, context) => seal(masterKey, dataKey, Buffer.from(context)),
    unwrap: async (wrapped, context) => open(masterKey, wrapped, Buffer.from(context)),
  };
}
