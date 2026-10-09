// The key management service that wraps each Organization's data key (see secrets.ts). The platform holds only
// wrapped keys, so what opens them is the KMS: AWS KMS and Azure Key Vault are meant to plug in behind this
// interface; the local implementation below is for development and tests.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export interface Kms {
  /** Wraps `dataKey`, binding it to `context` (an Organization's id) so it unwraps only for the same context. */
  wrap(dataKey: Uint8Array, context: string): Promise<Uint8Array>;
  /** Throws when `wrapped` was not produced by this KMS for this `context`. */
  unwrap(wrapped: Uint8Array, context: string): Promise<Uint8Array>;
}

const IV_BYTES = 12;
const TAG_BYTES = 16;

/** A KMS whose master key is a base64 string of 32 bytes held in the platform's own configuration. */
export function createLocalKms(masterKeyBase64: string): Kms {
  const masterKey = Buffer.from(masterKeyBase64, "base64");
  if (masterKey.length !== 32) throw new Error("the local KMS key must be 32 bytes, base64-encoded");
  return {
    async wrap(dataKey, context) {
      const iv = randomBytes(IV_BYTES);
      const cipher = createCipheriv("aes-256-gcm", masterKey, iv).setAAD(Buffer.from(context));
      const body = Buffer.concat([cipher.update(dataKey), cipher.final()]);
      return Buffer.concat([iv, body, cipher.getAuthTag()]);
    },
    async unwrap(wrapped, context) {
      const bytes = Buffer.from(wrapped);
      const iv = bytes.subarray(0, IV_BYTES);
      const tag = bytes.subarray(bytes.length - TAG_BYTES);
      const decipher = createDecipheriv("aes-256-gcm", masterKey, iv).setAAD(Buffer.from(context)).setAuthTag(tag);
      return Buffer.concat([decipher.update(bytes.subarray(IV_BYTES, bytes.length - TAG_BYTES)), decipher.final()]);
    },
  };
}
