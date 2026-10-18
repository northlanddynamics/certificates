// AES-256-GCM as `iv ‖ ciphertext ‖ tag`, with associated data that must be presented again to open it.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const IV_BYTES = 12;
const TAG_BYTES = 16;

export function seal(key: Buffer, plaintext: Uint8Array, associatedData: Buffer): Buffer {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, iv).setAAD(associatedData);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, body, cipher.getAuthTag()]);
}

/** Throws when `sealed` was altered, or was sealed under another key or other associated data. */
export function open(key: Buffer, sealed: Uint8Array, associatedData: Buffer): Buffer {
  const bytes = Buffer.from(sealed);
  const iv = bytes.subarray(0, IV_BYTES);
  const tag = bytes.subarray(bytes.length - TAG_BYTES);
  const decipher = createDecipheriv("aes-256-gcm", key, iv).setAAD(associatedData).setAuthTag(tag);
  return Buffer.concat([decipher.update(bytes.subarray(IV_BYTES, bytes.length - TAG_BYTES)), decipher.final()]);
}
