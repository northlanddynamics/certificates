// SHA-256 as the platform writes it everywhere it keeps or compares one: lower-case hex. What is hashed may be text
// (as UTF-8), such as a credential, a Shared Challenge or a script's content, or bytes.
import { createHash } from "node:crypto";

/** The SHA-256 of `data` (text as UTF-8), lower-case hex. */
export const sha256Hex = (data: string | Uint8Array) => createHash("sha256").update(data).digest("hex");
