// An authenticator app, for the tests: the RFC 6238 code (HMAC-SHA1, 30-second steps) of an `otpauth://` URI's secret.
import { createHmac } from "node:crypto";

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(text: string): Buffer {
  let bits = "";
  for (const c of text.replace(/=+$/, "").toUpperCase()) bits += BASE32.indexOf(c).toString(2).padStart(5, "0");
  const bytes = bits.match(/.{8}/g) ?? [];
  return Buffer.from(bytes.map((b) => parseInt(b, 2)));
}

/** The code an authenticator app shows for `totpURI` at `at` (now, unless given). */
export function totpCode(totpURI: string, at = Date.now()): string {
  const url = new URL(totpURI);
  const secret = base32Decode(url.searchParams.get("secret")!);
  const digits = Number(url.searchParams.get("digits") ?? 6);
  const period = Number(url.searchParams.get("period") ?? 30);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / period)));
  const mac = createHmac("sha1", secret).update(counter).digest();
  const offset = mac[mac.length - 1]! & 0xf;
  const value = (mac.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits;
  return String(value).padStart(digits, "0");
}
