// A passkey, for the tests: a software WebAuthn authenticator holding one P-256 key, answering Better Auth's registration
// and authentication options as a browser would (attestation "none", user present and verified).
import { createHash, randomBytes, webcrypto } from "node:crypto";

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const sha256 = (data: Uint8Array | string) => createHash("sha256").update(data).digest();

/** Just enough CBOR (RFC 8949) for an attestation object and a COSE key: integers, byte and text strings, maps. */
function cbor(value: unknown): Buffer {
  const head = (major: number, n: number) => {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 256) return Buffer.from([(major << 5) | 24, n]);
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(n, 1);
    return b;
  };
  if (typeof value === "number") return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === "string") return Buffer.concat([head(3, Buffer.byteLength(value)), Buffer.from(value)]);
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), value]);
  if (value instanceof Map) return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])]);
  throw new Error(`cannot encode ${typeof value}`);
}

/** An ECDSA signature as WebCrypto gives it (r ‖ s), as WebAuthn wants it (ASN.1 DER). */
function derSignature(raw: Uint8Array): Buffer {
  const integer = (b: Uint8Array) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = Buffer.from(b.subarray(i));
    if (v[0]! & 0x80) v = Buffer.concat([Buffer.from([0]), v]);
    return Buffer.concat([Buffer.from([0x02, v.length]), v]);
  };
  const body = Buffer.concat([integer(raw.subarray(0, 32)), integer(raw.subarray(32))]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

export interface PasskeyDouble {
  /** The credential's id, as Better Auth stores it. */
  readonly credentialId: string;
  /** The browser's answer to registration options: a `PublicKeyCredential` as JSON. */
  register(options: { challenge: string; rp: { id?: string } }, origin: string): Promise<unknown>;
  /** The browser's answer to authentication options. */
  authenticate(options: { challenge: string; rpId?: string }, origin: string): Promise<unknown>;
}

export async function createPasskeyDouble(): Promise<PasskeyDouble> {
  const keys = (await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
  const jwk = await webcrypto.subtle.exportKey("jwk", keys.publicKey);
  const rawId = randomBytes(16);
  let counter = 0;

  const authenticatorData = (rpId: string, flags: number, attested?: Buffer) => {
    const count = Buffer.alloc(4);
    count.writeUInt32BE(++counter);
    return Buffer.concat([sha256(rpId), Buffer.from([flags]), count, ...(attested ? [attested] : [])]);
  };
  const clientData = (type: string, challenge: string, origin: string) => Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));

  return {
    credentialId: b64url(rawId),
    async register(options, origin) {
      const coseKey = cbor(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, "base64url")], [-3, Buffer.from(jwk.y!, "base64url")]]));
      const idLength = Buffer.alloc(2);
      idLength.writeUInt16BE(rawId.length);
      const attested = Buffer.concat([Buffer.alloc(16), idLength, rawId, coseKey]); // an all-zero AAGUID, as with attestation "none"
      // User present (0x01), user verified (0x04), attested credential data included (0x40).
      const authData = authenticatorData(options.rp.id ?? new URL(origin).hostname, 0x45, attested);
      const attestationObject = cbor(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
      return {
        id: b64url(rawId),
        rawId: b64url(rawId),
        type: "public-key",
        response: { clientDataJSON: b64url(clientData("webauthn.create", options.challenge, origin)), attestationObject: b64url(attestationObject), transports: ["internal"] },
        clientExtensionResults: {},
        authenticatorAttachment: "platform",
      };
    },
    async authenticate(options, origin) {
      const authData = authenticatorData(options.rpId ?? new URL(origin).hostname, 0x05);
      const clientDataJSON = clientData("webauthn.get", options.challenge, origin);
      const signature = await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, Buffer.concat([authData, sha256(clientDataJSON)]));
      return {
        id: b64url(rawId),
        rawId: b64url(rawId),
        type: "public-key",
        response: { clientDataJSON: b64url(clientDataJSON), authenticatorData: b64url(authData), signature: b64url(derSignature(new Uint8Array(signature))) },
        clientExtensionResults: {},
        authenticatorAttachment: "platform",
      };
    },
  };
}
