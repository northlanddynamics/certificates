// The contract every Kms's signing keys keep: a key made for one context (an Organization's id) gives its public key
// and signs a digest that WebCrypto verifies, and is refused under any other context. The local KMS runs it in
// kms.test.ts; an AWS KMS or Azure Key Vault implementation runs it unchanged against its own service.
import { describe, expect, test } from "bun:test";
import { webcrypto } from "node:crypto";
import { KEY_ALGORITHMS, type KeyAlgorithm } from "../src/csr";
import { SIGNATURE_HASH, type Kms } from "../src/kms";

const IMPORT_PARAMS: Record<KeyAlgorithm, RsaHashedImportParams | EcKeyImportParams> = {
  "ecdsa-p256": { name: "ECDSA", namedCurve: "P-256" },
  "ecdsa-p384": { name: "ECDSA", namedCurve: "P-384" },
  "rsa-2048": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
  "rsa-3072": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
  "rsa-4096": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
};

async function verifies(algorithm: KeyAlgorithm, spki: Uint8Array, signature: Uint8Array, data: Uint8Array) {
  const params = IMPORT_PARAMS[algorithm];
  const key = await webcrypto.subtle.importKey("spki", new Uint8Array(spki), params, false, ["verify"]);
  return webcrypto.subtle.verify({ name: params.name, hash: SIGNATURE_HASH[algorithm] }, key, new Uint8Array(signature), new Uint8Array(data));
}

const digestOf = async (algorithm: KeyAlgorithm, data: Uint8Array) =>
  new Uint8Array(await webcrypto.subtle.digest(SIGNATURE_HASH[algorithm], new Uint8Array(data)));

export function kmsSigningContract(name: string, makeKms: () => Kms | Promise<Kms>) {
  describe(`${name}: signing keys`, () => {
    const ORG = "organization-a";
    const data = new TextEncoder().encode("the bytes of a certificate to be signed");

    test.each([...KEY_ALGORITHMS])("a %s key signs a digest that verifies under its public key", async (algorithm) => {
      const kms = await makeKms();
      const key = await kms.createSigningKey(algorithm, ORG);
      const spki = await kms.publicKey(key, ORG);
      const signature = await kms.sign(key, ORG, await digestOf(algorithm, data));

      expect(await verifies(algorithm, spki, signature, data)).toBe(true);
      expect(await verifies(algorithm, spki, signature, new TextEncoder().encode("other bytes"))).toBe(false);
    });

    test("a key is refused under any context but the one it was made for", async () => {
      const kms = await makeKms();
      const key = await kms.createSigningKey("ecdsa-p256", ORG);
      const digest = await digestOf("ecdsa-p256", data);

      await expect(kms.sign(key, "organization-b", digest)).rejects.toThrow();
      await expect(kms.publicKey(key, "organization-b")).rejects.toThrow();
      expect(await kms.sign(key, ORG, digest)).toBeInstanceOf(Uint8Array);
    });

    test("each key is its own", async () => {
      const kms = await makeKms();
      const first = await kms.createSigningKey("ecdsa-p256", ORG);
      const second = await kms.createSigningKey("ecdsa-p256", ORG);
      const signature = await kms.sign(first, ORG, await digestOf("ecdsa-p256", data));

      expect(await verifies("ecdsa-p256", await kms.publicKey(second, ORG), signature, data)).toBe(false);
    });

    test("a digest not made with the key algorithm's hash is refused", async () => {
      const kms = await makeKms();
      const key = await kms.createSigningKey("ecdsa-p384", ORG);

      await expect(kms.sign(key, ORG, await digestOf("ecdsa-p256", data))).rejects.toThrow();
    });
  });
}
